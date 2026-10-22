package stun

// TCP 出站保活链路管理器（每个 TCP 任务一个实例）：负责在运营商 CGNAT 上建立并维持
// TCP 映射的出站连接，按优先级选择通道：
//   1. STUN-over-TCP 长连接（配置的 + 维护列表 + 内置候选，排除单事务型）：取得精确映射地址
//   2. 双链路模式（参考 natmap，首选升级路径）：出站保活连接与映射探测分离——
//      从本地端口连接公共端点（qq/baidu 等）作为长寿命保活链路维持 NAT 映射，再用同端口
//      向 STUN/TCP 服务器新建短连接探测一次映射地址后即弃（即连即用，单事务型服务器完全可用）。
//      全锥/受限锥 NAT（EIM 端口保持）下同源端口的出站映射端口与目标无关，探测地址即保活链路的
//      真实映射；双源（两台不同 STUN 服务器）探测一致才确认为精确地址，
//      不一致为对称型特征（探测地址不代表保活链路映射）退端口保留展示
//   3. 公共出站端点（端口保留模式兜底）：无任何可用 STUN/TCP 服务器时，出站长连接仅维持
//      运营商 CGNAT 上的 TCP 映射，连接上不做应用层交互。外网映射端口无法直接探测，
//      由运行器取同本地端口的 UDP STUN 映射尽力估计展示
//
// 与 Java 的实现差异（语义等价适配）：
//   - Java 在监听开启前预绑定一批备用出站 socket（同端口、未连接），链路死亡时直接 connect
//     实现零监听中断重建；Go 标准库无法持有「已 bind 未 connect」的 TCP socket，改为
//     配额计数：openSpares 记入等效配额，轮换时经 dialBoundTCP 在 dial 时绑定同本地端口
//     （dialer 出生即带 SO_LINGER(0)，见 lingerControl；Linux 下与 LISTEN 同端口的 connected
//     绑定由具体实现放行，Windows 由绑定具体源地址兜底），配额仅用于保持 Java
//     「备用耗尽即放弃本轮」的耗散上界语义；「预绑定备用出站socket失败」告警在 Go 侧
//     无对应探测点，不会出现。
//   - abandon（SO_LINGER(0) 后 close 发 RST）：Go 侧连接出生即带 linger，Close 即 RST。

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// freshGraceMS 新链路宽限期：建立/重建刚完成交互验证，期内再交互只会白白翻动连接
// （重建后立即自测失败的根源）
const freshGraceMS = 8_000

// 单事务服务器黑名单持久化键（重启后仍生效，启动建链不再重选注定握不住映射的服务器）
const singleTxKey = "stun.tcpSingleTx"

// 双链路探测服务器持久化键（重启后优先复用，免去逐候选探测）
const probeServerKey = "stun.tcpProbeServer"

// 最近成功 STUN/TCP 服务器持久化键
const lastServerKey = "stun.tcpLastServer"

// punchLink 一条保活链路：连接 + 模式 + 端点 + 精确映射地址（端口保留模式为空）+ 建立时刻。
//   - viaStun=true 且 split=false：STUN 长连接，conn 即 STUN 连接，映射地址可反复交互刷新
//   - viaStun=true 且 split=true：双链路（natmap 式），conn 为公共端点保活连接，
//     mapped 为同端口 STUN 短连接探测所得（即连即弃，不可在 conn 上刷新）；
//     映射随保活连接存活而恒定，保活连接死亡重建后需重探测刷新
//   - viaStun=false：端口保留模式（无可用 STUN/TCP），mapped 恒为空
type punchLink struct {
	conn     *net.TCPConn
	viaStun  bool
	endpoint string
	mapped   string
	at       int64
	split    bool
}

// punch TCP 出站保活链路管理器
type punch struct {
	mu sync.Mutex // 等价 Java synchronized（方法级）

	taskName string
	stunHost string
	stunPort int
	srcIp    string
	onReady  func(*punchLink) // 链路就绪/映射地址变化回调（调用方据此更新权威展示地址与日志）

	current         *punchLink
	addrPresumed    bool   // 端口保留模式：展示地址语义为「出口IP:本地端口」
	tcpStunServer   string // 最近成功的 STUN-over-TCP 服务器（host:port），重建链路时优先复用
	outEndpoint     string // 最近成功的出站连接端点（host:port），重建链路时优先复用
	probeFailAt     int64  // STUN/TCP 候选最近一次整体失败时刻：退避期内跳过 STUN 探测直接用公共出站端点
	downWarned      bool   // 链路死亡已告警标志（避免每个保活周期重复刷屏，重建成功后复位）
	spareBudget     int    // 备用配额（等价 Java 预绑备用 socket 数量，见文件头差异说明）
	warnedEndpoints map[string]bool
	singleTx        map[string]bool
	// currentKeepalives 当前链路已完成的保活交互次数：为 0 即死亡 = 单事务型服务器特征
	currentKeepalives int
	probeServer       string // 最近成功的双链路探测服务器（host:port），重建/重探测时优先复用
	lastSplitMapped   string // 最近一次双链路精确映射地址：独立于链路对象跟踪（链路死亡/关闭后仍保留）
}

// newPunch 构造链路管理器；读取持久化的单事务黑名单与探测服务器
func newPunch(taskName, srcIp, stunHost string, stunPort int, onReady func(*punchLink)) *punch {
	p := &punch{
		taskName:        taskName,
		srcIp:           srcIp,
		stunHost:        stunHost,
		stunPort:        stunPort,
		onReady:         onReady,
		warnedEndpoints: map[string]bool{},
		singleTx:        map[string]bool{},
	}
	for _, x := range strings.Split(loadConfigQuiet(singleTxKey), ",") {
		if x = strings.TrimSpace(x); x != "" {
			p.singleTx[x] = true
		}
	}
	if v := loadConfigQuiet(probeServerKey); v != "" && strings.LastIndex(v, ":") > 0 {
		p.probeServer = v
	}
	return p
}

// loadConfigQuiet 读取 app_config，失败返回空串（不影响主流程）
func loadConfigQuiet(key string) string {
	v, err := core.GetConfig(key)
	if err != nil {
		return ""
	}
	return v
}

// punchAddrPresumed 端口保留模式：展示地址语义为「出口IP:本地端口」（外部端口=本地源端口假设）
func (p *punch) punchAddrPresumed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrPresumed
}

// splitActive 当前链路是否双链路模式（natmap 式：出站端点保活 + STUN 短连接探测的精确映射）
func (p *punch) splitActive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current != nil && p.current.split
}

// allowStunNow STUN/TCP 候选是否已过退避期（整体失败 300 秒后允许再试）
func (p *punch) allowStunNow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allowStunNowLocked()
}

func (p *punch) allowStunNowLocked() bool {
	return time.Now().UnixMilli()-p.probeFailAt > 300_000
}

// keepaliveOnce 当前链路交互一次（保活 + 存活验证）。
// 新链路宽限：建立/重建刚成功即完成过交互验证，期内直接返回存活，不重复翻动连接。
// STUN 精确模式：存活优先——先做 TCP 级存活检测（短超时读：EOF/复位=死亡，超时=存活）。
// 连接存活时在原连接上做刷新交互：映射挂在原四元组上，外部端口恒定不漂移，
// 发包本身即刷新沿途 NAT；服务器对二次请求无响应但连接仍存活时视为映射随连接保活；
// 仅当连接确已死亡（实测公共服务器多为单事务型，响应后约 1 秒内 RST/FIN 断开）
// 才从同本地端口轮换新建连接；轮换失败返回 false，由调用方走备用/弹跳重建流程。
// 出站端点模式（端口保留/双链路）：出站长连接存活即运营商 CGNAT 映射存活——先做 TCP 级
// 存活检测，存活直接返回；死亡时先 RST 废弃旧连接释放四元组，再同端口轮换新建出站连接
// （端点可能为单事务/短空闲超时类型，死亡轮换是该模式常态，静默完成不打日志）。
func (p *punch) keepaliveOnce() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.current
	if cur == nil {
		return false
	}
	if time.Now().UnixMilli()-cur.at < freshGraceMS {
		return true // 新建链路刚验证过，无需再交互
	}
	if cur.viaStun && !cur.split { // split 双链路的 conn 是端点保活连接（非 STUN），走下方端点分支
		if linkAlive(cur.conn) {
			// 连接存活：在原连接上刷新交互（映射挂在原四元组上，外部端口恒定，避免重建即漂移）
			mapped := bindingOverTcp(cur.conn, 3000)
			if mapped != "" {
				p.current = &punchLink{conn: cur.conn, viaStun: true, endpoint: cur.endpoint, mapped: mapped, at: cur.at}
				p.currentKeepalives++
				if mapped != cur.mapped {
					p.onReady(p.current) // 映射漂移：更新权威展示地址
				}
				return true
			}
			if linkAlive(cur.conn) {
				p.currentKeepalives++
				return true // 服务器不应答二次请求但连接存活：映射随连接保活，地址不变
			}
		}
		// 连接已死（服务器单事务断开/网络切换）：同本地端口轮换新建连接重建映射
		if p.currentKeepalives == 0 {
			p.markSingleTx(cur.endpoint) // 从未存活过一个保活周期：单事务型服务器
		}
		ep := cur.endpoint
		if p.singleTx[ep] {
			for _, c := range p.stunCandidates() {
				ep = c
				break
			} // 改选持久型候选，避免反复轮换到单事务服务器
		}
		localPort := cur.conn.LocalAddr().(*net.TCPAddr).Port
		_ = cur.conn.Close() // 出生即带 SO_LINGER(0)：Close 即 RST
		p.current = nil
		rotated := p.rotateStun(localPort, ep)
		if rotated != nil {
			p.downWarned = false
			p.tcpStunServer = ep
			p.persistStunServer(ep)
			if rotated.mapped != cur.mapped {
				p.onReady(rotated) // 映射漂移：更新权威展示地址
			}
			return true
		}
		return false // 轮换失败（服务器不可达/无响应）：由调用方走备用/弹跳重建流程
	}
	if linkAlive(cur.conn) {
		p.currentKeepalives++
		return true // 保活长连接存活：CGNAT 映射存活，无需轮换（双链路/端口保留的映射地址均不变）
	}
	// 链路死亡：先废弃旧连接释放四元组，再轮换新建（当前端点优先，失败依次尝试其余候选）。
	// 双链路模式（split）下轮换成功后需重探测刷新精确映射（旧映射随旧连接失效）；
	// 端口保留模式在非退避期顺带尝试探测升级为双链路（地址从估计值精确化）
	localPort := cur.conn.LocalAddr().(*net.TCPAddr).Port
	if cur.split && cur.mapped != "" {
		p.lastSplitMapped = cur.mapped // 供重建后比对是否变化
	}
	_ = cur.conn.Close()
	p.current = nil
	for _, ep := range p.outboundCandidates() {
		// 等价 Java：优先消耗备用配额，配额耗尽回退新建绑定（Go 侧同一路径：dial 时绑定）；
		// 无配额且绑定被拒（监听占用）时放弃本轮，端点不可达则换下一候选
		hasSpare := p.pollSpareLocked()
		host, port := splitHostPort(ep)
		conn, err := dialBoundTCP(host, port, localPort, p.srcIp, 3000)
		if err != nil {
			if !hasSpare && isBindFailure(err) {
				return false // 等价 Java freshBound 绑定失败
			}
			continue // 端点不可达：换下一个端点（配额已耗即连接失败的 socket 无法复用）
		}
		link := &punchLink{conn: conn, viaStun: false, endpoint: ep, at: time.Now().UnixMilli()}
		p.outEndpoint = ep
		return p.installEndpointLink(link, localPort) != nil
	}
	return false
}

// installEndpointLink 登记端点链路并按需升级为双链路：曾取得过精确映射（lastSplitMapped 非空）或
// 端口保留模式下非退避期重探测一次精确映射——成功则升级/维持双链路，失败时曾为双链路则
// 保留旧探测值（下轮重探测修正），否则退回端口保留估计展示。
// 每个成功分支都必须回调 onReady：调用方（运行器）据此恢复「TCP映射已建立」就绪状态。
// 只在映射地址变化时回调会让链路重建后的就绪标志永久停在 false——外网映射实际可用
// 却持续报「TCP映射未建立」，这是自检误报 FAIL 的直接来源。
func (p *punch) installEndpointLink(base *punchLink, localPort int) *punchLink {
	prevMapped := p.lastSplitMapped
	var mapped string
	if p.allowStunNowLocked() {
		mapped = p.probeMappedOnce(localPort, true) // 监听已开：优先消耗备用配额
	}
	if mapped != "" {
		p.lastSplitMapped = mapped
		split := &punchLink{conn: base.conn, viaStun: true, endpoint: base.endpoint, mapped: mapped,
			at: time.Now().UnixMilli(), split: true}
		p.current = split
		p.addrPresumed = false
		p.downWarned = false
		p.currentKeepalives = 0
		p.onReady(split) // 就绪/映射变化：更新权威展示地址
		return split
	}
	if prevMapped != "" {
		// 退避期内探测不可用：保留旧探测值（地址可能已随旧连接失效，退避期结束后下轮重探测修正）
		split := &punchLink{conn: base.conn, viaStun: true, endpoint: base.endpoint, mapped: prevMapped,
			at: time.Now().UnixMilli(), split: true}
		p.current = split
		p.addrPresumed = false
		p.downWarned = false
		p.currentKeepalives = 0
		p.onReady(split)
		return split
	}
	// 端口保留模式：展示地址语义为「出口IP:本地端口」，回退调用方跟随同端口 UDP STUN 映射修正
	p.current = base
	p.addrPresumed = true
	p.onReady(base)
	return base
}

// linkAliveNow 当前链路是否存活（只读探测，不改变链路状态）：供运行器在就绪标志可能滞后时校正。
func (p *punch) linkAliveNow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current != nil && linkAlive(p.current.conn)
}

// probeMappedOnce 双链路重探测：从同本地端口向 STUN/TCP 服务器新建短连接探测一次精确映射。
// 优先用上次探测成功的服务器（快路径），失败顺延下一候选（限 2 个控制耗时）。
// 探测连接即连即弃（RST 释放），不占用保活链路。
func (p *punch) probeMappedOnce(localPort int, useSpare bool) string {
	tried := 0
	for _, addr := range p.stunProbeCandidates() {
		if tried++; tried > 2 {
			break // 限制耗时：重探测是保活周期的附带动作，不占过多预算
		}
		if m := p.probeOnce(addr, localPort, useSpare); m != "" {
			p.probeServer = addr
			p.persistProbeServer(addr)
			return m
		}
	}
	return ""
}

// probeOnce 单次短连接探测：新建同端口连接 → 绑定交互 → RST 释放，失败返回空串。
// useSpare 在 Java 中区分「消耗预绑备用/新建绑定」；Go 侧无预绑 socket，dial 时绑定等价
// 两条路径（备用耗尽也回退新建绑定），故仅保留参数语义不消耗配额。
func (p *punch) probeOnce(addr string, localPort int, useSpare bool) string {
	_ = useSpare
	host, port := splitHostPort(addr)
	// 探测连接交互后由本函数关闭；出生即带 linger，Close 即 RST 复位即弃：
	// 单事务型服务器本就活不长，长连接型也不作保活用
	conn, err := dialBoundTCP(host, port, localPort, p.srcIp, 2500)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }() // 交互完成后即弃：单事务型服务器本就活不长，长连接型也不作保活用
	return bindingOverTcp(conn, 2500)   // 连接异常/无响应返回空串
}

// persistProbeServer 持久化最近成功的双链路探测服务器：重启后优先复用
func (p *punch) persistProbeServer(addr string) {
	_ = core.SetConfig(probeServerKey, addr) // 写入失败不影响主流程：运行期内仍有内存态兜底
}

// rotateStun STUN 精确模式轮换重建：旧连接死亡后从同一本地端口新建出站连接做一次绑定交互。
// 本地端口必须与监听一致（CGNAT 映射挂在出站五元组上）。失败返回 nil（由调用方走重建流程）。
func (p *punch) rotateStun(localPort int, endpoint string) *punchLink {
	p.pollSpareLocked() // 有备用则消耗一个配额（Java 预绑 socket 在此场景直接 connect）
	host, port := splitHostPort(endpoint)
	conn, err := dialBoundTCP(host, port, localPort, p.srcIp, 3000)
	if err != nil {
		return nil
	}
	mapped := bindingOverTcp(conn, 3000)
	if mapped != "" {
		link := &punchLink{conn: conn, viaStun: true, endpoint: endpoint, mapped: mapped, at: time.Now().UnixMilli()}
		p.current = link
		p.currentKeepalives = 0
		return link
	}
	_ = conn.Close() // 轮换失败：交由调用方重建流程处理（备用重连/弹跳）
	return nil
}

// linkAlive 出站长连接的 TCP 级存活检测：短超时读，超时（无数据且无复位）=存活，EOF/IO 异常=死亡。
// connect-only 模式连接上无应用层流量，常态即「无数据可读」；已关闭的旧连接读立即得 EOF。
func linkAlive(conn *net.TCPConn) bool {
	if conn == nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	b := make([]byte, 1)
	n, err := conn.Read(b)
	if err != nil {
		// 超时（无数据无复位）=存活；其余错误（EOF/复位/IO 异常）=死亡
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return true
		}
		return false
	}
	if n == 0 {
		return true
	}
	// 有数据到达（多为迟到的上一事务响应，预期外但证明链路存活）：全部读掉保持流对齐，
	// 只吞 1 字节会使后续绑定交互的报文头解析错位（被误判为交互无响应）
	for {
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := conn.Read(b); err != nil {
			return true // 排空完成（超时=暂无更多数据）或读取异常（不影响存活判定）
		}
	}
}

// markSingleTx 标记单事务型 STUN/TCP 服务器（首次告警）：持久化黑名单并清空最近成功记录，避免快速路径重选。
// 黑名单仅约束长连接保活链路的选择（单事务连接活不过一个保活周期、映射随轮换漂移）；
// 双链路的短连接探测不受限（即连即用即弃，单事务型完全可用，见 stunProbeCandidates）。
func (p *punch) markSingleTx(ep string) {
	if !p.singleTx[ep] {
		p.singleTx[ep] = true
		core.LogWarn(core.LogStun, "任务["+p.taskName+"] STUN/TCP服务器 "+ep+
			" 为单事务型(响应后即断连)，不宜作保活长连接(映射随轮换漂移)，降权改选持久型；仍可用作双链路短连接探测")
		var keys []string
		for k := range p.singleTx {
			keys = append(keys, k)
		}
		_ = core.SetConfig(singleTxKey, strings.Join(keys, ",")) // 持久化失败不影响主流程
	}
	if ep == p.tcpStunServer {
		p.tcpStunServer = ""
	}
}

// diedQuickly 单事务判定：绑定响应后稍候再做存活检测——单事务型服务器响应后即 RST 断连
// （实测约 1 秒），持久型服务器保持连接存活。只有持久型才值得作为保活链路。
func diedQuickly(conn *net.TCPConn) bool {
	time.Sleep(1600 * time.Millisecond)
	return !linkAlive(conn)
}

// noteLinkDownIfNeeded 链路已死亡时的提示（每个死亡周期只告警一次，重建成功自动复位）
func (p *punch) noteLinkDownIfNeeded() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.downWarned {
		p.downWarned = true
		core.LogWarn(core.LogStun, "任务["+p.taskName+"] TCP保活链路失效(交互无响应)，重建出站链路")
	}
}

// establishEx 全新建立出站链路（新连接，从指定本地端口出站）：依次尝试 STUN/TCP 候选
// （allowStun=false 时跳过，用于退避期），全部失败回退公共出站端点。成功登记为当前链路
// 并回调 onReady；失败返回 nil。本地端口必须尚未被监听占用（LISTEN 存在时无法 bind）。
// budgetMs 为时间预算：STUN/TCP 候选逐个探测（被封锁/失效候选每个都要等满连接与交互超时，
// 全表 20+ 个候选总耗时可达数分钟），超预算即跳出候选循环直接回退公共出站端点
// （仅 6 个、耗时有界），避免把弹跳窗口与调用线程拖到分钟级。
func (p *punch) establishEx(localPort int, allowStun bool, budgetMs int64) *punchLink {
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline := time.Now().UnixMilli() + budgetMs
	if allowStun {
		for _, addr := range p.stunCandidates() {
			if time.Now().UnixMilli() >= deadline {
				break // 预算耗尽：不再逐个等超时，直接回退公共端点
			}
			host, port := splitHostPort(addr)
			pr := probeOverTcp(host, port, p.srcIp, localPort, 2500)
			if pr != nil {
				if diedQuickly(pr.conn) {
					// 绑定有响应但连接随即断开：单事务服务器，注定握不住映射（建立的地址也在数秒内失效），
					// 拉黑换下一候选，避免每次（重）启动都先展示一个马上失效的映射地址
					p.markSingleTx(addr)
					_ = pr.conn.Close()
					continue
				}
				p.tcpStunServer = addr
				p.probeFailAt = 0
				p.persistStunServer(addr)
				return p.install(&punchLink{conn: pr.conn, viaStun: true, endpoint: addr,
					mapped: pr.mapped, at: time.Now().UnixMilli()})
			}
		}
		// natmap 双链路升级：长连接候选全败后，改用「短连接探测」——同端口向 STUN/TCP
		// 服务器即连即用即弃，单事务型服务器完全可用；双源一致才作为精确映射（见 probeSplitMapped）
		var splitMapped string
		if time.Now().UnixMilli() < deadline-15_000 { // 预留端点连接预算，避免启动拖到分钟级
			splitMapped = p.probeSplitMapped(localPort, deadline-15_000)
		}
		if splitMapped != "" {
			p.lastSplitMapped = splitMapped
		} else {
			if time.Now().UnixMilli()-p.probeFailAt > 300_000 {
				// 刚进入新的退避期才告警（含首次）：避免每个保活周期重复刷屏
				core.LogWarn(core.LogStun, "任务["+p.taskName+"] 长连接与短连接探测均无可用STUN-over-TCP服务器，"+
					"回退端口保留模式(公共端点出站维持CGNAT映射，展示端口取同端口UDP STUN估计、"+
					"入站不保证可达；登记可用TCP STUN服务器可获得精确映射)")
			}
			p.probeFailAt = time.Now().UnixMilli()
		}
		return p.establishEndpoint(localPort, splitMapped)
	}
	return p.establishEndpoint(localPort, "")
}

// establishEndpoint 端点连接段（双链路保活段/端口保留兜底）：依次连接公共出站端点，
// 探测到精确映射则升级双链路
func (p *punch) establishEndpoint(localPort int, splitMapped string) *punchLink {
	for _, ep := range p.outboundCandidates() {
		host, port := splitHostPort(ep)
		conn, err := dialBoundTCP(host, port, localPort, p.srcIp, 2500)
		if err != nil {
			// 端点失效原因告警仅首次：端点被网络策略拦截时无法从外部观察，这是定位关键
			key := host + ":" + strconv.Itoa(port)
			if !p.warnedEndpoints[key] {
				p.warnedEndpoints[key] = true
				core.LogWarn(core.LogStun, "任务["+p.taskName+"] TCP出站端点不可用("+key+"): "+err.Error())
			}
			continue
		}
		p.outEndpoint = host + ":" + strconv.Itoa(port)
		delete(p.warnedEndpoints, p.outEndpoint) // 端点恢复可用：复位告警以便下次失效再提示
		if splitMapped != "" {
			// 双链路（natmap 式）：端点连接仅负责保活，展示地址用同端口 STUN 短连接探测所得
			// （EIM 端口保持 NAT 下同源端口的出站映射与目标无关，二者为同一映射）
			return p.install(&punchLink{conn: conn, viaStun: true, endpoint: p.outEndpoint,
				mapped: splitMapped, at: time.Now().UnixMilli(), split: true})
		}
		return p.install(&punchLink{conn: conn, viaStun: false, endpoint: p.outEndpoint,
			at: time.Now().UnixMilli()})
	}
	return nil
}

// probeSplitMapped 双链路探测（natmap 式）：从同本地端口向 STUN/TCP 服务器新建短连接探测映射地址，
// 依次取两台不同服务器各探测一次——映射一致（EIM 端口保持特征）确认为保活链路的精确映射；
// 不一致是对称型特征返回空串退端口保留。仅一台可达时接受单源结果。
func (p *punch) probeSplitMapped(localPort int, deadline int64) string {
	var first string
	for _, addr := range p.stunProbeCandidates() {
		if time.Now().UnixMilli() >= deadline {
			break
		}
		m := p.probeOnce(addr, localPort, false) // 监听未开：新建绑定即可，备用留给监听开启后
		if m == "" {
			continue
		}
		if first == "" {
			first = m
			p.probeServer = addr
			p.persistProbeServer(addr)
			continue
		}
		if m == first {
			core.LogInfo(core.LogStun, "任务["+p.taskName+"] 双源STUN探测映射一致(端口保持/EIM特征): "+first+
				"，作为保活链路精确映射")
			return first
		}
		core.LogWarn(core.LogStun, "任务["+p.taskName+"] 不同STUN服务器探测映射不一致(对称型NAT特征): "+
			first+" vs "+m+"，探测地址不代表保活链路映射，退端口保留模式展示")
		return ""
	}
	if first != "" {
		core.LogInfo(core.LogStun, "任务["+p.taskName+"] STUN短连接探测: "+first+"（仅单源可达，未做双源校验）")
	}
	return first
}

// persistStunServer 持久化最近成功的 STUN/TCP 服务器：容器/任务重启后优先复用，免去逐候选探测的启动延迟
func (p *punch) persistStunServer(addr string) {
	_ = core.SetConfig(lastServerKey, addr) // 写入失败不影响主流程：运行期内仍有内存态兜底
}

// stunProbeCandidates 双链路探测候选（短连接即连即弃）：上次探测成功服务器优先（重启快路径）→
// 持久型优先的长连接候选 → 单事务型兜底。单事务型服务器在本模式下完全可用（不要求保持连接）。
func (p *punch) stunProbeCandidates() []string {
	all := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			all = append(all, v)
		}
	}
	add(p.probeServer)
	for _, c := range p.stunCandidates() {
		add(c)
	}
	for k := range p.singleTx { // 单事务型兜底：长连接黑名单仅约束保活链路选择，探测不受限
		add(k)
	}
	return all
}

// stunCandidates STUN-over-TCP 候选：上次成功服务器 → 持久化的上次成功（重启快路径） →
// 配置服务器 → 内置列表（实测可达优先） → 维护列表。
// 单事务型服务器降权：仅在无其他候选时兜底。
func (p *punch) stunCandidates() []string {
	all := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			all = append(all, v)
		}
	}
	add(p.tcpStunServer)
	if last := loadConfigQuiet(lastServerKey); last != "" && strings.LastIndex(last, ":") > 0 {
		add(last)
	}
	add(p.stunHost + ":" + strconv.Itoa(p.stunPort))
	// 内置列表按电信 CGNAT 实测可达排序，优先于维护列表：失效候选探测每个耗时数秒，
	// 维护列表历史种子多为 3478 端口（本类运营商封锁），排在后面仅作其他网络兜底
	for _, s := range tcpStunServers {
		add(s[0] + ":" + s[1])
	}
	for _, s := range tcpServers() {
		add(s[0] + ":" + s[1])
	}
	var kept []string
	for _, a := range all {
		if !p.singleTx[a] {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 {
		return all
	}
	return kept
}

// outboundCandidates 出站端点候选：最近成功的优先
func (p *punch) outboundCandidates() []string {
	list := []string{}
	if p.outEndpoint != "" {
		list = append(list, p.outEndpoint)
	}
	for _, ep := range keepaliveTCPEndpoints {
		v := ep[0] + ":" + ep[1]
		if p.outEndpoint == "" || p.outEndpoint != v {
			list = append(list, v)
		}
	}
	return list
}

// install 登记新链路并回调（端口保留模式地址由调用方在回调中组装展示）
func (p *punch) install(link *punchLink) *punchLink {
	p.current = link
	p.addrPresumed = !link.viaStun
	p.downWarned = false
	p.currentKeepalives = 0
	p.onReady(link)
	return link
}

// reconnect 链路死亡后重连：优先消耗备用配额（监听不中断），STUN 优先（非退避期且有过成功），
// 失败转公共出站端点；每次尝试恰好消耗一个备用配额，配额耗尽或全部失败返回 nil
// （由调用方决定弹跳重建）。
func (p *punch) reconnect(localPort int, allowStun bool) *punchLink {
	p.mu.Lock()
	defer p.mu.Unlock()
	if allowStun && p.tcpStunServer != "" && !p.singleTx[p.tcpStunServer] {
		if p.pollSpareLocked() {
			if link := p.connectStun(p.tcpStunServer, localPort); link != nil {
				return p.install(link)
			}
		}
	}
	for _, ep := range p.outboundCandidates() {
		if !p.pollSpareLocked() {
			return nil
		}
		if link := p.connectOutboundLink(ep, localPort); link != nil {
			return p.installEndpointLink(link, localPort)
		}
	}
	return nil
}

// reconnectAll 弹跳后用备用配额逐候选彻底重建：依次尝试全部 STUN/TCP 候选（非退避期）与
// 公共出站端点，每次尝试恰好消耗一个备用配额。与 reconnect 的区别：reconnect 仅尝试最近
// 成功的 STUN 服务器（快速路径），本方法遍历全部候选——弹跳刚在监听重开前的端口空闲窗口内
// 完成备用补充、配额充足，适合做一次彻底重建而不再占用监听端口。
// 配额耗尽或全部失败返回 nil（由调用方在下次弹跳时重新补充再试）。
func (p *punch) reconnectAll(localPort int, allowStun bool) *punchLink {
	p.mu.Lock()
	defer p.mu.Unlock()
	if allowStun {
		for _, addr := range p.stunCandidates() {
			if !p.pollSpareLocked() {
				return nil
			}
			if link := p.connectStun(addr, localPort); link != nil {
				p.tcpStunServer = addr
				p.persistStunServer(addr)
				return p.install(link)
			}
		}
		// 弹跳窗口备用充足：顺带做一次双源探测（长连接候选全败时升级双链路，单事务型可用）
		splitMapped := p.probeSplitMapped(localPort, time.Now().UnixMilli()+10_000)
		if splitMapped != "" {
			p.lastSplitMapped = splitMapped
			return p.establishEndpoint(localPort, splitMapped)
		}
		p.probeFailAt = time.Now().UnixMilli() // 全部候选失败：进入退避期，快速路径期间不再逐个探测
	}
	for _, ep := range p.outboundCandidates() {
		if !p.pollSpareLocked() {
			return nil
		}
		if link := p.connectOutboundLink(ep, localPort); link != nil {
			return p.installEndpointLink(link, localPort)
		}
	}
	return nil
}

// connectStun 用备用配额重连指定 STUN/TCP 服务器：失败返回 nil（配额已作废）
func (p *punch) connectStun(server string, localPort int) *punchLink {
	host, port := splitHostPort(server)
	conn, err := dialBoundTCP(host, port, localPort, p.srcIp, 3000)
	if err != nil {
		return nil // 服务器连接失败：备用配额作废
	}
	mapped := bindingOverTcp(conn, 3000)
	if mapped != "" {
		p.probeFailAt = 0
		return &punchLink{conn: conn, viaStun: true, endpoint: server, mapped: mapped, at: time.Now().UnixMilli()}
	}
	_ = conn.Close() // 无响应：连接作废
	return nil
}

// connectOutboundLink 用备用配额重连出站端点：TCP 连接建立（握手完成）即映射刷新成功，
// 通过返回链路，失败返回 nil。连接上不做应用层交互。
func (p *punch) connectOutboundLink(ep string, localPort int) *punchLink {
	host, port := splitHostPort(ep)
	conn, err := dialBoundTCP(host, port, localPort, p.srcIp, 3000)
	if err != nil {
		return nil // 端点不可达：换下一个端点
	}
	p.outEndpoint = host + ":" + strconv.Itoa(port)
	return &punchLink{conn: conn, viaStun: false, endpoint: p.outEndpoint, at: time.Now().UnixMilli()}
}

// openSpares 补充备用配额：必须在监听开启前完成（等价 Java 预绑定窗口）。
// 数量由调用方按内核同端口绑定容量上限约束；Go 侧无预绑探测点，绑定失败将在实际
// dial 时暴露（连接失败自然走候选切换/弹跳流程），此处仅记入配额。
func (p *punch) openSpares(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.spareBudget += count
}

// pollSpareLocked 消耗一个备用配额；调用方持锁
func (p *punch) pollSpareLocked() bool {
	if p.spareBudget > 0 {
		p.spareBudget--
		return true
	}
	return false
}

// closeLink 关闭当前链路（幂等，RST 复位以释放四元组），备用配额保留
func (p *punch) closeLink() {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.current
	p.current = nil
	if cur != nil {
		_ = cur.conn.Close()
	}
}

// drainSpares 废弃全部备用配额：换本地端口重试时旧端口备用已作废，
// 残留会被重连误用而从错误端口出站建映射
func (p *punch) drainSpares() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.spareBudget = 0
}

// closeAll 释放全部资源（任务停止时调用）
func (p *punch) closeAll() {
	p.closeLink()
	p.drainSpares()
}

// splitHostPort 拆解 "host:port" 候选串（host 为 IPv4/域名，不含冒号）
func splitHostPort(addr string) (string, int) {
	ci := strings.LastIndex(addr, ":")
	if ci <= 0 {
		return addr, 0
	}
	port, _ := strconv.Atoi(addr[ci+1:])
	return addr[:ci], port
}
