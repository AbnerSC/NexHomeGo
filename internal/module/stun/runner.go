package stun

// STUN 穿透任务运行器（每个任务一个实例），穿透通道承载 UDP / TCP 两类数据转发。
// 复刻 Java StunRunner，纯标准库实现。
//
// UDP 模式：在绑定端口上打开 UDP Socket，持续向 STUN 服务器发送绑定请求
// 建立并保活 NAT 映射；外网发入映射端口的数据包按会话转发到目标内网服务，
// 响应沿原路回传给对端（简易会话表实现）。
//
// TCP 模式（多级 NAT/运营商 CGNAT 场景按优先级自动选择出站通道，详见 punch.go）：
//  1. 路由器 WAN 口为公网：UPnP 端口映射即权威入站通道（外网端口=本地端口），跳过出站探测
//  2. 存在持久型 STUN-over-TCP 服务器：长连接保活 + 原连接刷新交互，取得精确映射地址
//  3. 双链路模式（出站保活 + STUN 短连接探测，双源一致确认精确映射）
//  4. 端口保留模式（兜底）：出站连公共透传端点维持 CGNAT 映射，展示取同端口 UDP STUN 估计
//
// 出站保活长连接与本地监听共用同一端口（SO_REUSEADDR 允许已连接 socket 与 LISTEN socket 共存）：
// 长连接维持沿途全部 NAT 的映射不回收，外网连入由监听 accept 后管道化转发到目标服务。
// 配置了「对端公网地址」时额外周期性从同端口主动向对端打洞（双端 NAT 建立过滤条目）。
//
// 地址权威性：UDP 任务与 STUN/TCP 精确映射展示真实探测的映射地址；端口保留模式展示
// 「UDP STUN 映射地址（同本地端口）」——实测本类运营商 CGNAT 对同一本地端口的 TCP/UDP 出站
// 分配的外部端口并不相同，该展示仅为尽力而为的估计，入站不保证可达；
// UDP STUN 暂无响应时退回「出口 IP + 本地端口」占位。UPnP 仅打通家用路由器一层，
// 运营商 CGNAT 层的映射端口不受 UPnP 控制，因此 WAN 非公网时绝不用 UPnP 外部端口拼装展示地址。
//
// 可用性自测：验证「映射保活存活」而非回环连通，并按 NAT 类型给出入站可达性结论。
// TCP 自测另验「公网入站可达」：优先本机直连穿透出的公网 IP:端口（hairpin 回流），
// 直连失败退回第三方探测节点真实连接映射地址验证（手动自测必验）。
//
// 周期巡检：仅按保活健康度触发重建，不因回环自测超时反复重新穿透丢弃可用映射；
// TCP 映射缺失时退避重试出站探测。
// 局限性：对称型 NAT（Symmetric）下 UDP 映射端口随机，纯 STUN 无法稳定穿透。
//
// 与 Java 的实现差异：
//   - spareCapacity 同端口绑定容量探测移除（Go 无「已 bind 未 connect」socket，备用改为 dial 时绑定，
//     见 punch.go 文件头说明）；openSpares 直接记入 TCP_SPARES 配额。
//   - TCP 监听 backlog 256：Go 标准库监听使用内核默认 backlog（Linux SOMAXCONN），不小于 256，无需设置。
//   - Java Tasks.every 可调度的保活/打洞/巡检任务在 Go 侧由 runner 自管 goroutine + stop channel
//     （core.Every 无取消句柄），串行防重入语义一致（上一轮未结束跳过本轮）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"NexHomeGo/internal/core"
)

// tcpSpares 备用出站配额数：端口保留模式仅在保活检测发现链路死亡时消耗一个配额轮换
// 新建出站连接（连接存活期间不消耗）。端点若为短空闲超时类型会周期性死亡轮换，
// 60 个可支撑较长时间才需弹跳一次。
const tcpSpares = 60

// WAN 腿 socket 显式发送/接收缓冲（字节）：CGNAT/移动宽带链路 RTT 高（实测可达 200ms），
// 内核自动扩窗在短连接上来不及涨到线速所需的带宽时延积（BDP=带宽×RTT，50Mbps×200ms≈1.25MB）。
// 显式给足 4MB 让单流一次爬坡即可填满 BDP。注意：显式设置会关闭该 socket 的内核自动调优，
// 故取值须覆盖「上行带宽×最大 RTT」并留余量，过小反而封死窗口上限。
const (
	wanSoSndBuf = 4 * 1024 * 1024
	wanSoRcvBuf = 4 * 1024 * 1024
)

// stunFullCycle 保活分级周期：每 N 个保活周期做一次全候选兜底轮询，
// 其余周期仅发包给配置+最近响应服务器
const stunFullCycle = 5

// 公网入站验证专用串行执行队列（第三方 API 响应可达数十秒，绝不能占用全局调度池——
// 占用会延迟保活导致 CGNAT 映射超时被回收：穿透静默失效的直接诱因），周期验证异步执行只留上次结论
var (
	extCheckQueue    = newSerialExec("stun-ext-check")
	tcpRebuildExec   = newSerialExec("stun-tcp-rebuild")
	extCheckHTTP     = &http.Client{Timeout: 13 * time.Second}
	serialExecOnce   sync.Once
	serialExecQueues []*serialExec
)

// serialExec 单线程串行执行器（等价 Java newSingleThreadExecutor：任务排队不丢弃）
type serialExec struct {
	mu      sync.Mutex
	queue   []func()
	running bool
	name    string
}

func newSerialExec(name string) *serialExec {
	serialExecOnce.Do(func() {})
	e := &serialExec{name: name}
	serialExecQueues = append(serialExecQueues, e)
	return e
}

func (e *serialExec) submit(job func()) {
	e.mu.Lock()
	e.queue = append(e.queue, job)
	shouldRun := !e.running
	if shouldRun {
		e.running = true
	}
	e.mu.Unlock()
	if shouldRun {
		go e.drain()
	}
}

func (e *serialExec) drain() {
	for {
		e.mu.Lock()
		if len(e.queue) == 0 {
			e.running = false
			e.mu.Unlock()
			return
		}
		job := e.queue[0]
		e.queue = e.queue[1:]
		e.mu.Unlock()
		safeCall(job)
	}
}

func safeCall(job func()) {
	defer func() {
		if r := recover(); r != nil {
			core.LogWarn(core.LogStun, "STUN 异步任务异常")
		}
	}()
	job()
}

// runner STUN 穿透任务运行器
type runner struct {
	id           int64
	name         string
	protocol     string
	targetIp     string
	targetPort   int
	stunHost     string
	stunPort     int
	bindPort     int
	keepaliveSec int
	peerAddr     string
	upnpEnabled  bool

	mu sync.Mutex // 等价 Java synchronized 方法（refreshTcpLink 等）

	// 映射状态（Java volatile 字段；updateMapped 用 mappingMu，避免与 punch 锁交叉死锁）
	mappingMu          sync.Mutex
	punched            atomic.Bool
	punchedMapped      string
	watchFails         int
	upnpWanAddr        atomic.Pointer[string]
	wanTcpReady        atomic.Bool
	addrPresumedPtr    atomic.Bool // 备用：punch.addrPresumed 的直接镜像（stop 判空需要）
	lastPeerInbound    atomic.Int64
	selfProbeUntil     atomic.Int64
	lastMappedAt       atomic.Int64
	udpMappedAddr      atomic.Pointer[string]
	lastMappedChangeAt atomic.Int64
	pendingMapped      string
	flapWarned         atomic.Bool
	upnpPublicWan      atomic.Bool
	tcpMappedViaUpnp   atomic.Bool
	tcpRefreshing      atomic.Bool
	warnedKeepaliveMu  sync.Mutex
	warnedKeepalive    map[string]bool
	lastExtCheckAt     atomic.Int64
	lastExtReachable   atomic.Int64 // -1=未判定 0=不可达 1=可达
	extCheckRunning    atomic.Bool

	upnpGateway *gateway
	upnpMapped  bool
	upnpPort    int
	punch       *punch

	running    atomic.Bool
	udpSocket  *net.UDPConn
	tcpServer  *net.TCPListener
	sessions   map[string]*net.UDPConn
	sessionsMu sync.Mutex

	stopMu sync.Mutex
	stopCh chan struct{}
	taskWg sync.WaitGroup

	// STUN 服务器候选地址缓存（配置服务器 + 维护列表），60s 刷新：
	// 入站包判定与保活都高频使用，逐包查库成本过高
	candMu               sync.Mutex
	cachedStunCandidates []string
	cachedCandidatesAt   int64
	stunCycle            int
	lastStunOk           atomic.Pointer[string]
}

func strField(row *core.Row, key string) string {
	v := row.Get(key)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func intField(row *core.Row, key string) int {
	switch v := row.Get(key).(type) {
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

// newRunner 从任务行构造运行器
func newRunner(row *core.Row) *runner {
	r := &runner{
		id:              int64(intField(row, "id")),
		name:            strField(row, "name"),
		protocol:        strField(row, "protocol"),
		targetIp:        strField(row, "target_ip"),
		targetPort:      intField(row, "target_port"),
		stunHost:        strField(row, "stun_host"),
		stunPort:        intField(row, "stun_port"),
		bindPort:        intField(row, "bind_port"),
		keepaliveSec:    intField(row, "keepalive_sec"),
		peerAddr:        strings.TrimSpace(strField(row, "peer_addr")),
		upnpEnabled:     intField(row, "upnp_enabled") != 0,
		sessions:        map[string]*net.UDPConn{},
		warnedKeepalive: map[string]bool{},
	}
	if r.keepaliveSec < 10 {
		r.keepaliveSec = 10
	}
	return r
}

// isUdp 是否 UDP 协议任务
func (r *runner) isUdp() bool { return strings.EqualFold(r.protocol, "UDP") }

// start 启动穿透任务（启动中途异常时释放已建立的 UPnP 映射，避免路由器残留）
func (r *runner) start() error {
	r.running.Store(true)
	r.punched.Store(false)
	r.wanTcpReady.Store(false)
	empty := ""
	r.upnpWanAddr.Store(&empty)
	r.upnpPublicWan.Store(false)
	r.tcpMappedViaUpnp.Store(false)
	r.tcpRefreshing.Store(false)
	r.stopCh = make(chan struct{})
	// 出站源 IP（通配绑定被拒时的具体地址兜底，Windows 监听后解锁同端口绑定，natmap 同款）
	r.punch = newPunch(r.name, r.lanIp(), r.stunHost, r.stunPort, r.onTcpLinkReady)
	var err error
	if r.isUdp() {
		err = r.startUdp()
	} else {
		err = r.startTcp()
	}
	if err != nil {
		r.stop() // 释放 socket 与已建立的 UPnP 映射，防止启动失败残留路由器映射
		return err
	}
	r.updateStatus("RUNNING")
	core.LogInfo(core.LogStun, "穿透任务["+r.name+"] 已启动 ("+r.protocol+")")
	// 启动后自测一次并记录结果（仅验证映射保活存活，不触发自动重穿，理由见文件头）
	core.Delay(2, r.verifyQuietly)
	// 周期巡检：按保活健康度监测映射，静默失效时自动重建
	r.startWatcher()
	return nil
}

// verifyQuietly 静默执行一次可用性自测（结果仅记录，异常不打断调度）
func (r *runner) verifyQuietly() {
	if !r.running.Load() {
		return
	}
	if _, err := r.verifyChannel(false); err != nil {
		core.LogWarn(core.LogStun, "任务["+r.name+"] 可用性自测异常: "+err.Error())
	}
}

// detectNatWithFallback NAT 类型探测：配置的服务器不可达（域名失效/被墙）时回退到维护列表候选服务器，
// 保证 NAT 类型与外网映射地址展示不受单点服务器故障影响。
func (r *runner) detectNatWithFallback(conn *net.UDPConn) *stunResult {
	res := detectNatType(conn, r.stunHost, r.stunPort, 3000)
	if res != nil && res.mapped != "" {
		return res
	}
	for _, addr := range r.stunServerCandidates() {
		host, port := splitHostPort(addr)
		f := detectNatType(conn, host, port, 3000)
		if f != nil && f.mapped != "" {
			return f
		}
	}
	return res
}

func (r *runner) startUdp() error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: r.bindPort})
	if err != nil {
		return err
	}
	r.udpSocket = conn

	// 首次 STUN 探测：建立 NAT 映射并识别 NAT 类型
	res := r.detectNatWithFallback(conn)
	mapped, natType := "", "Unknown"
	if res != nil {
		mapped, natType = res.mapped, res.natType
	}
	r.updateMapped(mapped, natType, false)
	core.LogInfo(core.LogStun, "任务["+r.name+"] NAT类型: "+natType+"，映射地址: "+orNone(mapped))

	// 配合 UPnP：在路由器上显式开放入站端口，对称/受限 NAT 下外网也可主动连入
	if r.upnpEnabled {
		r.applyUpnpMapping(conn.LocalAddr().(*net.UDPAddr).Port, false)
	} else {
		core.LogInfo(core.LogStun, "任务["+r.name+"] UPnP端口映射已按任务配置关闭，仅依赖STUN打洞")
	}
	r.startUdpReceiver(true)
	r.startKeepalive()
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "无"
	}
	return s
}

// startUdpReceiver UDP 接收线程：STUN 响应仅用于刷新映射地址；
// relayData=true 时其余数据包按会话转发到内网目标（UDP 模式）。
func (r *runner) startUdpReceiver(relayData bool) {
	r.trackTask(func() {
		buf := make([]byte, 65535)
		for r.running.Load() && r.udpSocket != nil {
			_ = r.udpSocket.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, src, err := r.udpSocket.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue // 超时继续循环
				}
				if r.running.Load() {
					core.LogWarn(core.LogStun, "任务["+r.name+"] UDP接收异常: "+err.Error())
					return
				}
				continue
			}
			stunSrc := r.stunCandidateOf(src.IP, src.Port)
			if stunSrc != "" {
				// 保活响应（配置的或兜底 STUN 服务器）：刷新外网映射地址并记录响应来源（常规周期优先向它续命）
				mapped := parseBindingMapped(buf[:n])
				if mapped != "" {
					v := stunSrc
					r.lastStunOk.Store(&v)
					r.updateUdpMapped(mapped, "")
				}
				continue
			}
			if relayData {
				// 真实对端数据到达（非STUN响应）：通道实际在用的证据，巡检据此避免误重穿丢端口
				r.lastPeerInbound.Store(time.Now().UnixMilli())
				r.forwardToTarget(buf[:n], src)
			}
		}
	})
}

// startKeepalive 周期保活：周期性刷新 NAT 映射防止超时回收。
// UDP 模式向配置的与兜底的 STUN 服务器发绑定请求（响应由接收线程解析刷新映射地址）；
// TCP 模式周期刷新保活链路：STUN 精确模式存活优先，端口保留模式检测出站长连接存活、死亡即轮换。
func (r *runner) startKeepalive() {
	tcpMode := !r.isUdp()
	tick := r.keepaliveSec
	if tcpMode && tick > 10 {
		tick = 10 // TCP 刷新 tick=min(keepaliveSec,10)
	}
	// UDP 绑定保活两模式都需要：UDP 模式维持映射；TCP 模式维持同端口 STUN 映射（展示与锥形回连）
	r.startTicker(tick, func() {
		r.repunchUdpMapping()
		// UPnP 公网直通时无需刷新 STUN/TCP 映射（刷新需短暂关监听，会造成入站中断与自测误报）
		if tcpMode && !r.upnpPublicWan.Load() {
			r.refreshTcpLink()
		}
	})
}

// repunchUdpMapping 刷新 UDP STUN 映射（保活/重新穿透共用），分级发包（参考 natmap -c 周期思想）：
// 常规周期仅向配置服务器与最近响应服务器发绑定请求（fire-and-forget，响应由接收线程
// 解析后刷新映射地址）——既维持映射又降低多服务器响应引起的地址抖动与服务器负载；
// 每 stunFullCycle 个周期向全部候选兜底轮询一次，配置服务器单点失效时自动切换。
func (r *runner) repunchUdpMapping() {
	if r.udpSocket == nil {
		return
	}
	var targets []string
	r.stunCycle++
	if r.stunCycle%stunFullCycle == 0 {
		targets = r.stunServerCandidates() // 全候选兜底轮询：服务器故障自动切换，保持单点失效自愈能力
	} else {
		targets = []string{r.stunHost + ":" + strconv.Itoa(r.stunPort)}
		if v := r.lastStunOk.Load(); v != nil && *v != "" {
			targets = append(targets, *v) // 最近响应的服务器优先续命（映射挂在它认识的会话上）
		}
	}
	for _, addr := range targets {
		host, port := splitHostPort(addr)
		if err := sendBindingRequest(r.udpSocket, host, port); err != nil {
			// 失效服务器（如域名已注销）每次保活都会解析失败，仅首次告警避免刷屏
			r.warnedKeepaliveMu.Lock()
			_, warned := r.warnedKeepalive[addr]
			r.warnedKeepalive[addr] = true
			r.warnedKeepaliveMu.Unlock()
			if !warned {
				core.LogWarn(core.LogStun, "任务["+r.name+"] STUN保活失败("+addr+"): "+err.Error())
			}
		}
	}
}

// stunServerCandidates STUN 服务器候选地址（host:port）：配置的服务器 + 维护列表中全部服务器
// （按维护排序兜底），结果缓存 60s
func (r *runner) stunServerCandidates() []string {
	r.candMu.Lock()
	defer r.candMu.Unlock()
	now := time.Now().UnixMilli()
	if len(r.cachedStunCandidates) == 0 || now-r.cachedCandidatesAt > 60_000 {
		seen := map[string]bool{}
		var list []string
		add := func(v string) {
			if !seen[v] {
				seen[v] = true
				list = append(list, v)
			}
		}
		add(r.stunHost + ":" + strconv.Itoa(r.stunPort))
		for _, s := range allServers() {
			add(s[0] + ":" + s[1])
		}
		r.cachedStunCandidates = list
		r.cachedCandidatesAt = now
	}
	return r.cachedStunCandidates
}

// stunCandidateOf 入站包是否来自任一候选 STUN 服务器（保活响应判定），是则返回匹配的候选地址（host:port）
func (r *runner) stunCandidateOf(ip net.IP, port int) string {
	for _, candidate := range r.stunServerCandidates() {
		host, cport := splitHostPort(candidate)
		if port != cport {
			continue
		}
		resolved, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			continue // 域名解析失败：视为不匹配，继续比较其余候选
		}
		if resolved.IP.Equal(ip) {
			return candidate
		}
	}
	return ""
}

// forwardToTarget UDP 业务数据转发：对端 -> 目标服务；目标响应经会话 socket 回流
func (r *runner) forwardToTarget(data []byte, peer *net.UDPAddr) {
	peerKey := peer.IP.String() + ":" + strconv.Itoa(peer.Port)
	r.sessionsMu.Lock()
	session, ok := r.sessions[peerKey]
	if !ok {
		target := &net.UDPAddr{IP: net.ParseIP(r.targetIp), Port: r.targetPort}
		if target.IP == nil {
			r.sessionsMu.Unlock()
			return
		}
		s, err := net.DialUDP("udp", nil, target) // 连接模式：只收发目标服务的包
		if err != nil {
			r.sessionsMu.Unlock()
			core.LogError(core.LogStun, "任务["+r.name+"] 创建会话失败: "+err.Error())
			return
		}
		session = s
		r.sessions[peerKey] = s
		core.LogInfo(core.LogStun, "任务["+r.name+"] 新会话: "+peerKey+" -> "+r.targetIp+":"+strconv.Itoa(r.targetPort))
		r.trackTask(func() { r.relayBack(s, peer, peerKey) })
	}
	r.sessionsMu.Unlock()
	if _, err := session.Write(data); err == nil {
		recordTraffic(r.id, int64(len(data))) // 入站方向（对端 -> 目标）计入流量
	}
}

// relayBack 目标服务响应回传对端，会话空闲 120 秒自动关闭
func (r *runner) relayBack(session *net.UDPConn, peer *net.UDPAddr, peerKey string) {
	buf := make([]byte, 65535)
	for r.running.Load() {
		_ = session.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := session.Read(buf)
		if err != nil {
			break // 超时或任务停止，正常结束会话
		}
		if r.udpSocket != nil {
			if _, err := r.udpSocket.WriteToUDP(buf[:n], peer); err == nil {
				recordTraffic(r.id, int64(n)) // 出站方向（目标 -> 对端）计入流量
			}
		}
	}
	r.sessionsMu.Lock()
	delete(r.sessions, peerKey)
	r.sessionsMu.Unlock()
	_ = session.Close()
}

// startTcp TCP 模式启动（详见文件头通道优先级说明）
func (r *runner) startTcp() error {
	// 先判断 UPnP 能否提供公网直达通道：路由器 WAN 口为公网时，UPnP 端口映射即权威入站路径，
	// 跳过出站探测（出站映射不受控，是展示端口漂移与周期关监听抖动的根源）
	skipProbe := false
	if r.upnpEnabled {
		if r.upnpGateway == nil {
			r.upnpGateway = discoverUpnp(3000)
		}
		wanIp := ""
		if r.upnpGateway != nil {
			wanIp = upnpExternalIp(r.upnpGateway)
		}
		skipProbe = wanIp != "" && isPublicIp(wanIp)
		if skipProbe {
			core.LogInfo(core.LogStun, "任务["+r.name+"] 路由器WAN口 "+wanIp+
				" 为公网，以UPnP端口映射为权威入站通道，跳过STUN/TCP出站探测")
		}
	}
	// 先出站探测，再监听：① 出站连接在沿途全部 NAT（含运营商 CGNAT）上建立真实 TCP 映射，
	// 返回地址即权威外网地址；② 监听存在后同端口出站绑定受限，探测与备用配额都必须先行
	// （链路日后重连优先耗用配额，关监听弹跳仅为兜底）。
	// 随机端口偶发被占用（监听开启失败）时：丢弃已建链路、换新端口整体重试，
	// 避免一次端口冲突直接判任务死刑；固定端口冲突无替代端口，报错由用户调整配置。
	var listener *net.TCPListener
	attempts := 0
	for {
		attempts++
		// 先固定本地端口（bind_port=0 时取随机端口）：出站链路与监听共用同一本地端口，
		// 固定本地端口使外网映射端口在链路重建间保持稳定
		listenPort := r.bindPort
		if listenPort <= 0 {
			tmp, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: 0})
			if err != nil {
				return err
			}
			listenPort = tmp.Addr().(*net.TCPAddr).Port
			_ = tmp.Close()
		}
		if !skipProbe {
			// 预算 60s：被封锁候选逐个等满超时可达数分钟，超出预算直接回退公共出站端点，
			// 避免任务启动（HTTP 线程）长时间无响应
			link := r.punch.establishEx(listenPort, true, 60_000)
			if link != nil {
				// 补充备用出站配额：链路断开时无需关监听即可重连（零入站中断）。
				// Go 侧无预绑容量探测，直接记入 TCP_SPARES 配额（见 punch.go 差异说明）
				r.punch.openSpares(tcpSpares)
			} else {
				core.LogWarn(core.LogStun, "任务["+r.name+"] TCP出站链路建立失败(STUN与公共出站端点均不可达)，"+
					"TCP映射未建立，巡检将按退避重试；UDP映射照常保活展示")
			}
		}

		// 入站方向：同一本地端口监听 TCP，外网连接进来后转发到目标内网服务（HTTP 等 TCP 流量透明传输）
		var err error
		listener, err = r.openTcpListener(listenPort)
		if err != nil {
			r.punch.closeLink()   // 释放已建立的出站链路（RST 复位立即释放端口占用）
			r.punch.drainSpares() // 废弃旧端口的备用配额：残留会被后续重连误用，从错误本地端口出站建映射
			if r.bindPort > 0 || attempts >= 3 {
				return err // 固定端口无替代端口/重试耗尽：按原流程报错
			}
			core.LogWarn(core.LogStun, "任务["+r.name+"] 端口"+strconv.Itoa(listenPort)+"开启监听失败(被占用)，"+
				"更换随机端口重试: "+err.Error())
			continue // 换新随机端口整体重试（重新出站探测，映射地址以新端口为准）
		}
		break
	}
	r.tcpServer = listener
	localPort := listener.Addr().(*net.TCPAddr).Port

	// 同端口维护 UDP STUN 映射：展示外网地址并保活，锥形 NAT 下对端可经该映射打洞回连
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return err
	}
	r.udpSocket = udpConn
	res := r.detectNatWithFallback(udpConn)
	mapped, natType := "", "Unknown"
	if res != nil {
		mapped, natType = res.mapped, res.natType
	}
	r.updateUdpMapped(mapped, natType)
	core.LogInfo(core.LogStun, "任务["+r.name+"] NAT类型: "+natType+"，映射地址: "+orNone(mapped))
	r.startUdpReceiver(false)

	// 配合 UPnP：在路由器上显式开放入站端口（外网端口=本地端口，入站包经 CGNAT 翻译后以此端口到达路由器）
	if r.upnpEnabled {
		r.applyUpnpMapping(localPort, false)
	}
	r.startKeepalive()
	r.startAcceptor()

	// 出站方向：配置了对端公网地址时，周期性主动向对端打洞（TCP 需双方向建立 NAT 过滤条目）
	if r.peerAddr != "" {
		r.startTicker(r.keepaliveSec, func() { r.punchToPeer(r.peerAddr) }, 3)
	}
	return nil
}

// openTcpListener 在指定端口开启 TCP 监听（重试以容忍刚关闭连接的端口释放延迟）
func (r *runner) openTcpListener(port int) (*net.TCPListener, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: port})
		if err == nil {
			return ln, nil
		}
		lastErr = err
		time.Sleep(800 * time.Millisecond)
	}
	return nil, lastErr
}

// startAcceptor TCP 入站接收线程：外网连接进来后逐条并入转发管道（监听重建时需重新启动）
func (r *runner) startAcceptor() {
	r.trackTask(func() {
		for r.running.Load() && r.tcpServer != nil {
			client, err := r.tcpServer.AcceptTCP()
			if err != nil {
				if r.running.Load() && r.tcpServer != nil {
					core.LogWarn(core.LogStun, "任务["+r.name+"] TCP接收异常: "+err.Error())
					return
				}
				continue
			}
			c := client
			r.trackTask(func() { r.pipeToTarget(c) })
		}
	})
}

// onTcpLinkReady TCP 保活链路就绪回调（punch 建立/重建链路或映射地址变化时调用）：
// STUN 精确模式直接登记映射地址；端口保留模式优先按同端口 UDP STUN 映射组装展示地址（尽力而为），
// UDP 映射暂无时退回「出口 IP + 本地端口」占位（待 UDP STUN 响应后由 updateUdpMapped 修正）。
// 注意：本回调在 punch 锁内被调用，不得再进入 punch 的其他方法（锁序 punch.mu → mappingMu）。
func (r *runner) onTcpLinkReady(link *punchLink) {
	r.wanTcpReady.Store(true)
	r.tcpMappedViaUpnp.Store(false)
	if link.viaStun {
		r.updateTcpMapped(link.mapped)
		mode := "STUN/TCP服务器 " + link.endpoint + "，精确映射"
		if link.split {
			mode = "双链路:出站端点 " + link.endpoint + " 保活 + STUN短连接探测，精确映射"
		}
		core.LogInfo(core.LogStun, "任务["+r.name+"] TCP映射已建立("+mode+"): "+link.mapped)
		return
	}
	presumed := r.presumedAddr()
	if presumed != "" {
		r.updateTcpMapped(presumed)
		core.LogInfo(core.LogStun, "任务["+r.name+"] TCP出站链路已建立(出站端点 "+link.endpoint+
			"，端口保留模式): "+presumed+"；展示端口取自同端口UDP STUN探测"+
			"(仅尽力而为估计，外网入站不保证可达，请用外部设备验证)")
	} else {
		core.LogInfo(core.LogStun, "任务["+r.name+"] TCP出站链路已建立(出站端点 "+link.endpoint+
			"，端口保留模式)：暂无UDP STUN映射，待响应后组装展示地址")
	}
}

// presumedAddr 端口保留模式展示地址：优先「UDP STUN 出口 IP + UDP 映射端口」，
// UDP 映射暂无时退回「出口 IP + 本地端口」。实测同本地端口的 TCP/UDP 出站外部端口并不相同，
// 该地址仅为无 TCP 探测能力时的尽力估计，入站不保证可达。
func (r *runner) presumedAddr() string {
	if v := r.udpMappedAddr.Load(); v != nil && *v != "" && strings.LastIndex(*v, ":") > 0 {
		return *v // UDP 映射完整可用：ip:port 直接作为展示地址
	}
	exitIp := r.currentMappedIp()
	localPort := 0
	if r.tcpServer != nil {
		localPort = r.tcpServer.Addr().(*net.TCPAddr).Port
	} else if r.udpSocket != nil {
		localPort = r.udpSocket.LocalAddr().(*net.UDPAddr).Port
	}
	if exitIp != "" && localPort > 0 {
		return exitIp + ":" + strconv.Itoa(localPort)
	}
	return ""
}

// refreshTcpLink TCP 映射保活与链路维护：优先在保活周期内完成链路刷新（STUN 精确模式存活时
// 原连接刷新交互/死亡才轮换新建，监听不中断）；链路死亡时优先消耗备用配额重连（零监听中断），
// 备用耗尽才「弹跳」重建（异步）。STUN/TCP 候选整体失败后退避 300 秒（期间只用公共出站端点）。
func (r *runner) refreshTcpLink() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running.Load() || r.tcpServer == nil || r.upnpPublicWan.Load() || r.tcpRefreshing.Load() {
		return
	}
	if r.punch.keepaliveOnce() {
		return // 长连接交互保活成功：监听不中断、映射端口不漂移
	}
	// 链路死亡（服务器断开/网络切换）：优先消耗备用配额重连（零监听中断）
	port := r.tcpServer.Addr().(*net.TCPAddr).Port
	r.punch.noteLinkDownIfNeeded()
	r.punch.closeLink()
	if r.punch.reconnect(port, r.punch.allowStunNow()) != nil {
		return
	}
	// 备用耗尽：弹跳重建（异步提交，避免逐候选探测长时间占用共享调度池）
	r.bounceRebuild(port)
}

// bounceRebuild 弹跳重建（异步串行队列执行）：关闭监听释放本地端口后，在端口空闲的窗口内
// 立即补充备用配额并马上重开监听——入站中断从「全候选探测完」（可达分钟级）收敛到亚秒级；
// 随后用配额逐候选重建出站链路（见 reconnectAll），不再需要端口空闲。
// （Java 的「无预绑容量退回旧流程」分支在 Go 侧不存在：配额恒可用。）
func (r *runner) bounceRebuild(port int) {
	r.tcpRefreshing.Store(true)
	tcpRebuildExec.submit(func() {
		listenerReopened := false
		defer func() {
			if !listenerReopened && r.running.Load() && r.listenerClosed() {
				r.reopenListener(port) // 异常路径兜底：尽力恢复监听，避免重建失败后监听永久丢失
			}
			r.tcpRefreshing.Store(false)
		}()
		if !r.running.Load() {
			return
		}
		if err := r.tcpServer.Close(); err != nil {
			core.LogWarn(core.LogStun, "任务["+r.name+"] 关闭TCP监听失败，跳过本次链路重建: "+err.Error())
			return
		}
		time.Sleep(300 * time.Millisecond) // 等待端口释放
		if !r.running.Load() {
			return
		}
		// 端口空闲窗口内补充备用配额（弹跳时主链路已废弃，全额容量可用）
		r.punch.openSpares(tcpSpares)
		// 立即重开监听：入站中断收敛到亚秒级；重建走配额 dial 绑定，与监听互不抢占端口
		r.reopenListener(port)
		listenerReopened = true
		if !r.running.Load() {
			return
		}
		if r.punch.reconnectAll(port, r.punch.allowStunNow()) == nil {
			r.wanTcpReady.Store(false)
			core.LogWarn(core.LogStun, "任务["+r.name+"] TCP出站链路重建失败(STUN与公共出站端点均不可达)，"+
				"TCP映射暂缺，巡检将退避重试；UDP映射照常保活")
		}
	})
}

func (r *runner) listenerClosed() bool {
	return r.tcpServer == nil || !runningListener(r.tcpServer)
}

// runningListener 监听是否仍打开（等价 ServerSocket.isClosed）
func runningListener(ln *net.TCPListener) bool {
	return ln != nil && !isClosedListener(ln)
}

func isClosedListener(ln *net.TCPListener) bool {
	// 通过控制消息探测监听关闭状态
	return ln.SetDeadline(time.Now()) != nil
}

// reopenListener 重开 TCP 监听并重启接收线程（弹跳重建后调用）
func (r *runner) reopenListener(port int) {
	ln, err := r.openTcpListener(port)
	if err != nil {
		core.LogError(core.LogStun, "任务["+r.name+"] 重建TCP监听失败: "+err.Error())
		return
	}
	r.tcpServer = ln
	r.startAcceptor()
}

// punchToPeer TCP 打洞：从与监听相同的本地端口主动向对端发起连接，在双端 NAT 上建立过滤条目。
// 连接建立后并入转发管道，双向承载 TCP/HTTP 数据（无论连接由哪一端发起）。
func (r *runner) punchToPeer(addr string) {
	if !r.running.Load() {
		return
	}
	host, port := splitHostPort(addr)
	listenPort := 0
	if r.tcpServer != nil {
		listenPort = r.tcpServer.Addr().(*net.TCPAddr).Port
	}
	conn, err := dialPeer(host, port, listenPort, 3000)
	if err != nil {
		core.LogWarn(core.LogStun, "任务["+r.name+"] TCP打洞未成功("+addr+"): "+err.Error())
		return
	}
	core.LogInfo(core.LogStun, "任务["+r.name+"] TCP打洞成功，与对端 "+addr+" 建立转发通道")
	c := conn
	r.trackTask(func() { r.pipeToTarget(c) })
}

// dialPeer 打洞出站连接：优先与监听同端口绑定（锥形 NAT 下对端可直接回连该映射端口），
// 同端口绑定受限时退回随机端口（主动连接方向仍可建立数据通道）
func dialPeer(host string, port, listenPort, timeoutMs int) (*net.TCPConn, error) {
	if listenPort > 0 {
		if conn, err := dialBoundTCP(host, port, listenPort, "", timeoutMs); err == nil {
			return conn, nil
		}
	}
	d := net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := d.Dial("tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc, nil
	}
	return nil, fmt.Errorf("不是 TCP 连接")
}

// pipeToTarget TCP 双向管道：外网连接 <-> 目标内网服务（字节级透明，HTTP 等应用层协议直接可用）
func (r *runner) pipeToTarget(client *net.TCPConn) {
	target, err := net.DialTimeout("tcp4", net.JoinHostPort(r.targetIp, strconv.Itoa(r.targetPort)), 5*time.Second)
	if err != nil {
		core.LogWarn(core.LogStun, "任务["+r.name+"] 转发失败: "+err.Error())
		_ = client.Close()
		return
	}
	defer func() { _ = client.Close(); _ = target.Close() }()
	tclient, ok := target.(*net.TCPConn)
	if !ok {
		return
	}
	core.LogInfo(core.LogStun, "任务["+r.name+"] 外网连接: "+client.RemoteAddr().String())
	// WAN 腿调优：关 Nagle（小请求不积包、不掉一个 RTT 的停顿）+ 显式大收发缓冲（单流更快填满 BDP）。
	// 这是与 Lucky 单隧道相比每连接冷启动最直接的缓解点；对多流并发超发导致的衰减只能部分改善。
	tuneWanSocket(client)
	_ = tclient.SetNoDelay(true) // 内网腿多为 localhost，仅需关 Nagle，缓冲交内核自动调优
	// 对端不是自测回环连接时记录真实外网访问时刻：作为通道实际在用的证据，
	// 自测未通过时据此避免误重穿把可用映射丢弃。自测回环判定：本机直连公网映射的
	// 探测窗口内（源经回流改写，LAN IP/路由器 IP/公网出口 IP 均有可能），
	// 或源地址即当前映射出口 IP（旧路径兜底）
	selfProbe := time.Now().UnixMilli() < r.selfProbeUntil.Load()
	mappedIp := r.currentMappedIp()
	peerIp := client.RemoteAddr().(*net.TCPAddr).IP.String()
	if !selfProbe && (mappedIp == "" || mappedIp != peerIp) {
		r.lastPeerInbound.Store(time.Now().UnixMilli())
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.copyConn(tclient, client) // 目标 -> 外网
	}()
	r.copyConn(client, tclient) // 外网 -> 目标
	<-done
}

// tuneWanSocket 对 WAN 腿 socket 做低延迟 + 大缓冲调优。缓冲须在连接建立后尽早设置以覆盖
// 整个传输生命周期；单项失败（平台/内核限制）静默跳过，绝不因调优异常中断转发管道。
func tuneWanSocket(s *net.TCPConn) {
	_ = s.SetNoDelay(true)
	_ = s.SetWriteBuffer(wanSoSndBuf)
	_ = s.SetReadBuffer(wanSoRcvBuf)
}

// copyConn 单方向拷贝：每块无锁累加流量，不逐包写库；任一端断开即结束管道，
// 完成后向对端 shutdownOutput 半关闭（触发 FIN，让对端读到 EOF）
func (r *runner) copyConn(from, to *net.TCPConn) {
	buf := make([]byte, 16384)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if _, werr := to.Write(buf[:n]); werr != nil {
				break
			}
			recordTraffic(r.id, int64(n))
		}
		if err != nil {
			break
		}
	}
	_ = to.CloseWrite()
}

// stop 停止任务并释放资源
func (r *runner) stop() {
	r.stopCommon()
	r.updateStatus("STOPPED")
	// 停止后清除外网映射地址、穿透成功时间与可用性自测结果，下次启动重新记录
	_, err := core.Update("UPDATE stun_task SET punched_at=NULL, check_time=NULL, check_result=NULL,"+
		" mapped_addr=NULL, nat_type=NULL WHERE id=?", r.id)
	if err != nil {
		core.LogError(core.LogStun, "清除自测状态失败: "+err.Error())
	}
	core.LogInfo(core.LogStun, "穿透任务["+r.name+"] 已停止")
}

// stopSilently 关停静默停止：释放资源但不更新任务启停状态（进程即将退出，无需再写库）。
func (r *runner) stopSilently() {
	r.stopCommon()
}

func (r *runner) stopCommon() {
	r.running.Store(false)
	r.punched.Store(false)
	empty := ""
	r.upnpWanAddr.Store(&empty)
	r.releaseUpnpMapping()
	r.stopTasks()
	if r.udpSocket != nil {
		_ = r.udpSocket.Close()
		r.udpSocket = nil
	}
	if r.punch != nil {
		r.punch.closeAll()
	}
	if r.tcpServer != nil {
		_ = r.tcpServer.Close()
		r.tcpServer = nil
	}
	r.sessionsMu.Lock()
	for k, s := range r.sessions {
		_ = s.Close()
		delete(r.sessions, k)
	}
	r.sessionsMu.Unlock()
}

// releaseUpnpMapping 释放路由器上的 UPnP 端口映射（幂等，重复调用安全）
func (r *runner) releaseUpnpMapping() {
	if r.upnpMapped && r.upnpGateway != nil {
		upnpDeletePortMapping(r.upnpGateway, r.protocol, r.upnpPort)
		r.upnpMapped = false
		core.LogInfo(core.LogStun, "任务["+r.name+"] UPnP端口映射已移除")
	}
}

func (r *runner) isRunning() bool { return r.running.Load() }

func (r *runner) updateStatus(status string) {
	if _, err := core.Update("UPDATE stun_task SET status=? WHERE id=?", status, r.id); err != nil {
		core.LogError(core.LogStun, "更新任务状态失败: "+err.Error())
	}
}

// updateMapped natType 为空串时只更新映射地址。
// 写库去重：保活每周期会收到多个 STUN 服务器的响应（每个都走到这里），地址未变化时
// 不再写库/打日志（原来每周期十余次无谓写库，既占数据库锁也造成前端展示抖动）。
// 对称型 NAT 抖动冻结：对称型 NAT 对不同服务器分配不同外部端口，多个服务器的响应会
// 让地址每周期跳变（展示/穿透时间反复变更+日志刷屏）。短时间内地址反复变化时冻结展示，
// 同一新地址连续出现两次（真实变更，如出口 IP 变化/重穿）才接受并告警一次抖动特征。
// authoritative true=TCP 权威映射（链路轮换/重建即换外部端口）：新地址即当前真相立即接受，
// 不做抖动冻结——冻结会把展示/库/自测停留在已失效旧端口（公网访问失败的直接诱因）。
func (r *runner) updateMapped(mapped, natType string, authoritative bool) {
	r.updateMappedInner(mapped, natType, authoritative, false)
}

func (r *runner) updateMappedInner(mapped, natType string, authoritative, tcpAuthoritative bool) {
	r.mappingMu.Lock()
	writeMapped := false
	wasPunched := r.punched.Load() // 记录本次调用前是否已穿透，用于区分「首次穿透」与「映射地址变化」
	punchedAt := ""
	if mapped != "" {
		nowMs := time.Now().UnixMilli()
		r.lastMappedAt.Store(nowMs) // 保活/穿透有效：刷新映射时间，供巡检判断保活是否失效
		if !wasPunched {
			r.punched.Store(true)
			r.punchedMapped = mapped
			r.lastMappedChangeAt.Store(nowMs)
			writeMapped = true
			punchedAt = core.Now()
			core.LogInfo(core.LogStun, "任务["+r.name+"] 穿透成功，外网映射地址: "+mapped)
		} else if mapped != r.punchedMapped {
			if authoritative {
				// TCP 权威映射变更（链路轮换/重建换端口）：立即接受为当前真相，不冻结
				r.flapWarned.Store(false)
				r.pendingMapped = ""
				punchedAt = r.acceptMappedChange(mapped, nowMs)
				writeMapped = true
			} else if nowMs-r.lastMappedChangeAt.Load() < r.freezeWindowMS() {
				// 短时间内映射地址随响应来源变化：对称型 NAT 特征，冻结展示等待地址稳定
				if mapped == r.pendingMapped {
					// 同一新地址连续出现两次：真实变更（出口IP变化/重穿），接受
					r.flapWarned.Store(false)
					r.pendingMapped = ""
					punchedAt = r.acceptMappedChange(mapped, nowMs)
					writeMapped = true
				} else {
					r.pendingMapped = mapped
					if !r.flapWarned.Load() {
						r.flapWarned.Store(true)
						core.LogWarn(core.LogStun, "任务["+r.name+"] 映射地址随STUN服务器不同而变化"+
							"(对称型NAT特征)，展示地址保持为 "+r.punchedMapped+
							"；对称型NAT纯STUN无法稳定穿透，请用端口转发/UPnP")
					}
				}
			} else {
				r.flapWarned.Store(false)
				r.pendingMapped = ""
				punchedAt = r.acceptMappedChange(mapped, nowMs)
				writeMapped = true
			}
		}
	}
	r.mappingMu.Unlock()

	var err error
	if punchedAt != "" {
		if _, err = core.Update("UPDATE stun_task SET punched_at=? WHERE id=?", punchedAt, r.id); err != nil {
			core.LogError(core.LogStun, "更新映射状态失败: "+err.Error())
			return
		}
	}
	if natType != "" {
		if writeMapped || mapped == "" {
			_, err = core.Update("UPDATE stun_task SET mapped_addr=?, nat_type=? WHERE id=?", mapped, natType, r.id)
		} else {
			_, err = core.Update("UPDATE stun_task SET nat_type=? WHERE id=?", natType, r.id)
		}
	} else if writeMapped {
		_, err = core.Update("UPDATE stun_task SET mapped_addr=? WHERE id=?", mapped, r.id)
	}
	if err != nil {
		core.LogError(core.LogStun, "更新映射状态失败: "+err.Error())
		return
	}
	// 映射地址落库后推送穿透结果（writeMapped 仅在首次穿透或接受真实变更时为 true）
	if writeMapped {
		event := "stun.punched"
		if wasPunched {
			event = "stun.mapped_changed"
		}
		r.onMappedChanged(event)
	}
}

// freezeWindowMS 抖动冻结窗口：max(60s, keepaliveSec*3)
func (r *runner) freezeWindowMS() int64 {
	w := int64(r.keepaliveSec) * 3_000
	if w < 60_000 {
		w = 60_000
	}
	return w
}

// acceptMappedChange 接受映射地址真实变更：更新穿透成功时间并记日志（地址（端口）变化即重新穿透）；
// 返回应写入的 punched_at 时间串（调用方持 mappingMu）
func (r *runner) acceptMappedChange(mapped string, nowMs int64) string {
	r.punchedMapped = mapped
	r.lastMappedChangeAt.Store(nowMs)
	core.LogInfo(core.LogStun, "任务["+r.name+"] 外网映射地址变更为 "+mapped+"，穿透时间已同步更新")
	return core.Now()
}

// updateTcpMapped 更新 TCP 方向外网映射（STUN/TCP 精确探测或 UPnP 公网直通），TCP 自测以此为准
func (r *runner) updateTcpMapped(mapped string) {
	r.wanTcpReady.Store(true)
	r.updateMapped(mapped, "", true)
}

// updateUdpMapped UDP STUN 映射刷新（启动探测/保活响应）。
// TCP 模式下权威外网地址以 TCP 出站映射为准（STUN/TCP 精确映射或端口保留地址），UDP 映射端口
// 与其通常不同：若用 UDP 映射覆盖展示地址，穿透端口会在两个值之间来回跳变。
// 但端口保留模式例外：无 TCP 探测能力时只能以同端口 UDP 映射尽力估计展示地址，
// 每次刷新持续修正（链路重建窗口内保留最后已知地址）。
func (r *runner) updateUdpMapped(mapped, natType string) {
	if mapped != "" {
		v := mapped
		r.udpMappedAddr.Store(&v)
	}
	if !r.isUdp() && (r.wanTcpReady.Load() || r.punched.Load()) {
		if mapped != "" {
			r.lastMappedAt.Store(time.Now().UnixMilli()) // 保活有效：供巡检判断，但不改动权威地址
			if r.punch != nil && r.punch.punchAddrPresumed() {
				// 端口保留模式：展示地址跟随同端口 UDP STUN 映射（含启动初期的本地端口占位修正）
				if presumed := r.presumedAddr(); presumed != "" {
					r.updateTcpMapped(presumed)
				}
			}
		}
		if natType != "" {
			if _, err := core.Update("UPDATE stun_task SET nat_type=? WHERE id=?", natType, r.id); err != nil {
				core.LogError(core.LogStun, "更新NAT类型失败: "+err.Error())
			}
		}
		return
	}
	r.updateMapped(mapped, natType, false)
}

// lanIp 本机局域网 IP：UDP connect 仅选出出口网卡（不真实发包），避免通配绑定 socket 返回 0.0.0.0
func (r *runner) lanIp() string {
	conn, err := net.Dial("udp4", net.JoinHostPort(r.stunHost, strconv.Itoa(r.stunPort)))
	if err != nil {
		// 配置的 STUN 域名失效时退回公共 DNS 地址选出口网卡（UDP connect 仅本机路由决策，不真实发包）
		conn, err = net.Dial("udp4", "223.5.5.5:53")
	}
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return la.IP.String()
	}
	return ""
}

// currentMappedIp 当前 DB 中 STUN 映射地址的 IP 部分（即 STUN 看到的出口公网 IP）
func (r *runner) currentMappedIp() string {
	row, err := core.QueryOne("SELECT mapped_addr FROM stun_task WHERE id=?", r.id)
	if err == nil && row != nil {
		m := strField(row, "mapped_addr")
		ci := strings.LastIndex(m, ":")
		if ci > 0 {
			return m[:ci]
		}
	}
	return "" // 查询失败时返回空串，调用方回退展示 UPnP WAN IP
}

// isPublicIp 是否公网 IP：排除环回/私网/链路本地/组播及运营商 CGNAT(100.64.0.0/10)
func isPublicIp(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if b := ip.To4(); b != nil {
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // RFC6598 共享地址空间
			return false
		}
	}
	return true
}

// mappedAddr 当前登记的外网映射地址（异步验证回调时取最新值记日志）
func (r *runner) mappedAddr() string {
	row, err := core.QueryOne("SELECT mapped_addr FROM stun_task WHERE id=?", r.id)
	if err != nil || row == nil {
		return ""
	}
	return strField(row, "mapped_addr")
}

// ---------- 任务基建（goroutine + stop channel，等价 Java ScheduledFuture 取消） ----------

// trackTask 后台任务包装：panic recover + WaitGroup 记账（stopTasks 等待收尾）
func (r *runner) trackTask(job func()) {
	r.taskWg.Add(1)
	go func() {
		defer r.taskWg.Done()
		defer func() {
			if rec := recover(); rec != nil {
				core.LogWarn(core.LogStun, "任务["+r.name+"] 后台任务异常: "+fmt.Sprint(rec))
			}
		}()
		job()
	}()
}

// startTicker 周期任务（等价 Tasks.every(initial, period, job)）：
// initial 为首次执行前的延迟秒数（可变参，缺省等于周期）；
// 串行防重入：上一轮未结束时跳过本轮（等价 Java 调度器对同一任务的排队跳过语义）。
func (r *runner) startTicker(periodSec int, job func(), initial ...int) {
	delay := periodSec
	if len(initial) > 0 {
		delay = initial[0]
	}
	r.trackTask(func() {
		timer := time.NewTimer(time.Duration(delay) * time.Second)
		defer timer.Stop()
		select {
		case <-r.stopCh:
			return
		case <-timer.C:
		}
		busy := false
		tick := time.NewTicker(time.Duration(periodSec) * time.Second)
		defer tick.Stop()
		for {
			if !r.running.Load() {
				return
			}
			if !busy {
				busy = true
				safeCall(job)
				busy = false
			}
			select {
			case <-r.stopCh:
				return
			case <-tick.C:
			}
		}
	})
}

// stopTasks 通知全部周期任务退出（UDP 接收/转发会话由 socket 关闭自然退出，无需等待）
func (r *runner) stopTasks() {
	r.stopMu.Lock()
	if r.stopCh != nil {
		select {
		case <-r.stopCh:
		default:
			close(r.stopCh)
		}
	}
	r.stopMu.Unlock()
}

// ---------- 可用性自测 ----------

// verifyNow 手动自测入口（REST 接口调用，同步执行并返回结果；必做公网入站验证，耗时数秒）
func (r *runner) verifyNow() (*core.Row, error) {
	return r.verifyChannel(true)
}

// verifyChannel 可用性自测：验证「映射保活存活」而非回环连通，结果写入 check_time / check_result。
//   - UDP 任务：向候选 STUN 服务器发绑定请求，接收线程在超时内收到响应（映射刷新）即存活
//   - TCP 任务：保活链路交互有响应且本地监听正常即存活，无响应时立即重建链路再复验
//
// 公网入站验证不影响保活结论：优先本机直连公网映射地址（支持 NAT 回流的网络连接会被送回本机，
// 成功即证明外网可主动连入）；直连失败的网络（确有无回流环境）不代表映射不可用，
// 退回第三方探测节点真实连接映射地址验证（周期自测限冷却，手动自测必验），
// 第三方服务不可用时静默跳过。
func (r *runner) verifyChannel(manual bool) (*core.Row, error) {
	// TCP 弹跳重建会短暂关闭监听（关监听→补配额→重开→全候选出站探测，候选全部超时时可达数十秒），
	// 手动自测的等待窗口须覆盖弹跳全程再自测，否则撞上关闭窗口会误报「本地TCP监听已关闭」；
	// 周期自测不等待（不能在共享调度池里睡眠等重建），由 verifyTcpKeepalive 按「重建中」返回
	if r.tcpRefreshing.Load() && manual {
		deadline := time.Now().UnixMilli() + 30_000
		for r.tcpRefreshing.Load() && time.Now().UnixMilli() < deadline {
			time.Sleep(200 * time.Millisecond)
		}
	}
	row, err := core.QueryOne("SELECT mapped_addr FROM stun_task WHERE id=?", r.id)
	if err != nil {
		return nil, err
	}
	mapped := ""
	if row != nil {
		mapped = strField(row, "mapped_addr")
	}
	var result string
	if mapped == "" {
		result = "FAIL(无外网映射地址)"
	} else if r.isUdp() {
		result = r.verifyUdpKeepalive()
	} else {
		result = r.verifyTcpKeepalive(manual)
	}
	// 公网入站真实验证：补上「保活存活 ≠ 外网可主动连入」盲区。优先本机直连公网映射地址——
	// 实测多数路由器/运营商 NAT 支持回流(hairpin)，局域网访问公网映射会被送回本机监听，
	// 连接成功即证明外网可主动连入（毫秒级完成且不依赖外部服务）。
	// 直连失败不代表映射不可用（确有无回流的网络连接到 WAN 侧即被丢弃），退回第三方探测节点验证：
	// 手动自测同步验证（HTTP 线程不受调度池影响）；周期自测限冷却且必须异步：
	// 第三方 API 可达数十秒，占用调度池会延迟保活致 CGNAT 映射超时，异步执行只留上次结论。
	if strings.HasPrefix(result, "OK") && !r.isUdp() {
		// TCP 自测过程中链路可能已重建并刷新映射地址：公网入站验证以最新登记地址为准，
		// 否则验证的还是自测前的旧地址，结果不代表当前通道
		rowNow, qerr := core.QueryOne("SELECT mapped_addr FROM stun_task WHERE id=?", r.id)
		if qerr == nil && rowNow != nil {
			if latest := strField(rowNow, "mapped_addr"); latest != "" {
				mapped = latest
			}
		}
		if r.probeLocalInbound(mapped) {
			r.noteExtVerdict("OK", true)
			result += "，公网入站验证可达"
		} else {
			now := time.Now().UnixMilli()
			if manual {
				r.lastExtCheckAt.Store(now)
				ext := checkExternalInbound(mapped)
				r.noteExtVerdict(ext, false)
				if ext != "" {
					if ext == "OK" {
						result += "，公网入站验证可达"
					} else {
						result += "，公网入站验证不可达" + ext[4:]
					}
				}
			} else {
				if now-r.lastExtCheckAt.Load() > 300_000 && r.extCheckRunning.CompareAndSwap(false, true) {
					r.lastExtCheckAt.Store(now)
					target := mapped
					extCheckQueue.submit(func() {
						defer r.extCheckRunning.Store(false)
						r.noteExtVerdict(checkExternalInbound(target), false)
					})
				}
				if v := r.lastExtReachable.Load(); v != 0 {
					if v == 1 {
						result += "，公网入站验证(上次)可达"
					} else {
						result += "，公网入站验证(上次)不可达"
					}
				}
			}
		}
	}
	timeStr := core.Now()
	// 展示/落库只保留核心结论（OK / FAIL / 重建中），去掉括号内明细；完整明细仍写入日志便于排查
	paren := strings.Index(result, "(")
	shown := result
	if paren > 0 {
		shown = result[:paren]
	}
	if _, err = core.Update("UPDATE stun_task SET check_time=?, check_result=? WHERE id=?", timeStr, shown, r.id); err != nil {
		return nil, err
	}
	core.LogInfo(core.LogStun, "任务["+r.name+"] 可用性自测: "+result+"，映射地址: "+mapped)
	// detail 保留括号内完整明细，供巡检确认失效时推送告警通知引用（result 为前端展示的简化结论）
	out := core.NewRow()
	out.Set("time", timeStr)
	out.Set("result", shown)
	out.Set("detail", result)
	return out, nil
}

// verifyUdpKeepalive UDP 自测：向全部候选 STUN 服务器发绑定请求，接收线程在超时前收到响应
// （lastMappedAt 前进）即保活存活
func (r *runner) verifyUdpKeepalive() string {
	before := r.lastMappedAt.Load()
	t0 := time.Now().UnixMilli()
	r.repunchUdpMapping()
	for r.lastMappedAt.Load() <= before && time.Now().UnixMilli()-t0 < 5000 {
		time.Sleep(100 * time.Millisecond)
	}
	if r.lastMappedAt.Load() > before {
		return "OK(映射保活存活，" + strconv.FormatInt(time.Now().UnixMilli()-t0, 10) + "ms)"
	}
	return "FAIL(STUN绑定无响应，映射可能已失效或服务器不可达)"
}

// verifyTcpKeepalive TCP 自测：保活链路存活 + 本地监听正常即映射存活；无响应时立即触发重建再复验，
// 重建成功即视为存活（新建链路在宽限期内不要求再次交互，避免「重建成功→立即再交互→又失败」的误报循环）。
// 弹跳重建已异步化：手动自测等待重建完成（候选探测可长达数十秒）再复验；周期自测不等待
// （不能在共享调度池里睡眠等重建），按「重建中」返回，下轮自测复验。
func (r *runner) verifyTcpKeepalive(manual bool) string {
	if r.tcpRefreshing.Load() {
		return "重建中(链路重建完成后自动复验)"
	}
	if !r.wanTcpReady.Load() {
		return "FAIL(TCP映射未建立，巡检自动重试)"
	}
	if r.tcpServer == nil || isClosedListener(r.tcpServer) {
		return "FAIL(本地TCP监听已关闭)"
	}
	t0 := time.Now().UnixMilli()
	if r.punch.keepaliveOnce() {
		return r.okTcp(time.Now().UnixMilli()-t0, false)
	}
	// 链路交互无响应（服务器断开/网络切换）：立即触发重建（多数经备用配额重连零监听中断完成），
	// 重建成功后新建链路在宽限期内即视为存活，不再强制立即交互一次（新链路刚完成交互验证）
	r.refreshTcpLink()
	if !r.tcpRefreshing.Load() && r.wanTcpReady.Load() && r.punch.keepaliveOnce() {
		return r.okTcp(time.Now().UnixMilli()-t0, true) // 快速路径（备用配额）重建成功
	}
	if !manual {
		// 周期自测不等待弹跳：按重建中返回（前端黄色展示），下轮自测复验
		return "重建中(已触发链路重建，完成后自动复验)"
	}
	deadline := time.Now().UnixMilli() + 60_000
	for r.tcpRefreshing.Load() && time.Now().UnixMilli() < deadline {
		time.Sleep(200 * time.Millisecond)
	}
	if r.wanTcpReady.Load() && r.punch.keepaliveOnce() {
		return r.okTcp(time.Now().UnixMilli()-t0, true)
	}
	return "FAIL(TCP保活链路无响应且重建未成功)"
}

// okTcp TCP 自测通过时的结果文案（区分映射来源，便于用户判断验证方式）
func (r *runner) okTcp(costMs int64, rebuilt bool) string {
	mode := "STUN精确映射"
	if r.tcpMappedViaUpnp.Load() {
		mode = "UPnP公网直通"
	} else if r.punch != nil && r.punch.splitActive() {
		mode = "双链路:出站保活+STUN探测"
	} else if r.punch != nil && r.punch.punchAddrPresumed() {
		mode = "端口保留模式(入站以公网入站验证为准)"
	}
	rebuiltTxt := ""
	if rebuilt {
		rebuiltTxt = "，链路已重建"
	}
	return "OK(TCP映射保活存活" + rebuiltTxt + "[" + mode + "]，" + strconv.FormatInt(costMs, 10) + "ms)"
}

// noteExtVerdict 公网入站验证结论处理：状态变化时记日志并缓存（空串=第三方服务不可用/未完成，本轮跳过）
func (r *runner) noteExtVerdict(ext string, local bool) {
	if ext == "" {
		return
	}
	reachable := ext == "OK"
	prev := r.lastExtReachable.Load()
	if prev == 0 || (prev == 1) != reachable {
		v := int64(0)
		if reachable {
			v = 1
		}
		r.lastExtReachable.Store(v)
		if reachable {
			src := "第三方节点真实连接 "
			if local {
				src = "本机直连公网映射地址 "
			}
			core.LogInfo(core.LogStun, "任务["+r.name+"] 公网入站验证通过: "+src+r.mappedAddr()+" 成功")
		} else {
			core.LogWarn(core.LogStun, "任务["+r.name+"] 公网入站验证失败"+ext[4:]+
				"：保活存活但外网无法连入，请检查上层NAT/运营商策略")
		}
	}
}

// probeLocalInbound 本机直连公网映射地址探测入站可达性：实测多数路由器/运营商 NAT 支持回流(hairpin)，
// 局域网内直连穿透出的公网 IP:端口 会被送回本机监听端口，TCP 连接成功即证明
// 「外网可主动连入」——毫秒级完成且不依赖外部服务。
// 失败（拒绝/超时）不代表映射不可用：确有无回流的网络连接到 WAN 侧即被丢弃，
// 由调用方退回第三方探测节点验证。探测窗口内的回环 accept 不记为真实外网访问证据。
func (r *runner) probeLocalInbound(mapped string) bool {
	ci := strings.LastIndex(mapped, ":")
	if ci <= 0 {
		return false
	}
	r.selfProbeUntil.Store(time.Now().UnixMilli() + 15_000)
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(mapped[:ci], mapped[ci+1:]), 4*time.Second)
	if err != nil {
		return false // 无回流网络/映射暂不可达：交由调用方退回第三方节点验证
	}
	_ = conn.Close()
	return true
}

// checkExternalInbound 公网入站可达性验证（本机直连失败后的兜底）：第三方探测节点（check-host.net 免费 API）
// 真实 TCP 连接映射地址，验证「外网能否主动连入」（无回流网络本机直连无法自验）。
// 提交后轮询结果（实测约 3 秒完成）：
// 响应为顶层节点结果表，节点值 null=仍在探测；样本对象含 address 即连接成功，含 error 即失败。
// 任一节点成功即视为可达；全部报错视为不可达（携带首个错误原因）；持续未完成/服务异常返回空串（本轮跳过）。
// 第三方服务不可用不影响主流程，自测结论退回保活存活语义。
func checkExternalInbound(mapped string) string {
	submit, body, err := extCheckGet("https://check-host.net/check-tcp?host=" + mapped)
	if err != nil || submit.StatusCode != 200 {
		return "" // 第三方服务不可用/解析异常：静默跳过，保持原保活自测结论
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return ""
	}
	reqIdRaw, has := root["request_id"]
	if !has {
		return ""
	}
	var reqId string
	if json.Unmarshal(reqIdRaw, &reqId) != nil || reqId == "" {
		return ""
	}
	for round := 0; round < 3; round++ {
		time.Sleep(3 * time.Second) // 实测探测约 3 秒出结果，最多轮询 3 次覆盖慢节点/排队
		poll, pbody, perr := extCheckGet("https://check-host.net/check-result/" + reqId)
		if perr != nil || poll.StatusCode != 200 {
			return ""
		}
		var rroot map[string]json.RawMessage
		if json.Unmarshal(pbody, &rroot) != nil {
			return ""
		}
		if verdict := parseCheckResult(rroot, reqId); verdict != "" {
			return verdict
		}
	}
	return "" // 持续未完成：本轮跳过，下轮自测再验
}

// extCheckGet 公网入站验证 HTTP GET（单次 8s 超时，等价 Java HttpRequest.timeout）
func extCheckGet(url string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NexHome-STUN")
	ctx, cancel := context.WithTimeout(req.Context(), 8*time.Second)
	defer cancel()
	resp, err := extCheckHTTP.Do(req.WithContext(ctx))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	return resp, b, nil
}

// parseCheckResult 解析 check-host 轮询响应：结果可能包裹在 request_id 键下，也可能直接平铺在顶层（实测后者）。
// 全部节点仍为 null（探测中）返回空串继续轮询；否则按样本汇总：含 address 即连接成功，含 error 即失败。
func parseCheckResult(rroot map[string]json.RawMessage, reqId string) string {
	var nodes map[string]json.RawMessage
	if wrapped, ok := rroot[reqId]; ok {
		var m map[string]json.RawMessage
		if json.Unmarshal(wrapped, &m) == nil && m != nil {
			nodes = m // 包裹在 request_id 键下
		}
	}
	if nodes == nil && len(rroot) > 0 {
		// 实测响应直接以节点 id 为顶层键（无 request_id 包裹）；仍为 pending 时响应为空对象/全 null 由下方汇总判定
		nodes = rroot
	}
	if nodes == nil {
		return ""
	}
	anyOk, anyDone := false, false
	firstErr := ""
	for _, v := range nodes {
		var samples []json.RawMessage
		if json.Unmarshal(v, &samples) != nil {
			continue // null=该节点仍在探测
		}
		for _, sample := range samples {
			var obj map[string]json.RawMessage
			if json.Unmarshal(sample, &obj) != nil || obj == nil {
				continue
			}
			if _, hasAddr := obj["address"]; hasAddr {
				anyOk = true // 含 address：探测节点真实连接成功（time 为连接耗时）
			} else if errEl, hasErr := obj["error"]; hasErr && firstErr == "" {
				var s string
				if json.Unmarshal(errEl, &s) == nil {
					firstErr = s
				}
			}
			anyDone = true
		}
	}
	if anyOk {
		return "OK"
	}
	if anyDone {
		return "FAIL(" + firstErr + ")"
	}
	return ""
}

// ---------- UPnP 配合与重新穿透 ----------

// applyUpnpMapping UPnP 端口映射：SSDP 发现路由器并添加 WAN->LAN 映射（外网端口=本地端口），
// 映射成功后以路由器 WAN IP + 本地端口作为权威外网地址展示。
// quiet=true 为巡检周期静默重挂（路由器重启后映射会丢失）：成功不打日志避免刷屏，失败仍告警。
func (r *runner) applyUpnpMapping(localPort int, quiet bool) {
	defer func() {
		if rec := recover(); rec != nil {
			core.LogWarn(core.LogStun, "任务["+r.name+"] UPnP映射异常: "+fmt.Sprint(rec))
		}
	}()
	if r.upnpGateway == nil {
		r.upnpGateway = discoverUpnp(3000)
	}
	if r.upnpGateway == nil {
		core.LogWarn(core.LogStun, "任务["+r.name+"] 未发现UPnP网关(需路由器开启UPnP)，仅依赖STUN打洞")
		return
	}
	lan := r.lanIp()
	if lan == "" {
		core.LogWarn(core.LogStun, "任务["+r.name+"] 无法确定本机局域网IP，跳过UPnP映射")
		return
	}
	// 外网端口=本地端口：入站包经运营商 CGNAT 翻译后，以本地端口号到达路由器 WAN 口
	extPort := localPort
	label := "NexHome " + r.name
	ok := upnpAddPortMapping(r.upnpGateway, r.protocol, extPort, localPort, lan, label)
	if !ok { // 端口可能被旧映射占用：先删除再重试
		upnpDeletePortMapping(r.upnpGateway, r.protocol, extPort)
		ok = upnpAddPortMapping(r.upnpGateway, r.protocol, extPort, localPort, lan, label)
	}
	if !ok {
		core.LogWarn(core.LogStun, "任务["+r.name+"] UPnP端口映射失败，仅依赖STUN打洞")
		return
	}
	r.upnpMapped = true
	r.upnpPort = extPort
	wanIp := upnpExternalIp(r.upnpGateway)
	// 路由器 WAN 公网：UPnP 映射即权威入站通道，关闭 TCP 方向周期 STUN 出站刷新
	if wanIp != "" && isPublicIp(wanIp) {
		r.upnpPublicWan.Store(true)
	}
	if wanIp != "" {
		v := wanIp + ":" + strconv.Itoa(extPort)
		r.upnpWanAddr.Store(&v)
	}
	displayIp := wanIp
	if wanIp != "" && !isPublicIp(wanIp) {
		// 路由器 WAN 口是私网/CGNAT 地址（如 100.64.x），展示改用 STUN 探测的出口公网 IP + UPnP 外网端口
		if stunIp := r.currentMappedIp(); stunIp != "" {
			displayIp = stunIp
		}
		core.LogWarn(core.LogStun, "任务["+r.name+"] 路由器WAN口地址 "+wanIp+
			" 非公网(可能处于运营商CGNAT后)，展示改用STUN出口IP；外网能否主动连入取决于上层NAT")
	}
	if !quiet {
		wanTxt := wanIp
		if wanTxt == "" {
			wanTxt = "外网IP未知"
		}
		core.LogInfo(core.LogStun, "任务["+r.name+"] UPnP端口映射成功: "+wanTxt+":"+
			strconv.Itoa(extPort)+" -> "+lan+":"+strconv.Itoa(localPort))
	}
	// TCP 模式已建立权威 TCP 映射时不用 UPnP 地址覆盖（入站以 STUN/TCP 探测映射为准），
	// 否则每次启动/重穿都会把已验证可用的穿透端口换成 UPnP 展示地址；仅在无 TCP 映射时以 UPnP 地址兜底展示
	if displayIp != "" && !r.wanTcpReady.Load() {
		r.tcpMappedViaUpnp.Store(true) // UPnP 映射可被外网主动访问，自测成功即代表外网可达（受路由器防火墙约束）
		r.updateTcpMapped(displayIp + ":" + strconv.Itoa(extPort))
	}
}

// ---------- 周期有效性巡检 ----------

// checkIntervalSec 巡检周期：至少 60 秒，且不低于保活周期的 2 倍（保证两次保活后仍无响应才判定失效）
func (r *runner) checkIntervalSec() int {
	sec := r.keepaliveSec * 2
	if sec < 60 {
		sec = 60
	}
	return sec
}

// startWatcher 穿透成功后的周期有效性巡检：NAT 映射可能因超时、网络切换或运营商策略静默失效且无任何提示，
// 巡检持续监测并驱动自愈，防止长时间运行后穿透失效不可用。
//   - UPnP 重挂：路由器重启后 UPnP 映射会丢失，曾成功过的任务周期幂等重挂（静默，失败才告警）
//   - UDP 保活静默：连续超过 3 个保活周期未收到 STUN 绑定响应，立即重发绑定请求
//   - TCP 映射缺失：出站链路建立失败时周期重试，直到成功
//   - 自测未通过（保活失效）：链路重建已在自测中触发，保活调度持续重试，不额外丢弃端口重建
func (r *runner) startWatcher() {
	sec := r.checkIntervalSec()
	r.startTicker(sec, r.watchChannel, sec)
}

func (r *runner) watchChannel() {
	if !r.running.Load() || !r.punched.Load() {
		return
	}
	if r.tcpRefreshing.Load() {
		return // TCP 弹跳重建短暂关闭监听，本周期跳过避免误判
	}
	defer func() {
		if rec := recover(); rec != nil {
			core.LogWarn(core.LogStun, "任务["+r.name+"] 周期巡检异常: "+fmt.Sprint(rec))
		}
	}()
	// 路由器重启后 UPnP 映射会丢失：曾发现过网关的任务周期幂等重挂
	// （从未发现过网关的环境不反复 SSDP 探测，避免每周期无谓等待）
	if r.upnpEnabled && r.upnpGateway != nil && r.udpSocket != nil {
		r.applyUpnpMapping(r.udpSocket.LocalAddr().(*net.UDPAddr).Port, true)
	}
	silentMs := time.Now().UnixMilli() - r.lastMappedAt.Load()
	if r.isUdp() && silentMs > int64(r.keepaliveSec)*3_000 {
		// 保活连续无响应：映射可能已静默失效（网络切换/STUN 服务器故障），立即重发绑定请求
		core.LogWarn(core.LogStun, "任务["+r.name+"] STUN保活 "+strconv.FormatInt(silentMs/1000, 10)+
			"s 无响应，映射可能已失效，已重发绑定请求重建")
		r.repunchUdpMapping()
	}
	if !r.isUdp() && !r.wanTcpReady.Load() {
		// TCP 映射尚未建立（出站链路全端点不可达），周期重试直到成功
		core.LogInfo(core.LogStun, "任务["+r.name+"] TCP映射未建立，巡检重试出站探测")
		r.refreshTcpLink()
		return
	}
	check, err := r.verifyChannel(false)
	if err != nil {
		return // 写库异常由 core 记日志，巡检不重复告警
	}
	result := strField(check, "result")
	if strings.HasPrefix(result, "重建中") {
		return // 弹跳重建异步进行中：本轮跳过，重建完成后下轮自测复验，不计失败
	}
	if strings.HasPrefix(result, "OK") {
		if r.watchFails > 0 {
			core.LogInfo(core.LogStun, "任务["+r.name+"] 巡检复测通过，穿透通道已恢复")
		}
		r.watchFails = 0
		return
	}
	// 自测未通过但近期仍有真实外网数据到达：通道实际在用（STUN 链路故障≠转发不可用），
	// 不丢弃现有端口重建，保活调度会继续尝试恢复
	peerAgoMs := time.Now().UnixMilli() - r.lastPeerInbound.Load()
	if peerAgoMs < int64(r.keepaliveSec)*6_000 {
		core.LogInfo(core.LogStun, "任务["+r.name+"] 巡检自测未通过但 "+strconv.FormatInt(peerAgoMs/1000, 10)+
			"s 前仍有真实外网访问，通道视为可用，保活调度继续恢复")
		r.watchFails = 0
		return
	}
	// 自测失败=保活链路失效：链路重建已在自测内部触发（零监听中断优先），
	// 保活调度每周期持续重试，无需额外丢弃端口重建
	r.watchFails++
	// 首次确认失效（0→1）即推送告警通知，后续连续失败周期不重复打扰；恢复后 watchFails 归零，再次失效会重新告警
	if r.watchFails == 1 {
		r.notifyVerifyFailed(strField(check, "detail"))
	}
	core.LogWarn(core.LogStun, "任务["+r.name+"] 巡检自测未通过("+result+")，已触发链路重建"+
		"(连续第 "+strconv.Itoa(r.watchFails)+" 次)，保活调度将持续重试)")
}

// ---------- 联动出口（webhook / 通知中心 / ESA 同步，实现在 links 文件） ----------

// onMappedChanged 映射地址落库后的联动动作（同一份最新任务行只查一次库）：按任务配置推送 webhook 与
// 通知中心（勾选的渠道），并把映射 IP/端口同步到阿里云 ESA 的解析记录与回源 HTTPS 端口。
// 三者均在各自独立线程异步执行、失败仅记日志，不占用调度池也不影响穿透与保活。
func (r *runner) onMappedChanged(event string) {
	defer func() {
		if rec := recover(); rec != nil {
			core.LogWarn(core.LogStun, "任务["+r.name+"] 触发穿透结果联动失败: "+fmt.Sprint(rec))
		}
	}()
	row, err := core.QueryOne("SELECT * FROM stun_task WHERE id=?", r.id)
	if err != nil || row == nil {
		return
	}
	pushWebhook(row, event)
	notifyTrigger(row, event)
	esaSyncTriggerAsync(row)
}

// notifyVerifyFailed 巡检自测确认通道失效（FAIL）时推送告警通知（仅通知中心，不触发 webhook/ESA）。
// 未启用通知或未勾选渠道时由 notifyTrigger 静默跳过；detail 为自测括号内完整原因。
func (r *runner) notifyVerifyFailed(detail string) {
	defer func() {
		if rec := recover(); rec != nil {
			core.LogWarn(core.LogStun, "任务["+r.name+"] 自测失败告警通知推送异常: "+fmt.Sprint(rec))
		}
	}()
	row, err := core.QueryOne("SELECT * FROM stun_task WHERE id=?", r.id)
	if err != nil || row == nil {
		return
	}
	if detail != "" {
		row.Set("verify_detail", detail)
	}
	notifyTrigger(row, eventVerifyFailed)
}
