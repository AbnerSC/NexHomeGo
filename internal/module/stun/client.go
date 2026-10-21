package stun

// STUN 协议客户端（RFC 5389/8489 Binding 请求/响应 + RFC 3489/RFC 5780 风格 NAT 类型探测）。
// 复刻 Java StunClient：纯标准库实现（net + crypto/rand），不依赖第三方库。
//
// NAT 类型与穿透成功率说明（界面同步展示）：
//   - Open Internet / 端口保持型 NAT：外网可直达或映射端口不变，穿透成功率较高（入站仍受路由器防火墙策略约束）
//   - Full Cone（全锥形）：任意主机可发入，成功率高
//   - Restricted / Port Restricted（受限锥形）：需要对方先"打洞"握手，配合保活可用，成功率中等
//   - Symmetric（对称型）：每次出站映射端口不同，纯 STUN 无法穿透，需要中继服务器，成功率极低
//
// 注意：STUN 只负责建立/探测 NAT 映射；映射端口上的数据转发由 runner.go 完成。

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// STUN Binding Request
	msgBindingRequest = 0x0001
	// STUN Binding Success Response
	msgBindingResponse = 0x0101
	// RFC 5389 魔术饼干
	magicCookie = 0x2112A442

	attrMappedAddress  = 0x0001
	attrChangeRequest  = 0x0003
	attrXorMappedAddr  = 0x0020
	attrChangedAddress = 0x0005
	attrOtherAddress   = 0x802C
)

// 支持 STUN-over-TCP 的公共 STUN 服务器候选（host:port），配置的服务器仅支持 UDP 时兜底。
// TCP 穿透优先借助支持 TCP 的 STUN 服务器出站，才能在运营商 CGNAT 上建立可探测端口的 TCP 映射。
//
// 列表顺序为电信 CGNAT 实测可达优先（裸 STUN 消息格式，2026-08 实测）：80/443 出站不被拦截；
// 3478/TCP 出站被本类运营商封锁，仅作其他网络兜底。实测部分运营商 CGNAT 封锁 3478/TCP 出站，
// 本列表全不可用时自动回退「端口保留模式」（出站连 keepaliveTCPEndpoints 建立并保活 CGNAT 映射，
// 展示端口取同本地端口的 UDP STUN 映射，不保证可入站）；若自建/发现可用的 TCP STUN 服务器，
// 可在「STUN 服务器维护」中登记（tcp_support）获得精确映射。
var tcpStunServers = [][2]string{
	{"global.turn.twilio.com", "443"},
	{"global.turn.twilio.com", "80"},
	{"stun.nextcloud.com", "443"},
	{"fwa.lifesizecloud.com", "443"},
	{"stun.telnyx.com", "3478"},
	{"stun.sonetel.com", "3478"},
	{"stun.radiojar.com", "3478"},
	{"stun.voip.blackberry.com", "3478"},
	{"stun.antisip.com", "3478"},
	{"stun.nextcloud.com", "3478"},
	{"turn.cloudflare.com", "3478"},
	{"stun.freeswitch.org", "3478"},
}

// 公共出站连接端点（host:port）：无可用 STUN-over-TCP 服务器时的 TCP 穿透兜底。
// 从本地端口出站连接端点即可在运营商 CGNAT 上建立 TCP 映射，出站长连接存活期间
// 映射不回收（死亡时由调用方轮换新建连接维持）。外部映射端口无法直接探测，由调用方取同本地端口
// 的 UDP STUN 映射尽力估计展示（实测同本地端口 TCP/UDP 外部端口并不相同，入站不保证可达）。
//
// 端点必须是非 DNS 端口的透传服务（qq.com:443/80 等，与 Lucky 的 TCP 通道保活
// 服务器同路）：实测运营商 CGNAT 对 53/TCP 做透明拦截——连接能建立但终结在 CGNAT 上
// （合法 DNS 查询永远无响应），此类映射不接受入站，外网无法主动连入；非 DNS 端口的
// 连接真实穿透 CGNAT，映射方可入站。连接上不做任何应用层交互（域名解析按其设计走
// UDP 53，由系统解析器承担，不占用 TCP 连接）。DNS 53 端点仅列末尾，供无拦截策略的网络兜底。
var keepaliveTCPEndpoints = [][2]string{
	{"qq.com", "443"},
	{"qq.com", "80"},
	{"www.baidu.com", "443"},
	{"www.baidu.com", "80"},
	{"223.5.5.5", "53"},
	{"119.29.29.29", "53"},
}

// stunResult STUN 探测结果：外网映射地址 + NAT 类型
type stunResult struct {
	mapped string
	natType string
}

// tcpProbe STUN-over-TCP 探测结果：外网映射地址 + 本地出站端口（绑定 0 时用于回填实际占用端口）
// + 保持打开的探测连接（需长期保活维持运营商NAT映射时由调用方持有，不用时调用方负责关闭）。
type tcpProbe struct {
	mapped    string
	localPort int
	conn      *net.TCPConn
}

// buildRequest 构造 Binding Request，可选携带 CHANGE-REQUEST 属性
func buildRequest(tid []byte, changeRequest bool) []byte {
	attrLen := 0
	if changeRequest {
		attrLen = 8
	}
	buf := make([]byte, 20+attrLen)
	writeU16(buf, 0, msgBindingRequest)
	writeU16(buf, 2, attrLen)
	writeU32(buf, 4, magicCookie)
	copy(buf[8:20], tid)
	if changeRequest {
		writeU16(buf, 20, attrChangeRequest)
		writeU16(buf, 22, 4)
		writeU32(buf, 24, 0x06) // change IP + change port
	}
	return buf
}

// newTxID 生成 12 字节事务 ID
func newTxID() []byte {
	tid := make([]byte, 12)
	_, _ = rand.Read(tid)
	return tid
}

// bindingResponse 绑定响应解析结果（src 为响应包源地址，供 CHANGE-REQUEST 换址回复判定）
type bindingResponse struct {
	mapped       string
	otherAddress *net.UDPAddr
	src          *net.UDPAddr
}

// extractMapped 从绑定响应报文中提取映射地址（支持 MAPPED-ADDRESS 与 XOR-MAPPED-ADDRESS）
func extractMapped(data []byte) string {
	if len(data) < 20 {
		return ""
	}
	msgLen := readU16(data, 2)
	pos := 20
	for pos+4 <= 20+msgLen && pos+4 <= len(data) {
		attrType := readU16(data, pos)
		attrLen := readU16(data, pos+2)
		valStart := pos + 4
		if valStart+attrLen > len(data) {
			break
		}
		if attrType == attrMappedAddress {
			return parseAddress(data, valStart, false)
		}
		if attrType == attrXorMappedAddr {
			return parseAddress(data, valStart, true)
		}
		pos = valStart + ((attrLen + 3) & ^3)
	}
	return ""
}

// parseAddress 解析 MAPPED-ADDRESS / XOR-MAPPED-ADDRESS（IPv4）。
// RFC 5389 §15.2：XOR 编码仅与魔术饼干异或（端口异或高 16 位、IP 异或全 32 位），与事务 ID 无关。
func parseAddress(data []byte, offset int, xorMapped bool) string {
	if offset+8 > len(data) {
		return ""
	}
	family := data[offset+1]
	if family != 0x01 {
		return "" // 仅处理 IPv4（家庭 NAT 穿透场景以 IPv4 为主）
	}
	port := readU16(data, offset+2)
	ip := readU32(data, offset+4)
	if xorMapped {
		port ^= (magicCookie >> 16) & 0xFFFF
		ip ^= magicCookie
	}
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String() + ":" + strconv.Itoa(port)
}

func writeU16(buf []byte, pos, v int) {
	buf[pos] = byte(v >> 8)
	buf[pos+1] = byte(v)
}

func writeU32(buf []byte, pos, v int) {
	buf[pos] = byte(v >> 24)
	buf[pos+1] = byte(v >> 16)
	buf[pos+2] = byte(v >> 8)
	buf[pos+3] = byte(v)
}

func readU16(buf []byte, pos int) int {
	return int(buf[pos])<<8 | int(buf[pos+1])
}

func readU32(buf []byte, pos int) int {
	return int(buf[pos])<<24 | int(buf[pos+1])<<16 | int(buf[pos+2])<<8 | int(buf[pos+3])
}

// ---------- UDP 绑定交互 ----------

// bind 通过指定 socket 发送 Binding 请求，返回映射地址（ip:port）。
// 该请求会在 NAT 上建立一条映射（即"打洞"），失败返回空串。
func bind(conn *net.UDPConn, stunHost string, stunPort, timeoutMs int) string {
	tid := newTxID()
	req := buildRequest(tid, false)
	target, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(stunHost, strconv.Itoa(stunPort)))
	if err != nil {
		return ""
	}
	r := exchange(conn, target, req, tid, timeoutMs, 2)
	if r == nil {
		return ""
	}
	return r.mapped
}

// sendBindingRequest 只发送一次 Binding 请求，不等待响应（fire-and-forget 保活）。
// 供与接收 goroutine 共用同一 socket 的保活场景使用：响应包由接收线程通过
// parseBindingMapped 解析，避免两个 goroutine 在同一个 socket 上竞争 receive。
func sendBindingRequest(conn *net.UDPConn, stunHost string, stunPort int) error {
	tid := newTxID()
	req := buildRequest(tid, false)
	target, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(stunHost, strconv.Itoa(stunPort)))
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(req, target)
	return err
}

// parseBindingMapped 解析入站报文：若是 STUN Binding 响应则返回映射地址（ip:port），否则返回空串。
// 用于接收线程在区分业务数据的同时刷新映射地址。
func parseBindingMapped(data []byte) string {
	if len(data) < 20 || readU16(data, 0) != msgBindingResponse {
		return ""
	}
	return extractMapped(data)
}

// exchange 请求-响应交换：按 RFC 5389 §7.2.1 的 RTO 机制重发（起始 500ms，指数退避封顶 2s），
// 总时长不超过 timeoutMs；全部超时返回 nil。
func exchange(conn *net.UDPConn, target *net.UDPAddr, req, tid []byte, timeoutMs, maxRetries int) *bindingResponse {
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	wait := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		if _, err := conn.WriteTo(req, target); err != nil {
			return nil
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		w := wait
		if remain < w {
			w = remain
		}
		if r := receiveOnce(conn, tid, w); r != nil {
			return r
		}
		if attempt >= maxRetries || time.Now().After(deadline) {
			break
		}
		if wait *= 2; wait > 2*time.Second {
			wait = 2 * time.Second
		}
	}
	return nil
}

// receiveOnce 接收并解析一次绑定响应（忽略类型/事务 ID 不匹配的包），超时返回 nil
func receiveOnce(conn *net.UDPConn, tid []byte, wait time.Duration) *bindingResponse {
	buf := make([]byte, 512)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil // 超时或 socket 关闭
		}
		data := buf[:n]
		if len(data) < 20 {
			continue
		}
		if readU16(data, 0) != msgBindingResponse {
			continue
		}
		if string(tid) != string(data[8:20]) {
			continue
		}
		mapped := ""
		var other *net.UDPAddr
		length := readU16(data, 2)
		pos := 20
		for pos+4 <= 20+length && pos+4 <= len(data) {
			attrType := readU16(data, pos)
			attrLen := readU16(data, pos+2)
			valStart := pos + 4
			if valStart+attrLen > len(data) {
				break
			}
			switch attrType {
			case attrMappedAddress:
				mapped = parseAddress(data, valStart, false)
			case attrXorMappedAddr:
				mapped = parseAddress(data, valStart, true)
			case attrChangedAddress, attrOtherAddress:
				addr := parseAddress(data, valStart, false)
				if addr != "" {
					if ua, e := net.ResolveUDPAddr("udp4", addr); e == nil {
						other = ua
					}
				}
			}
			pos = valStart + ((attrLen + 3) & ^3) // 属性值按 4 字节对齐
		}
		if mapped != "" {
			return &bindingResponse{mapped: mapped, otherAddress: other, src: src}
		}
	}
}

// detectNatType NAT 类型探测（RFC 3489 / RFC 5780 简化流程）：
//  1. Test1：普通绑定，取得映射地址（RTO 重发）
//  2. 本地地址 == 映射地址 => Open Internet / 1:1 NAT
//  3. Test2：带 CHANGE-REQUEST 标志，响应来自服务器更换后的地址 => Full Cone；
//     同源回复说明服务器忽略该属性，继续测试
//  4. Test3：向服务器的备用地址(OTHER-ADDRESS)再探测，映射不同 => Symmetric
//  5. 其余 => Restricted / Port Restricted；服务器不支持检测时给出保守结论
func detectNatType(conn *net.UDPConn, stunHost string, stunPort, timeoutMs int) *stunResult {
	server, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(stunHost, strconv.Itoa(stunPort)))
	if err != nil {
		// 配置的服务器域名失效/不可达：返回未知结果，不阻断任务启动（运行期保活另有维护列表服务器兜底）
		return &stunResult{natType: "Unknown(STUN服务器无响应)"}
	}
	// Test1：普通绑定，取得映射地址（RTO 重发，UDP 单次丢包不至于误判服务器无响应）
	tid1 := newTxID()
	r1 := exchange(conn, server, buildRequest(tid1, false), tid1, timeoutMs, 2)
	if r1 == nil {
		return &stunResult{natType: "Unknown(STUN服务器无响应)"}
	}

	// 本机出口 == 映射地址 => 无 NAT；映射端口 == 本地端口 => 端口保持型 NAT
	local := conn.LocalAddr().(*net.UDPAddr)
	localStr := local.IP.String() + ":" + strconv.Itoa(local.Port)
	if r1.mapped == localStr {
		return &stunResult{mapped: r1.mapped, natType: "Open Internet(无NAT)"}
	}
	if strings.HasSuffix(r1.mapped, ":"+strconv.Itoa(local.Port)) && !strings.HasPrefix(r1.mapped, "0.0.0.0") {
		return &stunResult{mapped: r1.mapped, natType: "端口保持型NAT(映射端口=本地端口)"}
	}

	// Test2：请求服务器更换 IP+端口 回复（CHANGE-REQUEST 标志位 0x06）。
	// 只有响应确实来自更换后的地址才是 Full Cone；多数现代服务器不支持该属性会原址回复，
	// 同源响应不能作为入站无过滤的证据（否则会被误判为 Full Cone），继续后续测试。
	tid2 := newTxID()
	r2 := exchange(conn, server, buildRequest(tid2, true), tid2, timeoutMs, 1)
	if r2 != nil && (r2.src.IP.String() != server.IP.String() || r2.src.Port != server.Port) {
		return &stunResult{mapped: r1.mapped, natType: "Full Cone(全锥形)"}
	}

	// Test3：向备用地址（OTHER-ADDRESS / CHANGED-ADDRESS，RFC 5780）再探测，映射端口变化说明是对称型
	if r1.otherAddress != nil {
		tid3 := newTxID()
		r3 := exchange(conn, r1.otherAddress, buildRequest(tid3, false), tid3, timeoutMs, 1)
		if r3 != nil && r3.mapped != r1.mapped {
			return &stunResult{mapped: r1.mapped, natType: "Symmetric(对称型)"}
		}
		return &stunResult{mapped: r1.mapped, natType: "Restricted(受限锥形)"}
	}
	return &stunResult{mapped: r1.mapped, natType: "Restricted(受限锥形)"}
}

// ---------- STUN over TCP ----------

// dialBoundTCP 出站 TCP 连接：从指定本地端口（0=随机）连向目标，socket 出生即带 SO_LINGER(0)
// （close 发 RST 而非 FIN，见 lingerControl），返回已连接的 TCPConn。
// 通配绑定被拒时（如 Windows 上 0.0.0.0 监听已开启）退回绑定具体源地址 srcIp 重试
// ——具体地址出站绑定可与通配 LISTEN 共存（natmap 同款做法，等价 Java bindOutbound 的兜底链）。
func dialBoundTCP(host string, port, localPort int, srcIp string, timeoutMs int) (*net.TCPConn, error) {
	addr, err := net.ResolveTCPAddr("tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	d := net.Dialer{
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
		Control:   lingerControl,
		LocalAddr: &net.TCPAddr{Port: localPort},
	}
	conn, err := d.Dial("tcp4", addr.String())
	if err != nil && srcIp != "" && localPort > 0 && isBindFailure(err) {
		// 通配绑定被拒：绑定具体源地址重试（Windows 语义，等价 Java bindOutbound 的 BindException 兜底）
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(srcIp), Port: localPort}
		conn, err = d.Dial("tcp4", addr.String())
	}
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// isBindFailure 判定连接失败是否为本地端口绑定被拒（区别于对端拒绝/超时，决定是否走具体源地址兜底）
func isBindFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "bind") || strings.Contains(s, "Only one usage of each socket address") ||
		strings.Contains(s, "address already in use") || strings.Contains(s, "cannot assign requested address")
}

// bindOverTcp STUN-over-TCP 探测（兼容旧调用）：仅返回外网映射地址，探测连接用后即关闭。
func bindOverTcp(stunHost string, stunPort, localPort, timeoutMs int) string {
	p := probeOverTcp(stunHost, stunPort, "", localPort, timeoutMs)
	if p == nil {
		return ""
	}
	_ = p.conn.Close()
	return p.mapped
}

// probeOverTcp STUN-over-TCP 探测（RFC 5389 §7.1）：从指定本地端口向 STUN 服务器建立 TCP 连接
// 并发送绑定请求，返回该 TCP 出口的外网映射地址、实际本地端口与保持打开的探测连接。
//
// 出站连接会在沿途全部 NAT（含运营商 CGNAT）上建立真实 TCP 映射，
// CGNAT 通常会改写外网端口，入站访问需以返回的映射地址为准。
// 连接不关闭：实测该类映射的入站可达性依赖出站连接的活跃状态，连接关闭后映射很快失效；
// 调用方应持有该连接。注意公共服务器多为单事务型（响应后约 1 秒内断开），周期保活需按同本地端口轮换新建连接；
// 不用时调用方负责关闭。服务器不支持 STUN/TCP 或本地端口绑定失败时返回 nil。
func probeOverTcp(stunHost string, stunPort int, srcIp string, localPort, timeoutMs int) *tcpProbe {
	conn, err := dialBoundTCP(stunHost, stunPort, localPort, srcIp, timeoutMs)
	if err != nil {
		return nil
	}
	mapped := exchangeTcpBinding(conn, timeoutMs)
	if mapped == "" {
		_ = conn.Close()
		return nil
	}
	return &tcpProbe{mapped: mapped, localPort: conn.LocalAddr().(*net.TCPAddr).Port, conn: conn}
}

// bindingOverTcp 在已建立的 STUN-over-TCP 长连接上做一次绑定交互（保活复用同一连接时外网映射端口不漂移），
// 返回外网映射地址；连接异常/服务器无响应时返回空串（连接本身保持，由调用方决定重连或关闭）。
func bindingOverTcp(conn *net.TCPConn, timeoutMs int) string {
	return exchangeTcpBinding(conn, timeoutMs)
}

// connectOutboundEx 公共出站端点连接（端口保留模式/双链路保活段）：从指定本地端口向端点建立 TCP 连接，
// 连接建立即返回——出站连接在沿途全部 NAT（含运营商 CGNAT）上建立映射，TCP 三次握手完成
// 本身就是双向链路的验证，连接上不做任何应用层交互（域名解析按其设计走 UDP 53，由系统解析器承担）。
// 注意端点须为透传服务：53/TCP 等被运营商透明拦截的端口，连接终结在 CGNAT 上，
// 建立的映射不接受入站。调用方持有连接至下一保活周期（映射跟随连接存活），
// 失败携带原因上抛（连接被拒/超时等，供调用方记录端点失效原因）。
func connectOutboundEx(host string, port int, srcIp string, localPort, timeoutMs int) (*net.TCPConn, error) {
	return dialBoundTCP(host, port, localPort, srcIp, timeoutMs)
}

// exchangeTcpBinding STUN-over-TCP 绑定交互（RFC 5389 §7.1）：发送 Binding 请求并解析响应返回映射地址。
// 直接读底层流不做缓冲保留，方法本身可在同一连接上反复调用；但实测公共 STUN/TCP 服务器
// 多为单事务型（响应后约 1 秒内发 RST/FIN 断开，如 stun.nextcloud.com），此类连接上复用交互会失败，
// 保活按「存活优先：连接存活则原连接刷新交互，死亡才同本地端口轮换新建」。
//
// 请求帧格式先裸后帧：实测 Twilio/Telnyx/Sonetel/nextcloud 等公共 STUN/TCP 服务器
// 只接受裸 STUN 消息（与 Natter 一致，不带帧头），按 RFC §7.2.2 加 2 字节长度帧头时静默丢弃；
// coturn 等标准服务器两者兼容，故先发裸消息，无响应再按 RFC 加帧头重试。响应解析兼容两种格式。
// 连接确已损坏（复位/EOF）时返回空串终止本次交互。
func exchangeTcpBinding(conn *net.TCPConn, timeoutMs int) string {
	mapped, alive := tcpBindingOnce(conn, timeoutMs/2, false)
	if mapped != "" {
		return mapped
	}
	if !alive {
		return "" // 连接已断（非超时）：不再尝试帧格式
	}
	// 裸消息无响应（服务器静默丢弃），改用帧格式重试；连接本身仍存活
	mapped, _ = tcpBindingOnce(conn, timeoutMs/2, true)
	return mapped
}

// tcpBindingOnce 单次绑定交互；framed 为 true 时按 RFC 5389 §7.2.2 写 2 字节长度帧头，否则发裸消息。
// 事务 ID 不符的响应（多为迟到的上一次响应，高延迟链路上常见）不立即判无响应，
// 丢弃该消息保持流对齐后继续读下一条，直到匹配或超时——否则迟到响应会把紧随其后的
// 正确响应一起误判为「交互无响应」。
// 返回 (映射地址, 连接是否可能仍存活)：空串+true 表示超时无响应，空串+false 表示连接已损坏。
func tcpBindingOnce(conn *net.TCPConn, timeoutMs int, framed bool) (string, bool) {
	so := time.Duration(timeoutMs) * time.Millisecond
	if so < 500*time.Millisecond {
		so = 500 * time.Millisecond
	}
	tid := newTxID()
	req := buildRequest(tid, false)
	deadline := time.Now().Add(so)
	_ = conn.SetDeadline(time.Now().Add(so))
	if framed {
		if _, err := conn.Write([]byte{byte(len(req) >> 8), byte(len(req))}); err != nil {
			return "", false
		}
	}
	if _, err := conn.Write(req); err != nil {
		return "", false
	}
	for time.Now().Before(deadline) {
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(remain))
		// 先读 20 字节消息头判定帧格式（多读会把属性首字节混入头部缓冲，后续读数错位导致解析失败）
		head := make([]byte, 20)
		if _, err := io.ReadFull(conn, head); err != nil {
			if isTimeout(err) {
				return "", true
			}
			return "", false // EOF/复位：连接已死
		}
		var msgLen int
		switch {
		case readU16(head, 0) == msgBindingResponse && readU32(head, 4) == magicCookie:
			// 裸消息（Natter 式，多数公共 STUN/TCP 服务器只接受该格式）
			msgLen = readU16(head, 2)
		case readU16(head, 2) == msgBindingResponse && readU32(head, 6) == magicCookie:
			// RFC 5389 §7.2.2：2 字节长度帧头 + 消息体，帧值即消息长度；
			// 首次读数只含帧头 + 18 字节消息头，补齐末尾 2 字节事务 ID
			frame := readU16(head, 0)
			if frame < 20 || (frame-20)%4 != 0 {
				return "", true
			}
			rest := make([]byte, 2)
			if _, err := io.ReadFull(conn, rest); err != nil {
				return "", !isTimeout(err)
			}
			copy(head[0:18], head[2:20])
			copy(head[18:20], rest)
			// Java 侧此处写作 msgLen = frame（帧值=报文总长时会多读 20 字节，疑为笔误），
			// Go 按 RFC §7.2.2 正确语义取帧值减去消息头长度
			msgLen = frame - 20
		default:
			return "", true
		}
		if msgLen%4 != 0 || msgLen > 4096 {
			return "", true // STUN 消息长度恒为 4 字节倍数；超限视为异常报文防失控跳读
		}
		if string(tid) != string(head[8:20]) {
			// 迟到的其他事务响应：丢弃消息体保持流对齐，继续等匹配响应
			skip := make([]byte, msgLen)
			if _, err := io.ReadFull(conn, skip); err != nil {
				if isTimeout(err) {
					return "", true
				}
				return "", false
			}
			continue
		}
		attrs := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, attrs); err != nil {
			if isTimeout(err) {
				return "", true
			}
			return "", false
		}
		full := make([]byte, 0, 20+msgLen)
		full = append(full, head...)
		full = append(full, attrs...)
		return extractMapped(full), true
	}
	return "", true
}

// isTimeout 判定读写错误是否为超时（区别于连接损坏，决定 TCP 存活检测语义）
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	// io.ErrUnexpectedEOF 是消息读到一半连接断开：属连接损坏而非超时
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}
