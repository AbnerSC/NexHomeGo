package monitor

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 服务/端口可用性监控。
// 复刻 Java MonitorService：HTTP/HTTPS（URL 状态码 + 关键字判定）、TCP（连接可达）、UDP（尽力探测）三类探测。
// UDP 中 53 端口按标准 DNS 查询探测（有应答才判可用），其余端口收不到回包且未收到 ICMP 端口不可达差错时按可达处理。
// 探测按任务间隔周期调度，每个任务独立 goroutine（等价 Java 的虚拟线程池提交），绝不占用 core 调度池
// （慢速网络 IO 会饥饿 DDNS 同步 / 证书续期等关键周期任务，遵循既有线程隔离规范）。
//
// 抗抖动（与 Java 一致的四个根治点）：
//   - 单个周期内对传输层瞬时故障（连接/读超时、DNS 解析失败、TLS 握手失败、连接被拒）自动重试
//     probeAttempts 次，任一成功即判可用；应用层判定（状态码/关键字不符）不做无意义重试；
//   - 单次尝试超时不低于 minAttemptTimeoutSec 秒——HTTPS 握手叠加 VPN/overlay 链路 RTT 时，
//     1~2 秒的预算极易把健康目标判成故障；
//   - 各任务按 ID 确定性错峰触发，避免同一秒齐发冷连接互相放大时延（编辑任务也不会重新对齐）；
//   - DOWN→UP 需连续多个周期成功才确认恢复，避免链路抖动时状态与通知来回翻转。
//
// 状态机（通知去重，保证一个故障周期内异常/恢复各只发一次）：
//   - UP→DOWN：连续失败刚达到 fail_threshold 时触发一次 monitor.down 告警；
//     持续宕机期间 fail_count 继续累加，不再重复发送异常通知。
//   - DOWN→UP：仅当本故障周期确实发过告警（fail_count 曾达阈值）时，
//     且连续成功数达到恢复确认次数，触发一次 monitor.up 恢复通知。
//
// 结果写回 monitor_task。

// NotifyBroadcast 通知广播钩子（event/title/message）：NOTIFY 模块建成后注入实现；
// 未注入时为空操作，监控告警仅落运行日志，不影响状态机。
var NotifyBroadcast func(event, title, message string)

func broadcast(event, title, message string) {
	if NotifyBroadcast != nil {
		NotifyBroadcast(event, title, message)
	}
}

const (
	// 探测固定用 HTTP/1.1：Go 默认 Transport 会为 https 协商 HTTP/2，且明文 h2c 升级头
	// 让路由器/NAS 这类嵌入式 Web 服务常处理不了而直接挂起，表现为偶发连接超时（与 Java 注释同源问题）。
	probeAttempts        = 3        // 单个周期内的探测尝试次数：吸收一次链路抖动，不至于一抖就告警
	retryGapMs           = 800      // 两次尝试之间的间隔（毫秒）
	minAttemptTimeoutSec = 3        // 单次尝试的最小超时（秒）：低于此值的配置对 HTTPS/overlay 链路不现实
	recoverConfirmMin    = 2        // DOWN→UP 恢复至少需连续成功的周期数（与 fail_threshold 取较大值）
	probeFirstDelaySec   = 3        // 任务启用/编辑后的首个探测延迟基准（秒），叠加按 ID 的错峰偏移
	maxProbeBodyBytes    = 10 << 20 // 关键字判定读取的响应体上限（10MB，防御性截断）

	// dnsProbeName DNS（UDP 53）探测用的查询域名：任意 A 记录查询能拿到应答即证明解析服务存活。
	dnsProbeName = "example.com"
	// udpICMPGraceMs 尽力型 UDP 探测：首包无回包后，补发一包给 ICMP 端口不可达差错留的短等待窗口（毫秒）。
	udpICMPGraceMs = 500
)

var (
	httpClient = &http.Client{
		// NORMAL 重定向策略：Go 默认最多跟随 10 次，与 Java HttpClient.Redirect.NORMAL 对齐
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			// 空且非 nil 的 TLSNextProto 显式关闭 HTTP/2，强制 HTTP/1.1
			TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		},
	}

	mu        sync.Mutex
	probing   = map[int64]bool{}               // 防重入：同一任务同一时刻只有一个探测周期
	streaks   = map[int64]int{}                // 本故障周期的连续成功计数（内存态，重启归零，仅用于 DOWN→UP 恢复确认）
	schedules = map[int64]context.CancelFunc{} // 各任务的调度 goroutine 取消句柄
)

// RegisterRoutes 注册 REST 接口（路径/方法与 Java MonitorService.registerRoutes 一致）。
func RegisterRoutes() {
	web.Route("GET", "/api/monitor/tasks", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM monitor_task ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
	web.Route("POST", "/api/monitor/tasks", create)
	web.Route("PUT", "/api/monitor/tasks/{id}", update)
	web.Route("DELETE", "/api/monitor/tasks/{id}", remove)
	web.Route("POST", "/api/monitor/tasks/{id}/run", func(c *web.Ctx) error {
		id := c.ParamLong("id")
		if _, err := mustGet(id); err != nil {
			return err
		}
		if isProbing(id) {
			c.Ok("该任务正在探测中，请稍候刷新查看结果")
			return nil
		}
		core.Run(func() { probe(id, true) })
		c.Ok("已触发一次探测，请在列表中查看结果")
		return nil
	})
}

// Init 启动时加载启用任务并建立调度。
func Init() {
	rows, err := core.Query("SELECT * FROM monitor_task")
	if err != nil {
		core.LogError(core.LogMonitor, "加载监控任务失败: "+err.Error())
		return
	}
	for _, task := range rows {
		schedule(task)
	}
	mu.Lock()
	n := len(schedules)
	mu.Unlock()
	core.LogInfo(core.LogMonitor, "监控任务已加载，共 "+strconv.Itoa(n)+" 个定时探测")
}

// ---------- 增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	id, err := core.Insert(`INSERT INTO monitor_task(name, type, target, method, keyword, expect_status,
		interval_sec, timeout_sec, fail_threshold, enabled, notify_on_recovery)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		core.BodyStr(b, "name"), strings.ToUpper(core.BodyStr(b, "type")), strings.TrimSpace(core.BodyStr(b, "target")),
		normalizeMethod(core.BodyStr(b, "method")), core.BodyStr(b, "keyword"),
		core.BodyNum(b, "expect_status", 200), core.BodyNum(b, "interval_sec", 60),
		core.BodyNum(b, "timeout_sec", 10), core.BodyNum(b, "fail_threshold", 1),
		boolToInt(core.BodyBool(b, "enabled", true)), boolToInt(core.BodyBool(b, "notify_on_recovery", true)))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogMonitor, "新增监控任务: "+core.BodyStr(b, "name"))
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	schedule(task)
	core.Run(func() { probe(id, false) })
	c.Ok(task)
	return nil
}

func update(c *web.Ctx) error {
	id := c.ParamLong("id")
	if _, err := mustGet(id); err != nil {
		return err
	}
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	if _, err := core.Update(`UPDATE monitor_task SET name=?, type=?, target=?, method=?, keyword=?, expect_status=?,
		interval_sec=?, timeout_sec=?, fail_threshold=?, enabled=?, notify_on_recovery=? WHERE id=?`,
		core.BodyStr(b, "name"), strings.ToUpper(core.BodyStr(b, "type")), strings.TrimSpace(core.BodyStr(b, "target")),
		normalizeMethod(core.BodyStr(b, "method")), core.BodyStr(b, "keyword"),
		core.BodyNum(b, "expect_status", 200), core.BodyNum(b, "interval_sec", 60),
		core.BodyNum(b, "timeout_sec", 10), core.BodyNum(b, "fail_threshold", 1),
		boolToInt(core.BodyBool(b, "enabled", true)), boolToInt(core.BodyBool(b, "notify_on_recovery", true)), id); err != nil {
		return err
	}
	core.LogInfo(core.LogMonitor, "更新监控任务 #"+strconv.FormatInt(id, 10)+": "+core.BodyStr(b, "name"))
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	schedule(task)
	c.Ok(task)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	cancelSchedule(id)
	if _, err := core.Update("DELETE FROM monitor_task WHERE id=?", id); err != nil {
		return err
	}
	core.LogInfo(core.LogMonitor, "删除监控任务 #"+strconv.FormatInt(id, 10)+": "+rowStr(task, "name"))
	c.Ok("已删除")
	return nil
}

// validate 表单校验（HTTP/HTTPS/TCP/UDP 四类均支持，目标格式按类型分别校验，与 Java MonitorService 一致）。
func validate(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("任务名称不能为空")
	}
	typ := strings.ToUpper(core.BodyStr(b, "type"))
	switch typ {
	case "HTTP", "HTTPS", "TCP", "UDP":
	default:
		return core.NewBadRequest("不支持的探测类型: %s", core.BodyStr(b, "type"))
	}
	target := strings.TrimSpace(core.BodyStr(b, "target"))
	if target == "" {
		return core.NewBadRequest("探测目标不能为空")
	}
	if typ == "HTTP" || typ == "HTTPS" {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			return core.NewBadRequest("HTTP(S) 探测目标需为完整 URL（含 http:// 或 https://）")
		}
	} else {
		hp := splitHostPort(target)
		if hp == nil {
			return core.NewBadRequest("TCP/UDP 探测目标需为 host:port 格式")
		}
		port, err := strconv.Atoi(strings.TrimSpace(hp[1]))
		if err != nil {
			return core.NewBadRequest("TCP/UDP 探测端口非法: %s", hp[1])
		}
		if port < 1 || port > 65535 {
			return core.NewBadRequest("TCP/UDP 探测端口需在 1-65535")
		}
	}
	if core.BodyNum(b, "timeout_sec", 10) <= 0 {
		return core.NewBadRequest("超时时间需大于 0")
	}
	return nil
}

func normalizeMethod(m string) string {
	v := strings.ToUpper(strings.TrimSpace(m))
	if v == "POST" {
		return "POST"
	}
	return "GET"
}

// ---------- 探测执行 ----------

// transientErr 传输层瞬时故障（连接/读超时、DNS 解析失败、TLS 握手失败、连接被拒），周期内可重试；
// 其余错误（配置/格式类、应用层判定）重试只会白耗时间。
type transientErr struct{ msg string }

func (e transientErr) Error() string { return e.msg }

// probe 执行一个探测周期（内含瞬时故障重试）并做状态机告警判定。
// manual 为手动「立即探测」：跳过 DOWN→UP 的连续成功确认，结果立即反映到状态，便于改完配置马上验证。
func probe(taskID int64, manual bool) {
	mu.Lock()
	if probing[taskID] {
		mu.Unlock()
		return
	}
	probing[taskID] = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(probing, taskID)
		mu.Unlock()
	}()

	task, err := mustGet(taskID)
	if err != nil {
		core.LogError(core.LogMonitor, "监控任务 #"+strconv.FormatInt(taskID, 10)+" 探测异常: "+err.Error())
		return
	}
	prev := rowStr(task, "last_status")
	prevFail := rowInt(task, "fail_count")
	threshold := rowInt(task, "fail_threshold")
	if threshold < 1 {
		threshold = 1
	}
	timeout := rowInt(task, "timeout_sec")
	if timeout < minAttemptTimeoutSec {
		timeout = minAttemptTimeoutSec
	}
	// 本周期时间预算：不超过约半个探测间隔，避免重试把后续调度周期整个顶掉
	interval := rowInt(task, "interval_sec")
	if interval < 15 {
		interval = 15
	}
	if interval > 60 {
		interval = 60
	}
	budgetMs := int64(interval) * 500

	cycleStart := time.Now()
	var (
		up        bool
		detail    string
		latencyMs int64
	)
	for attempt := 1; ; attempt++ {
		var retryable bool
		var probeErr error
		up, detail, probeErr = doProbe(task, timeout)
		if probeErr != nil {
			up = false
			var te transientErr
			retryable = errors.As(probeErr, &te)
			detail = probeErr.Error()
		}
		latencyMs = time.Since(cycleStart).Milliseconds()
		if attempt > 1 {
			detail = detail + "（已重试 " + strconv.Itoa(attempt-1) + " 次）"
		}
		if up || !retryable || attempt >= probeAttempts {
			break
		}
		if latencyMs+int64(timeout)*1000+retryGapMs > budgetMs {
			break // 超出预算，留给下个周期
		}
		time.Sleep(time.Duration(retryGapMs) * time.Millisecond)
	}
	now := core.Now()

	if up {
		// DOWN→UP 恢复确认：告警已发出的故障周期内，单次成功不改状态、不发恢复通知，
		// 需连续 recoverConfirm 个周期成功才确认，避免链路抖动时「异常/恢复」来回翻转。
		hadAlerted := prev == "DOWN" && prevFail >= threshold
		streak := 0
		if hadAlerted {
			mu.Lock()
			streaks[taskID]++
			streak = streaks[taskID]
			mu.Unlock()
		}
		if hadAlerted && !manual && streak < recoverConfirm(threshold) {
			if _, err := core.Update("UPDATE monitor_task SET last_check=?, last_latency_ms=? WHERE id=?",
				now, latencyMs, taskID); err != nil {
				core.LogError(core.LogMonitor, "监控任务 #"+strconv.FormatInt(taskID, 10)+" 结果写回失败: "+err.Error())
			}
			core.LogInfo(core.LogMonitor, "监控["+rowStr(task, "name")+"] 探测已恢复，等待连续确认（"+
				strconv.Itoa(streak)+"/"+strconv.Itoa(recoverConfirm(threshold))+"）")
			return
		}
		mu.Lock()
		delete(streaks, taskID)
		mu.Unlock()
		if _, err := core.Update("UPDATE monitor_task SET last_status='UP', last_check=?, last_latency_ms=?, fail_count=0 WHERE id=?",
			now, latencyMs, taskID); err != nil {
			core.LogError(core.LogMonitor, "监控任务 #"+strconv.FormatInt(taskID, 10)+" 结果写回失败: "+err.Error())
			return
		}
		// 恢复通知只在「本故障周期确实发过告警」时发送一次：
		// 已告警 <=> 上次状态为 DOWN 且连续失败数已达阈值（fail_count 跨阈值后仍会累加，故用 >=）。
		if hadAlerted {
			notifyIfRecovery(task, latencyMs)
		}
	} else {
		mu.Lock()
		delete(streaks, taskID)
		mu.Unlock()
		fail := prevFail + 1
		if _, err := core.Update("UPDATE monitor_task SET last_status='DOWN', last_check=?, last_latency_ms=?, fail_count=? WHERE id=?",
			now, latencyMs, fail, taskID); err != nil {
			core.LogError(core.LogMonitor, "监控任务 #"+strconv.FormatInt(taskID, 10)+" 结果写回失败: "+err.Error())
			return
		}
		// 异常告警只在连续失败「刚跨过阈值」的那一次发出（fail 精确等于 threshold）；
		// 之后持续宕机时 fail 继续累加（> threshold），不再重复发送异常通知，直到恢复后进入新周期。
		if fail == threshold {
			alertDown(task, detail, fail)
		}
	}
}

// recoverConfirm 恢复确认所需连续成功周期数：与告警阈值对称，至少 recoverConfirmMin 次。
func recoverConfirm(failThreshold int) int {
	if failThreshold > recoverConfirmMin {
		return failThreshold
	}
	return recoverConfirmMin
}

// doProbe 发起一次探测尝试，返回是否可用与详情；transientErr 表示可重试的瞬时故障。
func doProbe(task *core.Row, timeout int) (bool, string, error) {
	switch rowStr(task, "type") {
	case "HTTP", "HTTPS":
		return probeHTTP(task, timeout)
	case "TCP":
		return probeTCP(task, timeout)
	case "UDP":
		return probeUDP(task, timeout)
	default:
		return false, "", errors.New("未知探测类型: " + rowStr(task, "type"))
	}
}

func probeHTTP(task *core.Row, timeout int) (bool, string, error) {
	target := rowStr(task, "target")
	u, err := url.Parse(target)
	if err != nil {
		return false, "", errors.New("探测目标 URL 非法: " + target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var req *http.Request
	if rowStr(task, "method") == "POST" {
		req, err = http.NewRequestWithContext(ctx, "POST", u.String(), http.NoBody)
		if err == nil {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	}
	if err != nil {
		return false, "", errors.New("探测目标 URL 非法: " + target)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// 连接/读超时、DNS 解析失败、TLS 握手失败：均属瞬时故障，交由周期内重试
		return false, "", transientErr{msg: err.Error()}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return false, "", transientErr{msg: err.Error()}
	}
	code := resp.StatusCode
	expect := rowInt(task, "expect_status")
	codeOK := statusOK(code, expect)
	keyword := rowStr(task, "keyword")
	kwOK := keyword == "" || strings.Contains(string(body), keyword)
	detail := "HTTP " + strconv.Itoa(code)
	if keyword != "" {
		if kwOK {
			detail += " 命中关键字"
		} else {
			detail += " 未命中关键字"
		}
	}
	return codeOK && kwOK, detail, nil
}

// statusOK 状态码判定：指定期望码则精确匹配，否则 2xx/3xx 视为可用（与 Java 一致）。
func statusOK(code, expect int) bool {
	if expect > 0 {
		return code == expect
	}
	return code >= 200 && code < 400
}

func probeTCP(task *core.Row, timeout int) (bool, string, error) {
	hp := hostPort(task)
	if hp == nil {
		return false, "", errors.New("探测目标需为 host:port 格式: " + rowStr(task, "target"))
	}
	if _, err := strconv.Atoi(strings.TrimSpace(hp[1])); err != nil {
		return false, "", errors.New("TCP 探测端口非法: " + hp[1])
	}
	// net.DialTimeout 内含 DNS 解析，失败均抛可重试错误（与 Java 显式 getByName 使
	// UnknownHostException 归入 IOException 可重试的意图一致）
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(hp[0], strings.TrimSpace(hp[1])), time.Duration(timeout)*time.Second)
	if err != nil {
		// 向上抛出走周期内重试：连接超时/被拒在链路抖动、目标端 backlog 满时多为一次性
		return false, "", transientErr{msg: "TCP 连接失败: " + err.Error()}
	}
	_ = conn.Close()
	return true, "TCP 连接成功", nil
}

// probeUDP 入口：DNS（53 端口）走标准查询，其余端口走尽力型探测（与 Java probeUdp 一致）。
func probeUDP(task *core.Row, timeout int) (bool, string, error) {
	hp := hostPort(task)
	if hp == nil {
		return false, "", errors.New("探测目标需为 host:port 格式: " + rowStr(task, "target"))
	}
	port, err := strconv.Atoi(strings.TrimSpace(hp[1]))
	if err != nil {
		return false, "", errors.New("UDP 探测端口非法: " + hp[1])
	}
	// DNS 服务器对无关随机报文根本不回包，必须发标准查询，否则永远判故障
	if port == 53 {
		return probeDNS(hp[0], timeout)
	}
	return probeUDPBestEffort(hp[0], port, timeout)
}

// probeDNS 发送标准 A 记录查询，收到 ID 匹配且 QR=1 的应答即判可用（NXDOMAIN 等错误码同样
// 证明解析服务存活）；DNS 是有应答服务，超时无应答抛可重试错误，交由周期内重试吸收上游递归的偶发慢应答。
func probeDNS(host string, timeout int) (bool, string, error) {
	query := dnsQuery(dnsProbeName, rand.Intn(0x10000))
	conn, err := net.Dial("udp", net.JoinHostPort(host, "53"))
	if err != nil {
		// 地址解析失败/不可达：属瞬时故障，可重试
		return false, "", transientErr{msg: "DNS 连接失败: " + err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if _, err = conn.Write(query); err != nil {
		return false, "", transientErr{msg: "DNS 查询发送失败: " + err.Error()}
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false, "", transientErr{msg: "DNS 查询 " + dnsProbeName + " 超时无应答"}
		}
		return false, "", transientErr{msg: "DNS 查询失败: " + err.Error()}
	}
	// 校验：至少头部 12 字节、QR=1（buf[2] 高位）、应答 ID 与查询一致
	if n < 12 || buf[2]&0x80 == 0 || buf[0] != query[0] || buf[1] != query[1] {
		return false, "", transientErr{msg: "DNS 应答报文非法（" + strconv.Itoa(n) + " 字节）"}
	}
	rcode := int(buf[3] & 0x0F)
	answers := (int(buf[6]&0xFF) << 8) | int(buf[7]&0xFF)
	return true, "DNS 应答 " + rcodeName(rcode) + "，" + strconv.Itoa(answers) + " 条记录", nil
}

// probeUDPBestEffort 尽力型 UDP 探测：UDP 无连接，多数服务不会对未知报文回包，因此
// 「收到回包」与「无回包但未收到端口不可达差错」均判可达，仅端口明确不可达时判故障。
// Go 里 connected UDP socket 收到 ICMP 差错后 Read 会报非超时错误（Linux ECONNREFUSED /
// Windows WSAECONNRESET），超时则说无回包——以此替代 Java 的 PortUnreachableException 判定。
func probeUDPBestEffort(host string, port, timeout int) (bool, string, error) {
	payload := []byte("NEXHOME-UDP-PING\n")
	conn, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		// 目标地址解析失败：属瞬时故障，可重试（与 Java getByName 抛 UnknownHostException 同源）
		return false, "", transientErr{msg: "UDP 连接失败: " + err.Error()}
	}
	defer conn.Close()
	reply := make([]byte, 256)
	for round := 0; round < 2; round++ {
		if _, err = conn.Write(payload); err != nil {
			return false, "", transientErr{msg: "UDP 发送失败: " + err.Error()}
		}
		wait := time.Duration(timeout) * time.Second
		if round == 1 {
			wait = time.Duration(udpICMPGraceMs) * time.Millisecond // 补发包短等，给首包可能延迟到达的 ICMP 差错一次机会
		}
		_ = conn.SetDeadline(time.Now().Add(wait))
		n, err := conn.Read(reply)
		if err == nil {
			return true, "UDP 收到回包 " + strconv.Itoa(n) + " 字节", nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue // 无回包：round 0 补发一轮；round 1 仍无回包则按可达处理
		}
		// 非超时错误：connected socket 上即 ICMP 端口不可达差错（Windows 上表现为
		// 上一轮 Write 或本轮 Read 报 connection refused/reset），明确判故障，不重试。
		return false, "UDP 端口不可达（ICMP port unreachable）", nil
	}
	return true, "UDP 无回包且未收到端口不可达差错，按可达处理", nil
}

// dnsQuery 拼装标准 DNS 查询报文：1 条 A 记录问题，无选项（与 Java dnsQuery 逐字节一致）。
func dnsQuery(name string, id int) []byte {
	out := make([]byte, 0, 64)
	out = append(out, byte(id>>8), byte(id), 0x01, 0x00, // flags: 期望递归
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00) // ARCOUNT
	for _, label := range strings.Split(name, ".") {
		lb := []byte(label)
		if len(lb) == 0 || len(lb) > 63 {
			continue
		}
		out = append(out, byte(len(lb)))
		out = append(out, lb...)
	}
	out = append(out, 0, // 根标签
		0x00, 0x01, // QTYPE = A
		0x00, 0x01) // QCLASS = IN
	return out
}

func rcodeName(rcode int) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// ---------- 告警通知 ----------

func alertDown(task *core.Row, detail string, fail int) {
	core.LogWarn(core.LogMonitor, "监控["+rowStr(task, "name")+"] 不可用: "+detail)
	msg := "目标: " + rowStr(task, "target") + "\n类型: " + rowStr(task, "type") +
		"\n原因: " + detail + "\n连续失败: " + strconv.Itoa(fail) + " 次\n时间: " + core.Now()
	broadcast("monitor.down", "监控告警："+rowStr(task, "name")+" 不可用", msg)
}

func notifyIfRecovery(task *core.Row, latencyMs int64) {
	core.LogInfo(core.LogMonitor, "监控["+rowStr(task, "name")+"] 已恢复")
	if rowInt(task, "notify_on_recovery") != 1 {
		return
	}
	msg := "目标: " + rowStr(task, "target") + "\n类型: " + rowStr(task, "type") +
		"\n延迟: " + strconv.FormatInt(latencyMs, 10) + " ms\n时间: " + core.Now()
	broadcast("monitor.up", "监控恢复："+rowStr(task, "name")+" 已恢复", msg)
}

// ---------- 调度 ----------

// schedule 重建任务的周期调度：先取消旧句柄，再启用独立 goroutine 按 initial/interval 触发。
// 探测在自身 goroutine 内串行执行（等价 Java 提交虚拟线程池，不占 core 调度池；
// 慢周期由 probing 防重入兜底，不会跨任务互相影响）。
func schedule(task *core.Row) {
	id := rowInt64(task, "id")
	cancelSchedule(id)
	if rowInt(task, "enabled") != 1 {
		return
	}
	interval := rowInt(task, "interval_sec")
	if interval < 15 {
		interval = 15
	}
	// 按任务 ID 确定性错峰：否则所有任务都在「保存后 3 秒 + 整间隔」上触发，同一秒齐发冷连接
	// （DNS 解析 + TCP 握手 + TLS 叠在一起）会互相放大时延，一个链路毛刺就把全部任务同时带倒。
	// 偏移只由 id 与 interval 决定，所以编辑任务不会把相位重新拉齐。
	spread := int64(interval - probeFirstDelaySec)
	if spread < 1 {
		spread = 1
	}
	initial := int64(probeFirstDelaySec) + floorMod(id*13, spread)

	ctx, cancel := context.WithCancel(context.Background())
	mu.Lock()
	schedules[id] = cancel
	mu.Unlock()
	go func() {
		if !sleepCtx(ctx, time.Duration(initial)*time.Second) {
			return
		}
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				probe(id, false)
			}
		}
	}()
}

// cancelSchedule 取消任务调度并清理恢复确认计数。
func cancelSchedule(id int64) {
	mu.Lock()
	if cancel, ok := schedules[id]; ok {
		cancel()
		delete(schedules, id)
	}
	delete(streaks, id)
	mu.Unlock()
}

func isProbing(id int64) bool {
	mu.Lock()
	defer mu.Unlock()
	return probing[id]
}

// sleepCtx 可取消睡眠；期间被取消返回 false。0 及以下表示不等待。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---------- 工具 ----------

// splitHostPort 拆 host:port，IPv6 字面量带括号：[::1]:53（与 Java 实现逐字节对齐）。
func splitHostPort(target string) []string {
	if strings.HasPrefix(target, "[") {
		c := strings.Index(target, "]:")
		if c < 0 || c == len(target)-2 {
			return nil
		}
		return []string{target[1:c], target[c+2:]}
	}
	c := strings.LastIndexByte(target, ':')
	if c <= 0 || c == len(target)-1 {
		return nil
	}
	return []string{target[:c], target[c+1:]}
}

// hostPort 取任务的 host/port，格式非法（存量脏数据）时返回 nil。
func hostPort(task *core.Row) []string {
	return splitHostPort(rowStr(task, "target"))
}

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM monitor_task WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("监控任务不存在: #%d", id)
	}
	return row, nil
}

// floorMod 非负取模（对齐 Java Math.floorMod，id 为正是等价 a%b，防御负数输入）。
func floorMod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func rowStr(row *core.Row, key string) string {
	switch v := row.Get(key).(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func rowInt(row *core.Row, key string) int { return int(rowInt64(row, key)) }

func rowInt64(row *core.Row, key string) int64 {
	switch v := row.Get(key).(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case []byte:
		n, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	default:
		return 0
	}
}
