package stun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"NexHomeGo/internal/core"
)

// ==================== STUN 协议编解码 ====================

func TestBuildRequest(t *testing.T) {
	tid := make([]byte, 12)
	for i := range tid {
		tid[i] = byte(i + 1)
	}
	// 无 CHANGE-REQUEST：仅 20 字节头
	req := buildRequest(tid, false)
	if len(req) != 20 {
		t.Fatalf("普通绑定请求应为 20 字节，got %d", len(req))
	}
	if readU16(req, 0) != msgBindingRequest {
		t.Errorf("消息类型不符: %d", readU16(req, 0))
	}
	if readU16(req, 2) != 0 {
		t.Errorf("属性长度应为 0")
	}
	if readU32(req, 4) != magicCookie {
		t.Errorf("魔术饼干不符")
	}
	if string(req[8:20]) != string(tid) {
		t.Errorf("事务 ID 未正确写入")
	}
	// 带 CHANGE-REQUEST：20 + 8 属性
	req2 := buildRequest(tid, true)
	if len(req2) != 28 || readU16(req2, 2) != 8 {
		t.Errorf("CHANGE-REQUEST 请求应为 28 字节、属性长 8，got len=%d attrLen=%d", len(req2), readU16(req2, 2))
	}
	if readU16(req2, 20) != attrChangeRequest {
		t.Errorf("CHANGE-REQUEST 属性类型不符")
	}
}

// craftMappedResponse 构造含 MAPPED-ADDRESS 属性的绑定响应报文（IPv4）。
func craftMappedResponse(xor bool, port int, ip [4]byte) []byte {
	attrLen := 8
	buf := make([]byte, 20+4+attrLen)
	writeU16(buf, 0, msgBindingResponse)
	writeU16(buf, 2, 4+attrLen)
	writeU32(buf, 4, magicCookie)
	// 事务 ID 保持零
	writeU16(buf, 20, func() int {
		if xor {
			return attrXorMappedAddr
		}
		return attrMappedAddress
	}())
	writeU16(buf, 22, attrLen)
	// value: 1 字节保留 + 1 字节族 + 2 字节端口 + 4 字节 IP
	buf[25] = 0x01 // family = IPv4
	p := port
	ipn := int(ip[0])<<24 | int(ip[1])<<16 | int(ip[2])<<8 | int(ip[3])
	if xor {
		p ^= (magicCookie >> 16) & 0xFFFF
		ipn ^= magicCookie
	}
	writeU16(buf, 26, p)
	writeU32(buf, 28, ipn)
	return buf
}

func TestExtractMapped(t *testing.T) {
	plain := craftMappedResponse(false, 12345, [4]byte{203, 0, 113, 7})
	if got := extractMapped(plain); got != "203.0.113.7:12345" {
		t.Errorf("MAPPED-ADDRESS got %q, want 203.0.113.7:12345", got)
	}
	// XOR 编码应与魔术饼干异或后还原出同一地址
	xored := craftMappedResponse(true, 12345, [4]byte{203, 0, 113, 7})
	if got := extractMapped(xored); got != "203.0.113.7:12345" {
		t.Errorf("XOR-MAPPED-ADDRESS got %q, want 203.0.113.7:12345", got)
	}
	// 短包/无属性应安全返回空
	if got := extractMapped(make([]byte, 10)); got != "" {
		t.Errorf("短包应返回空串，got %q", got)
	}
	empty := make([]byte, 20)
	writeU16(empty, 0, msgBindingResponse)
	writeU16(empty, 2, 0)
	if got := extractMapped(empty); got != "" {
		t.Errorf("无属性响应应返回空串，got %q", got)
	}
}

// ==================== 序列化（存储用 JSON 串） ====================

func TestSerializeWebhooks(t *testing.T) {
	// 无 webhooks 字段 → 空串
	if got := serializeWebhooks(map[string]interface{}{}); got != "" {
		t.Errorf("缺失 webhooks 应为空串，got %q", got)
	}
	// 空数组 / 全空地址 → 空串
	if got := serializeWebhooks(map[string]interface{}{"webhooks": []interface{}{}}); got != "" {
		t.Errorf("空数组应为空串，got %q", got)
	}
	b := map[string]interface{}{
		"webhooks": []interface{}{
			map[string]interface{}{
				"url":     "  https://a.test/hook  ",
				"method":  "get", // 归一化为大写 GET
				"headers": map[string]interface{}{"X-A": "1", "X-B": float64(2)},
				"params":  map[string]interface{}{},
			},
			map[string]interface{}{"url": "   "}, // 空地址忽略
			map[string]interface{}{
				"url":    "http://b.test/x",
				"method": "PUT", // 非 GET 一律回落 POST
				"body":   "  {\"k\":1}  ",
			},
		},
	}
	got := serializeWebhooks(b)
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(got), &items); err != nil {
		t.Fatalf("输出非合法 JSON: %v (%s)", err, got)
	}
	if len(items) != 2 {
		t.Fatalf("应保留 2 项，got %d: %s", len(items), got)
	}
	if items[0]["url"] != "https://a.test/hook" || items[0]["method"] != "GET" {
		t.Errorf("首项归一化错误: %v", items[0])
	}
	if hs, ok := items[0]["headers"].(map[string]interface{}); !ok || hs["X-A"] != "1" || hs["X-B"] != "2" {
		t.Errorf("headers 应统一为字符串值: %v", items[0]["headers"])
	}
	if items[1]["method"] != "POST" {
		t.Errorf("非法方式应回落 POST，got %v", items[1]["method"])
	}
	if items[1]["body"] != "{\"k\":1}" {
		t.Errorf("body 应保留并 trim，got %v", items[1]["body"])
	}
	// 键序：url,method,headers,params(,body)
	if !strings.HasPrefix(got, `[{"url":"https://a.test/hook","method":"GET","headers":`) {
		t.Errorf("首项键序不符: %s", got)
	}
}

func TestSerializePicked(t *testing.T) {
	if got := serializePicked(map[string]interface{}{}, "esa_records"); got != "" {
		t.Errorf("缺失字段应为空串，got %q", got)
	}
	b := map[string]interface{}{
		"esa_records": []interface{}{
			map[string]interface{}{"id": float64(123), "name": " *.edge.test "},
			map[string]interface{}{"id": "0", "name": "占位"},   // id<=0 丢弃
			map[string]interface{}{"id": "abc", "name": "非法"}, // 非数字丢弃
			map[string]interface{}{"id": float64(456)},        // name 缺失→空串
		},
	}
	got := serializePicked(b, "esa_records")
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(got), &items); err != nil {
		t.Fatalf("输出非合法 JSON: %v (%s)", err, got)
	}
	if len(items) != 2 {
		t.Fatalf("应保留 2 项，got %d: %s", len(items), got)
	}
	if items[0]["id"].(float64) != 123 || items[0]["name"] != "*.edge.test" {
		t.Errorf("首项错误: %v", items[0])
	}
	if !strings.HasPrefix(got, `[{"id":123,"name":"*.edge.test"}`) {
		t.Errorf("键序应为 id,name: %s", got)
	}
}

func TestSerializeNotifyChannels(t *testing.T) {
	if got := serializeNotifyChannels(map[string]interface{}{}); got != "" {
		t.Errorf("缺失应为空串，got %q", got)
	}
	b := map[string]interface{}{
		"notify_channels": []interface{}{float64(1), "2", float64(1), "abc", float64(-3), nil},
	}
	got := serializeNotifyChannels(b)
	if got != "[1,2]" {
		t.Errorf("应去重并过滤非法项得 [1,2]，got %q", got)
	}
}

func TestParseChannelIds(t *testing.T) {
	ids := parseChannelIds(`[3, "4", 3, "x", 0, 5]`)
	if len(ids) != 3 || ids[0] != 3 || ids[1] != 4 || ids[2] != 5 {
		t.Errorf("got %v, want [3 4 5]", ids)
	}
	if len(parseChannelIds("")) != 0 {
		t.Errorf("空串应解析为空")
	}
	if len(parseChannelIds("非法json")) != 0 {
		t.Errorf("非法 JSON 应返回空")
	}
}

// ==================== 表单校验（不触库分支） ====================

func TestValidateBase(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"name": "task", "protocol": "TCP", "target_ip": "192.168.1.10",
			"target_port": float64(22), "bind_port": float64(0),
			"stun_host": "stun.l.google.com", "stun_port": float64(19302),
		}
	}
	if err := validate(base()); err != nil {
		t.Fatalf("合法表单应通过: %v", err)
	}
	cases := []struct {
		title string
		mod   map[string]interface{}
		want  string
	}{
		{"名称空", map[string]interface{}{"name": "  "}, "任务名称不能为空"},
		{"协议非法", map[string]interface{}{"protocol": "tcp"}, "协议必须为 TCP 或 UDP"},
		{"目标IP空", map[string]interface{}{"target_ip": ""}, "内网目标 IP 不能为空"},
		{"目标端口越界", map[string]interface{}{"target_port": float64(70000)}, "内网目标端口需在 1-65535 之间"},
		{"STUN地址空", map[string]interface{}{"stun_host": " "}, "STUN 服务器地址不能为空"},
		{"绑定端口非法", map[string]interface{}{"bind_port": float64(-1)}, "本地绑定端口需在 0-65535 之间（0=随机）"},
		{"对端格式", map[string]interface{}{"peer_addr": "1.2.3.4"}, "对端公网地址格式需为 ip:端口"},
		{"对端端口非数字", map[string]interface{}{"peer_addr": "1.2.3.4:abc"}, "对端公网地址端口需为数字"},
		{"对端端口越界", map[string]interface{}{"peer_addr": "1.2.3.4:70000"}, "对端端口需在 1-65535 之间"},
	}
	for _, c := range cases {
		m := base()
		for k, v := range c.mod {
			m[k] = v
		}
		err := validate(m)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v want %q", c.title, err, c.want)
		}
	}
	// 合法对端地址
	m := base()
	m["peer_addr"] = "1.2.3.4:8080"
	if err := validate(m); err != nil {
		t.Errorf("合法对端地址应通过: %v", err)
	}
	// Webhook 校验：非法协议
	m = base()
	m["webhooks"] = []interface{}{map[string]interface{}{"url": "ftp://x"}}
	if err := validate(m); err == nil || !strings.Contains(err.Error(), "Webhook 地址必须以 http:// 或 https:// 开头") {
		t.Errorf("非法 webhook 协议应报错，got %v", err)
	}
	m = base()
	m["webhooks"] = []interface{}{map[string]interface{}{"url": "https://x", "method": "DELETE"}}
	if err := validate(m); err == nil || !strings.Contains(err.Error(), "Webhook 请求方式只能为 GET 或 POST") {
		t.Errorf("非法 webhook 方式应报错，got %v", err)
	}
}

// ==================== ESA 同步纯函数 ====================

func TestEsaFamAndNameField(t *testing.T) {
	if esaFam("203.0.113.7") != "IPv4" || esaFam("fe80::1") != "IPv6" {
		t.Error("esaFam 判定错误")
	}
	if esaNameField("ConfigId") != "RuleName" || esaNameField("RecordId") != "RecordName" {
		t.Error("esaNameField 推导错误")
	}
}

func TestParseEsaPicked(t *testing.T) {
	if parseEsaPicked("") != nil {
		t.Error("空串应返回 nil")
	}
	if parseEsaPicked("不是json") != nil {
		t.Error("非法 JSON 应返回 nil")
	}
	picked := parseEsaPicked(`[{"id":10,"name":"a.test"},{"id":20,"name":"b.test"}]`)
	if len(picked) != 2 || picked[0].id != 10 || picked[1].name != "b.test" {
		t.Errorf("解析错误: %+v", picked)
	}
}

func TestEsaLocate(t *testing.T) {
	online := []map[string]interface{}{
		{"RecordId": float64(10), "RecordName": "A.EDGE.TEST"},
		{"RecordId": float64(20), "RecordName": "b.edge.test"},
	}
	// 按 id 命中
	if got := esaLocate(online, 20, "忽略", "RecordId", "RecordName"); got == nil || esaLong(got, "RecordId") != 20 {
		t.Errorf("按 id 定位失败: %v", got)
	}
	// id 未命中回退名称（大小写不敏感）
	if got := esaLocate(online, 999, "a.edge.test", "RecordId", "RecordName"); got == nil || esaLong(got, "RecordId") != 10 {
		t.Errorf("按名称回退失败: %v", got)
	}
	// 都没有 → nil
	if got := esaLocate(online, 999, "nope", "RecordId", "RecordName"); got != nil {
		t.Errorf("未命中应返回 nil，got %v", got)
	}
}

func TestEsaSummarize(t *testing.T) {
	if got := esaSummarize(core.NewRowList()); got != "FAIL(无可同步项)" {
		t.Errorf("空明细 got %q", got)
	}
	l := core.NewRowList()
	l.Append(esaItem("record", "a", "", "", "SKIP", ""))
	l.Append(esaItem("record", "b", "", "", "SKIP", ""))
	if got := esaSummarize(l); got != "OK(无变化)" {
		t.Errorf("全跳过 got %q", got)
	}
	l.Append(esaItem("record", "c", "", "", "OK", ""))
	if got := esaSummarize(l); got != "OK(更新 1 项)" {
		t.Errorf("有更新 got %q", got)
	}
	l2 := core.NewRowList()
	l2.Append(esaItem("record", "x", "", "", "FAIL", ""))
	l2.Append(esaItem("record", "y", "", "", "FAIL", ""))
	if got := esaSummarize(l2); got != "FAIL(2 项全部失败)" {
		t.Errorf("全失败 got %q", got)
	}
	l3 := core.NewRowList()
	l3.Append(esaItem("record", "x", "", "", "OK", ""))
	l3.Append(esaItem("record", "y", "", "", "FAIL", ""))
	if got := esaSummarize(l3); got != "PARTIAL(成功 1/2)" {
		t.Errorf("部分成功 got %q", got)
	}
}

// ==================== 公网入站探测结果解析 ====================

func TestParseCheckResult(t *testing.T) {
	toRoot := func(s string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("用例 JSON 非法: %v", err)
		}
		return m
	}
	// 包裹在 request_id 下，节点连接成功（含 address）
	if got := parseCheckResult(toRoot(`{"rid":{"n1":[{"address":"1.2.3.4:22","time":5}]}}`), "rid"); got != "OK" {
		t.Errorf("成功用例 got %q, want OK", got)
	}
	// 顶层平铺，节点报错
	if got := parseCheckResult(toRoot(`{"n1":[{"error":"connection refused"}]}`), "missing"); got != "FAIL(connection refused)" {
		t.Errorf("失败用例 got %q", got)
	}
	// null：仍在探测 → 空串
	if got := parseCheckResult(toRoot(`{"n1":null}`), "missing"); got != "" {
		t.Errorf("pending 用例 got %q, want 空串", got)
	}
	// 空对象 → 空串
	if got := parseCheckResult(toRoot(`{}`), "rid"); got != "" {
		t.Errorf("空对象 got %q, want 空串", got)
	}
}

// ==================== 自测仲裁：近期真实外网访问证据 ====================

// TestRecentPeerInboundDesc 自测遇到「重建中」时以真实外网访问仲裁：
// 无记录或超出窗口（max(60s, keepaliveSec*6)）返回空串，窗口内有记录返回描述文案。
func TestRecentPeerInboundDesc(t *testing.T) {
	r := &runner{keepaliveSec: 10} // 窗口取下限 60s
	if got := r.recentPeerInboundDesc(); got != "" {
		t.Errorf("无访问记录应返回空串，got %q", got)
	}
	r.lastPeerInbound.Store(time.Now().UnixMilli() - 30_000)
	if got := r.recentPeerInboundDesc(); !strings.Contains(got, "30秒前") {
		t.Errorf("窗口内应返回证据文案，got %q", got)
	}
	r.lastPeerInbound.Store(time.Now().UnixMilli() - 90_000)
	if got := r.recentPeerInboundDesc(); got != "" {
		t.Errorf("超出窗口应返回空串，got %q", got)
	}
	// keepaliveSec=25 → 窗口 150s：90s 前的访问仍在窗口内
	r2 := &runner{keepaliveSec: 25}
	r2.lastPeerInbound.Store(time.Now().UnixMilli() - 90_000)
	if got := r2.recentPeerInboundDesc(); got == "" {
		t.Error("keepaliveSec*6 窗口内应返回证据")
	}
}

// TestRebuildBackoff 出站重建失败退避状态机：失败后设置重试点并只告警一次，
// 恢复后清零——避免每个保活周期（10s）重复探测/弹跳与日志刷屏。
func TestRebuildBackoff(t *testing.T) {
	r := &runner{name: "test", keepaliveSec: 10}
	r.deferRebuild("测试失败")
	until := r.tcpRetryAt.Load()
	if remain := until - time.Now().UnixMilli(); remain <= 0 || remain > rebuildBackoffSec*1000 {
		t.Fatalf("退避窗口异常: %dms", remain)
	}
	if !r.rebuildWarned.Load() {
		t.Fatal("失败后应标记已告警（同一故障不重复刷屏）")
	}
	// 再次失败：重试点滚动后移，告警标记保持（不再重复告警）
	time.Sleep(10 * time.Millisecond)
	r.deferRebuild("测试失败")
	if r.tcpRetryAt.Load() <= until {
		t.Fatal("重复失败应刷新重试时间")
	}
	r.cleanRebuildBackoff()
	if r.tcpRetryAt.Load() != 0 || r.rebuildWarned.Load() {
		t.Fatal("恢复后应清除退避与告警标记")
	}
}

// TestMarkPeerVerifiedThrottle 真实外网访问刷新自测：同一自测周期内只刷一次，
// 窗口外允许再次刷新；数据库未初始化时 Update 失败不应崩溃。
func TestMarkPeerVerifiedThrottle(t *testing.T) {
	r := &runner{name: "test", id: 1, keepaliveSec: 10}
	now := time.Now().UnixMilli()
	if r.markPeerVerified(now) {
		t.Error("数据库未初始化时不应报告刷新成功")
	}
	if got := r.lastPeerVerifiedAt.Load(); got != now {
		t.Fatalf("首次尝试应记录节流基准时间，got %d want %d", got, now)
	}
	// 窗口内（10s）第二次：直接跳过，不重复写库
	if r.markPeerVerified(now + 9_000) {
		t.Error("节流窗口内不应重复刷新")
	}
	if got := r.lastPeerVerifiedAt.Load(); got != now {
		t.Errorf("窗口内时间不应变化，got %d", got)
	}
	// 窗口外：允许再次尝试（记录新基准，Update 仍失败但基准已前进）
	_ = r.markPeerVerified(now + 10_000)
	if got := r.lastPeerVerifiedAt.Load(); got != now+10_000 {
		t.Errorf("窗口外应更新基准时间，got %d", got)
	}
}

// ==================== 公网 IP 判定 ====================

func TestIsPublicIp(t *testing.T) {
	public := []string{"203.0.113.7", "8.8.8.8", "114.114.114.114"}
	private := []string{"10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "100.64.0.1", "169.254.1.1", "", "not-an-ip"}
	for _, ip := range public {
		if !isPublicIp(ip) {
			t.Errorf("%s 应为公网", ip)
		}
	}
	for _, ip := range private {
		if isPublicIp(ip) {
			t.Errorf("%s 应为非公网", ip)
		}
	}
}

// ==================== 大整数 ID 精度（UseNumber 语义） ====================

// TestEsaBigNumberPrecision ESA RecordId/ConfigId 可达 18 位，响应层 json.Number 必须
// 按原始字面量精确取值（等价 Gson getAsLong/getAsString），不可经 float64 丢精度
func TestEsaBigNumberPrecision(t *testing.T) {
	var o map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(`{"RecordId":9123456789012345678,"Ttl":120,"Proxied":true}`))
	dec.UseNumber()
	if err := dec.Decode(&o); err != nil {
		t.Fatal(err)
	}
	if got := esaLong(o, "RecordId"); got != 9123456789012345678 {
		t.Errorf("esaLong=%d", got)
	}
	if got := esaInt(o, "Ttl", 1); got != 120 {
		t.Errorf("esaInt Ttl=%d", got)
	}
	if got := esaStr(o, "RecordId"); got != "9123456789012345678" {
		t.Errorf("esaStr=%q", got)
	}
	if !core.BodyBool(o, "Proxied", false) {
		t.Error("Proxied 应为 true")
	}
	if got := esaInt(o, "Missing", 1); got != 1 {
		t.Errorf("缺失键应回退默认值，got %d", got)
	}
}

// TestParseEsaPickedBigID 勾选快照 JSON 里的大整数 id 必须无损解析
func TestParseEsaPickedBigID(t *testing.T) {
	picked := parseEsaPicked(`[{"id":9123456789012345678,"name":"a.edge.test"}]`)
	if len(picked) != 1 || picked[0].id != 9123456789012345678 || picked[0].name != "a.edge.test" {
		t.Errorf("解析错误: %+v", picked)
	}
}
