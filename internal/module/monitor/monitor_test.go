package monitor

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// ---------- 纯工具函数 ----------

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		target string
		want   []string
	}{
		{"192.168.1.10:22", []string{"192.168.1.10", "22"}},
		{"example.com:8443", []string{"example.com", "8443"}},
		{"[::1]:53", []string{"::1", "53"}},
		{"[fe80::1]:8080", []string{"fe80::1", "8080"}},
		{"no-colon", nil},
		{"host:", nil},
		{":80", nil},
		{"[::1]:", nil}, // 端口为空，Java 同判非法
		{"[::1", nil},   // 缺右括号
	}
	for _, c := range cases {
		got := splitHostPort(c.target)
		if (c.want == nil && got != nil) ||
			(c.want != nil && (got == nil || got[0] != c.want[0] || got[1] != c.want[1])) {
			t.Errorf("splitHostPort(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestNormalizeMethod(t *testing.T) {
	for _, m := range []string{"post", " POST ", "POST"} {
		if got := normalizeMethod(m); got != "POST" {
			t.Errorf("normalizeMethod(%q) = %q, want POST", m, got)
		}
	}
	for _, m := range []string{"", "get", "put", "HEAD"} {
		if got := normalizeMethod(m); got != "GET" {
			t.Errorf("normalizeMethod(%q) = %q, want GET", m, got)
		}
	}
}

func TestRecoverConfirm(t *testing.T) {
	cases := map[int]int{0: 2, 1: 2, 2: 2, 3: 3, 10: 10}
	for th, want := range cases {
		if got := recoverConfirm(th); got != want {
			t.Errorf("recoverConfirm(%d) = %d, want %d", th, got, want)
		}
	}
}

func TestFloorMod(t *testing.T) {
	if got := floorMod(13, 5); got != 3 {
		t.Errorf("floorMod(13,5) = %d, want 3", got)
	}
	if got := floorMod(-1, 5); got != 4 { // 对齐 Java Math.floorMod
		t.Errorf("floorMod(-1,5) = %d, want 4", got)
	}
	if got := floorMod(7, 1); got != 0 {
		t.Errorf("floorMod(7,1) = %d, want 0", got)
	}
}

func TestStatusOK(t *testing.T) {
	// 指定期望码：精确匹配
	if !statusOK(200, 200) || statusOK(302, 200) || statusOK(201, 200) {
		t.Error("expect>0 时应精确匹配期望状态码")
	}
	// 未指定期望码（0/负数）：2xx/3xx 可用
	for _, code := range []int{200, 204, 301, 399} {
		if !statusOK(code, 0) {
			t.Errorf("statusOK(%d,0) 应为 true", code)
		}
	}
	for _, code := range []int{100, 400, 404, 503} {
		if statusOK(code, 0) {
			t.Errorf("statusOK(%d,0) 应为 false", code)
		}
	}
}

func TestValidate(t *testing.T) {
	b := func(kv map[string]interface{}) map[string]interface{} { return kv }
	if err := validate(b(map[string]interface{}{"name": "", "type": "HTTP", "target": "http://x.com"})); err == nil {
		t.Error("名称为空应校验失败")
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "FTP", "target": "http://x.com"})); err == nil {
		t.Error("不支持的类型应校验失败")
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "HTTP", "target": "x.com"})); err == nil {
		t.Error("HTTP 目标缺协议前缀应校验失败")
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "TCP", "target": "host"})); err == nil {
		t.Error("TCP 目标缺端口应校验失败")
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "TCP", "target": "host:abc"})); err == nil {
		t.Error("TCP 端口非法应校验失败")
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "TCP", "target": "host:70000"})); err == nil {
		t.Error("端口越界应校验失败")
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "HTTP", "target": "https://x.com", "timeout_sec": float64(0)})); err == nil {
		t.Error("超时非正应校验失败")
	}
	// UDP 表单层面通过校验（真实探测在执行期进行），与 Java 前端零改动
	if err := validate(b(map[string]interface{}{"name": "n", "type": "UDP", "target": "[::1]:53"})); err != nil {
		t.Errorf("UDP 表单应通过校验: %v", err)
	}
	if err := validate(b(map[string]interface{}{"name": "n", "type": "http", "target": "http://x.com"})); err != nil {
		t.Errorf("合法 HTTP 任务应通过校验: %v", err)
	}
}

// ---------- 状态机端到端（真 SQLite + httptest） ----------

func setupTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := core.InitDB(dir + "/test.db"); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

func TestProbeStateMachine(t *testing.T) {
	setupTestDB(t)

	var (
		evMu   sync.Mutex
		events []string
	)
	NotifyBroadcast = func(event, title, message string) {
		evMu.Lock()
		events = append(events, event)
		evMu.Unlock()
	}
	t.Cleanup(func() { NotifyBroadcast = nil })

	var alive atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if alive.Load() {
			_, _ = io.WriteString(w, "OK-service")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "down")
	}))
	defer srv.Close()
	alive.Store(true)

	// expect_status=0（2xx/3xx 判定）、fail_threshold=2、关键字 service
	id, err := core.Insert(`INSERT INTO monitor_task(name, type, target, method, keyword, expect_status,
		interval_sec, timeout_sec, fail_threshold, enabled, notify_on_recovery)
		VALUES('状态机','HTTP',?,'GET','service',0,15,3,2,1,1)`, srv.URL)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// 1) 首轮成功 → UP，无通知（无故障历史不发恢复）
	probe(id, false)
	assertTask(t, id, "UP", 0)
	assertEvents(t, &evMu, &events, nil)

	// 2) 失败第 1 次（未达阈值，不告警）
	alive.Store(false)
	probe(id, false)
	assertTask(t, id, "DOWN", 1)
	assertEvents(t, &evMu, &events, nil)

	// 3) 失败第 2 次（刚跨阈值，恰好一次 monitor.down）
	probe(id, false)
	assertTask(t, id, "DOWN", 2)
	assertEvents(t, &evMu, &events, []string{"monitor.down"})

	// 4) 持续宕机第 3 次：fail 累加但不重复告警
	probe(id, false)
	assertTask(t, id, "DOWN", 3)
	assertEvents(t, &evMu, &events, []string{"monitor.down"})

	// 5) 恢复第 1 个成功周期：等待连续确认（recoverConfirm(2)=2），不改状态不发通知
	alive.Store(true)
	probe(id, false)
	assertTask(t, id, "DOWN", 3) // 等待确认分支只更新 last_check/last_latency_ms，fail_count 保留原值（与 Java 一致）
	assertEvents(t, &evMu, &events, []string{"monitor.down"})

	// 6) 恢复第 2 个成功周期：确认恢复 → UP 清零 + 一次 monitor.up
	probe(id, false)
	assertTask(t, id, "UP", 0)
	assertEvents(t, &evMu, &events, []string{"monitor.down", "monitor.up"})

	// 7) 再次故障达阈值后，manual 探测跳过连续确认立即恢复并通知
	alive.Store(false)
	probe(id, false)
	probe(id, false)
	assertTask(t, id, "DOWN", 2)
	assertEvents(t, &evMu, &events, []string{"monitor.down", "monitor.up", "monitor.down"})
	alive.Store(true)
	probe(id, true) // manual=true
	assertTask(t, id, "UP", 0)
	assertEvents(t, &evMu, &events, []string{"monitor.down", "monitor.up", "monitor.down", "monitor.up"})
}

func TestProbeTCPTransientRetry(t *testing.T) {
	setupTestDB(t)

	var (
		evMu    sync.Mutex
		events  []string
		details []string
	)
	NotifyBroadcast = func(event, title, message string) {
		evMu.Lock()
		events = append(events, event)
		details = append(details, message)
		evMu.Unlock()
	}
	t.Cleanup(func() { NotifyBroadcast = nil })

	// 占一个端口后立即关闭，制造稳定「连接被拒」的瞬时故障
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	id, err := core.Insert(`INSERT INTO monitor_task(name, type, target, method, keyword, expect_status,
		interval_sec, timeout_sec, fail_threshold, enabled, notify_on_recovery)
		VALUES('TCP端口','TCP',?,'GET','',0,15,3,1,1,0)`, addr)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	probe(id, false)
	assertTask(t, id, "DOWN", 1)
	assertEvents(t, &evMu, &events, []string{"monitor.down"})
	evMu.Lock()
	msg := details[0]
	evMu.Unlock()
	if !strings.Contains(msg, "TCP 连接失败") || !strings.Contains(msg, "已重试 2 次") {
		t.Errorf("瞬时故障应在周期内重试 3 次并标注重试次数，实际告警详情: %s", msg)
	}
}

func TestProbeUDPBestEffortUp(t *testing.T) {
	setupTestDB(t)
	// 起一个回显 UDP 服务：收到任何报文即原样回一包，验证尽力型探测「收到回包=可用」路径。
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], addr)
		}
	}()
	target := pc.LocalAddr().String() // 127.0.0.1:<随机端口>，非 53 走尽力型分支
	id, err := core.Insert(`INSERT INTO monitor_task(name, type, target, interval_sec, timeout_sec, fail_threshold, enabled)
		VALUES('UDP回显','UDP',?,15,3,1,1)`, target)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	up, detail, err := doProbe(mustGetRowForTest(t, id), 3)
	if err != nil {
		t.Fatalf("UDP 探测不应报错: %v", err)
	}
	if !up || !strings.Contains(detail, "收到回包") {
		t.Errorf("收到回包应判可用，实际: up=%v detail=%q", up, detail)
	}
}

// ---------- 断言辅助 ----------

func assertTask(t *testing.T, id int64, wantStatus string, wantFail int) {
	t.Helper()
	row, err := core.QueryOne("SELECT last_status, fail_count FROM monitor_task WHERE id=?", id)
	if err != nil || row == nil {
		t.Fatalf("查询任务失败: %v", err)
	}
	if got := rowStr(row, "last_status"); got != wantStatus {
		t.Errorf("last_status = %s, want %s", got, wantStatus)
	}
	if got := rowInt(row, "fail_count"); got != wantFail {
		t.Errorf("fail_count = %d, want %d", got, wantFail)
	}
}

func assertEvents(t *testing.T, mu *sync.Mutex, events *[]string, want []string) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if len(*events) != len(want) {
		t.Fatalf("通知事件 = %v, want %v", *events, want)
	}
	for i := range want {
		if (*events)[i] != want[i] {
			t.Fatalf("通知事件 = %v, want %v", *events, want)
		}
	}
}

func mustGetRowForTest(t *testing.T, id int64) *core.Row {
	t.Helper()
	row, err := mustGet(id)
	if err != nil {
		t.Fatalf("mustGet: %v", err)
	}
	return row
}
