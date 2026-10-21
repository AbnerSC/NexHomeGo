package ddns

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	core.CloseDB() // 允许重复初始化（多用例共享进程）
	if err := core.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

// insertTask 插入一条最小可用的 DDNS 任务并返回 id（MANUAL 模式避免真实网络请求）。
func insertTask(t *testing.T, providerName string, esa bool) int64 {
	t.Helper()
	siteID := ""
	if esa {
		siteID = "555"
	}
	id, err := core.Insert(`INSERT INTO ddns_task(name, provider, domain, rr, type, ttl, ip_mode, manual_ip,
		access_key_id, access_key_secret, esa_site_id, interval_sec, enabled)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)`,
		"测试任务", providerName, "example.com", "www", "A", 600, "MANUAL", "8.8.8.8",
		"AKID-test", "SECRET-test", siteID, 300)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	return id
}

func getTask(t *testing.T, id int64) *core.Row {
	t.Helper()
	row, err := mustGet(id)
	if err != nil {
		t.Fatalf("mustGet: %v", err)
	}
	return row
}

// ==================== 纯函数 ====================

func TestFullRecordName(t *testing.T) {
	if got := fullRecordName("@", "example.com"); got != "example.com" {
		t.Errorf("@ got %q", got)
	}
	if got := fullRecordName("www", "example.com"); got != "www.example.com" {
		t.Errorf("www got %q", got)
	}
}

func TestEsaRecordMatches(t *testing.T) {
	addrRec := map[string]interface{}{
		"RecordType": "A/AAAA", "Data": map[string]interface{}{"Value": "1.2.3.4"},
	}
	v6Rec := map[string]interface{}{
		"RecordType": "A/AAAA", "Data": map[string]interface{}{"Value": "2001::1"},
	}
	txtRec := map[string]interface{}{"RecordType": "TXT", "Data": map[string]interface{}{"Value": "x"}}
	typeRec := map[string]interface{}{"Type": "CNAME"}
	cases := []struct {
		taskType string
		r        map[string]interface{}
		want     bool
	}{
		{"A", addrRec, true},
		{"AAAA", addrRec, false},
		{"AAAA", v6Rec, true},
		{"A", v6Rec, false},
		{"TXT", txtRec, true},
		{"A", txtRec, false},
		{"CNAME", typeRec, true}, // RecordType 缺省时回落 Type
		{"AAAA", map[string]interface{}{"RecordType": "A", "Data": map[string]interface{}{"Value": "::1"}}, false},
		{"A", map[string]interface{}{"RecordType": "A/AAAA"}, true}, // Data 缺省 → 值按空串判 IPv4（与 Java 一致：A 匹配）
	}
	for _, c := range cases {
		if got := esaRecordMatches(c.taskType, c.r); got != c.want {
			t.Errorf("esaRecordMatches(%q, %v)=%v want %v", c.taskType, c.r, got, c.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	if got := summarize(nil); got != "" {
		t.Errorf("空列表 got %q", got)
	}
	records := []map[string]interface{}{
		{"RR": "www", "Type": "A"},
		{"RecordName": "a.example.com", "RecordType": "CNAME"},
		{"RR": "@", "Type": "TXT"},
	}
	if got := summarize(records); got != "www/A, a.example.com/CNAME, @/TXT" {
		t.Errorf("got %q", got)
	}
	// 超过 10 条以「 …」收尾
	var many []map[string]interface{}
	for i := 0; i < 12; i++ {
		many = append(many, map[string]interface{}{"RR": "r" + string(rune('a'+i)), "Type": "A"})
	}
	got := summarize(many)
	if !strings.HasSuffix(got, " …") || strings.Count(got, "/A") != 10 {
		t.Errorf("截断收尾不符: %q", got)
	}
}

func TestValidate(t *testing.T) {
	ok := map[string]interface{}{
		"name": "task", "domain": "example.com", "rr": "www", "provider": "ALIYUN_DNS",
		"ip_mode": "PUBLIC", "access_key_id": "ak", "access_key_secret": "sk",
	}
	if err := validate(ok); err != nil {
		t.Fatalf("合法表单应通过: %v", err)
	}
	cases := []struct {
		title string
		mod   map[string]interface{}
		want  string
	}{
		{"名称空", map[string]interface{}{"name": " "}, "任务名称不能为空"},
		{"域名空", map[string]interface{}{"domain": ""}, "域名不能为空"},
		{"主机记录空", map[string]interface{}{"rr": ""}, "主机记录不能为空"},
		{"无凭证", func() map[string]interface{} {
			m := copyMap(ok)
			m["access_key_id"] = ""
			m["access_key_secret"] = ""
			return m
		}(), "请选择阿里云凭证配置，或手动填写 AccessKey ID / Secret"},
		{"ESA缺SiteId", func() map[string]interface{} {
			m := copyMap(ok)
			m["provider"] = "ALIYUN_ESA"
			return m
		}(), "ESA 服务商需要填写站点 SiteId"},
		{"MANUAL缺IP", func() map[string]interface{} {
			m := copyMap(ok)
			m["ip_mode"] = "MANUAL"
			return m
		}(), "手动模式必须填写 IP 地址"},
	}
	for _, c := range cases {
		m := copyMap(ok)
		for k, v := range c.mod {
			m[k] = v
		}
		err := validate(m)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v want %q", c.title, err, c.want)
		}
	}
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ==================== IP 解析 ====================

func TestResolveFields(t *testing.T) {
	ip, err := resolveFields("MANUAL", "9.9.9.9", "")
	if err != nil || ip != "9.9.9.9" {
		t.Errorf("MANUAL got %q %v", ip, err)
	}
	_, err = resolveFields("MANUAL", "  ", "")
	if err == nil || err.Error() != "手动模式未填写 IP 地址" {
		t.Errorf("MANUAL 空应报错: %v", err)
	}
	_, err = resolveFields("LOCAL", "", "no-such-nic-xyz")
	if err == nil || err.Error() != "网卡 no-such-nic-xyz 未找到可用 IPv4 地址" {
		t.Errorf("LOCAL 指定网卡应报错: %v", err)
	}
	// MANUAL 值不 trim（对齐 Java yield 原值）
	ip, _ = resolveFields("MANUAL", " 1.2.3.4 ", "")
	if ip != " 1.2.3.4 " {
		t.Errorf("MANUAL 应保留原值: %q", ip)
	}
}

func TestPublicIpmultiURLAndFailure(t *testing.T) {
	setupTestDB(t)
	old := publicIPURLs
	defer func() { publicIPURLs = old }()

	srvGarbage := newIPServer(t, "not-an-ip")
	srvOK := newIPServer(t, " 1.2.3.4 \n")
	publicIPURLs = []string{srvGarbage, srvOK}
	ip, err := publicIP()
	if err != nil || ip != "1.2.3.4" {
		t.Fatalf("应跳过不合格式接口: got %q err %v", ip, err)
	}

	// 全部非 200：静默失败（无 last 异常），文案不带冒号
	srv404 := newStatusServer(t, 404)
	publicIPURLs = []string{srv404}
	_, err = publicIP()
	if err == nil || err.Error() != "获取公网 IP 失败，请检查网络或改用手动/本地网卡模式" {
		t.Fatalf("全失败文案不符: %v", err)
	}

	// 请求异常（服务器已关闭）：last 记录异常信息
	srvDown := newClosedServer(t)
	publicIPURLs = []string{srvDown}
	if _, err := publicIP(); err == nil {
		t.Fatal("连接被拒应失败")
	}
}

func newIPServer(t *testing.T, body string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newStatusServer(t *testing.T, code int) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newClosedServer 已关闭的服务器地址（触发连接被拒异常分支）。
func newClosedServer(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	u := srv.URL
	srv.Close()
	return u
}

// ==================== 同步状态机（真 SQLite + 假阿里云） ====================

func TestSyncFlowAliyunDNS(t *testing.T) {
	setupTestDB(t)
	f, _ := startFakeDNS(t)
	id := insertTask(t, "ALIYUN_DNS", false)

	// 1) 线上无记录 → 新增缓存 RecordId
	if err := doSync(id); err != nil {
		t.Fatalf("首次同步: %v", err)
	}
	task := getTask(t, id)
	if rowStr(task, "record_id") != "900" || rowStr(task, "last_status") != "SUCCESS" ||
		rowStr(task, "last_ip") != "8.8.8.8" {
		t.Fatalf("新增分支状态不符: %v %v %v", rowStr(task, "record_id"), rowStr(task, "last_status"), rowStr(task, "last_ip"))
	}
	if f.addCount != 1 || len(f.records) != 1 {
		t.Fatalf("服务端应新增 1 条: add=%d recs=%v", f.addCount, f.records)
	}

	// 2) 线上一致 → 无变化
	if err := doSync(id); err != nil {
		t.Fatalf("二次同步: %v", err)
	}
	if got := rowStr(getTask(t, id), "last_status"); got != "SUCCESS(无变化)" {
		t.Fatalf("无变化状态=%q", got)
	}

	// 3) 线上被他端改动 → 更新回写
	f.records[0]["Value"] = "7.7.7.7"
	if err := doSync(id); err != nil {
		t.Fatalf("三次同步: %v", err)
	}
	task = getTask(t, id)
	if rowStr(task, "last_status") != "SUCCESS" || f.updateCount != 1 {
		t.Fatalf("更新分支: status=%q updateCount=%d", rowStr(task, "last_status"), f.updateCount)
	}
	if fmt.Sprint(f.records[0]["Value"]) != "8.8.8.8" {
		t.Fatalf("线上值应被改回: %v", f.records[0]["Value"])
	}

	// 4) 查询盲区 + 缓存失效：线上记录消失、按 id 更新报 NotFound → 清缓存重新新增
	f.records = nil
	f.updateFailCode = "InvalidDomainRecord.NotFound"
	if err := doSync(id); err != nil {
		t.Fatalf("四次同步: %v", err)
	}
	task = getTask(t, id)
	if rowStr(task, "record_id") != "901" || f.addCount != 2 {
		t.Fatalf("兜底新增: record_id=%q add=%d", rowStr(task, "record_id"), f.addCount)
	}
	if rowStr(task, "last_status") != "SUCCESS" {
		t.Fatalf("状态=%q", rowStr(task, "last_status"))
	}

	// 5) 同步失败：syncTask 包裹 markStatus FAIL 且 last_ip 保持原值
	f.describeFail = true
	syncTask(id)
	task = getTask(t, id)
	if !strings.HasPrefix(rowStr(task, "last_status"), "FAIL: 阿里云API错误[InternalError]") ||
		rowStr(task, "last_ip") != "8.8.8.8" {
		t.Fatalf("FAIL 状态不符: %q / %q", rowStr(task, "last_status"), rowStr(task, "last_ip"))
	}
}

func TestSyncFlowESA(t *testing.T) {
	setupTestDB(t)
	f := startFakeESA(t)
	f.sk = "SECRET-test" // 与 insertTask 写入任务的手动凭证一致
	f.records = []map[string]interface{}{
		{"RecordName": "www.example.com", "RecordType": "A/AAAA",
			"Data": map[string]interface{}{"Value": "9.9.9.9"}, "RecordId": float64(777)},
	}
	id := insertTask(t, "ALIYUN_ESA", true)
	if err := doSync(id); err != nil {
		t.Fatalf("ESA 同步: %v", err)
	}
	task := getTask(t, id)
	// 匹配线上记录 → 缓存数字 RecordId 转十进制字符串并走更新
	if rowStr(task, "record_id") != "777" || rowStr(task, "last_status") != "SUCCESS" || f.updateCount != 1 {
		t.Fatalf("ESA 更新分支不符: %q %q %d", rowStr(task, "record_id"), rowStr(task, "last_status"), f.updateCount)
	}

	// AAAA 任务遇 IPv4 记录不匹配 → 新增分支
	if _, err := core.Update("UPDATE ddns_task SET type='AAAA', record_id=NULL WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := doSync(id); err != nil {
		t.Fatalf("ESA 新增: %v", err)
	}
	if rowStr(getTask(t, id), "record_id") != "888" {
		t.Fatalf("应走新增: %q", rowStr(getTask(t, id), "record_id"))
	}
}

func TestSyncTaskReentrancy(t *testing.T) {
	setupTestDB(t)
	_, _ = startFakeDNS(t)
	id := insertTask(t, "ALIYUN_DNS", false)
	if !tryEnter(id) {
		t.Fatal("tryEnter 应成功")
	}
	syncTask(id) // 占用中触发：应直接跳过，不改任何状态
	task := getTask(t, id)
	if task.Get("last_sync") != nil {
		t.Fatalf("重入触发不应写状态: %v", task.Get("last_sync"))
	}
	leave(id)
	syncTask(id) // 释放后正常执行
	if getTask(t, id).Get("last_sync") == nil {
		t.Fatal("释放后应完成一次同步")
	}
}

// ==================== 删除远程记录 ====================

func TestDeleteRemoteRecord(t *testing.T) {
	setupTestDB(t)
	f, _ := startFakeDNS(t)

	// 缓存 record_id → 直接删除
	id := insertTask(t, "ALIYUN_DNS", false)
	if _, err := core.Update("UPDATE ddns_task SET record_id='100' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	f.records = []map[string]interface{}{{"RR": "www", "Type": "A", "Value": "1.1.1.1", "RecordId": "100"}}
	if msg := deleteRemoteRecord(getTask(t, id)); msg != "（已删除远程解析记录 www.example.com）" {
		t.Fatalf("msg=%q", msg)
	}
	if f.deleteCount != 1 || len(f.records) != 0 {
		t.Fatalf("delete=%d recs=%v", f.deleteCount, f.records)
	}

	// 无缓存且线上无记录（先清本地缓存 id，回查分支才会生效）
	if _, err := core.Update("UPDATE ddns_task SET record_id=NULL WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if msg := deleteRemoteRecord(getTask(t, id)); msg != "（远程无 www.example.com 解析记录，无需删除）" {
		t.Fatalf("无记录 msg=%q", msg)
	}

	// NotFound 视为已删除成功
	if _, err := core.Update("UPDATE ddns_task SET record_id='100' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	f.deleteFailCode = "InvalidRecordRecord.NotFound"
	if msg := deleteRemoteRecord(getTask(t, id)); msg != "（远程解析记录已不存在）" {
		t.Fatalf("NotFound msg=%q", msg)
	}

	// 其他错误：描述失败原因但不阻断
	f.deleteFailCode = "Throttling"
	msg := deleteRemoteRecord(getTask(t, id))
	if !strings.HasPrefix(msg, "（远程解析记录删除失败: 阿里云API错误[Throttling]") {
		t.Fatalf("失败 msg=%q", msg)
	}
}
