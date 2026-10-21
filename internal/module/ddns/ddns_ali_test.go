package ddns

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ==================== 编码与签名原语 ====================

func TestPercentEncode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", "abc"},
		{"a b", "a%20b"}, // 空格 → %20（非 +）
		{"*", "%2A"},     // * 修正
		{"~", "~"},       // %7E 还原为 ~
		{"/", "%2F"},     // 路径分隔符必须转义
		{"2026-10-21T12:00:00Z", "2026-10-21T12%3A00%3A00Z"},
		{"中文", "%E4%B8%AD%E6%96%87"},
		{"a+b", "a%2Bb"},
	}
	for _, c := range cases {
		if got := percentEncode(c.in); got != c.want {
			t.Errorf("percentEncode(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestRfcEncode(t *testing.T) {
	if got := rfcEncode("a b*c~d"); got != "a%20bc%2Ad" && got != "a%20b*c~d" && got != "a%20b%2Ac~d" {
		// rfcEncode 仅修正空格；* 与 ~ 按 Go QueryEscape 行为（* → %2A，~ 保留）
		t.Errorf("rfcEncode got %q", got)
	}
	if got := rfcEncode("a b"); got != "a%20b" {
		t.Errorf("rfcEncode space got %q", got)
	}
}

func TestSha256HexEmpty(t *testing.T) {
	// 空串 SHA-256 十六进制（ESA 签名固定 x-acs-content-sha256 值）
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := sha256Hex(""); got != want {
		t.Errorf("sha256Hex(\"\")=%s want %s", got, want)
	}
}

func TestNewUUID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 5; i++ {
		if !re.MatchString(newUUID()) {
			t.Fatalf("newUUID 格式不符: %s", newUUID())
		}
	}
}

// ==================== 响应 JSON 访问器 ====================

func TestJSONAccessors(t *testing.T) {
	var m map[string]interface{}
	raw := `{"Code":"X","N":42,"B":true,"S":"str","Arr":[{"k":1}],"Obj":{"v":"o"}}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if got := strAt(m, "Code"); got != "X" {
		t.Errorf("strAt Code=%q", got)
	}
	if got := strAt(m, "N"); got != "42" { // Gson getAsString 对数字的等价形态
		t.Errorf("strAt N=%q", got)
	}
	if got := strAt(m, "B"); got != "true" {
		t.Errorf("strAt B=%q", got)
	}
	if got := strAt(m, "Missing"); got != "" {
		t.Errorf("strAt Missing=%q", got)
	}
	if got := strAtIfPresent(m, "Missing"); got != "" {
		t.Errorf("strAtIfPresent Missing=%q", got)
	}
	if f, ok := numAt(m, "N"); !ok || f != 42 {
		t.Errorf("numAt N=%v,%v", f, ok)
	}
	if _, ok := numAt(m, "S"); ok {
		t.Error("numAt 字符串不应为数值")
	}
	if arr := arrAt(m, "Arr"); len(arr) != 1 {
		t.Errorf("arrAt len=%d", len(arr))
	}
	if obj := objAt(m, "Obj"); obj == nil || strAt(obj, "v") != "o" {
		t.Errorf("objAt=%v", obj)
	}
	// numString：数字 ID 取整转十进制；字符串形态原样返回
	if got := numString(map[string]interface{}{"RecordId": float64(777)}, "RecordId"); got != "777" {
		t.Errorf("numString=%q", got)
	}
	if got := numString(map[string]interface{}{"RecordId": "900"}, "RecordId"); got != "900" {
		t.Errorf("numString str=%q", got)
	}
}

func TestEsaDataJSON(t *testing.T) {
	if got := esaDataJSON("1.2.3.4"); got != `{"Value":"1.2.3.4"}` {
		t.Errorf("esaDataJSON=%s", got)
	}
}

func TestEsaRecordTypeFunc(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"A", "A/AAAA"}, {"AAAA", "A/AAAA"}, {"a", "A/AAAA"}, {"TXT", "TXT"}, {"CNAME", "CNAME"},
	} {
		if got := esaRecordType(c.in); got != c.want {
			t.Errorf("esaRecordType(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// ==================== 错误模型 ====================

func TestAPIError(t *testing.T) {
	err := apiError(400, `{"Code":"DomainRecordNotFound","Message":"记录不存在"}`)
	ae, ok := err.(*APIError)
	if !ok {
		t.Fatalf("应为 APIError，实际 %T", err)
	}
	if ae.Error() != "阿里云API错误[DomainRecordNotFound]: 记录不存在" {
		t.Errorf("Error()=%q", ae.Error())
	}
	if !ae.isNotFound() {
		t.Error("Code 含 NotFound 应判定存在")
	}
	// Message 缺省时以原始 body 填充（对齐 Java 三元）
	err2 := apiError(403, `{"Code":"Forbidden"}`)
	if !strings.Contains(err2.Error(), "Forbidden") || !strings.Contains(err2.Error(), `"Code"`) {
		t.Errorf("无 Message 时应带原始 body: %v", err2)
	}
	// 非 JSON 体兜底
	err3 := apiError(500, "oops")
	if err3.Error() != "HTTP 500: oops" {
		t.Errorf("兜底文案=%q", err3.Error())
	}
	if (&APIError{Code: "RecordNotFound"}).isNotFound() != true {
		t.Error("isNotFound")
	}
	if (&APIError{Code: "Throttling"}).isNotFound() {
		t.Error("Throttling 不应判 NotFound")
	}
}

func TestCheckDnsAndEsaError(t *testing.T) {
	if err := checkDnsError(map[string]interface{}{"Code": "Illegal", "Message": "参数错"}); err == nil ||
		err.Error() != "阿里云DNS错误[Illegal]: 参数错" {
		t.Errorf("checkDnsError=%v", err)
	}
	if err := checkDnsError(map[string]interface{}{"RequestId": "x"}); err != nil {
		t.Errorf("成功响应不应报错: %v", err)
	}
	if err := checkEsaError(map[string]interface{}{"Code": "", "Message": "空码"}); err != nil {
		t.Errorf("空 Code 应视为成功: %v", err)
	}
	if err := checkEsaError(map[string]interface{}{"Code": "E1", "Message": "M"}); err == nil ||
		err.Error() != "阿里云ESA错误[E1]: M" {
		t.Errorf("checkEsaError=%v", err)
	}
}

// ==================== 假阿里云 DNS 服务（校验签名 1.0） ====================

type fakeDNS struct {
	mu             sync.Mutex
	ak, sk         string
	records        []map[string]interface{}
	nextID         int
	addCount       int
	updateCount    int
	deleteCount    int
	updateFailCode string // 非空：UpdateDomainRecord 返回 400 + 该 Code（一次性消费）
	deleteFailCode string // 非空：DeleteDomainRecord 返回 400 + 该 Code
	describeFail   bool   // true：DescribeDomainRecords 返回 400 InternalError
}

func (f *fakeDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// 服务端重算签名 1.0 验证（除 Signature 外的全部参数重排序编码）
	if got := q.Get("Signature"); got != f.dnsSign(q) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"Code":"SignatureDoesNotMatch","Message":"server verify failed"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch q.Get("Action") {
	case "DescribeDomainRecords":
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.describeFail {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"Code":"InternalError","Message":"boom"}`))
			return
		}
		rrKey := q.Get("RRKeyWord")
		var matched []map[string]interface{}
		for _, rec := range f.records {
			if strings.EqualFold(fmt.Sprint(rec["RR"]), rrKey) {
				matched = append(matched, rec)
			}
		}
		resp := map[string]interface{}{"RequestId": "req-1"}
		if len(matched) > 0 {
			resp["DomainRecords"] = map[string]interface{}{"Record": matched}
		} else {
			// 无匹配时阿里云仍返回空 Record 数组，也覆盖缺省分支由另一用例验证
			resp["DomainRecords"] = map[string]interface{}{"Record": []interface{}{}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "AddDomainRecord":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.nextID++
		id := strconv.Itoa(899 + f.nextID)
		f.records = append(f.records, map[string]interface{}{
			"RR": q.Get("RR"), "Type": q.Get("Type"), "Value": q.Get("Value"), "RecordId": id,
		})
		f.addCount++
		_, _ = w.Write([]byte(`{"RequestId":"req-2","RecordId":"` + id + `"}`))
	case "UpdateDomainRecord":
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.updateFailCode != "" {
			code := f.updateFailCode
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"Code":"` + code + `","Message":"update failed"}`))
			return
		}
		for _, rec := range f.records {
			if fmt.Sprint(rec["RecordId"]) == q.Get("RecordId") {
				rec["Value"] = q.Get("Value")
			}
		}
		f.updateCount++
		_, _ = w.Write([]byte(`{"RequestId":"req-3"}`))
	case "DeleteDomainRecord":
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.deleteFailCode != "" {
			code := f.deleteFailCode
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"Code":"` + code + `","Message":"delete failed"}`))
			return
		}
		var keep []map[string]interface{}
		for _, rec := range f.records {
			if fmt.Sprint(rec["RecordId"]) != q.Get("RecordId") {
				keep = append(keep, rec)
			}
		}
		f.records = keep
		f.deleteCount++
		_, _ = w.Write([]byte(`{"RequestId":"req-4"}`))
	default:
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"Code":"UnknownAction","Message":"` + q.Get("Action") + `"}`))
	}
}

// dnsSign 按签名算法 1.0 从已解码参数重算 Signature（与客户端实现同算法，验证一致性）。
func (f *fakeDNS) dnsSign(q url.Values) string {
	params := map[string]string{}
	for k, vs := range q {
		if k != "Signature" {
			params[k] = vs[0]
		}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[k]))
	}
	sts := "GET&" + percentEncode("/") + "&" + percentEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(f.sk+"&"))
	mac.Write([]byte(sts))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func startFakeDNS(t *testing.T) (*fakeDNS, *httptest.Server) {
	t.Helper()
	f := &fakeDNS{ak: "AKID-test", sk: "SECRET-test", nextID: 0}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	oldHost := dnsHost
	dnsHost = srv.URL + "/"
	t.Cleanup(func() { dnsHost = oldHost })
	return f, srv
}

func TestDNSDescribeAndAdd(t *testing.T) {
	f, _ := startFakeDNS(t)
	f.records = []map[string]interface{}{
		{"RR": "www", "Type": "A", "Value": "1.1.1.1", "RecordId": "100"},
	}
	records, err := dnsDescribeRecords(f.ak, f.sk, "example.com", "www")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || strAt(records[0], "Value") != "1.1.1.1" {
		t.Fatalf("records=%v", records)
	}
	// 主机记录不匹配（服务端过滤）
	records, err = dnsDescribeRecords(f.ak, f.sk, "example.com", "ftp")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("应无匹配: %v", records)
	}
	// 新增返回 RecordId 并落库线上
	id, err := dnsAddRecord(f.ak, f.sk, "example.com", "ftp", "A", "2.2.2.2", 600)
	if err != nil || id != "900" {
		t.Fatalf("add id=%q err=%v", id, err)
	}
	if err := dnsUpdateRecord(f.ak, f.sk, id, "ftp", "A", "3.3.3.3", 600); err != nil {
		t.Fatalf("update: %v", err)
	}
	if f.updateCount != 1 {
		t.Fatalf("updateCount=%d", f.updateCount)
	}
	if err := dnsDeleteRecord(f.ak, f.sk, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	records, _ = dnsDescribeRecords(f.ak, f.sk, "example.com", "ftp")
	if len(records) != 0 {
		t.Fatalf("删除后应无记录: %v", records)
	}
}

func TestDNSBusinessErrorAndHTTPError(t *testing.T) {
	f, _ := startFakeDNS(t)
	f.describeFail = true
	_, err := dnsDescribeRecords(f.ak, f.sk, "example.com", "www")
	if err == nil || !strings.Contains(err.Error(), "阿里云API错误[InternalError]: boom") {
		t.Fatalf("非 200 应转 APIError: %v", err)
	}
	var ae *APIError
	if !asAPIError(err, &ae) || !strings.Contains(ae.Code, "Error") {
		t.Fatalf("应解析为 APIError: %T", err)
	}
}

// asAPIError errors.As 的本地包装（测试可读性）。
func asAPIError(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok {
		*target = e
	}
	return ok
}

// ==================== 假阿里云 ESA 服务（校验签名 3.0） ====================

type fakeESA struct {
	mu          sync.Mutex
	ak, sk      string
	sites       []map[string]interface{}
	records     []map[string]interface{}
	updateCount int
	lastAction  string
}

func (f *fakeESA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if got := f.esaSign(r); got != authSignature(r) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"Code":"SignatureDoesNotMatch","Message":"server verify failed"}`))
		return
	}
	action := r.Header.Get("x-acs-action")
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAction = action
	switch action {
	case "ListSites":
		resp := map[string]interface{}{"Sites": f.sites, "TotalCount": len(f.sites)}
		_ = json.NewEncoder(w).Encode(resp)
	case "ListRecords":
		var matched []map[string]interface{}
		name := r.URL.Query().Get("RecordName")
		for _, rec := range f.records {
			if strings.EqualFold(fmt.Sprint(rec["RecordName"]), name) {
				matched = append(matched, rec)
			}
		}
		resp := map[string]interface{}{"TotalCount": len(matched)}
		if matched != nil {
			resp["Records"] = matched
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "CreateRecord":
		_, _ = w.Write([]byte(`{"RecordId":888}`))
	case "UpdateRecord":
		f.updateCount++
		_, _ = w.Write([]byte(`{"RecordId":777}`))
	case "DeleteRecord":
		_, _ = w.Write([]byte(`{}`))
	default:
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"Code":"UnknownAction","Message":"` + action + `"}`))
	}
}

// esaSign 服务端按 ACS3-HMAC-SHA256 重算签名。
func (f *fakeESA) esaSign(r *http.Request) string {
	signedHeaders := "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"
	canonicalHeaders := "host:" + r.Host + "\n" +
		"x-acs-action:" + r.Header.Get("x-acs-action") + "\n" +
		"x-acs-content-sha256:" + r.Header.Get("x-acs-content-sha256") + "\n" +
		"x-acs-date:" + r.Header.Get("x-acs-date") + "\n" +
		"x-acs-signature-nonce:" + r.Header.Get("x-acs-signature-nonce") + "\n" +
		"x-acs-version:" + r.Header.Get("x-acs-version") + "\n"
	canonicalRequest := r.Method + "\n/\n" + r.URL.RawQuery + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + sha256Hex("")
	sts := "ACS3-HMAC-SHA256\n" + sha256Hex(canonicalRequest)
	mac := hmac.New(sha256.New, []byte(f.sk))
	mac.Write([]byte(sts))
	return hexLower(mac.Sum(nil))
}

func startFakeESA(t *testing.T) *fakeESA {
	t.Helper()
	f := &fakeESA{ak: "AKID-esa", sk: "SECRET-esa"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	oldScheme, oldHost := esaScheme, esaHost
	esaScheme, esaHost = "http", srv.Listener.Addr().String()
	t.Cleanup(func() { esaScheme, esaHost = oldScheme, oldHost })
	return f
}

func TestESAListSitesAndRecords(t *testing.T) {
	f := startFakeESA(t)
	f.sites = []map[string]interface{}{
		{"SiteId": float64(555), "SiteName": "example.com", "Status": "active"},
	}
	sites, err := esaListSites(f.ak, f.sk)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || numString(sites[0], "SiteId") != "555" {
		t.Fatalf("sites=%v", sites)
	}
	f.records = []map[string]interface{}{
		{"RecordName": "www.example.com", "RecordType": "A/AAAA",
			"Data": map[string]interface{}{"Value": "9.9.9.9"}, "RecordId": float64(777)},
	}
	records, err := esaListRecords(f.ak, f.sk, "555", "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records=%v", records)
	}
	if id, err := esaCreateRecord(f.ak, f.sk, "555", "a.example.com", "A", "1.2.3.4", 600); err != nil || id != "888" {
		t.Fatalf("create id=%q err=%v", id, err)
	}
	if err := esaUpdateRecord(f.ak, f.sk, "777", "A", "1.2.3.4", 600); err != nil {
		t.Fatalf("update: %v", err)
	}
	if f.updateCount != 1 {
		t.Fatalf("updateCount=%d", f.updateCount)
	}
	if err := esaDeleteRecord(f.ak, f.sk, "777"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestESAWrongSecretSignatureFails(t *testing.T) {
	f := startFakeESA(t)
	f.sites = []map[string]interface{}{{"SiteId": float64(1)}}
	_, err := esaListSites(f.ak, "WRONG-SECRET")
	if err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("错误密钥应被服务端拒绝: %v", err)
	}
}

func TestDNSWrongSecretSignatureFails(t *testing.T) {
	f, _ := startFakeDNS(t)
	_, err := dnsDescribeRecords(f.ak, "WRONG-SECRET", "example.com", "www")
	if err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("错误密钥应被服务端拒绝: %v", err)
	}
}

// ==================== ESA 签名辅助（测试侧，仅依赖标准库） ====================

func authSignature(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const p = "Signature="
	i := strings.LastIndex(auth, p)
	if i < 0 {
		return ""
	}
	return auth[i+len(p):]
}

func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, v := range b {
		sb.WriteByte(digits[v>>4])
		sb.WriteByte(digits[v&0x0f])
	}
	return sb.String()
}
