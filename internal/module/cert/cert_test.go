package cert

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// setupTestDB 独立临时数据目录（t.Chdir 改变工作目录 + InitPaths 重解析，测试结束自动还原）。
func setupTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := core.InitPaths(); err != nil {
		t.Fatalf("InitPaths: %v", err)
	}
	core.CloseDB() // 允许重复初始化（多用例共享进程）
	if err := core.InitDB(filepath.Join(dir, "nexhome.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

// insertCertTask 插入一条最小可用的证书任务并返回 id。
func insertCertTask(t *testing.T, challengeType, saveDir, webhook string) int64 {
	t.Helper()
	id, err := core.Insert(`INSERT INTO cert_task(name, provider, domains, challenge_type, auto_renew, save_dir, webhook_url)
		VALUES(?,?,?,?,?,?,?)`, "测试证书", "LETSENCRYPT", "example.com", challengeType, 1, saveDir, webhook)
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

func TestDomainList(t *testing.T) {
	got := domainList(" A.com , b.cn;c.net\n d.org ,, ")
	want := []string{"a.com", "b.cn", "c.net", "d.org"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(domainList("")) != 0 {
		t.Error("空串应解析为空列表")
	}
	if n := normalizeDomains(" WWW.Example.com , *.example.com "); n != "www.example.com,*.example.com" {
		t.Errorf("normalizeDomains got %q", n)
	}
}

func TestPrimaryDomain(t *testing.T) {
	if got := primaryDomain([]string{"*.example.com", "b.com"}); got != "example.com" {
		t.Errorf("泛域名 got %q", got)
	}
	if got := primaryDomain([]string{"a_b.example.com"}); got != "a_b.example.com" {
		t.Errorf("合法字符保留 got %q", got)
	}
	if got := primaryDomain([]string{"统.cn"}); got != "_.cn" {
		t.Errorf("非安全字符替换 got %q", got)
	}
	if got := primaryDomain(nil); got != "cert" {
		t.Errorf("空列表 got %q", got)
	}
}

func TestJoinDomainsAndTruncate(t *testing.T) {
	// 复刻 Java List.toString() 格式
	if got := joinDomains([]string{"a.com", "b.com"}); got != "[a.com, b.com]" {
		t.Errorf("got %q", got)
	}
	if got := truncate(strings.Repeat("x", 250)); len(got) != 203 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncate got len %d", len(got))
	}
	if got := truncate("abc"); got != "abc" {
		t.Errorf("truncate got %q", got)
	}
}

func TestPemRoundTrip(t *testing.T) {
	der := make([]byte, 300)
	for i := range der {
		der[i] = byte(i)
	}
	text := pemEncode("PRIVATE KEY", der)
	if !strings.HasPrefix(text, "-----BEGIN PRIVATE KEY-----\n") ||
		!strings.HasSuffix(text, "-----END PRIVATE KEY-----\n") {
		t.Fatalf("PEM 头尾不符: %q", text[:40])
	}
	// 64 字符折行
	body := strings.TrimSuffix(strings.TrimPrefix(text[strings.Index(text, "\n")+1:], "-----END PRIVATE KEY-----\n"), "\n")
	for _, line := range strings.Split(body, "\n") {
		if len(line) > 64 {
			t.Fatalf("折行超 64: %d", len(line))
		}
	}
	back, err := parsePem(text, "PRIVATE KEY")
	if err != nil || string(back) != string(der) {
		t.Fatalf("parsePem 往返失败: %v", err)
	}
	if _, err := parsePem("no pem", "PRIVATE KEY"); err == nil {
		t.Error("非法 PEM 应报错")
	}
}

func TestValidateBranches(t *testing.T) {
	ok := map[string]interface{}{
		"name": "task", "provider": "LETSENCRYPT", "domains": "example.com",
		"challenge_type": "DNS01", "webhook_url": "",
	}
	if err := validate(ok); err != nil {
		t.Fatalf("合法表单应通过: %v", err)
	}
	cases := []struct {
		title string
		mod   map[string]interface{}
		want  string
	}{
		{"名称空", map[string]interface{}{"name": "  "}, "任务名称不能为空"},
		{"服务商非法", map[string]interface{}{"provider": "DNSPOD"}, "服务商必须为 LETSENCRYPT 或 ZEROSSL"},
		{"验证方式非法", map[string]interface{}{"challenge_type": "TLS-ALPN-01"}, "验证方式必须为 HTTP01 或 DNS01"},
		{"域名空", map[string]interface{}{"domains": " ,, "}, "域名不能为空"},
		{"域名格式", map[string]interface{}{"domains": "not_a_domain"}, "域名格式不正确: not_a_domain"},
		{"webhook 协议", map[string]interface{}{"webhook_url": "ftp://a"}, "Webhook 地址必须以 http:// 或 https:// 开头"},
	}
	for _, c := range cases {
		m := map[string]interface{}{}
		for k, v := range ok {
			m[k] = v
		}
		for k, v := range c.mod {
			m[k] = v
		}
		err := validate(m)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v want %q", c.title, err, c.want)
		}
	}
	// 泛域名合法
	m := map[string]interface{}{}
	for k, v := range ok {
		m[k] = v
	}
	m["domains"] = "*.example.com"
	if err := validate(m); err != nil {
		t.Errorf("泛域名应通过: %v", err)
	}
}

func TestJwkAndKeyAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := rsaJWK(&key.PublicKey)
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(jwk), &fields); err != nil {
		t.Fatalf("JWK 非法 JSON: %v", err)
	}
	if fields["kty"] != "RSA" {
		t.Fatalf("kty got %v", fields["kty"])
	}
	// n/e 还原后与公钥一致
	nBytes, err := base64.RawURLEncoding.DecodeString(fields["n"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(nBytes).Cmp(key.PublicKey.N) != 0 {
		t.Error("JWK n 与公钥不一致")
	}
	// 键序固定 e,kty,n（thumbprint 与发送自洽的前提）
	if !strings.HasPrefix(jwk, `{"e":`) || !strings.Contains(jwk, `,"kty":"RSA","n":`) {
		t.Errorf("JWK 键序不符: %s", jwk)
	}

	ka := keyAuthorization("tok123", jwk)
	if !strings.HasPrefix(ka, "tok123.") {
		t.Errorf("keyAuthorization 格式不符: %s", ka)
	}
	sum := sha256.Sum256([]byte(jwk))
	if ka != "tok123."+b64url(sum[:]) {
		t.Error("keyAuthorization 摘要不一致")
	}
	digest := dns01Digest(ka)
	sum2 := sha256.Sum256([]byte(ka))
	if digest != b64url(sum2[:]) {
		t.Error("dns-01 digest 不一致")
	}
}

func TestBuildCSR(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := buildCSR(key, []string{"example.com", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("CSR 无法解析: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR 自签校验失败: %v", err)
	}
	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "example.com" {
		t.Errorf("SAN 不符: %v", csr.DNSNames)
	}
}

func TestSplitChain(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	der1 := mustSelfCert(t, k1)
	der2 := mustSelfCert(t, k2)
	chain := pemEncode("CERTIFICATE", der1) + pemEncode("CERTIFICATE", der2)
	leaf, full, err := splitChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if string(leaf) != string(der1) {
		t.Error("叶子应为链中第一张证书")
	}
	if full != chain {
		t.Errorf("完整链重编码不一致:\n got %q\nwant %q", full, chain)
	}
	if _, _, err := splitChain("garbage"); err == nil {
		t.Error("空链应报错")
	}
}

func mustSelfCert(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		DNSNames:              []string{"leaf.example.com"},
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCaError(t *testing.T) {
	e := &caError{Type: "urn:ietf:params:acme:error:badNonce", Detail: "JWS has an invalid anti-replay nonce"}
	if !e.isBadNonce() {
		t.Error("badNonce 判定失败")
	}
	if e.Error() != "CA 错误[badNonce]: JWS has an invalid anti-replay nonce" {
		t.Errorf("错误文案不符: %s", e.Error())
	}
	e2 := &caError{Type: "urn:ietf:params:acme:error:rateLimited"}
	if e2.Error() != "CA 错误[rateLimited]" {
		t.Errorf("无 detail 文案不符: %s", e2.Error())
	}
	// 非 problem+json 响应回落 HTTP 状态文案
	resp := &http.Response{StatusCode: 500, Status: "500 Internal Server Error"}
	err := parseCAError([]byte("boom"), resp)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("回落文案不符: %v", err)
	}
}

func TestEabForAndMakeEAB(t *testing.T) {
	setupTestDB(t)
	// 未配置 EAB 的 ZeroSSL 必须报错
	if _, err := eabFor("ZEROSSL"); err == nil || !strings.Contains(err.Error(), "ZeroSSL 需要 EAB 凭证") {
		t.Errorf("缺 EAB 应报错: %v", err)
	}
	if err := core.SetConfig("zerossl.eab_kid", "kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := core.SetConfig("zerossl.eab_hmac", base64.RawURLEncoding.EncodeToString([]byte("hmac-secret-key"))); err != nil {
		t.Fatal(err)
	}
	eab, err := eabFor("ZEROSSL")
	if err != nil || eab == nil || eab.KID != "kid-1" {
		t.Fatalf("eabFor: %v %+v", err, eab)
	}
	if got, err := eabFor("LETSENCRYPT"); err != nil || got != nil {
		t.Errorf("非 ZeroSSL 应返回 nil: %v %v", got, err)
	}

	// makeEAB：三段紧凑序列化，HMAC 可验签，protected 携带 kid/url/nonce
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &acmeClient{
		dir:     acmeDirectory{NewAccount: "https://ca.example/acct"},
		key:     key,
		jwkJSON: rsaJWK(&key.PublicKey),
		nonce:   "nonce-1",
	}
	token, err := c.makeEAB(*eab)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("EAB 应为三段: %d", len(parts))
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var prot map[string]interface{}
	if err := json.Unmarshal(pb, &prot); err != nil {
		t.Fatalf("EAB protected 非法: %v", err)
	}
	if prot["alg"] != "HS256" || prot["kid"] != "kid-1" ||
		prot["url"] != "https://ca.example/acct" || prot["nonce"] != "nonce-1" {
		t.Errorf("EAB protected 字段不符: %v", prot)
	}
	rawKey, _ := base64.RawURLEncoding.DecodeString(eab.HMACBase64)
	mac := hmac.New(sha256.New, rawKey)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := b64url(mac.Sum(nil))
	if parts[2] != wantSig {
		t.Error("EAB HMAC 签名校验失败")
	}
	// 负载就是账号 JWK
	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || string(decodedPayload) != c.jwkJSON {
		t.Error("EAB 负载应为账号公钥 JWK")
	}
}

func TestFieldAccessors(t *testing.T) {
	m := map[string]interface{}{
		"RR":   "www",
		"Id":   float64(123),
		"Name": nil,
		"Data": map[string]interface{}{"Value": "txt-value"},
	}
	if fieldStr(m, "RR") != "www" {
		t.Error("RR")
	}
	if fieldStr(m, "Id") != "123" {
		t.Errorf("整数值应无小数点: %q", fieldStr(m, "Id"))
	}
	if fieldStr(m, "Name") != "" || fieldStr(m, "Missing") != "" {
		t.Error("nil/缺失应返回空串")
	}
	if fieldObj(m, "Data") == nil || fieldStr(fieldObj(m, "Data"), "Value") != "txt-value" {
		t.Error("Data 访问")
	}
	if fieldObj(m, "RR") != nil {
		t.Error("非对象应返回 nil")
	}
}

func TestTaskHelpers(t *testing.T) {
	setupTestDB(t)
	id := insertCertTask(t, "DNS01", "", "")
	task := getTask(t, id)
	if taskStr(task, "name") != "测试证书" {
		t.Errorf("name got %q", taskStr(task, "name"))
	}
	if taskStr(task, "dns_hint") != "" {
		t.Errorf("NULL 列应为空串: %q", taskStr(task, "dns_hint"))
	}
	if taskID(task) != id {
		t.Errorf("taskID got %d want %d", taskID(task), id)
	}
	// mustGet 不存在 → 400 文案
	_, err := mustGet(99999)
	if err == nil || err.Error() != "证书任务不存在: #99999" {
		t.Errorf("mustGet 文案不符: %v", err)
	}
	// setStatus/fail
	setStatus(id, "ISSUING", "进行中", nil)
	if s := taskStr(getTask(t, id), "status"); s != "ISSUING" {
		t.Errorf("status got %q", s)
	}
	fail(id, "手动申请失败: boom")
	after := getTask(t, id)
	if taskStr(after, "status") != "ERROR" || taskStr(after, "message") != "手动申请失败: boom" {
		t.Errorf("fail 落库不符: %s / %s", taskStr(after, "status"), taskStr(after, "message"))
	}
}

func TestAutoRenewCheckSkipBranches(t *testing.T) {
	setupTestDB(t)
	id := insertCertTask(t, "HTTP01", "", "")
	// not_after 远期：不触发续期（若误触发会访问真实 LE，测试网络不可达会表现为 ERROR，足以暴露）
	core.Update("UPDATE cert_task SET status='ISSUED', not_after='2099-01-01T00:00:00Z' WHERE id=?", id)
	autoRenewCheck()
	after := getTask(t, id)
	if taskStr(after, "status") != "ISSUED" {
		t.Errorf("远期证书不应被处理: %s %s", taskStr(after, "status"), taskStr(after, "message"))
	}
	// not_after 非法：中断本轮（与 Java Instant.parse 异常一致），不改状态
	core.Update("UPDATE cert_task SET not_after='garbage' WHERE id=?", id)
	autoRenewCheck()
	if taskStr(getTask(t, id), "status") != "ISSUED" {
		t.Error("解析失败应静默中断本轮")
	}
	// 未启 auto_renew/状态不符的过滤
	core.Update("UPDATE cert_task SET not_after='2099-01-01T00:00:00Z', auto_renew=0 WHERE id=?", id)
	autoRenewCheck()
}

func TestCfgDefault(t *testing.T) {
	setupTestDB(t)
	if got := cfg("not.exists.key", "def"); got != "def" {
		t.Errorf("cfg got %q", got)
	}
	core.SetConfig("not.exists.key", "")
	if got := cfg("not.exists.key", "def2"); got != "def2" {
		t.Errorf("空值应回落默认: %q", got)
	}
}
