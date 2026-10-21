package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"NexHomeGo/internal/core"
)

// fakeCA 内嵌真校验的 ACME 服务器（与 DDNS fake 阿里云同思路）：
// 服务端逐字节验证客户端 JWS RS256 签名、nonce 防重放、url 头匹配，
// 因此错误密钥/篡改负载必然失败，能对齐全链路协议行为。
type fakeCA struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	nonceSeq  int
	usedNonce map[string]bool

	acctPub *rsa.PublicKey
	acctJWK string // 归一化 JWK 文本（与服务端 rsaJWK 同函数生成）

	domains             []string
	authState           string // pending / valid
	triggered           bool
	finalized           bool
	certPEM             string
	newAccountCalls     int
	failNewOrderProblem string
	requireEABKid       string // 非空时校验 newAccount 必须携带对应 kid 的 externalAccountBinding
	badNonceOnce        bool   // 首个账号请求返回 badNonce，用于验证客户端自动重试
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	f := &fakeCA{t: t, usedNonce: map[string]bool{}, authState: "pending", badNonceOnce: false}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// inject 将 LETSENCRYPT 的 directory 指向假服务器（用例结束自动还原）。
func (f *fakeCA) inject() {
	old := providerDirs["LETSENCRYPT"]
	providerDirs["LETSENCRYPT"] = f.srv.URL + "/dir"
	f.t.Cleanup(func() { providerDirs["LETSENCRYPT"] = old })
}

func (f *fakeCA) base() string { return f.srv.URL }

func (f *fakeCA) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/dir":
		writeJSON(w, 200, map[string]string{
			"newNonce":   f.base() + "/nonce",
			"newAccount": f.base() + "/acct",
			"newOrder":   f.base() + "/ord",
		})
		return
	case "/nonce":
		w.Header().Set("Replay-Nonce", f.nextNonce())
		w.WriteHeader(200)
		return
	}

	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	// 统一 JWS 校验
	_, payload, pub, nonceBad, errJWS := f.verifyJWS(string(body), r.URL.Path, f.base()+r.URL.Path)
	if errJWS != nil {
		typ := "urn:ietf:params:acme:error:malformed"
		if nonceBad {
			typ = "urn:ietf:params:acme:error:badNonce" // 客户端应刷新 nonce 自动重试
		}
		problem(w, 400, typ, errJWS.Error())
		return
	}
	w.Header().Set("Replay-Nonce", f.nextNonce()) // 任意响应更新 nonce

	switch r.URL.Path {
	case "/acct":
		f.mu.Lock()
		f.newAccountCalls++
		calls := f.newAccountCalls
		f.mu.Unlock()
		if pub == nil {
			problem(w, 400, "urn:ietf:params:acme:error:malformed", "account creation requires jwk header")
			return
		}
		if calls > 1 {
			// 账号密钥应复用：注册仅发生一次；重复注册视为客户端账号管理错误
			problem(w, 400, "urn:ietf:params:acme:error:unauthorized", "account already exists")
			return
		}
		if f.requireEABKid != "" {
			var p struct {
				EAB string `json:"externalAccountBinding"`
			}
			_ = json.Unmarshal(payload, &p)
			if !strings.HasPrefix(p.EAB, "eyJ") || !strings.Contains(p.EAB, ".") {
				problem(w, 400, "urn:ietf:params:acme:error:malformed", "missing externalAccountBinding")
				return
			}
		}
		f.mu.Lock()
		f.acctPub = pub
		f.mu.Unlock()
		w.Header().Set("Location", f.base()+"/acct/1")
		writeJSON(w, 201, map[string]string{"status": "valid"})

	case "/ord":
		if f.failNewOrderProblem != "" {
			problem(w, 400, f.failNewOrderProblem, "simulated")
			return
		}
		var p struct {
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		if err := json.Unmarshal(payload, &p); err != nil || len(p.Identifiers) == 0 {
			problem(w, 400, "urn:ietf:params:acme:error:malformed", "bad order payload")
			return
		}
		f.mu.Lock()
		f.domains = nil
		for _, id := range p.Identifiers {
			f.domains = append(f.domains, id.Value)
		}
		f.mu.Unlock()
		w.Header().Set("Location", f.base()+"/order/1")
		writeJSON(w, 201, map[string]interface{}{
			"status":         "pending",
			"authorizations": []string{f.base() + "/auth/1"},
			"finalize":       f.base() + "/fin/1",
		})

	case "/auth/1":
		f.mu.Lock()
		state := f.authState
		if f.triggered {
			state = "valid"
		}
		domains := f.domains
		f.mu.Unlock()
		d := "example.com"
		if len(domains) > 0 {
			d = domains[0]
		}
		writeJSON(w, 200, map[string]interface{}{
			"identifier": map[string]string{"type": "dns", "value": d},
			"status":     state,
			"challenges": []map[string]string{
				{"type": "dns-01", "url": f.base() + "/chal/1", "token": "tok-dns"},
				{"type": "http-01", "url": f.base() + "/chal/2", "token": "tok-http"},
			},
		})

	case "/chal/1", "/chal/2":
		f.mu.Lock()
		f.triggered = true
		f.mu.Unlock()
		writeJSON(w, 200, map[string]string{"type": "dns-01", "status": "pending"})

	case "/fin/1":
		var p struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &p); err != nil || p.CSR == "" {
			problem(w, 400, "urn:ietf:params:acme:error:malformed", "missing csr")
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(p.CSR)
		if err != nil {
			problem(w, 400, "urn:ietf:params:acme:error:malformed", "bad csr b64")
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil {
			problem(w, 400, "urn:ietf:params:acme:error:malformed", "bad csr")
			return
		}
		f.mu.Lock()
		f.domains = csr.DNSNames
		f.mu.Unlock()
		f.certPEM = f.issueCert(csr)
		f.mu.Lock()
		f.finalized = true
		f.mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{"status": "processing"})

	case "/order/1":
		f.mu.Lock()
		finalized := f.finalized
		f.mu.Unlock()
		if !finalized {
			// 真实 CA 在未终态也返回完整订单字段
			writeJSON(w, 200, map[string]interface{}{
				"status":         "pending",
				"authorizations": []string{f.base() + "/auth/1"},
				"finalize":       f.base() + "/fin/1",
			})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"status":         "valid",
			"authorizations": []string{f.base() + "/auth/1"},
			"finalize":       f.base() + "/fin/1",
			"certificate":    f.base() + "/cert/1",
		})

	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write([]byte(f.certPEM))

	default:
		problem(w, 404, "urn:ietf:params:acme:error:malformed", "no such path "+r.URL.Path)
	}
}

// verifyJWS 校验 JWS 三段：签名（jwk 或已注册 kid 公钥）、url 头匹配、nonce 防重放。
// nonceBad=true 表示应回 badNonce 类型错误（客户端会自动重试）。
func (f *fakeCA) verifyJWS(jws, path, wantURL string) (map[string]interface{}, []byte, *rsa.PublicKey, bool, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, nil, nil, false, fmt.Errorf("not a compact jws")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("bad protected b64")
	}
	var prot map[string]interface{}
	if err := json.Unmarshal(pb, &prot); err != nil {
		return nil, nil, nil, false, fmt.Errorf("bad protected json")
	}
	var payload []byte
	if parts[1] != "" {
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("bad payload b64")
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("bad sig b64")
	}
	if u, _ := prot["url"].(string); u != wantURL {
		return nil, nil, nil, false, fmt.Errorf("url header mismatch: %s != %s", u, wantURL)
	}
	n, _ := prot["nonce"].(string)
	f.mu.Lock()
	bad := n == "" || f.usedNonce[n]
	if !bad && f.badNonceOnce && path == "/acct" {
		f.badNonceOnce = false // 刻意拒绝首个账号请求，验证客户端 badNonce 自动重试
		bad = true
	}
	if bad {
		f.mu.Unlock()
		return nil, nil, nil, true, fmt.Errorf("invalid anti-replay nonce")
	}
	f.usedNonce[n] = true
	f.mu.Unlock()

	var pub *rsa.PublicKey
	if jwkRaw, ok := prot["jwk"]; ok {
		jwk, ok := jwkRaw.(map[string]interface{})
		if !ok || jwk["kty"] != "RSA" {
			return nil, nil, nil, false, fmt.Errorf("bad jwk header")
		}
		nb, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("bad jwk n")
		}
		eb, err := base64.RawURLEncoding.DecodeString(jwk["e"].(string))
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("bad jwk e")
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
		jwkText := rsaJWK(pub) // 归一化文本（服务端与客户端同一函数，供 keyAuthorization 断言）
		f.mu.Lock()
		f.acctJWK = jwkText
		f.mu.Unlock()
	} else {
		kid, _ := prot["kid"].(string)
		f.mu.Lock()
		if kid == "" || (f.acctPub == nil) || kid != f.base()+"/acct/1" {
			f.mu.Unlock()
			return nil, nil, nil, false, fmt.Errorf("bad kid: %s", kid)
		}
		pub = f.acctPub
		f.mu.Unlock()
	}
	hashed := sha256Sum([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sig); err != nil {
		return nil, nil, nil, false, fmt.Errorf("signature verify failed: %w", err)
	}
	return prot, payload, pub, false, nil
}

// issueCert 按 CSR 签发两张自签证书组成链（leaf 在前，模拟 CA 中间证书），返回 PEM 链文本。
func (f *fakeCA) issueCert(csr *x509.CertificateRequest) string {
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		DNSNames:              csr.DNSNames,
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2002),
		SubjectKeyId:          []byte{2},
		DNSNames:              []string{"fake-inter"},
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// 叶子用 CA 密钥签发；CA 自签
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, csr.PublicKey, interKey)
	if err != nil {
		f.t.Fatal(err)
	}
	interDer, err := x509.CreateCertificate(rand.Reader, interTmpl, interTmpl, &interKey.PublicKey, interKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return pemEncode("CERTIFICATE", leafDer) + pemEncode("CERTIFICATE", interDer)
}

func (f *fakeCA) nextNonce() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonceSeq++
	return fmt.Sprintf("nonce-%d", f.nonceSeq)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func problem(w http.ResponseWriter, code int, typ, detail string) {
	writeJSON(w, code, map[string]string{"type": typ, "detail": detail})
}

// ==================== 端到端流程 ====================

func TestAcmeE2eDns01ManualFlow(t *testing.T) {
	setupTestDB(t)
	f := newFakeCA(t)
	f.inject()

	outDir := filepath.Join(t.TempDir(), "ssl-out")
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&p)
		if p["event"] != "certificate.issued" {
			t.Errorf("webhook event got %v", p["event"])
		}
		if p["name"] != "测试证书" {
			t.Errorf("webhook name got %v", p["name"])
		}
		if kp, _ := p["keyPem"].(string); !strings.HasPrefix(kp, "-----BEGIN PRIVATE KEY-----") {
			t.Errorf("webhook keyPem 不符")
		}
		if fc, _ := p["fullchainPem"].(string); strings.Count(fc, "BEGIN CERTIFICATE") != 2 {
			t.Errorf("webhook fullchain 应含两张证书: %q", fc)
		}
		w.WriteHeader(200)
	}))
	defer hook.Close()

	id := insertCertTask(t, "DNS01", outDir, hook.URL)

	// 第一步：无凭证配置 → 半自动模式，落 PENDING_VALIDATION 与 TXT 提示
	issue(id, "手动申请")
	task := getTask(t, id)
	if got := taskStr(task, "status"); got != "PENDING_VALIDATION" {
		t.Fatalf("status got %q (%s)", got, taskStr(task, "message"))
	}
	wantDigest := dns01Digest(keyAuthorization("tok-dns", f.acctJWK))
	hint := taskStr(task, "dns_hint")
	wantHint := "记录类型: TXT\n主机记录: _acme-challenge.example.com\n记录值: " + wantDigest + "\n\n"
	if hint != wantHint {
		t.Errorf("dns_hint 不符:\n got %q\nwant %q", hint, wantHint)
	}
	orderURL, _ := core.GetConfig("cert." + fmt.Sprintf("%d", id) + ".order")
	if orderURL != f.base()+"/order/1" {
		t.Errorf("order url 持久化不符: %q", orderURL)
	}

	// 第二步：模拟用户已添加 TXT → 完成验证 → 签发成功
	validateDns(id)
	task = getTask(t, id)
	if got := taskStr(task, "status"); got != "ISSUED" {
		t.Fatalf("status got %q (%s)", got, taskStr(task, "message"))
	}
	if taskStr(task, "message") != "证书签发成功" {
		t.Errorf("message got %q", taskStr(task, "message"))
	}
	if na := taskStr(task, "not_after"); na == "" {
		t.Error("not_after 未写入")
	} else if _, err := time.Parse(time.RFC3339, na); err != nil {
		t.Errorf("not_after 非 RFC3339: %q", na)
	}

	// 任务目录三文件 + cert_dir
	dir := taskDir(id)
	if taskStr(task, "cert_dir") != dir {
		t.Errorf("cert_dir got %q want %q", taskStr(task, "cert_dir"), dir)
	}
	for _, name := range []string{"domain.key.pem", "cert.pem", "fullchain.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("缺文件 %s: %v", name, err)
		}
	}
	keyPem, _ := os.ReadFile(filepath.Join(dir, "domain.key.pem"))
	if strings.Count(string(keyPem), "\n") < 10 || !strings.HasPrefix(string(keyPem), "-----BEGIN PRIVATE KEY-----\n") {
		t.Error("私钥 PEM 格式不符")
	}
	fc, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if strings.Count(string(fc), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("fullchain 应含两张证书:\n%s", fc)
	}

	// 自定义保存目录三文件
	base := primaryDomain([]string{"example.com"})
	for _, name := range []string{base + ".key", base + ".pem", base + ".fullchain.pem"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("save_dir 缺文件 %s: %v", name, err)
		}
	}

	// ACME 账号密钥文件持久化
	acctKey := filepath.Join(core.DataDir(), "certs", "acme", "letsencrypt", "account.pem")
	if _, err := os.Stat(acctKey); err != nil {
		t.Errorf("账号密钥未持久化: %v", err)
	}
	loc, _ := core.GetConfig("cert.account.LETSENCRYPT")
	if loc != f.base()+"/acct/1" {
		t.Errorf("账号位置不符: %q", loc)
	}
	if f.newAccountCalls != 1 {
		t.Errorf("注册应发生一次, got %d", f.newAccountCalls)
	}
}

func TestAcmeE2eHttp01AutoFlow(t *testing.T) {
	setupTestDB(t)
	f := newFakeCA(t)
	f.inject()

	id := insertCertTask(t, "HTTP01", filepath.Join(t.TempDir(), "ssl"), "")
	issue(id, "手动申请")
	task := getTask(t, id)
	if got := taskStr(task, "status"); got != "ISSUED" {
		t.Fatalf("status got %q (%s)", got, taskStr(task, "message"))
	}
	// http-01 应答注册表：token → keyAuthorization
	challengeMu.RLock()
	auth, ok := challenges["tok-http"]
	challengeMu.RUnlock()
	if !ok {
		t.Fatal("challenges 未登记 tok-http")
	}
	if want := keyAuthorization("tok-http", f.acctJWK); auth != want {
		t.Errorf("keyAuthorization 不符:\n got %q\nwant %q", auth, want)
	}
	if !f.triggered {
		t.Error("challenge 未触发")
	}
}

func TestAcmeE2eAccountReuseAndFailPaths(t *testing.T) {
	setupTestDB(t)
	f := newFakeCA(t)
	f.inject()

	// 第一次申请（半自动）建立账号
	id1 := insertCertTask(t, "DNS01", "", "")
	issue(id1, "手动申请")
	if get := getTask(t, id1); taskStr(get, "status") != "PENDING_VALIDATION" {
		t.Fatalf("首轮应进入待验证: %s %s", taskStr(get, "status"), taskStr(get, "message"))
	}

	// 订单创建失败 → ERROR，文案透出 CA 错误
	f.failNewOrderProblem = "urn:ietf:params:acme:error:rateLimited"
	id2 := insertCertTask(t, "DNS01", "", "")
	issue(id2, "手动申请")
	task2 := getTask(t, id2)
	if taskStr(task2, "status") != "ERROR" {
		t.Fatalf("status got %q", taskStr(task2, "status"))
	}
	if msg := taskStr(task2, "message"); !strings.HasPrefix(msg, "手动申请失败: CA 错误[rateLimited]") {
		t.Errorf("失败文案不符: %q", msg)
	}
	f.failNewOrderProblem = ""

	// 第二次成功申请复用账号：注册调用仍只有 1 次
	issue(id2, "手动申请")
	if get := getTask(t, id2); taskStr(get, "status") != "PENDING_VALIDATION" {
		t.Fatalf("二轮应进入待验证: %s %s", taskStr(get, "status"), taskStr(get, "message"))
	}
	if f.newAccountCalls != 1 {
		t.Errorf("账号应复用, 注册调用 %d 次", f.newAccountCalls)
	}

	// validateDns 前置校验：订单不存在 → ERROR
	id3 := insertCertTask(t, "DNS01", "", "")
	validateDns(id3)
	task3 := getTask(t, id3)
	if taskStr(task3, "status") != "ERROR" || !strings.Contains(taskStr(task3, "message"), "订单不存在，请先发起申请") {
		t.Errorf("无订单验证不符: %s / %s", taskStr(task3, "status"), taskStr(task3, "message"))
	}
	// 账号不存在的服务商（ZEROSSL 目录未指向假服务器，账号文件缺失 → 快速失败）
	core.Update("UPDATE cert_task SET provider='ZEROSSL' WHERE id=?", id3)
	core.SetConfig("cert."+fmt.Sprintf("%d", id3)+".order", "https://example.invalid/order")
	validateDns(id3)
	task3 = getTask(t, id3)
	if !strings.Contains(taskStr(task3, "message"), "ACME 账号不存在") {
		t.Errorf("账号缺失文案不符: %q", taskStr(task3, "message"))
	}
}

func TestAcmeE2eBadNonceRetry(t *testing.T) {
	setupTestDB(t)
	f := newFakeCA(t)
	f.inject()
	f.badNonceOnce = true // 首个账号请求刻意失败一次，客户端应刷新 nonce 自动重试

	id := insertCertTask(t, "DNS01", "", "")
	issue(id, "手动申请")
	task := getTask(t, id)
	if got := taskStr(task, "status"); got != "PENDING_VALIDATION" {
		t.Fatalf("badNonce 应被自动重试消化: %q (%s)", got, taskStr(task, "message"))
	}
}

func TestAcmeE2eZeroSSLEabRequired(t *testing.T) {
	setupTestDB(t)
	f := newFakeCA(t)
	f.inject()

	id := insertCertTask(t, "DNS01", "", "")
	core.Update("UPDATE cert_task SET provider='ZEROSSL' WHERE id=?", id)

	// 未配置 EAB 凭证：申请失败并给出中文引导（BadRequest 文案透出到 message）
	issue(id, "手动申请")
	task := getTask(t, id)
	if taskStr(task, "status") != "ERROR" || !strings.Contains(taskStr(task, "message"), "ZeroSSL 需要 EAB 凭证") {
		t.Fatalf("缺 EAB 应报错: %s / %s", taskStr(task, "status"), taskStr(task, "message"))
	}
}

// TestAcmeJwsNegative 直接验证客户端签名的自洽性：篡改 JWK 文本会使 keyAuthorization 与摘要错位。
func TestAcmeJwsNegative(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &acmeClient{key: key, jwkJSON: rsaJWK(&key.PublicKey), nonce: "n1"}
	jws, err := c.signJWS("https://ca.example/x", "{}")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatal("JWS 应三段")
	}
	pb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var prot map[string]interface{}
	if err := json.Unmarshal(pb, &prot); err != nil {
		t.Fatal(err)
	}
	if prot["alg"] != "RS256" || prot["nonce"] != "n1" || prot["url"] != "https://ca.example/x" {
		t.Errorf("JWS 头字段不符: %v", prot)
	}
	if _, ok := prot["jwk"]; !ok {
		t.Error("kid 为空时应使用 jwk 头")
	}
	// 验签（服务端视角）
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	hashed := sha256Sum([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed, sig); err != nil {
		t.Errorf("签名应可验证: %v", err)
	}
	// 篡改后验签必须失败
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sha256Sum([]byte(parts[0]+".x")), sig); err == nil {
		t.Error("篡改负载后验签应失败")
	}
	// kid 模式
	c.kid = "https://ca.example/acct/9"
	jws2, err := c.signJWS("https://ca.example/y", "")
	if err != nil {
		t.Fatal(err)
	}
	pb2, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws2, ".")[0])
	if !strings.Contains(string(pb2), `"kid"`) {
		t.Errorf("kid 模式应携带 kid 头: %s", pb2)
	}
}
