package cert

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// ---------- ACME 服务商目录（RFC8555，等价 Java 侧 acme4j 的 acme:// 协议地址） ----------

// providerDirs 服务商名 → ACME directory URL（等价 acme4j 内置的 acme://letsencrypt.org 与 acme://zerossl.com）。
var providerDirs = map[string]string{
	"LETSENCRYPT": "https://acme-v02.api.letsencrypt.org/directory",
	"ZEROSSL":     "https://acme.zerossl.com/v2/DV90/directory",
}

// ---------- 密码学工具（私钥/PEM/JWK/CSR，标准库实现替代 Java 侧 BouncyCastle） ----------

// b64url base64url 无填充编码（JWS 规范）。
func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// sha256Sum 计算 SHA-256 摘要。
func sha256Sum(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

// pemEncode DER 编码转 PEM 文本（64 字符折行，与 Java Base64.getMimeEncoder(64, "\n") 逐字节一致）。
func pemEncode(typeName string, der []byte) string {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + typeName + "-----\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END " + typeName + "-----\n")
	return sb.String()
}

// parsePem 从 PEM 文本中提取指定类型的 DER（等价 Java parsePem）。
func parsePem(text, typeName string) ([]byte, error) {
	begin := "-----BEGIN " + typeName + "-----"
	end := "-----END " + typeName + "-----"
	s := strings.Index(text, begin)
	e := strings.Index(text, end)
	if s < 0 || e < 0 {
		return nil, errors.New("PEM 格式错误")
	}
	body := strings.Join(strings.Fields(text[s+len(begin):e]), "")
	return base64.StdEncoding.DecodeString(body)
}

// generateRSA2048 生成 RSA 2048 密钥对（兼容性最好的域名密钥/账号密钥）。
func generateRSA2048() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// parseAccountKey 从 PKCS8 私钥 DER 恢复 RSA 私钥（等价 Java readKeyPair 的 CRT 推导）。
func parseAccountKey(der []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("账号密钥不是 RSA 私钥")
	}
	return rk, nil
}

// rsaJWK 计算账号公钥的 JWK JSON（键序 e,kty,n 与 acme4j 序列化一致；thumbprint 与发送共用同一文本保证自洽）。
func rsaJWK(pub *rsa.PublicKey) string {
	e := big.NewInt(int64(pub.E)).Bytes()
	n := pub.N.Bytes()
	jwk := core.NewRow().
		Set("e", b64url(e)).
		Set("kty", "RSA").
		Set("n", b64url(n))
	text, _ := core.MarshalJSON(jwk)
	return string(text)
}

// keyAuthorization http-01 应答内容：token.b64url(sha256(账号JWK))。
func keyAuthorization(token, jwkJSON string) string {
	return token + "." + b64url(sha256Sum([]byte(jwkJSON)))
}

// dns01Digest dns-01 TXT 记录值：b64url(sha256(keyAuthorization))。
func dns01Digest(keyAuth string) string {
	return b64url(sha256Sum([]byte(keyAuth)))
}

// buildCSR 用域名私钥构造 PKCS#10 证书请求（仅 SAN 域名列表，subject 为空，与 acme4j CSRBuilder 行为一致）。
func buildCSR(key *rsa.PrivateKey, domains []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		DNSNames:           domains,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

// ---------- ACME 错误 ----------

// caError ACME 协议错误（RFC8555 problem+json）。
// 说明：Java 侧此处透出的是 acme4j 内部异常文本（第三方库自有措辞），
// Go 侧以同样语义收敛为「CA 错误[类型]: 详情」，type 取 urn 末段。
type caError struct {
	Type   string
	Detail string
	Status int
}

func (e *caError) Error() string {
	t := e.Type
	if i := strings.LastIndex(t, ":"); i >= 0 {
		t = t[i+1:]
	}
	if e.Detail != "" {
		return "CA 错误[" + t + "]: " + e.Detail
	}
	return "CA 错误[" + t + "]"
}

// isBadNonce 判断重放号失效错误（可刷新 nonce 重试一次）。
func (e *caError) isBadNonce() bool {
	return strings.Contains(e.Type, "badNonce")
}

// ---------- ACME directory ----------

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

// ---------- ACME 订单/授权模型 ----------

type acmeOrder struct {
	URL            string
	Status         string
	Authorizations []string
	Finalize       string
	Certificate    string
}

type acmeChallenge struct {
	Type  string
	URL   string
	Token string
	Err   string // CA 回报的校验失败原因（problem+json 的 type/detail，校验通过时为空）
}

type acmeAuth struct {
	Domain     string
	Status     string
	Wildcard   bool
	Challenges []acmeChallenge
}

// challengeFailure 汇总授权下各挑战的失败原因，供授权状态为 invalid 时报错展示。
// CA 通常只在 challenge.error 里给出真正原因（如 TXT 记录不存在/值不符），
// 只报最终状态 INVALID 会让用户无从排查。
func (a *acmeAuth) challengeFailure() string {
	for i := range a.Challenges {
		if a.Challenges[i].Err == "" {
			continue
		}
		return a.Challenges[i].Err
	}
	return ""
}

// findChallenge 按类型查找验证方式（等价 acme4j findChallenge(...).orElseThrow）。
func (a *acmeAuth) findChallenge(typ string) (*acmeChallenge, error) {
	for i := range a.Challenges {
		if a.Challenges[i].Type == typ {
			return &a.Challenges[i], nil
		}
	}
	if typ == "http-01" {
		return nil, errors.New("CA 未提供 http-01 验证方式")
	}
	return nil, errors.New("CA 未提供 dns-01 验证方式")
}

// ---------- ACME 客户端 ----------

// eabParams ZeroSSL 外部账号绑定凭证（HMAC Key 为 base64url 文本）。
type eabParams struct {
	KID        string
	HMACBase64 string
}

type acmeClient struct {
	dir     acmeDirectory
	key     *rsa.PrivateKey
	jwkJSON string
	kid     string // 账号 URL；注册阶段为空（JWK 头模式）
	nonce   string
	http    *http.Client
}

// newAcmeClient 拉取服务商 directory 并绑定账号密钥与账号 URL（kid 为空表示注册阶段，用 JWK 头模式）。
func newAcmeClient(provider string, key *rsa.PrivateKey, kid string) (*acmeClient, error) {
	dirURL, ok := providerDirs[provider]
	if !ok {
		return nil, fmt.Errorf("未知的 ACME 服务商: %s", provider)
	}
	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          5,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	c := &acmeClient{key: key, kid: kid, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
	resp, err := c.http.Get(dirURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 ACME directory 失败: HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &c.dir); err != nil {
		return nil, fmt.Errorf("解析 ACME directory 失败: %w", err)
	}
	if key != nil {
		c.jwkJSON = rsaJWK(&key.PublicKey)
	}
	return c, nil
}

// fetchNonce HEAD newNonce 获取重放号（服务端会在任意响应头中更新，这里只在缓存为空时预取）。
func (c *acmeClient) fetchNonce() error {
	req, err := http.NewRequest(http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return errors.New("CA 未返回 Replay-Nonce")
	}
	c.nonce = n
	return nil
}

// flattenedJWS 输出 JWS 扁平 JSON 序列化（RFC7515 §7.2.2）。
// ACME 只接受该形式（RFC8555 §6.2）：紧凑三段式 "a.b.c" 会被 CA 判为 malformed。
func flattenedJWS(protected, payload, signature string) (string, error) {
	obj := core.NewRow().
		Set("protected", protected).
		Set("payload", payload).
		Set("signature", signature)
	b, err := core.MarshalJSON(obj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// signJWS 组装 JWS 请求体（RS256；jwk/kid 二选一）。
func (c *acmeClient) signJWS(url string, payload string) (string, error) {
	protected := core.NewRow().Set("alg", "RS256")
	if c.kid == "" {
		protected.Set("jwk", json.RawMessage(c.jwkJSON))
	} else {
		protected.Set("kid", c.kid)
	}
	protected.Set("nonce", c.nonce).Set("url", url)
	pText, err := core.MarshalJSON(protected)
	if err != nil {
		return "", err
	}
	pb := b64url(pText)
	payb := b64url([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sha256Sum([]byte(pb+"."+payb)))
	if err != nil {
		return "", err
	}
	return flattenedJWS(pb, payb, b64url(sig))
}

// marshalPayload 序列化请求负载：nil → 空串（POST-as-GET），string 原样，其余走 JSON。
func marshalPayload(payload interface{}) (string, error) {
	switch p := payload.(type) {
	case nil:
		return "", nil
	case string:
		return p, nil
	default:
		b, err := core.MarshalJSON(p)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

// post 发送 JWS 请求：badNonce 时刷新重放号重试一次；2xx 返回响应体与头。
func (c *acmeClient) post(url string, payload interface{}) ([]byte, http.Header, error) {
	text, err := marshalPayload(payload)
	if err != nil {
		return nil, nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if c.nonce == "" {
			if err := c.fetchNonce(); err != nil {
				return nil, nil, err
			}
		}
		jws, err := c.signJWS(url, text)
		if err != nil {
			return nil, nil, err
		}
		c.nonce = "" // 已消耗
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(jws))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if n := resp.Header.Get("Replay-Nonce"); n != "" {
			c.nonce = n
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, resp.Header, nil
		}
		lastErr = parseCAError(body, resp)
		var ce *caError
		if errors.As(lastErr, &ce) && ce.isBadNonce() && attempt == 0 {
			continue // 刷新 nonce 重试
		}
		return nil, nil, lastErr
	}
	return nil, nil, lastErr
}

// postAsGet POST-as-GET 拉取资源（空负载）。
func (c *acmeClient) postAsGet(url string) ([]byte, http.Header, error) {
	return c.post(url, nil)
}

// parseCAError 解析非 2xx 响应体为 ACME 错误对象。
func parseCAError(body []byte, resp *http.Response) error {
	var p struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &p) == nil && p.Type != "" {
		return &caError{Type: p.Type, Detail: p.Detail, Status: resp.StatusCode}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return fmt.Errorf("ACME 请求失败: HTTP %d %s", resp.StatusCode, msg)
}

// makeEAB 构造 ZeroSSL 外部账号绑定 JWS（HS256，负载为账号公钥 JWK，RFC8555 §7.3.4）。
func (c *acmeClient) makeEAB(eab eabParams) (string, error) {
	var key []byte
	var err error
	if key, err = base64.RawURLEncoding.DecodeString(eab.HMACBase64); err != nil {
		if key, err = base64.URLEncoding.DecodeString(eab.HMACBase64); err != nil {
			key, err = base64.StdEncoding.DecodeString(eab.HMACBase64)
		}
	}
	if err != nil {
		return "", fmt.Errorf("EAB HMAC Key 不是合法的 base64: %w", err)
	}
	protected := core.NewRow().
		Set("alg", "HS256").
		Set("kid", eab.KID).
		Set("url", c.dir.NewAccount).
		Set("nonce", c.nonce)
	pText, err := core.MarshalJSON(protected)
	if err != nil {
		return "", err
	}
	pb := b64url(pText)
	payb := b64url([]byte(c.jwkJSON))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(pb + "." + payb))
	return flattenedJWS(pb, payb, b64url(mac.Sum(nil)))
}

// ---------- 账号 ----------

// newAccount 注册/找回账号，返回账号 URL（JWK 头模式）。
// onlyExisting=true 时仅找回已有账号（密钥在、账号位置丢失的恢复场景）。
func (c *acmeClient) newAccount(email string, onlyExisting bool, eab *eabParams) (string, error) {
	payload := core.NewRow()
	if email != "" && !onlyExisting {
		payload.Set("contact", []string{"mailto:" + email})
	}
	payload.Set("termsOfServiceAgreed", true)
	if eab != nil {
		token, err := c.makeEAB(*eab)
		if err != nil {
			return "", err
		}
		payload.Set("externalAccountBinding", token)
	}
	if onlyExisting {
		payload.Set("onlyReturnExisting", true)
	}
	// 注册请求本身需要 nonce
	if c.nonce == "" {
		if err := c.fetchNonce(); err != nil {
			return "", err
		}
	}
	_, header, err := c.post(c.dir.NewAccount, payload)
	if err != nil {
		return "", err
	}
	loc := header.Get("Location")
	if loc == "" {
		return "", errors.New("CA 未返回账号 Location")
	}
	return loc, nil
}

// ---------- 订单与授权 ----------

// newOrder 创建订单，返回带 Location 的订单对象。
func (c *acmeClient) newOrder(domains []string) (*acmeOrder, error) {
	ids := make([]*core.Row, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, core.NewRow().Set("type", "dns").Set("value", d))
	}
	body, header, err := c.post(c.dir.NewOrder, core.NewRow().Set("identifiers", ids))
	if err != nil {
		return nil, err
	}
	o := &acmeOrder{URL: header.Get("Location")}
	if err := json.Unmarshal(body, o); err != nil {
		return nil, fmt.Errorf("解析 ACME 订单失败: %w", err)
	}
	return o, nil
}

// fetchOrder 重新拉取订单最新状态。
func (c *acmeClient) fetchOrder(url string) (*acmeOrder, error) {
	body, _, err := c.postAsGet(url)
	if err != nil {
		return nil, err
	}
	o := &acmeOrder{URL: url}
	if err := json.Unmarshal(body, o); err != nil {
		return nil, fmt.Errorf("解析 ACME 订单失败: %w", err)
	}
	return o, nil
}

// fetchAuth 拉取授权对象（identifier/挑战列表）。
func (c *acmeClient) fetchAuth(url string) (*acmeAuth, error) {
	body, _, err := c.postAsGet(url)
	if err != nil {
		return nil, err
	}
	var v struct {
		Identifier struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifier"`
		Status     string `json:"status"`
		Wildcard   bool   `json:"wildcard"`
		Challenges []struct {
			Type  string `json:"type"`
			URL   string `json:"url"`
			Token string `json:"token"`
			Error *struct {
				Type   string `json:"type"`
				Detail string `json:"detail"`
			} `json:"error"`
		} `json:"challenges"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("解析 ACME 授权失败: %w", err)
	}
	a := &acmeAuth{Domain: v.Identifier.Value, Status: v.Status, Wildcard: v.Wildcard}
	for _, ch := range v.Challenges {
		c := acmeChallenge{Type: ch.Type, URL: ch.URL, Token: ch.Token}
		if ch.Error != nil {
			c.Err = problemText(ch.Error.Type, ch.Error.Detail)
		}
		a.Challenges = append(a.Challenges, c)
	}
	return a, nil
}

// problemText 把 problem+json 的错误类型与详情压成一行文本（type 取 urn 末段）。
func problemText(typ, detail string) string {
	t := typ
	if i := strings.LastIndex(t, ":"); i >= 0 {
		t = t[i+1:]
	}
	switch {
	case t != "" && detail != "":
		return t + ": " + detail
	case detail != "":
		return detail
	default:
		return t
	}
}

// triggerChallenge 通知 CA 开始校验（POST 空对象负载）。
func (c *acmeClient) triggerChallenge(url string) error {
	_, _, err := c.post(url, core.NewRow())
	return err
}

// waitAuth 轮询授权直到离开 pending/processing 或超时（每秒一次，等价 acme4j waitForCompletion）。
func (c *acmeClient) waitAuth(url string, timeout time.Duration) (*acmeAuth, error) {
	deadline := time.Now().Add(timeout)
	for {
		a, err := c.fetchAuth(url)
		if err != nil {
			return nil, err
		}
		if a.Status != "pending" && a.Status != "processing" {
			return a, nil
		}
		if time.Now().After(deadline) {
			return a, errors.New("等待 CA 校验超时")
		}
		time.Sleep(time.Second)
	}
}

// finalize 提交 CSR 触发签发。
func (c *acmeClient) finalize(orderURL, finalizeURL string, csrDER []byte) (*acmeOrder, error) {
	body, _, err := c.post(finalizeURL, core.NewRow().Set("csr", b64url(csrDER)))
	if err != nil {
		return nil, err
	}
	o := &acmeOrder{URL: orderURL}
	if err := json.Unmarshal(body, o); err != nil {
		return nil, fmt.Errorf("解析 ACME 订单失败: %w", err)
	}
	return o, nil
}

// waitOrder 轮询订单直到进入终态 valid/invalid 或超时（pending/ready/processing 均继续等待，等价 acme4j 语义）。
func (c *acmeClient) waitOrder(url string, timeout time.Duration) (*acmeOrder, error) {
	deadline := time.Now().Add(timeout)
	for {
		o, err := c.fetchOrder(url)
		if err != nil {
			return nil, err
		}
		if o.Status != "pending" && o.Status != "processing" && o.Status != "ready" {
			return o, nil
		}
		if time.Now().After(deadline) {
			return o, errors.New("等待订单完成超时")
		}
		time.Sleep(time.Second)
	}
}

// getCertChain 下载证书链 PEM 文本（POST-as-GET certificate 端点）。
func (c *acmeClient) getCertChain(url string) (string, error) {
	body, _, err := c.postAsGet(url)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
