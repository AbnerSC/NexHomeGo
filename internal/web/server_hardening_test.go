package web

import (
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServeHTTPSecurityHeaders 所有面板响应（含免登录静态页）都必须带基础安全头，
// 否则可被 MIME 嗅探 / 点击劫持 / Referer 泄露 token。
func TestServeHTTPSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	serveHTTP(rec, httptest.NewRequest("GET", "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-XSS-Protection":       "0",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("响应头 %s=%q，期望 %q", k, got, v)
		}
	}
}

// TestUnboundedBodyWhitelist 只有流式测速上行可绕过请求体上限，其余接口（含免登录登录口）必须受限。
func TestUnboundedBodyWhitelist(t *testing.T) {
	if !unboundedBodyPath("/api/system/speedtest/up") {
		t.Fatal("测速上行需要流式读体，应在白名单内")
	}
	for _, p := range []string{
		"/api/auth/login",
		"/api/system/settings",
		"/api/nav/images/upload",
		"/api/system/backup/restore",
		"/api/auth/check",
	} {
		if unboundedBodyPath(p) {
			t.Fatalf("%s 不应绕过请求体上限", p)
		}
	}
}

// TestCanonicalPath 非规范路径必须被识别：鉴权用 HasPrefix("/api/") 判定，
// 路由匹配却按 Trim(path, "/") 拆分，"//api/**" 会在两者间产生结论差（鉴权绕过）。
func TestCanonicalPath(t *testing.T) {
	bad := []string{
		"//api/dashboard",
		"///api/dashboard",
		"/api//dashboard",
		"/api/./dashboard",
		"/entry//api/dashboard",
		"/../etc/passwd",
		"//",
		"",
		"api/dashboard",
	}
	for _, p := range bad {
		if canonicalPath(p) {
			t.Fatalf("%q 应判为非规范路径", p)
		}
	}
	good := []string{"/", "/api/dashboard", "/entry/", "/.well-known/acme-challenge/token", "/js/app.js"}
	for _, p := range good {
		if !canonicalPath(p) {
			t.Fatalf("%q 是合法路径，不应被拒", p)
		}
	}
}

// TestServeHTTPRejectsMultiSlashAPI 分发层面对 "//api/**" 必须直接拒绝，
// 不能交给后续鉴权/路由（否则会以未登录身份命中接口）。
func TestServeHTTPRejectsMultiSlashAPI(t *testing.T) {
	for _, p := range []string{"//api/dashboard", "///api/system/backup", "/api/./dashboard"} {
		r := httptest.NewRequest("GET", "/api/dashboard", nil)
		r.URL.Path = p
		rec := httptest.NewRecorder()
		serveHTTP(rec, r)
		if rec.Code != 400 && rec.Code != 404 {
			t.Fatalf("%q 应被拒绝，实际 code=%d body=%q", p, rec.Code, rec.Body.String())
		}
	}
}

// TestServeHTTPSHSTS HTTPS 访问必须下发 HSTS，防止后续请求降级到明文。
func TestServeHTTPSHSTS(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	serveHTTP(rec, r)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HTTPS 响应缺少 Strict-Transport-Security")
	}
}

// TestServeHTTPCSP 面板页面必须下发 CSP（拦住外部脚本引用与 object/base 注入）。
func TestServeHTTPCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	serveHTTP(rec, httptest.NewRequest("GET", "/", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("缺失 Content-Security-Policy")
	}
	for _, want := range []string{"default-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP 缺少 %q: %s", want, csp)
		}
	}
}

// TestAuthBodyLimit 免登录接口必须单独收紧请求体上限：匿名大包只需少量并发就能致命。
func TestAuthBodyLimit(t *testing.T) {
	for _, p := range []string{"/api/auth/login", "/api/auth/check"} {
		if got := apiBodyLimit(p); got != maxAuthBodyBytes {
			t.Fatalf("%s 请求体上限=%d，期望 %d", p, got, maxAuthBodyBytes)
		}
	}
	if got := apiBodyLimit("/api/logs"); got != maxAPIBodyBytes {
		t.Fatalf("普通接口上限被误改: %d", got)
	}
	if got := apiBodyLimit("/api/proxy/sites/upload"); got != maxUploadBodyBytes {
		t.Fatalf("zip 上传上限被误改: %d", got)
	}
	rec := httptest.NewRecorder()
	serveHTTP(rec, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(strings.Repeat("a", int(maxAuthBodyBytes)+1024))))
	if rec.Code != 413 {
		t.Fatalf("超大登录请求应回 413，实际 %d", rec.Code)
	}
}

// TestRedirectHost 强制 HTTPS 跳转的 Location 不得直接采信任意 Host（开放重定向 / 头注入）。
func TestRedirectHost(t *testing.T) {
	cases := map[string]string{
		"panel.lan:8090":    "panel.lan",
		"192.168.1.10:8090": "192.168.1.10",
		"[::1]:8090":        "::1",
	}
	for host, want := range cases {
		r := httptest.NewRequest("GET", "/x", nil)
		r.Host = host
		if got := redirectHost(r); got != want {
			t.Fatalf("Host=%q 得到 %q，期望 %q", host, got, want)
		}
	}
	// 含非法字符的 Host 一律回退（不得进入 Location）
	r := httptest.NewRequest("GET", "/x", nil)
	r.Host = "evil.com/path"
	if got := redirectHost(r); got != "localhost" {
		t.Fatalf("非法 Host 应回退到本地地址，实际 %q", got)
	}
}
