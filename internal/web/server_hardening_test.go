package web

import (
	"crypto/tls"
	"net/http/httptest"
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
