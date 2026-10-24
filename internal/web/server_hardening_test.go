package web

import (
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
