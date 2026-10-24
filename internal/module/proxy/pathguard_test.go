package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"NexHomeGo/internal/core"
)

// TestHasDotDotSegment 段级 ".." 才拦截：合法业务路径（a..b、..hidden）不能被误伤。
func TestHasDotDotSegment(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/a/../b", true},
		{"/..", true},
		{"/a/..", true},
		{"/a/../..", true},
		{`/a\..\b`, true},
		{`\..\b`, true},
		{"/a..b/c", false},
		{"/..hidden", false},
		{"/a/b..", false},
		{"/a/b/c", false},
		{"/", false},
	}
	for _, c := range cases {
		if got := hasDotDotSegment(c.path); got != c.want {
			t.Fatalf("hasDotDotSegment(%q)=%v，期望 %v", c.path, got, c.want)
		}
	}
}

// TestEncodedTraversalDecoded 回归：%2e%2e 在原始 RequestURI 中没有字面量 ".."，
// 必须靠解码后的 URL.Path 才能拦住（此前可透传到后端）。
func TestEncodedTraversalDecoded(t *testing.T) {
	r := httptest.NewRequest("GET", "/%2e%2e/%2e%2e/etc/passwd", nil)
	if !hasDotDotSegment(r.URL.Path) {
		t.Fatalf("解码后路径 %q 应判定为上跳段", r.URL.Path)
	}
	// 原始 RequestURI 仍保留编码形态，说明为什么必须两条路径都检查
	if hasDotDotSegment(r.URL.RequestURI()) {
		t.Fatalf("原始 URI %q 不应包含字面量上跳段（否则本用例失去意义）", r.URL.RequestURI())
	}
}

// TestParseRealIPPolicy 旧布尔值（"0"/"1"）与三态字符串共存；
// 旧默认 "1" 必须收敛为 auto（不能落成 always，否则存量安装升级后仍然裸信转发头）。
func TestParseRealIPPolicy(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0", "never"},
		{"false", "never"},
		{"never", "never"},
		{"1", "auto"},
		{"true", "auto"},
		{"always", "always"},
		{" ALWAYS ", "always"},
		{"auto", "auto"},
		{"", "auto"},
		{"garbage", "auto"},
	}
	for _, c := range cases {
		if got := parseRealIPPolicy(c.in); got != c.want {
			t.Fatalf("parseRealIPPolicy(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestResolveClientIp 访客 IP 解析：头优先级 + 可信对端闸门。
// 关键回归：ESA 回源对端是公网地址，auto 下必须不采信（否则直连源站可伪造）；
// 策略为 always（或对端命中可信网段）时才按 aliyun-esa-real-client-ip 取值。
func TestResolveClientIp(t *testing.T) {
	old := realIPPolicy
	defer func() { realIPPolicy = old }()

	mkReq := func() *http.Request {
		r := httptest.NewRequest("GET", "http://a.example/", nil)
		r.Header.Set(core.AliyunEsaRealClientIPHeader, "198.51.100.23")
		r.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.99")
		return r
	}

	// auto + 公网对端（ESA 回源在未配置可信网段时的默认情形）：忽略所有头
	realIPPolicy = core.TrustProxyAuto
	if got := resolveClientIp(mkReq(), "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("auto+公网对端应回退对端地址，实际 %q", got)
	}
	// auto + 内网对端（内网直连/局域网反代）：aliyun-esa-real-client-ip 优先于 XFF 链尾
	if got := resolveClientIp(mkReq(), "10.0.0.5"); got != "198.51.100.23" {
		t.Fatalf("auto+内网对端应采信 aliyun-esa-real-client-ip，实际 %q", got)
	}
	// never：即使内网对端也不采信
	realIPPolicy = core.TrustProxyNever
	if got := resolveClientIp(mkReq(), "10.0.0.5"); got != "10.0.0.5" {
		t.Fatalf("never 策略应回退对端地址，实际 %q", got)
	}
	// always：公网对端也采信（需配合源站仅允许回源代理访问）
	realIPPolicy = core.TrustProxyAlways
	if got := resolveClientIp(mkReq(), "203.0.113.9"); got != "198.51.100.23" {
		t.Fatalf("always 策略应采信 aliyun-esa-real-client-ip，实际 %q", got)
	}
	// 无头时回退对端
	emptyr := httptest.NewRequest("GET", "http://a.example/", nil)
	if got := resolveClientIp(emptyr, "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("无转发头应回退对端地址，实际 %q", got)
	}
}
