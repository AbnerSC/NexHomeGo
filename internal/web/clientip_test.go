package web

import (
	"net/http/httptest"
	"testing"
)

// TestClientIPIgnoresSpoofedHeadersFromPublicPeer 公网直连对端自报 XFF 时必须忽略：
// 否则每次请求换一个伪造 IP 就能绕过登录失败锁定。
func TestClientIPIgnoresSpoofedHeadersFromPublicPeer(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/auth/login", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	r.Header.Set("X-Real-IP", "9.9.9.9")
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.ClientIP(); got != "203.0.113.9" {
		t.Fatalf("公网对端的 ClientIP 应为 TCP 对端地址，实际 %q", got)
	}
	if got := c.PeerIP(); got != "203.0.113.9" {
		t.Fatalf("PeerIP 应为 TCP 对端地址，实际 %q", got)
	}
}

// TestClientIPTrustsForwardedFromPrivatePeer auto 策略下，内网代理追加在链尾的地址应被采信，
// 而客户端预置在链首的伪造值必须被忽略（nginx $proxy_add_x_forwarded_for 场景）。
func TestClientIPTrustsForwardedFromPrivatePeer(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/auth/login", nil)
	r.RemoteAddr = "10.0.0.5:41234"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.7")
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.ClientIP(); got != "198.51.100.7" {
		t.Fatalf("应采信链尾（代理所见）地址，实际 %q", got)
	}
	if got := c.PeerIP(); got != "10.0.0.5" {
		t.Fatalf("PeerIP 必须是 TCP 对端地址（锁定计数键），实际 %q", got)
	}
}

// TestClientIPRejectsMalformedForwardedValues 非法转发值不得污染日志与统计。
func TestClientIPRejectsMalformedForwardedValues(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "evil\r\nInjected")
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.ClientIP(); got != "127.0.0.1" {
		t.Fatalf("非法转发值应被丢弃并回退对端地址，实际 %q", got)
	}
}

// TestPeerIPEmptyRemoteAddr 非常规 RemoteAddr 不得返回任意文本。
func TestPeerIPEmptyRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/x", nil)
	r.RemoteAddr = "@@@"
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.PeerIP(); got != "unknown" {
		t.Fatalf("无法解析的对端地址应返回 unknown，实际 %q", got)
	}
}

// TestClientIPPrefersEsaHeader 可信对端上 aliyun-esa-real-client-ip（ESA 注入）优先于 XFF/X-Real-IP，
// 且客户端预置的伪造 XFF 前缀不影响结果。
func TestClientIPPrefersEsaHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/net/source", nil)
	r.RemoteAddr = "10.0.0.5:41234"
	r.Header.Set("Aliyun-Esa-Real-Client-Ip", "198.51.100.23")
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.99")
	r.Header.Set("X-Real-IP", "198.51.100.88")
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.ClientIP(); got != "198.51.100.23" {
		t.Fatalf("应优先采信 aliyun-esa-real-client-ip，实际 %q", got)
	}
}

// TestClientIPIgnoresEsaHeaderFromPublicPeer 公网直连对端自行携带 aliyun-esa-real-client-ip 同样是伪造，
// 必须忽略并回退到 TCP 对端（否则 ESA 自定义头会变成绕过白名单的后门）。
func TestClientIPIgnoresEsaHeaderFromPublicPeer(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/net/source", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	r.Header.Set("Aliyun-Esa-Real-Client-Ip", "10.0.0.1")
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.ClientIP(); got != "203.0.113.9" {
		t.Fatalf("不可信对端携带的 aliyun-esa-real-client-ip 必须忽略，实际 %q", got)
	}
}
