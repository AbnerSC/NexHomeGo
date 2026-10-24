package core

import (
	"net"
	"net/http"
	"testing"
)

// TestSanitizeIP 来源地址规范化：去掉端口/方括号/zone，并拒绝一切非 IP 文本
// （日志与统计直接回显该值，绝不能把任意字节带出去）。
func TestSanitizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{" 1.2.3.4 ", "1.2.3.4"},
		{"1.2.3.4:5678", "1.2.3.4"},
		{"[::1]:8090", "::1"},
		{"fe80::1%eth0", "fe80::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"300.1.1.1", ""},
		{"evil\r\nX-Injected: 1", ""},
		{"localhost", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeIP(c.in); got != c.want {
			t.Fatalf("SanitizeIP(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestClientForwardedIP 转发链取链尾一项（最近一跳代理所见的地址），
// 攻击者预置在链首的伪造值必须被忽略。
func TestClientForwardedIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"9.9.9.9, 203.0.113.7", "203.0.113.7"},
		{"9.9.9.9, 10.0.0.1, 1.2.3.4:99", "1.2.3.4"},
		{"  198.51.100.7  ,  10.0.0.1 ", "10.0.0.1"},
		{"203.0.113.7, garbage", "203.0.113.7"},
		{"garbage, evil", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := ClientForwardedIP(c.in); got != c.want {
			t.Fatalf("ClientForwardedIP(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestIsTrustedProxyPeer 只有环回/私网/链路本地对端才可能是本机前置代理。
func TestIsTrustedProxyPeer(t *testing.T) {
	trusted := []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.5.4", "192.168.1.9", "169.254.1.1", "fe80::1"}
	untrusted := []string{"8.8.8.8", "203.0.113.9", "2001:db8::1", "not-an-ip", ""}
	for _, ip := range trusted {
		if !IsTrustedProxyPeer(ip) {
			t.Fatalf("%s 应视为可信代理对端", ip)
		}
	}
	for _, ip := range untrusted {
		if IsTrustedProxyPeer(ip) {
			t.Fatalf("%s 不应视为可信代理对端", ip)
		}
	}
}

// TestTrustForwardedFromDefaultAuto 未配置（数据库未初始化 → 读取失败）时应落回 auto：
// 私网对端可信、公网对端一律不可信，保证「伪造 XFF 绕过白名单」在默认配置下不可用。
func TestTrustForwardedFromDefaultAuto(t *testing.T) {
	if got := TrustProxyMode(); got != TrustProxyAuto {
		t.Fatalf("默认策略应为 %s，实际 %s", TrustProxyAuto, got)
	}
	if !TrustForwardedFrom("192.168.1.5") {
		t.Fatal("auto 策略下私网对端应允许提供转发头")
	}
	if TrustForwardedFrom("203.0.113.5") {
		t.Fatal("auto 策略下公网对端不应允许提供转发头")
	}
}

// TestTrustForwardedFromPolicy 显式策略：always 全放、never 全禁（与对端地址无关）。
func TestTrustForwardedFromPolicy(t *testing.T) {
	if !TrustForwardedFromPolicy("203.0.113.5", TrustProxyAlways) {
		t.Fatal("always 策略下公网对端也应允许")
	}
	if TrustForwardedFromPolicy("192.168.1.5", TrustProxyNever) {
		t.Fatal("never 策略下私网对端也不允许")
	}
}

// TestClientIPFromHeaders 头优先级：aliyun-esa-real-client-ip 最高，其次 XFF 链尾，再 X-Real-IP / CF-Connecting-IP；
// 全部非法时返回空串由调用方决定回退。
func TestClientIPFromHeaders(t *testing.T) {
	mk := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}
	cases := []struct {
		name string
		h    http.Header
		want string
	}{
		{"aliyun-esa-real-client-ip 优先于 XFF", mk(AliyunEsaRealClientIPHeader, "203.0.113.7", "X-Forwarded-For", "9.9.9.9, 198.51.100.1"), "203.0.113.7"},
		{"aliyun-esa-real-client-ip 非法时回退 XFF 链尾", mk(AliyunEsaRealClientIPHeader, "evil", "X-Forwarded-For", "9.9.9.9, 198.51.100.1"), "198.51.100.1"},
		{"仅 X-Real-IP", mk("X-Real-IP", "198.51.100.9"), "198.51.100.9"},
		{"仅 CF-Connecting-IP", mk("CF-Connecting-IP", "198.51.100.11"), "198.51.100.11"},
		{"XFF 优先于 X-Real-IP", mk("X-Forwarded-For", "198.51.100.1", "X-Real-IP", "198.51.100.9"), "198.51.100.1"},
		{"全部缺失", mk(), ""},
		{"全部非法", mk(AliyunEsaRealClientIPHeader, "x", "X-Forwarded-For", "y", "X-Real-IP", "z"), ""},
	}
	for _, c := range cases {
		if got := ClientIPFromHeaders(c.h); got != c.want {
			t.Fatalf("%s: 实际 %q，期望 %q", c.name, got, c.want)
		}
	}
	// 多值头（Add 两次）应取最后一个合法项：ESA 规则追加而非覆盖时仍拿到真实 IP
	h := http.Header{}
	h.Add(AliyunEsaRealClientIPHeader, "1.1.1.1")
	h.Add(AliyunEsaRealClientIPHeader, "203.0.113.7")
	if got := ClientIPFromHeaders(h); got != "203.0.113.7" {
		t.Fatalf("多值 aliyun-esa-real-client-ip 应取最后一项，实际 %q", got)
	}
}

// TestNormalizeCIDRList 可信网段输入校验：CIDR 与单 IP 均接受并规范化，非法项必须报错
// （静默丢弃会让配置者以为已生效）。
func TestNormalizeCIDRList(t *testing.T) {
	ok := []struct{ in, want string }{
		{"", ""},
		{"192.168.0.0/16", "192.168.0.0/16"},
		{"192.168.1.9", "192.168.1.9/32"},
		{"203.0.113.7, 10.0.0.0/8", "10.0.0.0/8, 203.0.113.7/32"},
		{"203.0.113.7 ,  203.0.113.7/32", "203.0.113.7/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, c := range ok {
		got, err := NormalizeCIDRList(c.in)
		if err != nil || got != c.want {
			t.Fatalf("NormalizeCIDRList(%q)=(%q,%v)，期望 (%q,nil)", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"192.168.0.0/33", "not-an-ip", "10.0.0.0/8, oops"} {
		if _, err := NormalizeCIDRList(bad); err == nil {
			t.Fatalf("%q 应报错", bad)
		}
	}
}

// TestMatchNets 网段匹配（含 IPv4/IPv6 与越界地址）。
func TestMatchNets(t *testing.T) {
	nets := parseCIDRList("192.168.0.0/16, 203.0.113.7, 2001:db8::/32")
	if len(nets) != 3 {
		t.Fatalf("应解析出 3 个网段，实际 %d", len(nets))
	}
	if !matchNets(nets, net.ParseIP("192.168.9.9")) {
		t.Fatal("192.168.9.9 应命中")
	}
	if !matchNets(nets, net.ParseIP("203.0.113.7")) {
		t.Fatal("单 IP 配置应命中")
	}
	if matchNets(nets, net.ParseIP("203.0.113.8")) {
		t.Fatal("203.0.113.8 不应命中 /32")
	}
	if !matchNets(nets, net.ParseIP("2001:db8::5")) {
		t.Fatal("IPv6 网段应命中")
	}
	if matchNets(nets, net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 不应命中")
	}
}
