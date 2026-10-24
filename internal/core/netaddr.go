package core

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// 来源地址识别与转发头信任策略。
//
// X-Forwarded-For / X-Real-IP 这类头完全由客户端可控：若无条件采信，攻击者每次请求换一个
// 伪造 IP 即可绕过「登录失败锁定」「代理站点 IP 白名单」等一切基于来源地址的安全控制，
// 并把任意字符串写进操作日志。因此默认只在直连对端本身是可信代理（环回 / 私网 / 链路本地）
// 时才采用转发头；其余情况一律以 TCP 对端地址为准。
//
// 策略通过 app_config 的 security.trustProxy 控制：
//   - auto（默认）：仅当直连对端为可信代理时采信转发头；
//   - always：总是采信（面板挂在公网 CDN/反代之后且无法从对端地址判断时需要显式开启）；
//   - never：从不采信。
//
// 「可信代理」= 环回/私网/链路本地，或命中 security.trustedProxies 配置的网段（CIDR / 单 IP）。
// 后者用于回源地址是公网的回源代理（如阿里云 ESA 回源节点），既可采信真实 IP，
// 又不致于让绕过代理直连源站的客户端伪造头。
const (
	KeyTrustProxy = "security.trustProxy"

	// KeyTrustedProxies 可信代理网段：逗号或空白分隔的 CIDR / 单 IP，命中即视为可信代理。
	KeyTrustedProxies = "security.trustedProxies"

	// AliyunEsaRealClientIPHeader 阿里云 ESA（边缘安全加速）自定义回源头：由 ESA 规则注入真实客户端 IP。
	// 属于自定义头，客户端直连源站可自行伪造，因此仍受「可信对端」闸门约束。
	AliyunEsaRealClientIPHeader = "aliyun-esa-real-client-ip"

	TrustProxyNever  = "never"
	TrustProxyAuto   = "auto"
	TrustProxyAlways = "always"

	trustModeCacheTTL = 10 * time.Second
)

var (
	trustModeMu  sync.Mutex
	trustModeVal string
	trustNetsVal []*net.IPNet
	trustNetsRaw string
	trustModeAt  time.Time
)

// TrustProxyMode 读取转发头信任策略（缺省 auto，非法值同样回退 auto）。
// 带 10 秒缓存，避免每个请求都查一次数据库；策略变更最迟 10 秒后生效。
func TrustProxyMode() string {
	mode, _, _ := trustConfig()
	return mode
}

// trustConfig 一次读取策略与可信网段（共用一份缓存，避免每请求多次查库）。
func trustConfig() (mode string, nets []*net.IPNet, raw string) {
	trustModeMu.Lock()
	defer trustModeMu.Unlock()
	if trustModeVal != "" && time.Since(trustModeAt) < trustModeCacheTTL {
		return trustModeVal, trustNetsVal, trustNetsRaw
	}
	mode = TrustProxyAuto
	if v, err := GetConfig(KeyTrustProxy); err == nil {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case TrustProxyNever:
			mode = TrustProxyNever
		case TrustProxyAlways:
			mode = TrustProxyAlways
		}
	}
	raw, _ = GetConfig(KeyTrustedProxies)
	nets = parseCIDRList(raw)
	trustModeVal, trustNetsVal, trustNetsRaw, trustModeAt = mode, nets, raw, time.Now()
	return mode, nets, raw
}

// InvalidateTrustCache 配置变更后立即清缓存（否则最长 10 秒内仍用旧策略）。
func InvalidateTrustCache() {
	trustModeMu.Lock()
	trustModeAt = time.Time{}
	trustModeMu.Unlock()
}

// TrustedProxiesRaw 当前可信网段配置原文（供设置页回填）。
func TrustedProxiesRaw() string {
	_, _, raw := trustConfig()
	return strings.TrimSpace(raw)
}

// MatchTrustedProxy 直连对端是否命中配置的可信代理网段。
func MatchTrustedProxy(ip string) bool {
	_, nets, _ := trustConfig()
	p := net.ParseIP(SanitizeIP(ip))
	if p == nil {
		return false
	}
	return matchNets(nets, p)
}

func matchNets(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsTrustedProxyPeer 直连对端是否可能是可信代理（环回 / 私网 / 链路本地单播）。
func IsTrustedProxyPeer(ip string) bool {
	p := net.ParseIP(SanitizeIP(ip))
	if p == nil {
		return false
	}
	return p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast()
}

// TrustForwardedFrom 该直连对端在当前策略下是否允许提供转发头。
func TrustForwardedFrom(peer string) bool {
	return TrustForwardedFromPolicy(peer, TrustProxyMode())
}

// TrustForwardedFromPolicy 指定策略下的判断（面板与反向代理各有自己的策略开关，共用可信网段）。
func TrustForwardedFromPolicy(peer, policy string) bool {
	switch policy {
	case TrustProxyAlways:
		return true
	case TrustProxyNever:
		return false
	}
	if MatchTrustedProxy(peer) {
		return true
	}
	return IsTrustedProxyPeer(peer)
}

// ClientIPFromHeaders 按优先级从请求头解析真实客户端 IP：
// aliyun-esa-real-client-ip（ESA 注入，多值取最后一个合法项）→ X-Forwarded-For（链尾）→ X-Real-IP → CF-Connecting-IP。
// 全部缺失/非法返回空串，由调用方决定是否回退到 TCP 对端地址。
// 调用前必须确认对端可信（TrustForwardedFrom*），否则这些头都可被客户端伪造。
func ClientIPFromHeaders(h http.Header) string {
	if h == nil {
		return ""
	}
	// ESA 规则可能覆盖也可能追加，多值时取最后一个合法项（与 XFF 链尾语义一致）
	vals := h.Values(AliyunEsaRealClientIPHeader)
	for i := len(vals) - 1; i >= 0; i-- {
		if ip := ClientForwardedIP(vals[i]); ip != "" {
			return ip
		}
	}
	if ip := ClientForwardedIP(h.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := SanitizeIP(h.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if ip := SanitizeIP(h.Get("CF-Connecting-IP")); ip != "" {
		return ip
	}
	return ""
}

// NormalizeCIDRList 校验并规范化可信网段输入（逗号/空白分隔，支持 CIDR 与单 IP）。
// 任一项非法即报错，避免把拼写错误当成「不限制」静默放过。
func NormalizeCIDRList(raw string) (string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '；' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		s := strings.TrimSpace(f)
		if s == "" {
			continue
		}
		var key string
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return "", fmt.Errorf("网段格式非法: %s（示例 192.168.0.0/16）", s)
			}
			key = n.String()
		} else {
			p := net.ParseIP(s)
			if p == nil {
				return "", fmt.Errorf("IP 格式非法: %s（示例 203.0.113.7）", s)
			}
			bits := 128
			if p.To4() != nil {
				bits = 32
			}
			key = fmt.Sprintf("%s/%d", p.String(), bits)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return strings.Join(out, ", "), nil
}

// parseCIDRList 解析配置值（非法项静默忽略，配置入口已做校验）。
func parseCIDRList(raw string) []*net.IPNet {
	norm, err := NormalizeCIDRList(raw)
	if err != nil || norm == "" {
		return nil
	}
	nets := make([]*net.IPNet, 0, 4)
	for _, part := range strings.Split(norm, ", ") {
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// SanitizeIP 规范化来源地址：去空白 / 端口 / 方括号 / IPv6 zone，非法返回空串。
// 日志与统计一律经此过滤，避免把换行等任意字节回显进日志或页面。
func SanitizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if i := strings.IndexByte(s, '%'); i > 0 { // IPv6 zone（fe80::1%eth0）
		s = s[:i]
	}
	if p := net.ParseIP(s); p != nil {
		return p.String()
	}
	return ""
}

// ClientForwardedIP 从转发头链取「最近一跳可信代理所见的客户端地址」（链尾最后一个合法项）。
//
// 为什么取链尾而不是链首：nginx 等反代默认用 $proxy_add_x_forwarded_for 追加
// （值为 $http_x_forwarded_for, $remote_addr），攻击者自带的伪造值会落在链首，
// 只有链尾那一项是代理真实看到的地址；取链首等于取攻击者自报值。
func ClientForwardedIP(chain string) string {
	parts := strings.Split(chain, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if ip := SanitizeIP(parts[i]); ip != "" {
			return ip
		}
	}
	return ""
}
