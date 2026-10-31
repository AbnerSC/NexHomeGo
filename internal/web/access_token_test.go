package web

// 接口访问令牌（Header Access-Token）鉴权回归：与登录会话等价，缺失/错误一律 401；
// 令牌校验入口 /api/auth/check 的双桶失败计数与锁定同样在此回归。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"NexHomeGo/internal/auth"
	"NexHomeGo/internal/core"
)

// TestServeHTTPAccessToken 携带正确 Access-Token 可访问受保护接口；缺失或错误必须 401。
func TestServeHTTPAccessToken(t *testing.T) {
	setupWebTestDB(t)
	// routesBuf 为进程内全局路由表：注册一个仅供本用例使用的受保护接口
	Route("GET", "/api/test/access-token", func(c *Ctx) error {
		c.Ok("ok")
		return nil
	})

	const token = "test-access-token-1234567890abcdef"
	if err := auth.SetAccessToken(token); err != nil {
		t.Fatalf("SetAccessToken: %v", err)
	}
	t.Cleanup(func() { _ = auth.SetAccessToken("") })

	cases := []struct {
		name string
		hdr  string
		want int
	}{
		{"未携带令牌", "", http.StatusUnauthorized},
		{"令牌错误", "wrong-token-5678", http.StatusUnauthorized},
		{"令牌正确", token, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test/access-token", nil)
			if tc.hdr != "" {
				req.Header.Set("Access-Token", tc.hdr)
			}
			rec := httptest.NewRecorder()
			serveHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status got %d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestAuthCheckAccessTokenThrottle /api/auth/check 是免鉴权的令牌探测入口：
// 直连时按 TCP 对端（绝对桶）计数；位于显式可信代理后时按真实客户端（细分桶）计数。
// 两种情形都必须在连续失败达阈值后返回 429，且细分桶锁定不得连带其他客户端。
func TestAuthCheckAccessTokenThrottle(t *testing.T) {
	setupWebTestDB(t)
	registerAuthRoutes()     // 测试进程内路由表默认未注册业务接口
	const peer = "192.0.2.1" // httptest.NewRequest 的默认 RemoteAddr
	const clientA, clientB = "198.51.100.77", "198.51.100.78"
	const token = "test-access-token-1234567890abcdef"
	const wrong = "wrong-token-000000000000000000"
	if err := auth.SetAccessToken(token); err != nil {
		t.Fatalf("SetAccessToken: %v", err)
	}
	auth.ResetAccessTokenFailures(peer, "")
	auth.ResetAccessTokenFailures(peer, clientA)
	auth.ResetAccessTokenFailures(peer, clientB)
	t.Cleanup(func() {
		_ = auth.SetAccessToken("")
		auth.ResetAccessTokenFailures(peer, "")
		auth.ResetAccessTokenFailures(peer, clientA)
		auth.ResetAccessTokenFailures(peer, clientB)
		_ = core.SetConfig(core.KeyTrustProxy, "")
		core.InvalidateTrustCache()
	})

	check := func(tok, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)
		req.Header.Set("Access-Token", tok)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		serveHTTP(rec, req)
		return rec.Code
	}
	setPolicy := func(policy string) {
		if err := core.SetConfig(core.KeyTrustProxy, policy); err != nil {
			t.Fatalf("SetConfig(trustProxy=%s): %v", policy, err)
		}
		core.InvalidateTrustCache()
	}

	// 1) 直连：不采信转发头，绝对桶在 AccessTokenPeerMaxFails 次后锁定该对端
	setPolicy(core.TrustProxyNever)
	for i := 1; i <= auth.AccessTokenPeerMaxFails; i++ {
		if code := check(wrong, ""); code != http.StatusOK {
			t.Fatalf("直连第 %d 次失败应返回 200（loggedIn=false），got %d", i, code)
		}
	}
	if code := check(wrong, ""); code != http.StatusTooManyRequests {
		t.Fatalf("直连失败 %d 次后应返回 429，got %d", auth.AccessTokenPeerMaxFails, code)
	}

	// 2) 显式可信代理后：按真实客户端（细分桶）计数，10 次即锁定该客户端
	auth.ResetAccessTokenFailures(peer, "")
	setPolicy(core.TrustProxyAlways)
	for i := 1; i <= auth.AccessTokenMaxFails; i++ {
		if code := check(wrong, clientA); code != http.StatusOK {
			t.Fatalf("经代理第 %d 次失败应返回 200，got %d", i, code)
		}
	}
	if code := check(wrong, clientA); code != http.StatusTooManyRequests {
		t.Fatalf("经代理失败 %d 次后应返回 429，got %d", auth.AccessTokenMaxFails, code)
	}
	if code := check(wrong, clientB); code != http.StatusOK {
		t.Fatalf("其他真实客户端不应被连带锁定，got %d", code)
	}
	if code := check(token, clientB); code != http.StatusOK {
		t.Fatalf("锁定期间正确令牌的其他客户端应可正常校验，got %d", code)
	}
}
