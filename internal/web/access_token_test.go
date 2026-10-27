package web

// 接口访问令牌（Header Access-Token）鉴权回归：与登录会话等价，缺失/错误一律 401。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"NexHomeGo/internal/auth"
)

// TestServeHTTPAccessToken 携带正确 Access-Token 可访问受保护接口；缺失或错误必须 401。
func TestServeHTTPAccessToken(t *testing.T) {
	setupWebTestDB(t)
	// routesBuf 为进程内全局路由表：注册一个仅供本用例使用的受保护接口
	Route("GET", "/api/test/access-token", func(c *Ctx) error {
		c.Ok("ok")
		return nil
	})

	const token = "test-access-token-1234"
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
