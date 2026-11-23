package auth

import (
	"testing"

	"NexHomeGo/internal/core"
)

// resetSessions 清空内存会话表，避免用例间相互影响。
func resetSessions() {
	tokensMu.Lock()
	tokens = map[string]session{}
	platformTokens = map[string]string{}
	tokensMu.Unlock()
}

// TestNormalizePlatform 平台标识归一化：空值/大小写/空白兼容，未知平台拒绝。
func TestNormalizePlatform(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"", PlatformPC},
		{"pc", PlatformPC},
		{"PC", PlatformPC},
		{" pc ", PlatformPC},
		{"android", PlatformAndroid},
		{"Android", PlatformAndroid},
		{" ANDROID ", PlatformAndroid},
	}
	for _, c := range cases {
		got, err := NormalizePlatform(c.raw)
		if err != nil || got != c.want {
			t.Fatalf("NormalizePlatform(%q) = %q, %v; want %q", c.raw, got, err, c.want)
		}
	}
	// 未知平台必须拒绝：静默归并到 pc 会误踢 PC 平台的正常会话。
	for _, bad := range []string{"ios", "windows", "androidx", "pc|android"} {
		if got, err := NormalizePlatform(bad); err == nil {
			t.Fatalf("未知平台 %q 应被拒绝, got %q", bad, got)
		}
	}
}

// TestLoginPerPlatformSingleSession 平台内单点、跨平台共存：
// 默认平台为 pc；同平台再次登录注销旧会话；退出/改密只影响本平台或全部会话。
func TestLoginPerPlatformSingleSession(t *testing.T) {
	setupAuthTestDB(t)
	const password = "Passw0rd!-test"
	if err := core.SetConfig(KeyPassword, sha256Hex(password)); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	resetSessions()
	t.Cleanup(resetSessions)

	login := func(platform string) string {
		t.Helper()
		token, err := Login(password, "198.51.100.10", "198.51.100.10", platform)
		if err != nil || token == "" {
			t.Fatalf("Login(%q): token=%q err=%v", platform, token, err)
		}
		return token
	}

	pc1 := login("") // 未传平台 → pc（本机默认）
	if p, ok := SessionPlatform(pc1); !ok || p != PlatformPC {
		t.Fatalf("默认平台应为 %s, got %q ok=%v", PlatformPC, p, ok)
	}
	android1 := login("Android") // 大小写不敏感
	if !Check(pc1) || !Check(android1) {
		t.Fatal("不同平台会话应同时有效")
	}

	// 同平台再次登录：旧会话失效，其它平台不受影响。
	android2 := login("android")
	if Check(android1) {
		t.Fatal("同平台新登录必须注销旧会话")
	}
	if !Check(android2) || !Check(pc1) {
		t.Fatal("同平台新登录不得影响其它平台会话")
	}
	pc2 := login("pc")
	if Check(pc1) {
		t.Fatal("PC 平台再次登录后旧会话应失效")
	}
	if !Check(pc2) || !Check(android2) {
		t.Fatal("PC 重新登录不得影响 Android 会话")
	}

	// 退出只清理本平台会话槽位。
	Logout(pc2)
	if Check(pc2) {
		t.Fatal("退出后 token 应失效")
	}
	if !Check(android2) {
		t.Fatal("PC 退出不得影响 Android 会话")
	}
	if _, ok := SessionPlatform(pc2); ok {
		t.Fatal("已退出的 token 不应返回平台")
	}

	// 修改密码：全部平台会话失效。
	ok, err := ChangePassword(password, "NewPassw0rd!-test")
	if err != nil || !ok {
		t.Fatalf("ChangePassword: ok=%v err=%v", ok, err)
	}
	if Check(android2) {
		t.Fatal("修改密码后所有平台会话必须失效")
	}

	// 密码错误不颁发 token；未知平台直接报参数错误。
	if token, err := Login("wrong-password", "198.51.100.11", "198.51.100.11", "pc"); err != nil || token != "" {
		t.Fatalf("错误密码不得颁发 token: token=%q err=%v", token, err)
	}
	if _, err := Login("NewPassw0rd!-test", "198.51.100.12", "198.51.100.12", "ios"); err == nil {
		t.Fatal("未知平台应报参数错误")
	}
}
