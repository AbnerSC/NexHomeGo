package auth

import (
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// setupAuthTestDB 独立临时数据目录，供读写 app_config 的用例使用。
func setupAuthTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := core.InitPaths(); err != nil {
		t.Fatalf("InitPaths: %v", err)
	}
	core.CloseDB()
	if err := core.InitDB(filepath.Join(dir, "nexhome.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

// TestAccessToken 令牌长度/字符集校验、比对语义与停用行为。
func TestAccessToken(t *testing.T) {
	setupAuthTestDB(t)

	if CheckAccessToken("") || CheckAccessToken("any-token") {
		t.Fatal("未配置令牌时必须一律拒绝")
	}
	// 下限不足、超过上限、含非法字符（空格/中文/点号）一律拒绝
	for _, bad := range []string{
		"short",
		strings.Repeat("a", MaxAccessTokenLen+1),
		"bad token", "中文token", "with.dot",
	} {
		if err := SetAccessToken(bad); err == nil {
			t.Fatalf("非法令牌应被拒绝: %q", bad)
		}
	}
	if got, _ := GetAccessToken(); got != "" {
		t.Fatalf("非法输入不应落库, got %q", got)
	}

	valid := strings.Repeat("A-_9", 16) // 64 位，恰好上限
	if len(valid) != MaxAccessTokenLen {
		t.Fatalf("用例令牌长度应为 %d, got %d", MaxAccessTokenLen, len(valid))
	}
	if err := SetAccessToken(valid); err != nil {
		t.Fatalf("SetAccessToken: %v", err)
	}
	if !CheckAccessToken(valid) {
		t.Fatal("已配置令牌应校验通过")
	}
	if !CheckAccessToken("  " + valid + "  ") {
		t.Fatal("两侧空白应被忽略")
	}
	if CheckAccessToken(strings.Repeat("A", MaxAccessTokenLen)) {
		t.Fatal("内容不同不得判定通过")
	}
	if CheckAccessToken(valid[:MaxAccessTokenLen-1]) {
		t.Fatal("长度不同不得判定通过")
	}

	// 留空即停用：旧令牌立即失效
	if err := SetAccessToken(""); err != nil {
		t.Fatalf("停用令牌: %v", err)
	}
	if CheckAccessToken(valid) {
		t.Fatal("停用后旧令牌必须失效")
	}
}
