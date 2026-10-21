package core_test

import (
	"os"
	"path/filepath"
	"testing"

	// 兼容性回归测试需要真实 SQLite 驱动（cgo）；仅在 CGO_ENABLED=1 + C 编译器环境下运行。
	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// fixtureDB 返回 Java 侧生成的 nexhome.db 夹具路径（Phase 0 迁移而来）。
func fixtureDB(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "java_fixture", "nexhome.db")
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Skipf("夹具路径解析失败: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("未找到 Java 夹具库 %s（请先从 NexHome/data/nexhome.db 复制到 testdata/java_fixture）: %v", abs, err)
	}
	return abs
}

// copyToTemp 复制夹具到临时目录，避免 WAL 边车文件污染只读夹具。
func copyToTemp(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("读取夹具失败: %v", err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "nexhome.db")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("写入临时库失败: %v", err)
	}
	return dst
}

// TestJavaFixtureOpen 验证 Go(mattn/go-sqlite3) 能直接打开 Java(sqlite-jdbc) 生成的库并跑通建表脚本（幂等）。
func TestJavaFixtureOpen(t *testing.T) {
	src := fixtureDB(t)
	dbPath := copyToTemp(t, src)

	if err := core.InitDB(dbPath); err != nil {
		t.Fatalf("打开 Java 夹具库失败: %v", err)
	}
	defer core.CloseDB()

	// WAL 生效（与 Java Database.init 一致）。
	mode, err := core.Scalar("PRAGMA journal_mode")
	if err != nil {
		t.Fatalf("读取 journal_mode 失败: %v", err)
	}
	if got := toLower(mode); got != "wal" {
		t.Fatalf("期望 journal_mode=wal，实际=%v", mode)
	}
}

// TestJavaFixtureAuthSeed 验证能读到 Java 首次启动写入的 auth.password（SHA-256 hex，64 位），
// 这是「无缝切换、用户无需重设密码」的核心契约。
func TestJavaFixtureAuthSeed(t *testing.T) {
	src := fixtureDB(t)
	dbPath := copyToTemp(t, src)
	if err := core.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB 失败: %v", err)
	}
	defer core.CloseDB()

	pwd, err := core.GetConfig("auth.password")
	if err != nil {
		t.Fatalf("读取 auth.password 失败: %v", err)
	}
	if len(pwd) != 64 {
		t.Fatalf("期望 auth.password 为 64 位 SHA-256 hex，实际长度=%d 值=%q", len(pwd), pwd)
	}
}

// TestBackupVacuumInto 验证 VACUUM INTO 一致性快照可用（配置备份接口依赖，决策⑤落 data 目录内）。
func TestBackupVacuumInto(t *testing.T) {
	src := fixtureDB(t)
	dbPath := copyToTemp(t, src)
	if err := core.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB 失败: %v", err)
	}
	defer core.CloseDB()

	out := filepath.Join(t.TempDir(), "backup.db")
	if err := core.BackupTo(filepath.ToSlash(out)); err != nil {
		t.Fatalf("VACUUM INTO 备份失败: %v", err)
	}
	st, err := os.Stat(out)
	if err != nil || st.Size() == 0 {
		t.Fatalf("备份文件缺失或为空: err=%v", err)
	}
}

func toLower(v interface{}) string {
	if s, ok := v.(string); ok {
		return stringsLower(s)
	}
	if b, ok := v.([]byte); ok {
		return stringsLower(string(b))
	}
	return ""
}

func stringsLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}
