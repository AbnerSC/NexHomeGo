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
		"12345678", // 旧版下限 8 位：权限等同登录密码，绝不允许
		strings.Repeat("a", MinAccessTokenLen-1),
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

// TestAccessTokenFailureLockout 细分桶：位于显式可信代理后时按「对端|真实客户端」计数，
// 达到 AccessTokenMaxFails 次锁定该客户端，不得波及其他客户端与整个对端，校验成功后清零。
func TestAccessTokenFailureLockout(t *testing.T) {
	const peer, client, otherClient = "172.17.0.1", "203.0.113.30", "203.0.113.31"
	reset := func() {
		atFailsMu.Lock()
		delete(atPeerFails, peer)
		for k := range atClientFails {
			if strings.HasPrefix(k, peer+"|") {
				delete(atClientFails, k)
			}
		}
		atFailsMu.Unlock()
	}
	reset()
	defer reset()

	for i := 0; i < AccessTokenMaxFails-1; i++ {
		RecordAccessTokenFailure(peer, client)
		if AccessTokenLockRemainingMs(peer, client) != 0 {
			t.Fatalf("第 %d 次失败前不应处于锁定态", i+1)
		}
	}
	RecordAccessTokenFailure(peer, client)
	if AccessTokenLockRemainingMs(peer, client) <= 0 {
		t.Fatalf("连续失败 %d 次后应进入锁定态", AccessTokenMaxFails)
	}
	if AccessTokenLockRemainingMs(peer, otherClient) != 0 {
		t.Fatal("锁定不得波及其它客户端")
	}
	if AccessTokenLockRemainingMs(peer, "") != 0 {
		t.Fatal("细分桶锁定不得连带绝对桶（同一对端的其它调用应仍可用）")
	}
	before := AccessTokenLockRemainingMs(peer, client)
	RecordAccessTokenFailure(peer, client)
	if after := AccessTokenLockRemainingMs(peer, client); after > before {
		t.Fatalf("锁定期间不得延长锁定: before=%d after=%d", before, after)
	}
	ResetAccessTokenFailures(peer, client)
	if AccessTokenLockRemainingMs(peer, client) != 0 {
		t.Fatal("校验成功后应清除锁定状态")
	}
}

// TestAccessTokenPeerBucketLockout 绝对桶：不依赖任何转发头，任何单一 TCP 对端
// 连续失败达到 AccessTokenPeerMaxFails 次必定锁定；逐次更换（伪造的）客户端键也绕不过。
func TestAccessTokenPeerBucketLockout(t *testing.T) {
	const peer = "198.51.100.40"
	reset := func() {
		atFailsMu.Lock()
		delete(atPeerFails, peer)
		for k := range atClientFails {
			if strings.HasPrefix(k, peer+"|") {
				delete(atClientFails, k)
			}
		}
		atFailsMu.Unlock()
	}
	reset()
	defer reset()

	for i := 0; i < AccessTokenPeerMaxFails; i++ {
		// 每次换一个不同的客户端键：细分桶各自只累计 1 次，不会提前锁定
		RecordAccessTokenFailure(peer, "forged-client-"+itoa(i))
		if i < AccessTokenPeerMaxFails-1 && AccessTokenLockRemainingMs(peer, "") != 0 {
			t.Fatalf("第 %d 次失败前不应处于锁定态", i+1)
		}
	}
	if AccessTokenLockRemainingMs(peer, "") <= 0 {
		t.Fatalf("绝对桶连续失败 %d 次后应锁定", AccessTokenPeerMaxFails)
	}
	// 锁定后即使换一个新的客户端键也应被拦截（绝对桶已失效）
	if AccessTokenLockRemainingMs(peer, "another-client") <= 0 {
		t.Fatal("绝对桶锁定后任意客户端键均应被拦截")
	}
}
