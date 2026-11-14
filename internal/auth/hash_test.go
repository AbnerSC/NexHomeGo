package auth

import (
	"strconv"
	"testing"
)

// TestHashEqual 密码哈希比对：大小写/空白无关，长度或内容不同一律不等。
func TestHashEqual(t *testing.T) {
	h := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if !hashEqual(h, h) {
		t.Fatal("相同哈希应判定相等")
	}
	if !hashEqual("  "+h+"  ", h) {
		t.Fatal("两侧空白应被忽略")
	}
	if !hashEqual("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08", h) {
		t.Fatal("哈希为 hex，应大小写无关")
	}
	if hashEqual(h, "") {
		t.Fatal("空哈希不得判定相等")
	}
	if hashEqual(h, h[:63]) {
		t.Fatal("长度不同不得判定相等")
	}
	if hashEqual(h, h[:63]+"9") {
		t.Fatal("内容不同不得判定相等")
	}
}

// TestFailureLockoutPerPeer 细分桶按锁定键独立计数：达到上限后锁定，其它键不受影响。
func TestFailureLockoutPerPeer(t *testing.T) {
	const victim, other = "198.51.100.20", "198.51.100.21"
	failsMu.Lock()
	delete(fails, victim)
	delete(fails, other)
	failsMu.Unlock()
	peerFailsMu.Lock()
	delete(peerFails, victim)
	delete(peerFails, other)
	peerFailsMu.Unlock()
	defer func() {
		failsMu.Lock()
		delete(fails, victim)
		delete(fails, other)
		failsMu.Unlock()
		peerFailsMu.Lock()
		delete(peerFails, victim)
		delete(peerFails, other)
		peerFailsMu.Unlock()
	}()

	max, _ := GetMaxFails()
	for i := 0; i < max; i++ {
		if LockRemainingMs(victim, victim) != 0 {
			t.Fatalf("第 %d 次失败前不应处于锁定态", i+1)
		}
		recordFailure(victim, victim)
	}
	if LockRemainingMs(victim, victim) <= 0 {
		t.Fatalf("连续失败 %d 次后应进入锁定态", max)
	}
	if LockRemainingMs(other, other) != 0 {
		t.Fatal("锁定不得波及其它来源 IP")
	}
}

// TestFailureLockoutAbsoluteBucket 绝对桶（键=TCP 对端）兜底：细分键可被伪造转发头
// 逐次更换（已实测的登录锁定绕过），同一对端失败累计达 LoginPeerMaxFails 后，
// 换任意新细分键也必须整体锁定，且不得波及其它对端。
func TestFailureLockoutAbsoluteBucket(t *testing.T) {
	const peer = "203.0.113.77"
	peerFailsMu.Lock()
	delete(peerFails, peer)
	peerFailsMu.Unlock()
	defer func() {
		peerFailsMu.Lock()
		delete(peerFails, peer)
		peerFailsMu.Unlock()
	}()

	for i := 0; i < LoginPeerMaxFails; i++ {
		key := peer + "|spoofed-" + strconv.Itoa(i) // 每次换一个伪造客户端键
		recordFailure(key, peer)
	}
	if remain := LockRemainingMs(peer+"|fresh-spoof", peer); remain <= 0 {
		t.Fatal("绝对桶打满后，换新细分键也应处于锁定态（伪造转发头不可绕过）")
	}
	if LockRemainingMs(peer+"|fresh-spoof", "198.51.100.99") != 0 {
		t.Fatal("绝对桶不得波及其它对端")
	}
	failsMu.Lock()
	for i := 0; i < LoginPeerMaxFails; i++ {
		delete(fails, peer+"|spoofed-"+strconv.Itoa(i))
	}
	failsMu.Unlock()
}
