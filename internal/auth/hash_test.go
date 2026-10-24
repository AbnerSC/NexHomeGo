package auth

import "testing"

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

// TestFailureLockoutPerPeer 锁定按对端 IP 独立计数：达到上限后锁定，其它 IP 不受影响。
func TestFailureLockoutPerPeer(t *testing.T) {
	const victim, other = "198.51.100.20", "198.51.100.21"
	failsMu.Lock()
	delete(fails, victim)
	delete(fails, other)
	failsMu.Unlock()
	defer func() {
		failsMu.Lock()
		delete(fails, victim)
		delete(fails, other)
		failsMu.Unlock()
	}()

	max, _ := GetMaxFails()
	for i := 0; i < max; i++ {
		if LockRemainingMs(victim) != 0 {
			t.Fatalf("第 %d 次失败前不应处于锁定态", i+1)
		}
		recordFailure(victim)
	}
	if LockRemainingMs(victim) <= 0 {
		t.Fatalf("连续失败 %d 次后应进入锁定态", max)
	}
	if LockRemainingMs(other) != 0 {
		t.Fatal("锁定不得波及其它来源 IP")
	}
}
