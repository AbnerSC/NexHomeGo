package stun

import (
	"testing"
	"time"
)

// TestInstallEndpointLinkNotifiesReady 回归：端点链路登记的每个成功分支都必须回调 onReady。
// 只有映射地址变化才回调，会让运行器的「TCP映射已建立」标志在链路重建后永久停在 false，
// 自检持续误报 FAIL（外网端口实际仍可访问）。
func TestInstallEndpointLinkNotifiesReady(t *testing.T) {
	p := &punch{
		singleTx:        map[string]bool{},
		warnedEndpoints: map[string]bool{},
		probeFailAt:     time.Now().UnixMilli(), // 退避期内：不触发 STUN 短连接探测（测试不依赖网络）
	}
	notified := 0
	p.onReady = func(l *punchLink) { notified++ }

	// 分支1：首次端点链路、无历史精确映射 => 端口保留模式，必须回调并标记估计地址语义
	first := &punchLink{endpoint: "1.1.1.1:443"}
	if got := p.installEndpointLink(first, 0); got != first {
		t.Fatalf("端口保留分支应登记传入链路, got %+v", got)
	}
	if notified != 1 || !p.addrPresumed || p.current != first {
		t.Fatalf("端口保留分支必须回调就绪: notified=%d presumed=%v", notified, p.addrPresumed)
	}

	// 分支2：曾取得精确映射且探测不可用 => 保留旧映射（地址未变），同样必须回调
	p.lastSplitMapped = "2.2.2.2:3333"
	p.addrPresumed = true
	second := &punchLink{endpoint: "1.1.1.1:443"}
	got := p.installEndpointLink(second, 0)
	if got == nil || !got.viaStun || !got.split {
		t.Fatalf("应保留历史精确映射并登记为双链路, got %+v", got)
	}
	if got.mapped != "2.2.2.2:3333" {
		t.Fatalf("应保留历史映射地址, got %q", got.mapped)
	}
	if notified != 2 || p.addrPresumed {
		t.Fatalf("保留旧映射分支必须回调就绪: notified=%d presumed=%v", notified, p.addrPresumed)
	}
}

// TestLinkAliveNowWithoutLink 无当前链路时不应判存活（自检据此校正「映射未建立」标志）
func TestLinkAliveNowWithoutLink(t *testing.T) {
	p := &punch{}
	if p.linkAliveNow() {
		t.Fatal("无当前链路时不应判为存活")
	}
}
