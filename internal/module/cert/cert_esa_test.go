package cert

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestTxtChannelsPriority 凭证配置填了 ESA 站点时 ESA 优先，否则只走云解析。
// 选择顺序直接决定 TXT 写到哪个通道：域名托管在 ESA 时写云解析不会生效。
func TestTxtChannelsPriority(t *testing.T) {
	dnsOnly := txtChannels(&dnsCred{ak: "ak", sk: "sk"})
	if len(dnsOnly) != 1 || dnsOnly[0].name != "阿里云云解析" {
		t.Fatalf("未配置 ESA 站点应只走云解析: %+v", dnsOnly)
	}
	withESA := txtChannels(&dnsCred{ak: "ak", sk: "sk", esaSiteId: "555"})
	if len(withESA) != 2 || withESA[0].name != "阿里云ESA" || withESA[1].name != "阿里云云解析" {
		t.Fatalf("配置 ESA 站点后 ESA 应优先: %+v", withESA)
	}
}

// TestEsaHasTxt 统一按 ESA 返回字段（RecordType / RecordName / Data.Value）判同名同值。
// 旧实现读取 "Type"（云解析字段名），导致复用永远失败、每次重试都新增一条同名 TXT。
func TestEsaHasTxt(t *testing.T) {
	name, value := "_acme-challenge.edge.example.com", "digest-a"
	records := []map[string]interface{}{
		{"RecordName": name, "RecordType": "TXT", "Data": map[string]interface{}{"Value": "digest-old"}},
		{"RecordName": "other.example.com", "RecordType": "TXT", "Data": map[string]interface{}{"Value": value}},
		{"RecordName": name, "RecordType": "A/AAAA", "Data": map[string]interface{}{"Value": value}},
	}
	if esaHasTxt(records, name, value) {
		t.Fatal("不同名/不同值/不同类型都不应算命中")
	}
	records = append(records, map[string]interface{}{
		"RecordName": name, "RecordType": "TXT", "Data": map[string]interface{}{"Value": value},
	})
	if !esaHasTxt(records, name, value) {
		t.Fatal("同名同值 TXT 应命中复用")
	}
}

func TestWaitTxtPropagated(t *testing.T) {
	setupTestDB(t)
	oldLook, oldZone := lookupTXTFromFunc, zoneNSFunc
	oldTimeout, oldInterval, oldSettle := txtPropagateTimeout, txtPropagateInterval, txtPropagateSettle
	t.Cleanup(func() {
		lookupTXTFromFunc, zoneNSFunc = oldLook, oldZone
		txtPropagateTimeout, txtPropagateInterval, txtPropagateSettle = oldTimeout, oldInterval, oldSettle
	})
	txtPropagateSettle = 0 // 静默期在单测里无意义，避免每条用例白等 10s
	txtPropagateTimeout, txtPropagateInterval = 120*time.Millisecond, 5*time.Millisecond

	const name, value = "_acme-challenge.edge.example.com", "digest-a"
	auth := &zoneAuth{zone: "example.com", hosts: []string{"ns1.example.com", "ns2.example.com"},
		servers: []string{"1.1.1.1:53", "2.2.2.2:53"}}
	zoneNSFunc = func(string) (*zoneAuth, error) { return auth, nil }

	// 1) 全部权威都返回期望值：连续确认后通过
	lookupTXTFromFunc = func(string, string) ([]string, error) { return []string{"digest-old", value}, nil }
	if err := waitTxtPropagated(name, value); err != nil {
		t.Fatalf("权威全部命中应通过: %v", err)
	}

	// 2) 权威明确无记录：超时后报未生效（此时触发 CA 校验必然失败）
	lookupTXTFromFunc = func(_, n string) ([]string, error) {
		return nil, &net.DNSError{IsNotFound: true, Err: "no such host", Name: n}
	}
	if err := waitTxtPropagated(name, value); err == nil {
		t.Fatal("权威无记录应报未生效")
	}

	// 3) 只有部分权威节点能看到（secondary validation 失败的典型形态）：不能算生效
	lookupTXTFromFunc = func(server, _ string) ([]string, error) {
		if server == auth.servers[0] {
			return []string{value}, nil
		}
		return nil, &net.DNSError{IsNotFound: true, Err: "no such host"}
	}
	if err := waitTxtPropagated(name, value); err == nil {
		t.Fatal("只有部分权威节点可见不应算生效")
	}

	// 4) 探测能力不可用（DNS 不通）：连续失败后放行，不能因此阻断签发
	fails := 0
	lookupTXTFromFunc = func(string, string) ([]string, error) {
		fails++
		return nil, errors.New("dial udp 1.1.1.1:53: i/o timeout")
	}
	if err := waitTxtPropagated(name, value); err != nil {
		t.Fatalf("探测不可用应放行: %v", err)
	}
	if fails < 2 {
		t.Fatalf("应连续探测失败后才放行, fails=%d", fails)
	}

	// 5) 拿不到权威清单时退回公共递归：递归命中即放行
	zoneNSFunc = func(string) (*zoneAuth, error) { return nil, errors.New("no ns") }
	lookupTXTFromFunc = func(string, string) ([]string, error) { return []string{value}, nil }
	if err := waitTxtPropagated(name, value); err != nil {
		t.Fatalf("权威不可用时递归命中应放行: %v", err)
	}
}

// TestChallengeFailureDetail CA 只在 challenge.error 里给出真正原因，报错需带上详情。
func TestChallengeFailureDetail(t *testing.T) {
	if got := problemText("urn:ietf:params:acme:error:unauthorized", "No TXT record found"); got != "unauthorized: No TXT record found" {
		t.Fatalf("problemText=%q", got)
	}
	if got := problemText("", "only detail"); got != "only detail" {
		t.Fatalf("problemText=%q", got)
	}
	a := &acmeAuth{Domain: "edge.example.com", Status: "invalid", Challenges: []acmeChallenge{
		{Type: "http-01"},
		{Type: "dns-01", Err: "unauthorized: Incorrect TXT record"},
	}}
	if got := a.challengeFailure(); got != "unauthorized: Incorrect TXT record" {
		t.Fatalf("challengeFailure=%q", got)
	}
	if got := (&acmeAuth{}).challengeFailure(); got != "" {
		t.Fatalf("无详情应为空: %q", got)
	}
}
