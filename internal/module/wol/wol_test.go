package wol

import "testing"

func TestNormalizeMacs(t *testing.T) {
	cases := map[string]string{
		"00:11:22:33:44:55":              "00:11:22:33:44:55",
		"00-11-22-33-44-55":              "00:11:22:33:44:55",
		"001122334455":                   "00:11:22:33:44:55",
		"AA:BB:CC:DD:EE:FF":              "aa:bb:cc:dd:ee:ff",
		"001122334455;66-77-88-99-aa-bb": "00:11:22:33:44:55,66:77:88:99:aa:bb",
		"00:11:22:33:44:55 66778899aabb": "00:11:22:33:44:55,66:77:88:99:aa:bb",
	}
	for in, want := range cases {
		if got := normalizeMacs(in); got != want {
			t.Errorf("normalizeMacs(%q)=%q 期望=%q", in, got, want)
		}
	}
}

func TestMacListInvalid(t *testing.T) {
	bad := []string{"", "   ", "zz:11:22:33:44:55", "00:11:22:33:44", "00:11:22:33:44:55:66"}
	for _, in := range bad {
		if _, err := macListErr(in); err == nil {
			t.Errorf("macListErr(%q) 期望报错，实际通过", in)
		}
	}
}

func TestBuildMagicPacket(t *testing.T) {
	mac, err := parseMac("00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("parseMac 失败: %v", err)
	}
	p := buildMagicPacket(mac)
	if len(p) != 102 {
		t.Fatalf("魔术包长度=%d 期望 102", len(p))
	}
	for i := 0; i < 6; i++ {
		if p[i] != 0xFF {
			t.Fatalf("前导 6 字节应为 0xFF，第 %d 字节=%02X", i, p[i])
		}
	}
	for blk := 0; blk < 16; blk++ {
		for i := 0; i < 6; i++ {
			if p[6+blk*6+i] != mac[i] {
				t.Fatalf("第 %d 段 MAC 字节不符", blk)
			}
		}
	}
}

func TestParseMacBad(t *testing.T) {
	if _, err := parseMac("00:11:22"); err == nil {
		t.Fatal("非法 MAC 应报错")
	}
}
