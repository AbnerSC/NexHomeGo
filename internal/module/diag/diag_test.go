package diag

import "testing"

// TestBytesToMB 守住 MB 口径：1 MB 必须是 1048576 字节。
// 历史缺陷：除数误用 104857.6（少一位），使前端读数放大 10 倍——
// 142 MiB 的进程 RSS 会显示成 1.39 GB，看上去超过了容器的 512 MB 上限。
func TestBytesToMB(t *testing.T) {
	cases := []struct {
		in   int64
		want float64
	}{
		{0, 0},
		{1048576, 1},            // 1 MiB
		{512 << 20, 512},        // 512 MiB：容器上限
		{149317632, 142.4},      // 142.4 MiB：旧口径会显示 1424 MB（前端渲染为 1.39 GB）
		{536870912 / 1024, 0.5}, // 512 KiB
		{-1, -1},                // 不可读保持 -1
	}
	for _, c := range cases {
		if got := bytesToMB(c.in); got != c.want {
			t.Fatalf("bytesToMB(%d) = %v, want %v", c.in, got, c.want)
		}
	}
}
