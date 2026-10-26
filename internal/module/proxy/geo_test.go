package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"NexHomeGo/internal/core"
)

// TestGeoLoadFromEmbedWithoutDump 归属地库直接从内置资源读取的关键约束：
// 只把 512KB 向量索引读进内存，正文不复制到数据目录（不落盘），
// 且不再识别 data 根目录下的同名外置库（用户要求只认内置库）。
func TestGeoLoadFromEmbedWithoutDump(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := core.InitPaths(); err != nil {
		t.Fatalf("InitPaths: %v", err)
	}
	// 外置库已不支持：即便 data 根目录放同名脏文件，也必须被忽略
	if err := os.MkdirAll(core.DataDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	bogus := filepath.Join(core.DataDir(), "ip2region_v4.xdb")
	if err := os.WriteFile(bogus, []byte("bogus"), 0o644); err != nil {
		t.Fatal(err)
	}

	geoLoad()
	t.Cleanup(func() {
		geoClose()
		geoMu.Lock()
		geoCache = map[string]*Region{}
		geoCached = 0
		geoMu.Unlock()
	})

	if geoV4 == nil || geoV6 == nil {
		t.Fatal("内置 v4/v6 库应成功打开（data 根目录的脏文件不应参与加载）")
	}

	// 不落盘：数据目录里除测试自建的 bogus 外，不应出现任何 xdb 副本
	_ = filepath.WalkDir(core.DataDir(), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".xdb" || p == bogus {
			return nil
		}
		t.Errorf("内置库不应复制到数据目录: %s", p)
		return nil
	})

	// 索引常驻（512KB/侧）替代整库缓冲（10.6MB + 35.6MB），检索口径不变
	if r := geoRegionOf("8.8.8.8"); r == nil || r.Country == "" {
		t.Fatalf("公网 IPv4 应解析出归属地，got %+v", r)
	}
	if r := geoRegionOf("114.114.114.114"); r == nil || r.Country != "中国" {
		t.Fatalf("国内 IPv4 应解析为中国，got %+v", r)
	}
	if r := geoRegionOf("192.168.1.10"); r == nil || r.Country != "局域网" {
		t.Fatalf("内网地址应判定为局域网，got %+v", r)
	}

	// 关闭后可重新加载（句柄释放与重新打开都不依赖磁盘副本）
	geoClose()
	geoLoad()
	if geoV4 == nil || geoV6 == nil {
		t.Fatal("重新加载后应依然可用")
	}
	if r := geoRegionOf("1.1.1.1"); r == nil || r.Country == "" {
		t.Fatalf("重新加载后仍应解析，got %+v", r)
	}
}
