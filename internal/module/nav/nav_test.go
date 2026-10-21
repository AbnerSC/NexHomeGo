package nav

import (
	"path/filepath"
	"testing"
)

func TestNewUUIDMatchesIconName(t *testing.T) {
	name := newUUID() + ".png"
	if !iconNameRe.MatchString(name) {
		t.Fatalf("生成的图标名不符合白名单: %q", name)
	}
}

func TestExtOf(t *testing.T) {
	if extOf("icon.PNG") != "png" || extOf("noext") != "" || extOf("a.b.svg") != "svg" {
		t.Fatal("extOf 结果不符")
	}
}

func TestImgNameRe(t *testing.T) {
	ok := []string{"bg.png", "我的图片-1.jpg", "a.b_c.jpeg", "logo.svg", "f.webp"}
	for _, s := range ok {
		if !imgNameRe.MatchString(s) {
			t.Errorf("应通过: %q", s)
		}
	}
	bad := []string{"../etc/passwd", "a/b.png", ".hidden", "noext", "x.exe", "", "logo.SVG", "f.WebP"}
	for _, s := range bad {
		if imgNameRe.MatchString(s) {
			t.Errorf("应拒绝: %q", s)
		}
	}
}

func TestWithinDir(t *testing.T) {
	base := filepath.Join("data", "nav-icons")
	if !withinDir(filepath.Join(base, "x.png"), base) {
		t.Error("正常文件名应判定在目录内")
	}
	if withinDir(filepath.Join(base, "..", "..", "evil"), base) {
		t.Error("穿越路径应判定在目录外")
	}
}
