package proxy

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// writeZip 生成测试用压缩包：条目名 → 内容（以 / 结尾的条目写为空目录）。
func writeZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "site.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("创建 zip: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, werr := zw.Create(name)
		if werr != nil {
			t.Fatalf("写入条目 %s: %v", name, werr)
		}
		if _, werr := w.Write([]byte(body)); werr != nil {
			t.Fatalf("写入内容 %s: %v", name, werr)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭文件: %v", err)
	}
	return p
}

func TestZipEntryRel(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		prefix string
		want   string
		skip   bool
		fail   bool
	}{
		{name: "普通文件", raw: "index.html", want: "index.html"},
		{name: "剥离顶层目录", raw: "dist/assets/app.js", prefix: "dist", want: "assets/app.js"},
		{name: "目录条目", raw: "assets/", want: "assets"},
		{name: "反斜杠归一", raw: `assets\app.js`, want: "assets/app.js"},
		{name: "上跳路径", raw: "../etc/passwd", fail: true},
		{name: "中间上跳路径", raw: "a/../../b.txt", fail: true},
		{name: "绝对路径", raw: "/etc/passwd", fail: true},
		{name: "盘符路径", raw: `C:/windows/win.ini`, fail: true},
		{name: "控制字符", raw: "a\x01b.txt", fail: true},
		{name: "macOS 垃圾", raw: "__MACOSX/._index.html", skip: true},
		{name: "DS_Store", raw: "assets/.DS_Store", skip: true},
		{name: "空条目", raw: "", skip: true},
		{name: "剥离后为空", raw: "dist", prefix: "dist", skip: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, skip, err := zipEntryRel(tc.raw, tc.prefix)
			if tc.fail {
				if err == nil {
					t.Fatalf("%q 应被拒绝，实际得到 %q", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q 不应报错: %v", tc.raw, err)
			}
			if skip != tc.skip {
				t.Fatalf("%q skip=%v，期望 %v", tc.raw, skip, tc.skip)
			}
			if !tc.skip && got != tc.want {
				t.Fatalf("%q → %q，期望 %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestZipCommonPrefix(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  string
	}{
		{name: "统一顶层目录", names: []string{"dist/index.html", "dist/a/b.css", "dist/"}, want: "dist"},
		{name: "根级文件不剥离", names: []string{"index.html", "dist/a.css"}, want: ""},
		{name: "多个顶层目录不剥离", names: []string{"a/x.html", "b/y.html"}, want: ""},
		{name: "忽略打包垃圾", names: []string{"site/index.html", "__MACOSX/._x", ".DS_Store"}, want: "site"},
		{name: "空包", names: nil, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var files []*zip.File
			for _, n := range tc.names {
				files = append(files, &zip.File{FileHeader: zip.FileHeader{Name: n}})
			}
			if got := zipCommonPrefix(files); got != tc.want {
				t.Fatalf("prefix=%q，期望 %q", got, tc.want)
			}
		})
	}
}

// TestUnzipIntoStripsPrefix 压缩包里包一层 dist 目录时，解压结果应直接落在站点根。
func TestUnzipIntoStripsPrefix(t *testing.T) {
	zipPath := writeZip(t, map[string]string{
		"dist/index.html":     "<h1>hi</h1>",
		"dist/assets/app.css": "body{}",
		"__MACOSX/._stub":     "junk",
		".DS_Store":           "junk",
	})
	dest := filepath.Join(t.TempDir(), "site")
	st, err := unzipInto(zipPath, dest, defaultZipLimits)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if st.Files != 2 {
		t.Fatalf("应解出 2 个文件，got %d", st.Files)
	}
	if _, err := os.Stat(filepath.Join(dest, "index.html")); err != nil {
		t.Fatalf("index.html 应位于站点根: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "assets", "app.css")); err != nil {
		t.Fatalf("assets/app.css 应位于站点根: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "dist")); !os.IsNotExist(err) {
		t.Fatal("顶层目录应被剥离，不应留下 dist 目录")
	}
	for _, junk := range []string{".DS_Store", "__MACOSX"} {
		if _, err := os.Stat(filepath.Join(dest, junk)); !os.IsNotExist(err) {
			t.Fatalf("%s 应被跳过", junk)
		}
	}
}

// TestUnzipIntoRejectsUnsafeEntries zip-slip：上跳段、绝对路径、符号链接一律拒绝且不落盘。
func TestUnzipIntoRejectsUnsafeEntries(t *testing.T) {
	t.Run("上跳路径", func(t *testing.T) {
		base := t.TempDir()
		dest := filepath.Join(base, "site")
		zipPath := writeZip(t, map[string]string{"../escape.txt": "x"})
		if _, err := unzipInto(zipPath, dest, defaultZipLimits); err == nil {
			t.Fatal("包含 .. 的压缩包应被拒绝")
		}
		if _, err := os.Stat(filepath.Join(base, "escape.txt")); !os.IsNotExist(err) {
			t.Fatal("越界文件不应被写出")
		}
	})
	t.Run("绝对路径", func(t *testing.T) {
		zipPath := writeZip(t, map[string]string{"/etc/nexhome-test.txt": "x"})
		if _, err := unzipInto(zipPath, filepath.Join(t.TempDir(), "site"), defaultZipLimits); err == nil {
			t.Fatal("绝对路径条目应被拒绝")
		}
	})
	t.Run("符号链接", func(t *testing.T) {
		zipPath := filepath.Join(t.TempDir(), "link.zip")
		f, err := os.Create(zipPath)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		h := &zip.FileHeader{Name: "escape"}
		h.SetMode(os.ModeSymlink | 0o777)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("/etc/passwd")); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := unzipInto(zipPath, filepath.Join(t.TempDir(), "site"), defaultZipLimits); err == nil {
			t.Fatal("符号链接条目应被拒绝")
		}
	})
}

// TestUnzipIntoFileLimit 文件数超限即中止（zip bomb 防护）。
func TestUnzipIntoFileLimit(t *testing.T) {
	zipPath := writeZip(t, map[string]string{"a.txt": "1", "b.txt": "2", "c.txt": "3"})
	_, err := unzipInto(zipPath, filepath.Join(t.TempDir(), "site"),
		zipLimits{MaxFiles: 2, MaxBytes: 1 << 20, MaxFile: 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "文件数超过上限") {
		t.Fatalf("应因文件数超限报错，got %v", err)
	}
}

// TestUnzipIntoKeepsExistingFiles 同名覆盖、其余保留（增量发布语义）。
func TestUnzipIntoKeepsExistingFiles(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "site")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "old.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "index.html"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipPath := writeZip(t, map[string]string{"index.html": "new"})
	if _, err := unzipInto(zipPath, dest, defaultZipLimits); err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "index.html")); string(b) != "new" {
		t.Fatalf("同名文件应被覆盖，got %q", string(b))
	}
	if _, err := os.Stat(filepath.Join(dest, "old.txt")); err != nil {
		t.Fatal("既有文件应保留")
	}
}

// TestUploadTempPath 上传凭据必须是 32 位小写 hex，且路径解析结果落在 temp 目录内。
func TestUploadTempPath(t *testing.T) {
	setupTestDB(t)
	good := strings.Repeat("0123456789abcdef", 2)
	p, ok := uploadTempPath(good)
	if !ok {
		t.Fatal("合法凭据应通过")
	}
	if filepath.Dir(p) != htmlTempRoot() {
		t.Fatalf("临时包应落在 %s，got %s", htmlTempRoot(), p)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("A", 32), "../" + good,
		good + "/../../etc/passwd", strings.Repeat("g", 32)} {
		if _, ok := uploadTempPath(bad); ok {
			t.Fatalf("非法凭据应被拒绝: %q", bad)
		}
	}
}

// TestResolveStaticSiteDir 留空 → data/html/{id} 且自动创建；自填目录原样规范化。
func TestResolveStaticSiteDir(t *testing.T) {
	setupTestDB(t)
	const id int64 = 42

	def, err := resolveStaticSiteDir(id, "")
	if err != nil {
		t.Fatalf("默认目录解析失败: %v", err)
	}
	want := filepath.ToSlash(filepath.Join(core.DataDir(), "html", "42"))
	if def != want {
		t.Fatalf("默认目录 = %s，期望 %s", def, want)
	}
	if st, err := os.Stat(filepath.FromSlash(def)); err != nil || !st.IsDir() {
		t.Fatalf("默认目录应已自动创建: %v", err)
	}

	custom := t.TempDir()
	got, err := resolveStaticSiteDir(id, filepath.ToSlash(custom))
	if err != nil {
		t.Fatalf("自填目录解析失败: %v", err)
	}
	if got != filepath.ToSlash(custom) {
		t.Fatalf("自填目录 = %s，期望 %s", got, filepath.ToSlash(custom))
	}
	if _, err := resolveStaticSiteDir(id, filepath.Join(custom, "missing")); err == nil {
		t.Fatal("不存在的自填目录应报错")
	}
}

// TestRemoveDefaultSiteDir 只清理默认目录；自填目录一律不动（可能是只读挂载或共享目录）。
func TestRemoveDefaultSiteDir(t *testing.T) {
	setupTestDB(t)
	const id int64 = 7

	def, err := defaultSiteDir(id)
	if err != nil {
		t.Fatalf("创建默认目录: %v", err)
	}
	if err := os.WriteFile(filepath.Join(filepath.FromSlash(def), "index.html"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	removeDefaultSiteDir(id, def)
	if _, err := os.Stat(filepath.FromSlash(def)); !os.IsNotExist(err) {
		t.Fatal("默认目录应被递归删除")
	}

	custom := t.TempDir()
	keep := filepath.Join(custom, "index.html")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	removeDefaultSiteDir(id, filepath.ToSlash(custom))
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("自填目录不应被删除")
	}
}

// TestApplyUploadUnzipsAndDeletesZip 保存时解压到站点目录，压缩包无论成败都不保留。
func TestApplyUploadUnzipsAndDeletesZip(t *testing.T) {
	setupTestDB(t)
	if err := ensureHtmlDirs(); err != nil {
		t.Fatalf("初始化目录: %v", err)
	}
	token := strings.Repeat("ab", 16)
	zipPath, ok := uploadTempPath(token)
	if !ok {
		t.Fatal("凭据应合法")
	}
	src := writeZip(t, map[string]string{"www/index.html": "<h1>ok</h1>"})
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "site")
	if err := applyUpload(token, dest, "测试站点"); err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if _, err := os.Stat(zipPath); !os.IsNotExist(err) {
		t.Fatal("解压后应删除临时压缩包")
	}
	if b, err := os.ReadFile(filepath.Join(dest, "index.html")); err != nil || string(b) != "<h1>ok</h1>" {
		t.Fatalf("解压结果不正确: %v %q", err, string(b))
	}

	// 凭据不存在：报错且不产生副作用
	if err := applyUpload(strings.Repeat("cd", 16), dest, "测试站点"); err == nil {
		t.Fatal("缺失压缩包应报错")
	}
}
