package proxy

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 静态站点发布（mode=STATIC）：路径防护与交付语义的回归测试。
// 纯文件系统 + httptest，不依赖 SQLite/网络，可在无 cgo 环境运行。

// newStaticSite 构造一个指向 dir 的静态站点（Advanced 用默认值，按需覆写 Static 选项）。
func newStaticSite(t *testing.T, dir string, tweak func(*Advanced)) *Site {
	t.Helper()
	root, err := staticRootDir(filepath.ToSlash(dir), true)
	if err != nil {
		t.Fatalf("站点目录解析失败: %v", err)
	}
	adv := defaults()
	if tweak != nil {
		tweak(adv)
	}
	return &Site{ID: 1, Name: "static", Mode: ModeStatic, RootDir: root, Adv: adv, Enabled: true}
}

// writeFile 在站点目录内写文件（自动创建父目录）。
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
}

// doStatic 发起一次静态站点请求（accept 为空表示不设置 Accept 头）。
func doStatic(site *Site, method, target, accept string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	p := r.URL.Path
	q := r.URL.RawQuery
	serveStatic(w, r, site, p, q, statsFor(site.ID))
	return w
}

// TestStaticRootDir 站点目录必须为绝对路径且保存时要求存在。
func TestStaticRootDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := staticRootDir(filepath.ToSlash(dir)+"/", true); err != nil {
		t.Fatalf("合法绝对目录被拒绝: %v", err)
	}
	if _, err := staticRootDir("relative/site", true); err == nil {
		t.Fatalf("相对路径应被拒绝")
	}
	if _, err := staticRootDir("", true); err == nil {
		t.Fatalf("空目录应被拒绝")
	}
	if _, err := staticRootDir(filepath.ToSlash(dir)+"/nope", true); err == nil {
		t.Fatalf("不存在的目录应被拒绝")
	}
	// 加载期（checkExists=false）允许目录暂不存在：站点保留在路由表，请求期给出可读错误
	if _, err := staticRootDir(filepath.ToSlash(dir)+"/later", false); err != nil {
		t.Fatalf("加载期不应要求目录存在: %v", err)
	}
}

// TestStaticJoinTraversal 逐段校验：上跳段、隐藏名、盘符与反斜杠一律拒绝。
func TestStaticJoinTraversal(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	cases := []struct {
		rel  string
		want bool
	}{
		{"", true},
		{"index.html", true},
		{"assets/css/app.css", true},
		{"a/./b", true},
		{".well-known/acme-challenge/token", true},
		{"..", false},
		{"../etc/passwd", false},
		{"a/../../b", false},
		{".git/config", false},
		{".env", false},
		{"a/.htpasswd", false},
		{"C:/Windows/win.ini", false},
		{`a\b`, false},
	}
	for _, c := range cases {
		got, ok := staticJoin(root, c.rel)
		if ok != c.want {
			t.Fatalf("staticJoin(%q) ok=%v，期望 %v（结果 %q）", c.rel, ok, c.want, got)
		}
		if ok && !strings.HasPrefix(filepath.ToSlash(got), root) {
			t.Fatalf("staticJoin(%q)=%q 越出了站点目录 %q", c.rel, got, root)
		}
	}
}

// TestStaticRelPath 路径前缀剥离与重写（与回源路径改写同语义）。
func TestStaticRelPath(t *testing.T) {
	strip, from, to := "/portal", "/app", "/site"
	cases := []struct {
		name string
		adv  *Advanced
		in   string
		want string
	}{
		{"无改写", defaults(), "/a/b.js", "a/b.js"},
		{"根路径", defaults(), "/", ""},
		{"stripPrefix 命中", &Advanced{StripPrefix: &strip}, "/portal/a.js", "a.js"},
		{"stripPrefix 落根", &Advanced{StripPrefix: &strip}, "/portal", ""},
		{"stripPrefix 未命中", &Advanced{StripPrefix: &strip}, "/other/a.js", "other/a.js"},
		{"pathRewrite 命中", &Advanced{PathRewriteFrom: &from, PathRewriteTo: &to}, "/app/x.js", "site/x.js"},
	}
	for _, c := range cases {
		s := &Site{Adv: c.adv}
		if got := staticRelPath(s, c.in); got != c.want {
			t.Fatalf("%s：staticRelPath(%q)=%q，期望 %q", c.name, c.in, got, c.want)
		}
	}
}

// TestServeStaticBasic 文件交付：首页、目录补斜杠、404、非 GET 方法。
func TestServeStaticBasic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<h1>home</h1>")
	writeFile(t, dir, "assets/app.css", "body{color:red}")
	os.MkdirAll(filepath.Join(dir, "docs"), 0o755)
	site := newStaticSite(t, dir, nil)

	if w := doStatic(site, "GET", "/", "text/html"); w.Code != 200 || !strings.Contains(w.Body.String(), "home") {
		t.Fatalf("首页请求应命中 index.html，实际 code=%d body=%q", w.Code, w.Body.String())
	}
	w := doStatic(site, "GET", "/assets/app.css", "")
	if w.Code != 200 || w.Body.String() != "body{color:red}" {
		t.Fatalf("静态资源交付失败: code=%d body=%q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type 应按扩展名判定，实际 %q", ct)
	}
	// 目录缺少尾斜杠：301 到带斜杠形态（相对链接才不会解析错）
	if w := doStatic(site, "GET", "/docs", ""); w.Code != 301 || w.Header().Get("Location") != "/docs/" {
		t.Fatalf("目录应 301 补斜杠，实际 code=%d loc=%q", w.Code, w.Header().Get("Location"))
	}
	// 无首页文件且未开目录浏览：404
	if w := doStatic(site, "GET", "/docs/", "text/html"); w.Code != 404 {
		t.Fatalf("无首页的空目录应 404，实际 %d", w.Code)
	}
	if w := doStatic(site, "GET", "/missing.html", ""); w.Code != 404 {
		t.Fatalf("缺失文件应 404，实际 %d", w.Code)
	}
	if w := doStatic(site, "POST", "/index.html", ""); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("非 GET/HEAD 应 405 + Allow，实际 code=%d allow=%q", w.Code, w.Header().Get("Allow"))
	}
	// 隐藏文件不对外（.env 常见于误把站点根指到工程目录）
	writeFile(t, dir, ".env", "SECRET=1")
	if w := doStatic(site, "GET", "/.env", ""); w.Code != 404 {
		t.Fatalf("隐藏文件应 404，实际 %d", w.Code)
	}
	// .well-known 例外放行
	writeFile(t, dir, ".well-known/security.txt", "Contact: mailto:a@b.c")
	if w := doStatic(site, "GET", "/.well-known/security.txt", ""); w.Code != 200 {
		t.Fatalf(".well-known 应放行，实际 %d", w.Code)
	}
}

// TestServeStaticSPAFallback SPA 回退只对页面请求生效，资源请求仍 404。
func TestServeStaticSPAFallback(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<app-root>")
	site := newStaticSite(t, dir, func(a *Advanced) { a.Static.SPAFallback = true })

	w := doStatic(site, "GET", "/user/42", "text/html,application/xhtml+xml")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "app-root") {
		t.Fatalf("SPA 页面请求应回退首页，实际 code=%d body=%q", w.Code, w.Body.String())
	}
	if w := doStatic(site, "GET", "/api/missing.json", "*/*"); w.Code != 404 {
		t.Fatalf("非页面请求不应回退首页，实际 %d", w.Code)
	}
}

// TestServeStaticEncodingAndRange 预压缩变体与 Range 交付。
func TestServeStaticEncodingAndRange(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", strings.Repeat("var a=1;\n", 100))
	writeFile(t, dir, "app.js.br", "BROTLI")
	site := newStaticSite(t, dir, nil)

	r := httptest.NewRequest("GET", "/app.js", nil)
	r.Header.Set("Accept-Encoding", "gzip, br")
	w := httptest.NewRecorder()
	serveStatic(w, r, site, r.URL.Path, "", statsFor(site.ID))
	if w.Header().Get("Content-Encoding") != "br" || w.Body.String() != "BROTLI" {
		t.Fatalf(".br 变体应优先交付，实际 enc=%q body=%q", w.Header().Get("Content-Encoding"), w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("预压缩响应应带 Vary: Accept-Encoding，实际 %q", w.Header().Get("Vary"))
	}

	// 未声明压缩能力：交付原文件
	r2 := httptest.NewRequest("GET", "/app.js", nil)
	w2 := httptest.NewRecorder()
	serveStatic(w2, r2, site, r2.URL.Path, "", statsFor(site.ID))
	if enc := w2.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("未声明 Accept-Encoding 不应压缩，实际 %q", enc)
	}

	// Range：206 + 片段
	r3 := httptest.NewRequest("GET", "/app.js", nil)
	r3.Header.Set("Range", "bytes=0-8")
	w3 := httptest.NewRecorder()
	serveStatic(w3, r3, site, r3.URL.Path, "", statsFor(site.ID))
	if w3.Code != 206 || w3.Body.String() != "var a=1;\n" {
		t.Fatalf("Range 请求应 206 返回首行，实际 code=%d body=%q", w3.Code, w3.Body.String())
	}
}

// TestServeStaticListing 目录浏览：仅列出非隐藏项，目录带尾斜杠。
func TestServeStaticListing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "a")
	writeFile(t, dir, ".hidden", "x")
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	site := newStaticSite(t, dir, func(a *Advanced) { a.Static.DirListing = true; a.Static.IndexFiles = []string{} })

	w := doStatic(site, "GET", "/", "text/html")
	if w.Code != 200 {
		t.Fatalf("开启目录浏览后应 200，实际 %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "a.txt") || !strings.Contains(body, `href="sub/"`) {
		t.Fatalf("目录列表应包含文件与目录（目录带尾斜杠），实际 body=%q", body)
	}
	if strings.Contains(body, ".hidden") {
		t.Fatalf("目录列表不应显示隐藏文件，实际 body=%q", body)
	}
}

// TestServeStaticRootMissing 站点目录在运行期消失：503 + 可读原因（而不是静默 404）。
func TestServeStaticRootMissing(t *testing.T) {
	dir := t.TempDir()
	site := newStaticSite(t, dir, nil)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("删除站点目录失败: %v", err)
	}
	if w := doStatic(site, "GET", "/", "text/html"); w.Code != 503 {
		t.Fatalf("站点目录不可用应 503，实际 %d", w.Code)
	}
}

// TestStaticWithin 包含性判定（符号链接逃逸的最终闸门）。
func TestStaticWithin(t *testing.T) {
	root := filepath.Clean(filepath.Join(t.TempDir(), "root"))
	if !staticWithin(root, root) {
		t.Fatalf("根自身应判定在内")
	}
	if !staticWithin(root, filepath.Join(root, "a", "b.txt")) {
		t.Fatalf("子路径应判定在内")
	}
	if staticWithin(root, filepath.Dir(root)) {
		t.Fatalf("父目录必须判定在外")
	}
	if staticWithin(root, filepath.Join(root, "..", "x")) {
		t.Fatalf("上跳后的路径必须判定在外")
	}
}

// TestRealPath 符号链接解析：逃逸到站点目录外的软链必须被 staticWithin 拦住。
func TestRealPath(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "www")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	link := filepath.Join(root, "leak")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("当前环境不支持创建符号链接（Windows 需管理员/开发者模式）: %v", err)
	}
	if staticWithin(realPath(root), realPath(link)) {
		t.Fatalf("指向站点目录外的软链应判定越界")
	}
}
