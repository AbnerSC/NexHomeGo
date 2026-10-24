package proxy

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// 静态站点发布（mode=STATIC）：代理不经任何后端，直接把站点目录中的文件对外提供，
// 用于发布纯静态网站（对齐 nginx 的 root/index/autoindex 组合能力）。
//
// 安全边界（逐条都有对应测试）：
//   - 路径逐段校验：".." 上跳段、隐藏名（.git/.env 等，仅放行 .well-known）、
//     Windows 盘符与反斜杠一律拒绝，绝不拼出站点目录之外的路径；
//   - 符号链接逃逸：命中文件按真实路径（EvalSymlinks）复核仍在站点目录内，否则 404；
//   - 只读：仅 GET / HEAD，其余方法 405（不提供上传/删除等任何写能力）。
// 其余访问控制（IP 白名单 / BasicAuth / 限流 / 强制 HTTPS）与反向代理站点完全共用，
// 由 handler.go 的统一链路在进入本文件前完成。

// 站点目录缺失时的提示（请求期探测到目录不可达）。
const staticRootHint = "请在「代理中心」检查该静态站点的目录是否存在、是否已挂载且面板进程可读。"

// serveStatic 静态站点请求处理入口（path 为已解码、以 / 开头的请求路径，query 不含 ?）。
func serveStatic(w http.ResponseWriter, r *http.Request, site *Site, urlPath, query string, st *siteStats) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		sendSimple(w, 405, "静态站点仅支持 GET / HEAD 请求", "", "", true)
		return
	}
	// 请求期复核目录：站点目录可能被卸载/改名，需要给出可读原因而不是静默 404
	root, err := staticRootDir(site.RootDir, true)
	if err != nil {
		noteError(site, "站点目录不可用: "+site.RootDir)
		sendErrorPage(w, 503, "站点目录不可用: "+site.RootDir, staticRootHint, true)
		return
	}
	rel := staticRelPath(site, urlPath)
	full, ok := staticJoin(root, rel)
	if !ok {
		staticNotFound(w, r, site, root, rel, st)
		return
	}
	info, err := os.Stat(full) // 跟随符号链接：真实路径随后复核
	if err != nil {
		staticNotFound(w, r, site, root, rel, st)
		return
	}
	// 符号链接逃逸：目录内的软链可能指向目录外（如 ../.ssh），真实路径必须仍在站点根内
	if !staticWithin(realPath(root), realPath(full)) {
		noteError(site, "拒绝符号链接逃逸: "+rel)
		staticNotFound(w, r, site, root, rel, st)
		return
	}

	if info.IsDir() {
		if !strings.HasSuffix(urlPath, "/") {
			// 目录补斜杠（相对链接才不会解析到父目录）：保留查询串
			loc := r.URL.EscapedPath() + "/"
			if query != "" {
				loc += "?" + query
			}
			sendSimple(w, 301, "跳转到 "+loc, "Location", loc, true)
			return
		}
		if file, fi, ok := staticIndexFile(full, site.Adv.Static.IndexFiles); ok {
			staticServeFile(w, r, site, file, filepath.Base(file), fi, st)
			return
		}
		if site.Adv.Static.DirListing {
			staticListing(w, full, urlPath)
			return
		}
		staticNotFound(w, r, site, root, rel, st)
		return
	}
	if !info.Mode().IsRegular() { // 设备/管道等特殊文件不对外
		staticNotFound(w, r, site, root, rel, st)
		return
	}
	staticServeFile(w, r, site, full, filepath.Base(full), info, st)
}

// staticNotFound 404 输出：开了 SPA 回退且是页面请求（Accept 含 text/html）时返回首页文件，
// 让 history 路由的前端应用（/user/1 这类虚拟路径）能正常刷新与直达。
func staticNotFound(w http.ResponseWriter, r *http.Request, site *Site, root, rel string, st *siteStats) {
	if site.Adv.Static.SPAFallback && wantsHTML(r) {
		if file, fi, ok := staticIndexFile(root, site.Adv.Static.IndexFiles); ok {
			staticServeFile(w, r, site, file, filepath.Base(file), fi, st)
			return
		}
	}
	hint := "静态站点只对外提供站点目录内的文件；请确认文件已上传，且路径大小写与磁盘一致（Linux 区分大小写）。"
	sendErrorPage(w, 404, "文件不存在: /"+rel, hint, true)
}

// staticRelPath 请求路径 -> 站点内相对路径（应用 stripPrefix / pathRewrite，语义同回源路径改写）。
func staticRelPath(site *Site, urlPath string) string {
	p := urlPath
	if a := site.Adv; a != nil {
		if a.StripPrefix != nil && strings.HasPrefix(p, *a.StripPrefix) {
			p = p[len(*a.StripPrefix):]
		} else if a.PathRewriteFrom != nil && strings.HasPrefix(p, *a.PathRewriteFrom) {
			p = *a.PathRewriteTo + p[len(*a.PathRewriteFrom):]
		}
	}
	for strings.HasPrefix(p, "/") {
		p = p[1:]
	}
	return p
}

// staticJoin 相对路径 -> 站点目录内的绝对路径；任一段非法即返回 false。
// 拒绝：空段外的 ".."、隐藏名（.git/.env，放行 .well-known）、盘符冒号、反斜杠与控制字符。
func staticJoin(root, rel string) (string, bool) {
	rootDir := filepath.FromSlash(root)
	if rel == "" {
		return rootDir, true
	}
	parts := make([]string, 0, 8)
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." || !staticHiddenAllowed(seg) {
			return "", false
		}
		if strings.ContainsAny(seg, "\\:\x00") {
			return "", false
		}
		parts = append(parts, seg)
	}
	full := filepath.Join(append([]string{rootDir}, parts...)...)
	// 双保险：Join 结果必须仍在站点根内（异常输入或平台怪癖兜底）
	out, err := filepath.Rel(rootDir, full)
	if err != nil || out == ".." || strings.HasPrefix(out, ".."+string(filepath.Separator)) {
		return "", false
	}
	return full, true
}

// staticHiddenAllowed 隐藏项判定：以点开头的段默认拒绝（避免 .git/.env/.htpasswd 被直接下载），
// 仅放行 .well-known（ACME、security.txt、apple-app-site-association 等规范目录）。
func staticHiddenAllowed(seg string) bool {
	if !strings.HasPrefix(seg, ".") {
		return true
	}
	return strings.EqualFold(seg, ".well-known")
}

// staticWithin 判断 target 是否位于 root 之内（两参数均应为真实路径，分隔符已统一）。
func staticWithin(root, target string) bool {
	if root == "" || target == "" {
		return false
	}
	if strings.EqualFold(root, target) {
		return true
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// realPath 解析符号链接后的真实路径；解析失败（不存在等）时原样返回。
func realPath(p string) string {
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return p
}

// staticIndexFile 目录首页探测：按配置顺序返回第一个存在的普通文件。
func staticIndexFile(dir string, indexFiles []string) (string, os.FileInfo, bool) {
	for _, name := range indexFiles {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, fi, true
		}
	}
	return "", nil, false
}

// staticServeFile 输出静态文件：优先预压缩变体，Range / If-Modified-Since 由 ServeContent 处理。
func staticServeFile(w http.ResponseWriter, r *http.Request, site *Site, file, name string, fi os.FileInfo, st *siteStats) {
	st.active.Add(1)
	defer st.active.Add(-1)

	src, enc := staticEncodingVariant(file, site.Adv.Static, r)
	if enc != "" {
		fi2, err := os.Stat(src)
		if err != nil {
			src, enc = file, ""
		} else {
			fi = fi2
		}
	}
	f, err := os.Open(src)
	if err != nil {
		noteError(site, "静态文件读取失败: "+name)
		sendErrorPage(w, 500, "静态文件读取失败: "+err.Error(), staticRootHint, false)
		return
	}
	defer f.Close()

	h := w.Header()
	h.Set("Server", "NexHome")
	h.Set("X-Content-Type-Options", "nosniff")
	if cc := site.Adv.Static.CacheControl; cc != "" {
		h.Set("Cache-Control", cc)
	}
	if enc != "" {
		h.Set("Content-Encoding", enc)
		h.Add("Vary", "Accept-Encoding")
	}
	applyHeaderOps(site.Adv.RespHeaders, h)
	// name 用原始文件名（非 .br/.gz），Content-Type 才按真实扩展名判定
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// staticEncodingVariant 预压缩变体选择：br 优先于 gzip，只在客户端声明支持且变体确实存在时启用。
func staticEncodingVariant(file string, opts StaticOpts, r *http.Request) (string, string) {
	if !opts.Precompressed || r.Header.Get("Range") != "" {
		return file, "" // Range 与 Content-Encoding 组合的语义易踩坑，带 Range 时直接给原文件
	}
	accept := strings.ToLower(r.Header.Get("Accept-Encoding"))
	for _, enc := range []struct{ key, ext string }{{"br", ".br"}, {"gzip", ".gz"}} {
		if !strings.Contains(accept, enc.key) {
			continue
		}
		if fi, err := os.Stat(file + enc.ext); err == nil && fi.Mode().IsRegular() {
			return file + enc.ext, enc.key
		}
	}
	return file, ""
}

// wantsHTML 浏览器导航请求判定（Accept 含 text/html）：SPA 回退只对页面请求生效，
// 否则 /api/foo.js 之类的资源 404 也会被塞一个首页回来。
func wantsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// staticListing 目录浏览页（仅在站点开启 dirListing 时输出），默认隐藏项与非法名一律不列出。
func staticListing(w http.ResponseWriter, dir, urlPath string) {
	const maxEntries = 1000
	entries, err := os.ReadDir(dir)
	if err != nil {
		sendErrorPage(w, 500, "目录读取失败: "+err.Error(), staticRootHint, false)
		return
	}
	list := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !staticHiddenAllowed(name) || strings.ContainsAny(name, "\\:\x00") {
			continue
		}
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool {
		di, dj := list[i].IsDir(), list[j].IsDir()
		if di != dj {
			return di // 目录排前
		}
		return strings.ToLower(list[i].Name()) < strings.ToLower(list[j].Name())
	})
	truncated := false
	if len(list) > maxEntries {
		list, truncated = list[:maxEntries], true
	}

	title := escapeHtml(urlPath)
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>目录 " + title + "</title>\n<style>")
	b.WriteString("body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;" +
		"background:#f5f7fa;color:#1f2937;margin:0;padding:32px 20px;}")
	b.WriteString(".card{max-width:820px;margin:0 auto;background:#fff;border:1px solid #eef1f5;border-radius:16px;" +
		"box-shadow:0 12px 40px rgba(15,23,42,.08);padding:24px 28px;}")
	b.WriteString("h1{font-size:16px;font-weight:600;margin:0 0 16px;word-break:break-all;}h1 code{color:#2563eb;}")
	b.WriteString("ul{list-style:none;margin:0;padding:0;}li{display:flex;gap:12px;align-items:baseline;" +
		"padding:7px 0;border-bottom:1px dashed #eef1f5;font-size:14px;}")
	b.WriteString("a{color:#2563eb;text-decoration:none;word-break:break-all;}a:hover{text-decoration:underline;}")
	b.WriteString(".meta{margin-left:auto;color:#9ca3af;font-size:12px;white-space:nowrap;}")
	b.WriteString(".tip{margin-top:14px;color:#9ca3af;font-size:12px;}")
	b.WriteString("</style>\n</head>\n<body>\n<div class=\"card\">\n<h1>目录 <code>" + title + "</code></h1>\n<ul>\n")
	if urlPath != "/" {
		b.WriteString("<li><a href=\"../\">../</a><span class=\"meta\">上级目录</span></li>\n")
	}
	for _, e := range list {
		name := e.Name()
		href := url.PathEscape(name)
		label := escapeHtml(name)
		size := ""
		if e.IsDir() {
			href += "/"
			label += "/"
		} else if info, ierr := e.Info(); ierr == nil {
			size = staticSize(info.Size()) + " · " + info.ModTime().Format("2006-01-02 15:04")
		}
		b.WriteString("<li><a href=\"" + href + "\">" + label + "</a><span class=\"meta\">" + escapeHtml(size) + "</span></li>\n")
	}
	if len(list) == 0 {
		b.WriteString("<li class=\"tip\">该目录下没有可列出的文件。</li>\n")
	}
	b.WriteString("</ul>\n")
	if truncated {
		b.WriteString("<div class=\"tip\">条目过多，仅列出前 " + strconv.Itoa(maxEntries) + " 项。</div>\n")
	}
	b.WriteString("<div class=\"tip\">由 NexHome 静态站点发布</div>\n</div>\n</body>\n</html>\n")
	writeHTML(w, 200, b.String(), true)
}

// staticSize 文件大小的人类可读形态（目录浏览用）。
func staticSize(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatInt(n>>10, 10) + " KB"
	default:
		return strconv.FormatInt(n, 10) + " B"
	}
}
