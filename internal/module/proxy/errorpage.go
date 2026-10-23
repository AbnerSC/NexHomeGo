package proxy

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 代理错误页（404 与 5xx）与纯文本错误响应：文案、HTML 模板、转义与占位符替换顺序
// 逐一复刻 Java ProxyCenter.sendSimple/sendNotFoundPage/sendErrorPage/renderError。

// sendSimple 输出纯文本错误响应：text/plain + Content-Length + Server: NexHome + 可选附加头
func sendSimple(w http.ResponseWriter, status int, body string, extraName, extraValue string, keepAlive bool) {
	b := []byte(body)
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Server", "NexHome")
	if extraName != "" {
		h.Set(extraName, extraValue)
	}
	if !keepAlive {
		h.Set("Connection", "close")
	}
	w.WriteHeader(status)
	w.Write(b)
}

// sendNotFoundPage 输出「未找到匹配的站点」的 404 页（白底主题，与 sendErrorPage 同风格）。
// host / path 来自客户端，一律经 HTML 转义后嵌入，避免标记注入。
func sendNotFoundPage(w http.ResponseWriter, host, path string, keepAlive bool) {
	meta := metaBlock("Host", host, "路径", path)
	html := renderError("404", "未找到匹配的站点",
		"该域名尚未在代理中心配置，或当前未处于启用状态。",
		meta, "请在「代理中心」添加或启用该域名的站点", false)
	writeHTML(w, 404, html, keepAlive)
}

// sendErrorPage 输出转发过程中的错误页（500/502/503/504 等），与 404 页同风格（白底主题，5xx 用暖色强调）。
// detail 为技术原因（异常信息等），展示于详情块并 HTML 转义；hint 为空时按状态码给默认建议。
func sendErrorPage(w http.ResponseWriter, status int, detail, hint string, keepAlive bool) {
	html := buildErrorPageHTML(status, detail, hint)
	writeHTML(w, status, html, keepAlive)
}

// buildErrorPageHTML 按状态码组装错误页 HTML（文案与 Java sendErrorPage 一致）
func buildErrorPageHTML(status int, detail, hint string) string {
	var title, desc, defHint string
	switch status {
	case 504:
		title = "网关超时"
		desc = "后端服务未在规定时间内返回响应。"
		defHint = "后端处理可能过慢或已挂起，请检查后端负载与超时配置后重试。"
	case 503:
		title = "服务不可用"
		desc = "后端服务暂时不可用。"
		defHint = "请稍后重试，或检查后端服务是否已启动。"
	case 502:
		title = "网关错误"
		desc = "无法从后端服务获得有效响应。"
		defHint = "请检查后端服务是否运行，以及代理中心中该站点的后端地址与端口配置。"
	case 500:
		title = "服务器内部错误"
		desc = "代理在处理请求时发生内部错误。"
		defHint = "请稍后重试，若持续出现请查看「操作日志」定位原因。"
	default:
		title = "请求未成功"
		desc = "代理返回了一个错误状态。"
		defHint = "请稍后重试。"
	}
	meta := ""
	if strings.TrimSpace(detail) != "" {
		meta = metaBlock("详情", detail)
	}
	h := defHint
	if strings.TrimSpace(hint) != "" {
		h = hint
	}
	return renderError(strconv.Itoa(status), title, desc, meta, h, status >= 500)
}

// writeErrorPageTo 向已接管（hijack）的裸连接写错误页（Upgrade 隧道失败路径，
// 对齐 Java UpgradeBridge.fail：响应无法经 ResponseWriter，手写 HTTP 报文后关闭）
func writeErrorPageTo(conn net.Conn, status int, detail, hint string) {
	body := buildErrorPageHTML(status, detail, hint)
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(strconv.Itoa(status))
	sb.WriteString(" ")
	sb.WriteString(http.StatusText(status))
	sb.WriteString("\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ")
	sb.WriteString(strconv.Itoa(len(body)))
	sb.WriteString("\r\nServer: NexHome\r\nConnection: close\r\n\r\n")
	sb.WriteString(body)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte(sb.String()))
}

// writeHTML 输出 HTML 响应（供错误页等自包含页面复用）：charset=utf-8，keepAlive=false 时写后关闭
func writeHTML(w http.ResponseWriter, status int, html string, keepAlive bool) {
	b := []byte(html)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Server", "NexHome")
	if !keepAlive {
		h.Set("Connection", "close")
	}
	w.WriteHeader(status)
	w.Write(b)
}

// renderError 组装错误页 HTML：先替换固定样式变量，最后再注入含用户输入的 META / HINT，
// 避免其内容被后续占位符替换二次处理。
func renderError(code, title, desc, meta, hint string, serverError bool) string {
	grad, badgeFG, badgeBG := "linear-gradient(135deg, #2563eb, #7c3aed)", "#2563eb", "#eff6ff"
	if serverError {
		grad, badgeFG, badgeBG = "linear-gradient(135deg, #ef4444, #f97316)", "#dc2626", "#fef2f2"
	}
	r := strings.NewReplacer(
		"{{GRAD}}", grad,
		"{{BADGE_FG}}", badgeFG,
		"{{BADGE_BG}}", badgeBG,
		"{{CODE}}", escapeHtml(code),
		"{{TITLE}}", escapeHtml(title),
		"{{DESC}}", escapeHtml(desc),
	)
	// META 不转义（自身已是安全 HTML），HINT 最后注入
	out := r.Replace(errorPageTemplate)
	out = strings.Replace(out, "{{META}}", meta, 1)
	out = strings.Replace(out, "{{HINT}}", escapeHtml(hint), 1)
	return out
}

// metaBlock 详情块 HTML：成对的「标签-值」行，值经转义；无内容时返回空串（不渲染 meta 容器）
func metaBlock(kv ...string) string {
	var rows strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		rows.WriteString("<div class=\"row\"><span class=\"k\">")
		rows.WriteString(escapeHtml(kv[i]))
		rows.WriteString("</span><span class=\"v\">")
		rows.WriteString(escapeHtml(kv[i+1]))
		rows.WriteString("</span></div>")
	}
	if rows.Len() == 0 {
		return ""
	}
	return "<div class=\"meta\">" + rows.String() + "</div>"
}

// escapeHtml HTML 文本转义（& < > " '），用于把不可控输入安全嵌入页面
func escapeHtml(s string) string {
	if s == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(s) + 16)
	for _, c := range s {
		switch c {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '"':
			sb.WriteString("&quot;")
		case '\'':
			sb.WriteString("&#39;")
		default:
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// errorPageTemplate 代理错误页统一模板（白底主题）：404 与 5xx 共用，
// 占位符 {{CODE}} {{TITLE}} {{DESC}} {{META}} {{HINT}} 及样式变量 {{GRAD}} {{BADGE_FG}} {{BADGE_BG}}。
const errorPageTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{CODE}} · {{TITLE}}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: #f5f7fa;
    color: #1f2937;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    background: #ffffff;
    width: 100%;
    max-width: 520px;
    border-radius: 18px;
    padding: 48px 40px 40px;
    text-align: center;
    border: 1px solid #eef1f5;
    box-shadow: 0 12px 40px rgba(15, 23, 42, .08);
  }
  .badge {
    display: inline-block;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: .5px;
    color: {{BADGE_FG}};
    background: {{BADGE_BG}};
    padding: 6px 14px;
    border-radius: 999px;
    margin-bottom: 22px;
  }
  .code {
    font-size: 76px;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -2px;
    background: {{GRAD}};
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 14px;
  }
  h1 { font-size: 20px; font-weight: 600; margin-bottom: 10px; }
  .desc { font-size: 14px; color: #6b7280; line-height: 1.7; margin-bottom: 26px; }
  .meta {
    text-align: left;
    background: #f9fafb;
    border: 1px solid #eef1f5;
    border-radius: 12px;
    padding: 14px 18px;
    font-size: 13px;
    margin-bottom: 24px;
  }
  .meta .row { display: flex; gap: 10px; padding: 4px 0; }
  .meta .k { color: #9ca3af; min-width: 44px; }
  .meta .v {
    color: #374151;
    word-break: break-all;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .hint { font-size: 12px; color: #9ca3af; line-height: 1.6; }
</style>
</head>
<body>
  <div class="card">
    <div class="badge">NexHome 反向代理</div>
    <div class="code">{{CODE}}</div>
    <h1>{{TITLE}}</h1>
    <p class="desc">{{DESC}}</p>
    {{META}}
    <p class="hint">{{HINT}}</p>
  </div>
</body>
</html>
`
