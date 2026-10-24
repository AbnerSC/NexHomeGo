package web

import (
	"io"
	"net"
	"net/http"
	"strconv"

	"NexHomeGo/internal/core"
)

// Ctx 是 HTTP 请求上下文门面：封装 ResponseWriter/Request，对业务模块屏蔽底层 Web 框架，
// 提供统一 JSON 响应（{ok,data}/{ok,error}）、文件下载、查询参数、请求体解析、流式写出等能力。
// 与 Java Ctx 语义一一对应，保证前端零改动。
type Ctx struct {
	w        http.ResponseWriter
	r        *http.Request
	params   map[string]string
	wroteHdr bool
}

// Handler 业务路由处理器：返回 error 交由服务器统一映射为 {ok:false,error} 响应。
type Handler func(*Ctx) error

func newCtx(w http.ResponseWriter, r *http.Request, params map[string]string) *Ctx {
	return &Ctx{w: w, r: r, params: params}
}

func (c *Ctx) Method() string { return c.r.Method }
func (c *Ctx) Path() string   { return c.r.URL.Path }

// Param 路径参数，如 /api/ddns/tasks/{id} 中的 id；不存在返回 ""。
func (c *Ctx) Param(name string) string { return c.params[name] }

// ParamLong 路径参数按 int64 解析，缺省 0。
func (c *Ctx) ParamLong(name string) int64 {
	v := c.params[name]
	if v == "" {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// Query 查询参数，不存在返回 ""。
func (c *Ctx) Query(name string) string { return c.r.URL.Query().Get(name) }

// Header 请求头，不存在返回 ""。
func (c *Ctx) Header(name string) string { return c.r.Header.Get(name) }

// PeerIP 连接对端地址（TCP 层，绝不可伪造）。用于登录锁定等安全控制的计数键与日志。
func (c *Ctx) PeerIP() string {
	host, _, err := net.SplitHostPort(c.r.RemoteAddr)
	if err != nil {
		host = c.r.RemoteAddr
	}
	if ip := core.SanitizeIP(host); ip != "" {
		return ip
	}
	return "unknown"
}

// ClientIP 客户端来源 IP：仅当直连对端是可信代理（见 core.TrustForwardedFrom）时才采信请求头，
// 优先级：aliyun-esa-real-client-ip（ESA 注入）→ X-Forwarded-For（链尾）→ X-Real-IP → CF-Connecting-IP；
// 全部缺失时回退对端地址（局域网直连且浏览器不发头的情况）。
// 转发头由客户端完全可控，无条件采信会让登录锁定、IP 白名单等基于来源地址的控制全部失效。
// 注意：登录锁定计数另用 PeerIP，即使本方法被伪造也不影响锁定。
func (c *Ctx) ClientIP() string {
	peer := c.PeerIP()
	if !core.TrustForwardedFrom(peer) {
		return peer
	}
	if ip := core.ClientIPFromHeaders(c.r.Header); ip != "" {
		return ip
	}
	return peer
}

// BodyText 读取请求体文本。
func (c *Ctx) BodyText() string {
	if c.r.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(c.r.Body)
	return string(b)
}

// Body 请求体解析为对象（等价 ctx.body()）。
func (c *Ctx) Body() map[string]interface{} {
	return core.ParseBody(c.BodyText())
}

// ---------- 响应输出 ----------

const jsonContentType = "application/json; charset=utf-8"

// Json 输出 JSON（指定状态码）。
func (c *Ctx) Json(code int, data interface{}) {
	body, err := core.MarshalJSON(data)
	if err != nil {
		http.Error(c.w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.writeHeader(code, map[string]string{"Content-Type": jsonContentType})
	_, _ = c.w.Write(body)
}

// Ok 输出成功 JSON：{ok:true, data:...}。
func (c *Ctx) Ok(data interface{}) {
	r := core.NewRow().Set("ok", true).Set("data", data)
	c.Json(http.StatusOK, r)
}

// Fail 输出错误 JSON：{ok:false, error:...}。
func (c *Ctx) Fail(code int, message string) {
	r := core.NewRow().Set("ok", false).Set("error", message)
	c.Json(code, r)
}

// NotFound 输出 404。
func (c *Ctx) NotFound() { c.Fail(http.StatusNotFound, "接口不存在") }

// Text 纯文本响应（ACME http-01 校验文件）。
func (c *Ctx) Text(code int, content, contentType string) {
	c.writeHeader(code, map[string]string{"Content-Type": contentType})
	_, _ = io.WriteString(c.w, content)
}

// Raw 原始字节响应。
func (c *Ctx) Raw(code int, bytes []byte, contentType string) {
	c.writeHeader(code, map[string]string{"Content-Type": contentType})
	_, _ = c.w.Write(bytes)
}

// SetHeader 设置响应头（写出前有效）。
func (c *Ctx) SetHeader(name, value string) {
	if !c.wroteHdr {
		c.w.Header().Set(name, value)
	}
}

// Writer 暴露底层 ResponseWriter（供流式测速等需要 Flush/裸写的处理器）。
func (c *Ctx) Writer() http.ResponseWriter { return c.w }

// Request 暴露底层请求（供上传流式读取等）。
func (c *Ctx) Request() *http.Request { return c.r }

func (c *Ctx) writeHeader(code int, headers map[string]string) {
	if c.wroteHdr {
		return
	}
	for k, v := range headers {
		c.w.Header().Set(k, v)
	}
	c.w.WriteHeader(code)
	c.wroteHdr = true
}

// File 输出文件下载。
func (c *Ctx) File(path, downloadName string) error {
	data, err := readFileBytes(path)
	if err != nil {
		return err
	}
	c.SetHeader("Content-Disposition", "attachment; filename=\""+downloadName+"\"")
	c.Raw(http.StatusOK, data, "application/octet-stream")
	return nil
}

// FullURL 请求完整 URL（供 HTTPS 跳转构造）。
func (c *Ctx) FullURL() string {
	scheme := "http"
	if c.r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.r.Host + c.r.URL.RequestURI()
}

// Host 返回请求 Host（不含端口剥离）。
func (c *Ctx) Host() string { return c.r.Host }
