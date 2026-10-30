package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/auth"
	"NexHomeGo/internal/core"
)

// WebServer：内置单端口 Web 服务。同端口提供 /api/** REST + 前端静态资源 + ACME http-01 校验。
// 访问配置（端口/HTTPS/安全入口）持久化在数据库；HTTPS 通过同进程额外监听器提供，复用已签发证书；
// 安全入口模式下未带前缀的请求一律 404（ACME 除外）；修改后进程内重启生效，绑定失败自动回滚。
// 各业务模块启动前经 Route 声明接口，启动时统一注册。

type routeEntry struct {
	method  string
	pattern string
	seg     []segment
	handler Handler
}

type segment struct {
	literal string
	param   string // 非空表示 {name}
	// catchAll 预留的通配尾段标记（当前解析与匹配逻辑均未使用）
	catchAll bool
}

var paramRe = regexp.MustCompile(`^\{(\w+)\}$`)

// routesBuf 路由缓冲区：模块在 Start 前注册，Start（含每次重启）时统一回放。
var (
	routesMu  sync.Mutex
	routesBuf []routeEntry
)

// Route 注册 REST 路由，pattern 支持 {name} 路径参数。
func Route(method, pattern string, handler Handler) {
	routesMu.Lock()
	defer routesMu.Unlock()
	routesBuf = append(routesBuf, routeEntry{
		method:  strings.ToUpper(method),
		pattern: pattern,
		seg:     parsePattern(pattern),
		handler: handler,
	})
}

func parsePattern(pattern string) []segment {
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	segs := make([]segment, 0, len(parts))
	for _, p := range parts {
		if m := paramRe.FindStringSubmatch(p); m != nil {
			segs = append(segs, segment{param: m[1]})
		} else {
			segs = append(segs, segment{literal: p})
		}
	}
	return segs
}

// ---------- 运行态 ----------

var (
	runMu           sync.Mutex
	httpSrv         *http.Server
	httpsSrv        *http.Server
	boundPort             = -1
	activeCertID    int64 = -1
	currentCfg      *Snapshot
	lastHTTPSCertOK = true
)

// HTTPPort 当前实际生效的 HTTP 端口（尚未绑定回退配置端口）。
func HTTPPort() int {
	if p := boundPort; p > 0 {
		return p
	}
	if s, err := LoadAccessConfig(); err == nil {
		return s.HTTPPort
	}
	return core.Port()
}

// HTTPSActive HTTPS 是否实际生效（已成功挂载证书监听器）。
func HTTPSActive() bool { return activeCertID > 0 }

// ActiveCertTaskID HTTPS 当前使用的证书任务 ID（未启用返回 -1）。
func ActiveCertTaskID() int64 { return activeCertID }

// SetLastError 写回滚/降级提示（供设置页展示）。
func SetLastError(msg string) { _ = core.SetConfig(KeyLastError, msg) }

// ScheduleRestart 延迟触发进程内重启（响应已发出后再停服）。
func ScheduleRestart(delaySec int) {
	go func() {
		time.Sleep(time.Duration(delaySec) * time.Second)
		Restart()
	}()
}

// OnCertRenewed 证书续期成功后的热加载入口。
func OnCertRenewed(taskID int64) {
	if activeCertID == taskID {
		core.LogInfo(core.LogSys, fmt.Sprintf("HTTPS 证书 #%d 已续期，即将重启 Web 服务加载新证书", taskID))
		ScheduleRestart(1)
	}
}

// Start 启动服务：读取数据库中的访问配置，首次启动带端口自愈。
func Start() error {
	// 先按容器内存上限约束 Go 运行时（GOMEMLIMIT），再起服务，避免堆涨过 mem_limit 被 OOM kill。
	applyContainerMemoryLimit()
	// 保底：升级时关闭历史上的 HTTP 强制跳转，保证开启 HTTPS 后面板仍能通过 HTTP 访问
	MigrateHTTPRedirect()
	return startInternal(true)
}

func startInternal(selfHeal bool) error {
	snap, err := LoadAccessConfig()
	if err != nil {
		core.LogError(core.LogSys, "读取访问配置失败，已回退引导配置: "+err.Error())
		snap = &Snapshot{HTTPPort: core.Port(), HTTPSPort: 8443}
	}
	currentCfg = snap

	// HTTPS 证书解析前置：失败降级为仅 HTTP，避免服务无法启动。
	httpsOn := snap.HTTPSEnabled
	var cert *CertInfo
	if httpsOn {
		if c, err := ResolveCertFile(snap.CertTaskID); err != nil {
			core.LogError(core.LogSys, "HTTPS 证书解析失败，已降级为仅 HTTP 访问: "+err.Error())
			httpsOn = false
		} else {
			cert = c
		}
	}
	if !httpsOn {
		activeCertID = -1
	}

	if !selfHeal {
		boundPort = -1
		if err := launch(snap, httpsOn, cert, snap.HTTPPort, false); err != nil {
			return err
		}
		return nil
	}

	wanted := snap.HTTPPort
	httpsPort := -1
	if httpsOn {
		httpsPort = snap.HTTPSPort
	}
	var lastErr error
	for _, p := range portCandidates(wanted, httpsPort) {
		if p != wanted && !canBind(p) {
			core.LogWarn(core.LogSys, fmt.Sprintf("端口 %d 预绑探测不可用，跳过", p))
			continue
		}
		boundPort = -1
		if err := launch(snap, httpsOn, cert, p, true); err != nil {
			lastErr = err
			stopQuietly()
			boundPort = -1
			core.LogWarn(core.LogSys, fmt.Sprintf("端口 %d 启动失败，继续尝试备选: %v", p, err))
			continue
		}
		if p != wanted {
			msg := fmt.Sprintf("配置的 HTTP 端口 %d 启动时已被占用，面板临时改用端口 %d", wanted, p)
			if httpsOn && !HTTPSActive() {
				msg += fmt.Sprintf("；HTTPS 端口 %d 同样不可用，已临时降级为仅 HTTP 访问", snap.HTTPSPort)
			}
			msg += "（web.port 配置未改动，释放原端口后重启进程即恢复）"
			core.LogWarn(core.LogSys, msg)
			SetLastError(msg)
		} else if !(httpsOn && !HTTPSActive()) {
			SetLastError("")
		}
		return nil
	}
	return fmt.Errorf("Web 服务启动失败，已尝试候选端口: %w", lastErr)
}

// ---------- 请求体积与超时 ----------

// maxAPIBodyBytes 面板 API 请求体上限（默认 8 MB）。
// 登录等免登录接口存在预认证读体，不设上限时单个超大请求即可把进程内存拉满（DoS）。
// 流式测速上行（/api/system/speedtest/up）必须持续读取直到客户端结束，走白名单不套 MaxBytesReader。
const maxAPIBodyBytes = 8 << 20

// maxUploadBodyBytes 静态站点 zip 上传接口的请求体上限（与 proxy 侧 maxUploadBytes 保持一致，512 MB）。
// 站点包动辄几十上百 MB，复用 8 MB 上限会让上传一律 413。
const maxUploadBodyBytes = 512 << 20

// maxAuthBodyBytes 免登录鉴权接口（登录/状态检查）的请求体上限。
// 这两个接口在认证之前就要把请求体读进内存并解析，与业务接口共用 8 MB 时，
// 匿名攻击者只需并发若干个大包即可把 CPU（实测单个 7 MB 包解析耗时约 3 秒）与内存放大数十倍，
// 而登录表单实际只有几十字节，因此单独收紧到 16 KB。
const maxAuthBodyBytes = 16 << 10

// unboundedBodyPath 允许任意长度请求体的接口（流式测速上行）。
func unboundedBodyPath(p string) bool {
	return p == "/api/system/speedtest/up"
}

// apiBodyLimit 按接口给出请求体上限：zip 上传单独放宽、免登录鉴权接口单独收紧，其余接口为 8 MB。
func apiBodyLimit(p string) int64 {
	switch p {
	case "/api/proxy/sites/upload":
		return maxUploadBodyBytes
	case "/api/auth/login", "/api/auth/check":
		return maxAuthBodyBytes
	}
	return maxAPIBodyBytes
}

// fmtLimit 人类可读的请求体上限文案（16 KB / 8 MB / 512 MB），避免小上限被显示成 "0 MB"。
func fmtLimit(limit int64) string {
	if limit >= 1<<20 {
		return strconv.FormatInt(limit>>20, 10) + " MB"
	}
	return strconv.FormatInt(limit>>10, 10) + " KB"
}

// canonicalPath 判断请求路径是否已规范化：拒绝重复斜杠、点段与非规范尾斜杠。
// 合法形态只有 path.Clean(p) == p，或仅多一个目录尾斜杠（如 /entry/）。
func canonicalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	if p == "/" {
		return true
	}
	clean := pathpkg.Clean(p)
	if clean == p {
		return true
	}
	// 仅放行“目录路径尾巴多一个斜杠”（/entry/、/docs/）；根的 "//" 仍算非规范。
	return clean != "/" && clean+"/" == p
}

// setSecurityHeaders 统一安全响应头：阻止 MIME 嗅探、点击劫持与 Referer 泄漏 token。
// CSP 说明：前端为原生 JS，页面内以 innerHTML  + onclick 形式渲染列表操作按钮，
// 必须保留 'unsafe-inline'（否则整站按钮失效），但 default-src 'self' 仍能拦住
// 外部域脚本引用（<script src=//evil>）与 object/base 注入；frame-ancestors 与 XFO 双保险。
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-XSS-Protection", "0")
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data: blob: https: http:; font-src 'self' data:; connect-src 'self' https: http:; "+
			"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}

// launch 构建并启动一个 Web 实例（HTTP 监听器 + 可选 HTTPS 监听器），绑定失败返回错误。
func launch(snap *Snapshot, https bool, cert *CertInfo, httpPort int, selfHeal bool) error {
	httpSrv = &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(httpPort)),
		Handler:           http.HandlerFunc(serveHTTP),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       120 * time.Second, // 整个请求（含请求体）读取上限，防慢速请求体长期占用连接（8MB 上限下允许最低 66KB/s）
		IdleTimeout:       120 * time.Second, // 空闲长连接回收；写超时保持 0，兼容大文件下载与测速
		// 头部总量 64KB：默认 1MB 意味着未认证连接可先用近 1MB 头部占住内存，
		// 与反向代理侧 MaxHeaderBytes 保持一致。
		MaxHeaderBytes: 64 << 10,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", httpPort))
	if err != nil {
		return err
	}
	actual := ln.Addr().(*net.TCPAddr).Port
	boundPort = actual
	go func() {
		if e := httpSrv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			core.LogError(core.LogSys, "HTTP 服务异常退出: "+e.Error())
		}
	}()

	httpsMounted := true
	if https {
		if err := mountHTTPS(snap.HTTPSPort, cert, selfHeal); err != nil {
			if !selfHeal {
				stopQuietly()
				return fmt.Errorf("挂载 HTTPS 连接器失败: %w", err)
			}
			httpsMounted = false
			activeCertID = -1
			msg := fmt.Sprintf("HTTPS 端口 %d 启动时已被占用，已临时降级为仅 HTTP 访问: %v", snap.HTTPSPort, err)
			core.LogError(core.LogSys, msg)
			SetLastError(msg)
		}
	}

	addr := fmt.Sprintf("Web 服务已启动: http://localhost:%d", boundPort)
	if snap.Entry != "" {
		addr += "/" + snap.Entry + "/"
	}
	if httpsMounted {
		addr += fmt.Sprintf("（HTTPS: https://localhost:%d", snap.HTTPSPort)
		if snap.HTTPSRedirect {
			addr += "，HTTP 强制跳转"
		}
		addr += "）"
	}
	// 启动日志带上实例身份：与诊断页展示的 pid/host/cgroup 对照，
	// 可快速判定“浏览器访问到的到底是哪个 nexhome 进程”（同名容器不可能并存，但宿主原生进程可以）。
	core.LogInfo(core.LogSys, fmt.Sprintf("%s | 实例 pid=%d host=%s cgroup=%s",
		addr, os.Getpid(), HostName(), ContainerCgroupPath()))
	return nil
}

func mountHTTPS(httpsPort int, cert *CertInfo, selfHeal bool) error {
	tlsConf := cert.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	httpsSrv = &http.Server{
		Addr:              fmt.Sprintf(":%d", httpsPort),
		Handler:           http.HandlerFunc(serveHTTP),
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	raw, err := net.Listen("tcp", fmt.Sprintf(":%d", httpsPort))
	if err != nil {
		return err
	}
	ln := tls.NewListener(raw, tlsConf)
	go func() {
		if e := httpsSrv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			core.LogError(core.LogSys, "HTTPS 服务异常退出: "+e.Error())
		}
	}()
	activeCertID = cert.TaskID
	core.LogInfo(core.LogSys, fmt.Sprintf("HTTPS 连接器已挂载，端口: %d，证书任务 #%d %s", httpsPort, cert.TaskID, cert.Name))
	_ = selfHeal
	return nil
}

// Restart 进程内重启：停止旧实例后按数据库最新配置重建；新配置绑定失败自动回滚旧配置。
func Restart() {
	runMu.Lock()
	defer runMu.Unlock()
	old := currentCfg
	stopQuietly()
	_, err := startInternalCapture(false)
	if err == nil {
		SetLastError("")
		core.LogInfo(core.LogSys, "Web 服务已按新访问配置重启完成")
		return
	}
	core.LogError(core.LogSys, "应用新访问配置失败，正在回滚: "+err.Error())
	msg := "应用新访问配置失败，已回滚旧配置: " + err.Error()
	if old != nil {
		if e := old.Persist(); e == nil {
			stopQuietly()
			if _, e := startInternalCapture(false); e != nil {
				msg = "应用新访问配置失败且回滚异常，请检查端口占用后重启进程: " + e.Error()
			}
		}
	}
	SetLastError(msg)
	core.LogWarn(core.LogSys, msg)
}

func startInternalCapture(selfHeal bool) (*Snapshot, error) {
	if err := startInternal(selfHeal); err != nil {
		return nil, err
	}
	return currentCfg, nil
}

// contextTimeout 给优雅关停一个短超时上下文。
func contextTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func stopQuietly() {
	if httpSrv != nil {
		ctx, cancel := contextTimeout()
		_ = httpSrv.Shutdown(ctx)
		cancel()
		httpSrv = nil
	}
	if httpsSrv != nil {
		ctx, cancel := contextTimeout()
		_ = httpsSrv.Shutdown(ctx)
		cancel()
		httpsSrv = nil
	}
}

// ---------- 请求分发 ----------

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	// 安全响应头对所有面板响应（静态/接口/错误页）统一生效。
	setSecurityHeaders(w)
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=15552000")
	}
	// 非规范路径一律拒绝：鉴权用 strings.HasPrefix(innerPath, "/api/")，路由匹配却按 Trim(path, "/")
	// 拆分，"//api/**"、"/entry/%2fapi/**" 这类路径会让两者结论不一致，从而绕过登录校验。
	if !canonicalPath(path) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	entryOn := currentCfg != nil && currentCfg.Entry != ""
	prefix := ""
	if entryOn {
		prefix = "/" + currentCfg.Entry
	}

	// ACME http-01 校验：免登录、不受安全入口与 HTTPS 跳转影响。
	if strings.HasPrefix(path, "/.well-known/acme-challenge/") {
		if h, params, ok := matchRoute(r.Method, path); ok {
			runHandler(w, r, h, params)
			return
		}
	}

	// HTTPS 强制跳转（仅在明文 HTTP 连接上，且非 ACME）。
	// 保底：HTTPS 未真正生效（证书解析失败 / 端口被占用而降级）时不跳转，
	// 否则浏览器会被 302 到不可用的 HTTPS 端口，导致面板完全无法访问。
	if currentCfg != nil && currentCfg.HTTPSEnabled && currentCfg.HTTPSRedirect &&
		r.TLS == nil && HTTPSActive() {
		http.Redirect(w, r, toHTTPSURL(r, currentCfg.HTTPSPort), http.StatusFound)
		return
	}

	var innerPath string
	if entryOn {
		switch {
		case path == prefix:
			http.Redirect(w, r, prefix+"/", http.StatusFound)
			return
		case path == prefix+"/":
			serveIndex(w, r)
			return
		case strings.HasPrefix(path, prefix+"/"):
			innerPath = path[len(prefix):]
		default:
			// 安全入口网关：未携带前缀的请求一律 404（防端口扫描与爆破定位）。
			notFoundPlain(w)
			return
		}
	} else {
		innerPath = path
	}

	// 接口响应可能含会话令牌、AccessKey、证书私钥路径等敏感数据，
	// 统一禁止浏览器与中间代理缓存（先于鉴权写入，401 响应同样不缓存）。
	if strings.HasPrefix(innerPath, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}

	// 鉴权前置：/api/** 除登录与登录状态检查外均需有效凭证。
	// 两种方式等价：会话令牌（X-Token，或只读方法的 ?token=）或接口访问令牌（Access-Token 请求头，
	// 由系统设置页配置，供其他系统/脚本长期调用，不参与单点登录）。
	if strings.HasPrefix(innerPath, "/api/") &&
		innerPath != "/api/auth/login" && innerPath != "/api/auth/check" {
		token := r.Header.Get("X-Token")
		// 查询参数 token 仅为兼容浏览器链接直下（证书/备份下载）保留，且只允许只读方法，
		// 避免写操作可通过拼接 URL 触发；未携带 token 的参数一律不再回落到 URL。
		if token == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			token = r.URL.Query().Get("token")
			if token != "" {
				w.Header().Set("Cache-Control", "no-store")
			}
		}
		if !auth.Check(token) {
			if !auth.CheckAccessToken(r.Header.Get("Access-Token")) {
				writeFail(w, http.StatusUnauthorized, "未登录或登录已过期")
				return
			}
			// 令牌走请求头，响应不得被中间层缓存。
			w.Header().Set("Cache-Control", "no-store")
		}
	}

	// 请求体上限：免登录接口同样受限，防止单个超大请求耗尽内存（zip 上传接口单独放宽）。
	if strings.HasPrefix(innerPath, "/api/") && !unboundedBodyPath(innerPath) {
		limit := apiBodyLimit(innerPath)
		if innerPath == "/api/proxy/sites/upload" {
			// 站点包可达数百 MB：全局 ReadTimeout（120 秒）会在慢速链路上误杀上传，
			// 按接口放宽连接读截止时间（读取结束即回归正常，不影响其他接口）。
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Minute))
		}
		if r.ContentLength > limit {
			writeFail(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("请求体过大（上限 %s）", fmtLimit(limit)))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}

	// 业务路由匹配（innerPath）。
	if h, params, ok := matchRoute(r.Method, innerPath); ok {
		runHandler(w, r, h, params)
		return
	}

	// 根路径 / 静态回退（仅非入口模式；入口模式下前缀内的静态已用 innerPath 分发）。
	if !entryOn && path == "/" {
		serveIndex(w, r)
		return
	}
	serveStatic(w, r, innerPath)
}

func runHandler(w http.ResponseWriter, r *http.Request, h Handler, params map[string]string) {
	c := newCtx(w, r, params)
	defer func() {
		if rec := recover(); rec != nil {
			core.LogError(core.LogSys, fmt.Sprintf("接口异常 %s %s: %v", r.Method, r.URL.Path, rec))
			if !c.wroteHdr {
				writeFail(w, http.StatusInternalServerError, "操作失败")
			}
		}
	}()
	if err := h(c); err != nil {
		mapError(c, err)
	}
}

// mapError 等价 Java 统一异常映射：BadRequest→400，StatusError→code，其他→500。
func mapError(c *Ctx, err error) {
	if c.wroteHdr {
		return
	}
	var br *core.BadRequest
	switch {
	case errors.As(err, &br):
		core.LogWarn(core.LogSys, "参数错误 "+c.Method()+" "+c.Path()+": "+err.Error())
		c.Fail(http.StatusBadRequest, err.Error())
	default:
		var se *core.StatusError
		if errors.As(err, &se) {
			c.Fail(se.Code, se.Msg)
			return
		}
		// 内部错误细节只进日志：响应体回显底层错误会泄露路径、SQL 与依赖版本等信息。
		core.LogError(core.LogSys, "接口异常 "+c.Method()+" "+c.Path()+": "+err.Error())
		c.Fail(http.StatusInternalServerError, "操作失败，请查看系统日志")
	}
}

// matchRoute 按方法 + 路径匹配已注册路由，返回处理器与路径参数。
func matchRoute(method, path string) (Handler, map[string]string, bool) {
	routesMu.Lock()
	routes := routesBuf
	routesMu.Unlock()
	trimmed := strings.Trim(path, "/")
	segs := splitPath(trimmed)
	for i := range routes {
		rt := &routes[i]
		if rt.method != method {
			continue
		}
		if params, ok := matchSegs(rt.seg, segs); ok {
			return rt.handler, params, true
		}
	}
	return nil, nil, false
}

func splitPath(trimmed string) []string {
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func matchSegs(pat []segment, got []string) (map[string]string, bool) {
	params := map[string]string{}
	for i, s := range pat {
		if i >= len(got) {
			return nil, false
		}
		if s.param != "" {
			params[s.param] = got[i]
		} else if s.literal != got[i] {
			return nil, false
		}
	}
	if len(pat) != len(got) {
		return nil, false
	}
	return params, true
}

func notFoundPlain(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 Not Found"))
}

func writeFail(w http.ResponseWriter, code int, msg string) {
	r := core.NewRow().Set("ok", false).Set("error", msg)
	body, _ := core.MarshalJSON(r)
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func toHTTPSURL(r *http.Request, httpsPort int) string {
	host := redirectHost(r)
	portPart := ""
	if httpsPort != 443 {
		portPart = ":" + strconv.Itoa(httpsPort)
	}
	q := r.URL.RawQuery
	if q != "" {
		q = "?" + q
	}
	return "https://" + host + portPart + r.URL.Path + q
}

// redirectHost 生成跳转目标主机。Host 头完全由客户端控制，直接拼进 Location
// 会把面板变成任意域名的开放重定向（可被钓鱼/DNS rebinding 利用），
// 因此只接受合法主机名或 IP，其余（含非法字符、空值）回退到本地监听地址。
func redirectHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if validHostLiteral(host) {
		return host
	}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if h, _, err := net.SplitHostPort(la.String()); err == nil && validHostLiteral(h) {
			return h
		}
	}
	return "localhost"
}

// validHostLiteral 主机名/IP 格式校验：仅字母数字与 - . :，且长度为 1~253。
// 不允许出现 / @ 空白等可改变 URL 语义的字符。
func validHostLiteral(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(strings.Trim(s, "[]")) != nil {
		return true
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// portCandidates 启动期候选端口：期望端口 → 向后 autoFallback 个 → 内核随机(0)。跳过 HTTPS 端口。
func portCandidates(wanted, httpsPort int) []int {
	list := []int{wanted}
	span := core.PortFallbackSpan()
	for i := 1; i <= span; i++ {
		p := wanted + i
		if p > 65535 {
			break
		}
		if p != httpsPort && !contains(list, p) {
			list = append(list, p)
		}
	}
	list = append(list, 0)
	return list
}

func contains(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func canBind(port int) bool {
	if port <= 0 {
		return true
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
