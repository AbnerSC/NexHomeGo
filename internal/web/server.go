package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	// reg 仅用于通配尾段（如 /nav-icons/{file} 里 file 含点，仍按单段处理；扩展场景另用 catchAll）
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
	boundPort       = -1
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

// launch 构建并启动一个 Web 实例（HTTP 监听器 + 可选 HTTPS 监听器），绑定失败返回错误。
func launch(snap *Snapshot, https bool, cert *CertInfo, httpPort int, selfHeal bool) error {
	httpSrv = &http.Server{
		Addr:           net.JoinHostPort("", strconv.Itoa(httpPort)),
		Handler:        http.HandlerFunc(serveHTTP),
		ReadHeaderTimeout: 10 * time.Second,
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
	core.LogInfo(core.LogSys, addr)
	return nil
}

func mountHTTPS(httpsPort int, cert *CertInfo, selfHeal bool) error {
	tlsConf := cert.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	httpsSrv = &http.Server{
		Addr:           fmt.Sprintf(":%d", httpsPort),
		Handler:        http.HandlerFunc(serveHTTP),
		TLSConfig:      tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
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
	if currentCfg != nil && currentCfg.HTTPSEnabled && currentCfg.HTTPSRedirect && r.TLS == nil {
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
			serveIndex(w)
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

	// 鉴权前置：/api/** 除登录与登录状态检查外均需有效 token。
	if strings.HasPrefix(innerPath, "/api/") &&
		innerPath != "/api/auth/login" && innerPath != "/api/auth/check" {
		token := r.Header.Get("X-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if !auth.Check(token) {
			writeFail(w, http.StatusUnauthorized, "未登录或登录已过期")
			return
		}
	}

	// 业务路由匹配（innerPath）。
	if h, params, ok := matchRoute(r.Method, innerPath); ok {
		runHandler(w, r, h, params)
		return
	}

	// 根路径 / 静态回退（仅非入口模式；入口模式下前缀内的静态已用 innerPath 分发）。
	if !entryOn && path == "/" {
		serveIndex(w)
		return
	}
	serveStatic(w, innerPath)
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
		core.LogError(core.LogSys, "接口异常 "+c.Method()+" "+c.Path()+": "+err.Error())
		c.Fail(http.StatusInternalServerError, "操作失败: "+err.Error())
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

func serveIndex(w http.ResponseWriter) {
	data, ok := staticRead("index.html")
	if !ok {
		notFoundPlain(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func serveStatic(w http.ResponseWriter, rel string) {
	data, ok := staticRead(strings.TrimPrefix(rel, "/"))
	if !ok {
		notFoundPlain(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", contentType(rel))
	_, _ = w.Write(data)
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
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
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
