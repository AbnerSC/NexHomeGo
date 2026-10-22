package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"NexHomeGo/internal/core"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// 反向代理监听引擎（Go net/http 实现，等价 Java Netty 双组监听）：
//   - HTTP 口：h2c prior-knowledge（x/net/http2 h2c handler 按连接预面魔数自动识别），其余按 HTTP/1.1
//   - HTTPS 口：SNI 选证（sslstore），ALPN 协商 h2 / http/1.1
//
// 请求流水线：路由匹配（域名通配 + 路径前缀）→ force_https / IP 白名单 / BasicAuth / 限流 /
// 文件缓存 → 头部改写（XFF 等 + 自定义）→ 后端连接 → 响应流式回写（tee 写缓存）；
// Upgrade 请求走全原始字节隧道（101 后双端原始泵，仅 HTTP/1.1 连接且回源为 http1）。
// 站点与证书热更新：路由表/证书库原子替换，不影响存量连接。

type engineCfg struct {
	enabled   bool
	httpPort  int
	httpsPort int
}

var (
	engMu    sync.Mutex // start/stop 串行（Java synchronized start/stop）
	engCfg   = engineCfg{enabled: false, httpPort: 80, httpsPort: 443}
	sitesMu  sync.RWMutex
	engSites []*Site
	// trustRealIp 是否通过代理转发头解析访客真实来源 IP（XFF 首跳 / X-Real-IP / CF-Connecting-IP），
	// 供访问统计与 IP 白名单使用；回源追加的 XFF 链不受此开关影响，始终附加直连对端地址。
	trustRealIp        = true
	boundHttp    int32 = -1
	boundHttps   int32 = -1
	httpSrv      *http.Server
	httpsSrv     *http.Server
	httpLn       net.Listener
	httpsLn      net.Listener
	shuttingDown int32
)

// engineStart 按配置启动监听（已启动则先停）。HTTPS 口绑定失败降级为仅 HTTP 并返回警告文案，
// 由调用方写入 proxy.last_error；HTTP 口失败整体不监听并返回 error。
func engineStart(c engineCfg) (string, error) {
	engMu.Lock()
	defer engMu.Unlock()
	engineStopLocked()
	engCfg = c
	if !c.enabled {
		return "", nil
	}
	lst := loadAll()
	sitesMu.Lock()
	engSites = lst
	sitesMu.Unlock()
	sslReload()
	warn := ""

	// HTTP 明文口：h2c 自动识别连接预面，其余按 HTTP/1.1
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(c.httpPort))
	if err != nil {
		return "", fmt.Errorf("HTTP 端口 %d 绑定失败: %s", c.httpPort, err.Error())
	}
	httpLn = ln
	boundHttp = int32(c.httpPort)
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveRequest(w, r, false)
	}))
	h2srv := &http2.Server{}
	httpSrv = &http.Server{
		Handler:        h2c.NewHandler(mux, h2srv),
		MaxHeaderBytes: 65536,             // 头部总量 64KB（对齐 Java MAX_HEADER_SIZE；超限由 Go 回 431）
		IdleTimeout:    300 * time.Second, // 前端连接 300 秒空闲回收
	}
	go func(s *http.Server) {
		if err := s.Serve(ln); err != nil && err != http.ErrServerClosed && atomic.LoadInt32(&shuttingDown) == 0 {
			core.LogWarn(core.LogProxy, "代理 HTTP 监听异常: "+err.Error())
		}
	}(httpSrv)

	if c.httpsPort > 0 {
		tln, err := net.Listen("tcp", ":"+strconv.Itoa(c.httpsPort))
		if err != nil {
			warn = "HTTPS 端口 " + strconv.Itoa(c.httpsPort) + " 绑定失败，已降级为仅 HTTP 监听: " + err.Error()
			core.LogWarn(core.LogProxy, warn)
		} else {
			httpsLn = tln
			boundHttps = int32(c.httpsPort)
			tmux := http.NewServeMux()
			tmux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serveRequest(w, r, true)
			}))
			httpsSrv = &http.Server{
				Handler: tmux,
				TLSConfig: &tls.Config{
					GetConfigForClient: getConfigForClient,
					MinVersion:         tls.VersionTLS12,
				},
				MaxHeaderBytes: 65536,
				IdleTimeout:    300 * time.Second,
			}
			go func(s *http.Server, ln net.Listener) {
				// 证书由 GetConfigForClient 按 SNI 逐个提供，Server 自身无需 Certificates
				if err := s.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed && atomic.LoadInt32(&shuttingDown) == 0 {
					core.LogWarn(core.LogProxy, "代理 HTTPS 监听异常: "+err.Error())
				}
			}(httpsSrv, tln)
		}
	}

	msg := "代理监听已启动: HTTP:" + strconv.Itoa(int(boundHttp))
	if boundHttpsPort() > 0 {
		msg += " HTTPS:" + strconv.Itoa(int(boundHttps))
	}
	msg += "，站点 " + strconv.Itoa(len(lst)) + " 个，证书 " + strconv.Itoa(len(sslAPIView())) + " 张"
	core.LogInfo(core.LogProxy, msg)
	return warn, nil
}

// getConfigForClient SNI 握手选证：站点指定任务优先，其余按域名自动匹配；
// 未命中兜底剩余有效期最长的证书，证书库为空才终止握手；ALPN 按命中站点 frontProtocol 通告。
func getConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	cert, h2 := forSNI(chi.ServerName, currentSites())
	if cert == nil {
		core.LogWarn(core.LogProxy, "SNI 域名 "+chi.ServerName+" 无可用证书（证书库为空，请在 SSL 证书管理中签发）")
		return nil, fmt.Errorf("无可用证书")
	}
	next := []string{"http/1.1"}
	if h2 {
		next = []string{"h2", "http/1.1"}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   next,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// engineStop 停止监听（保留站点/证书状态）
func engineStop() {
	engMu.Lock()
	defer engMu.Unlock()
	engineStopLocked()
}

func engineStopLocked() {
	atomic.StoreInt32(&boundHttp, -1)
	atomic.StoreInt32(&boundHttps, -1)
	for _, pair := range []struct {
		srv *http.Server
		ln  net.Listener
	}{{httpSrv, httpLn}, {httpsSrv, httpsLn}} {
		if pair.srv != nil {
			atomic.StoreInt32(&shuttingDown, 1)
			_ = pair.srv.Close()
			atomic.StoreInt32(&shuttingDown, 0)
		} else if pair.ln != nil {
			_ = pair.ln.Close()
		}
	}
	httpSrv, httpsSrv = nil, nil
	httpLn, httpsLn = nil, nil
	closeIdleTransports()
}

// engineShutdown 停止监听并释放全部资源（进程退出/关闭开关时调用）
func engineShutdown() {
	engineStop()
}

// reloadSites 站点热更新（路由表原子替换，不影响存量连接）
func reloadSites() {
	lst := loadAll()
	sitesMu.Lock()
	engSites = lst
	sitesMu.Unlock()
}

func reloadCerts() {
	sslReload()
}

func currentSites() []*Site {
	sitesMu.RLock()
	defer sitesMu.RUnlock()
	return engSites
}

// boundHttpsPort 当前 HTTPS 实际绑定端口（未监听返回 -1，force_https 拼 Location 用）
func boundHttpsPort() int { return int(atomic.LoadInt32(&boundHttps)) }

// boundHttpPort 当前 HTTP 实际绑定端口（未监听返回 -1，总览代理状态卡用）
func boundHttpPort() int { return int(atomic.LoadInt32(&boundHttp)) }

// listenView 监听状态视图（/api/proxy/status 使用），键序与 Java LinkedHashMap 一致
func listenView() *core.Row {
	m := core.NewRow()
	c := engCfg
	m.Set("enabled", c.enabled)
	m.Set("httpPort", c.httpPort)
	m.Set("httpsPort", c.httpsPort)
	m.Set("boundHttp", boundHttpPort())
	m.Set("boundHttps", boundHttpsPort())
	m.Set("httpsActive", boundHttpsPort() > 0)
	m.Set("trustRealIp", trustRealIp)
	m.Set("certs", sslAPIView())
	return m
}

// sitesStatusView 各站点运行统计（活跃连接/每分钟请求/最近错误）
func sitesStatusView() []interface{} {
	list := make([]interface{}, 0)
	for _, s := range currentSites() {
		st := peekStats(s.ID)
		row := core.NewRow().Set("id", s.ID)
		if st == nil {
			row.Set("requests", int64(0)).Set("active", int64(0)).Set("qpm", int64(0)).
				Set("errors", int64(0)).Set("lastError", "")
		} else {
			row.Set("requests", st.requests.Load()).Set("active", int64(st.active.Load())).
				Set("qpm", int64(st.rate.perMinute())).Set("errors", st.errors.Load()).
				Set("lastError", st.lastErrLoad())
		}
		list = append(list, row)
	}
	return list
}

// ==================== 路由与统计 ====================

// siteStats 每站点统计
type siteStats struct {
	requests  atomic.Int64
	errors    atomic.Int64
	active    atomic.Int32
	rate      rateCounter
	lastMu    sync.Mutex
	lastError string
}

var (
	statsMu sync.Mutex
	STATS   = map[int64]*siteStats{}
)

func statsFor(siteId int64) *siteStats {
	statsMu.Lock()
	defer statsMu.Unlock()
	st := STATS[siteId]
	if st == nil {
		st = &siteStats{}
		STATS[siteId] = st
	}
	return st
}

func peekStats(siteId int64) *siteStats {
	statsMu.Lock()
	defer statsMu.Unlock()
	return STATS[siteId]
}

func noteError(s *Site, msg string) {
	st := statsFor(s.ID)
	st.errors.Add(1)
	v := core.Now() + " " + msg
	st.lastMu.Lock()
	st.lastError = v
	st.lastMu.Unlock()
}

func (st *siteStats) lastErrLoad() string {
	st.lastMu.Lock()
	defer st.lastMu.Unlock()
	return st.lastError
}

// dropSiteState 站点删除：清理其限流桶与运行统计（否则长期增删站点会让两个按 id 索引的表只增不减）
func dropSiteState(id int64) {
	bucketsMu.Lock()
	delete(BUCKETS, id)
	bucketsMu.Unlock()
	statsMu.Lock()
	delete(STATS, id)
	statsMu.Unlock()
}

// bucket 限流令牌桶（站点级，平滑速率）
type bucket struct {
	mu   sync.Mutex
	rps  float64
	next time.Time
}

func (b *bucket) tryAcquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.next.Before(now) {
		b.next = now
	}
	if b.next.Sub(now) > time.Second {
		return false // 积压超 1 秒拒绝
	}
	b.next = b.next.Add(time.Duration(float64(time.Second) / b.rps))
	return true
}

var (
	bucketsMu sync.Mutex
	BUCKETS   = map[int64]*bucket{}
)

// bucketFor 站点热更新后 rateLimitRps 变化时重建桶，避免改限流配置不生效
func bucketFor(s *Site) *bucket {
	bucketsMu.Lock()
	defer bucketsMu.Unlock()
	b := BUCKETS[s.ID]
	if b != nil && b.rps == s.Adv.RateLimitRps {
		return b
	}
	b = &bucket{rps: s.Adv.RateLimitRps}
	BUCKETS[s.ID] = b
	return b
}

// routeMatch 路由匹配：精确域名优于通配域名，长路径前缀优先，再按 id
func routeMatch(host, path string) *Site {
	var best *Site
	bestScore := -1
	for _, s := range currentSites() {
		if !s.Enabled || !s.matchDomain(host) || !s.matchPath(path) {
			continue
		}
		domScore := 100000
		if s.hasDomain(host) {
			domScore = 200000
		}
		pl := s.pathPrefixLen()
		if pl > 99999 {
			pl = 99999
		}
		score := domScore + pl
		if score > bestScore {
			bestScore = score
			best = s
		}
	}
	return best
}

// resolveClientIp 解析访客真实来源 IP（访问统计 / IP 白名单用）：trustRealIp 开启时按
// X-Forwarded-For 首跳 → X-Real-IP → CF-Connecting-IP 依次取值，全部为空回退直连对端地址；
// 关闭时恒返回直连对端地址。仅用于「识别访客」；回源追加的 XFF 链另取直连对端 peerIp。
func resolveClientIp(r *http.Request, peerIp string) string {
	if !trustRealIp || r == nil {
		return peerIp
	}
	if xff := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(xff) != "" {
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if first != "" {
			return first
		}
	}
	if real := r.Header.Get("X-Real-IP"); strings.TrimSpace(real) != "" {
		return strings.TrimSpace(real)
	}
	if cf := r.Header.Get("CF-Connecting-IP"); strings.TrimSpace(cf) != "" {
		return strings.TrimSpace(cf)
	}
	return peerIp
}

// ==================== 公共小工具 ====================

// hostOnly 去端口主机名：trim 小写，单冒号且纯数字才剥端口（避开 IPv6 字面量）
func hostOnly(host string) string {
	if host == "" {
		return ""
	}
	host = strings.ToLower(strings.TrimSpace(host))
	colon := strings.LastIndexByte(host, ':')
	if colon > 0 && strings.IndexByte(host, ':') == colon {
		maybePort := host[colon+1:]
		if allDigits(maybePort) {
			host = host[:colon]
		}
	}
	return host
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// upstreamPath 构造回源路径：stripPrefix / pathRewrite / 后端基础路径拼接
func upstreamPath(s *Site, path, query string) string {
	p := path
	if a := s.Adv; a.StripPrefix != nil && strings.HasPrefix(p, *a.StripPrefix) {
		p = p[len(*a.StripPrefix):]
		if p == "" || !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
	} else if a.PathRewriteFrom != nil && strings.HasPrefix(p, *a.PathRewriteFrom) {
		p = *a.PathRewriteTo + p[len(*a.PathRewriteFrom):]
		if p == "" || !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
	}
	if s.BasePath != "" {
		if p == "/" {
			p = ""
		}
		p = s.BasePath + p
	}
	if p == "" {
		p = "/"
	}
	if query != "" {
		p += "?" + query
	}
	return p
}

// hopByHop 逐跳头判定（请求与响应共用，小写比较）
func hopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade", "proxy-connection":
		return true
	}
	return false
}

// hopNoTunnel 隧道头过滤：剥离逐跳头但保留 Upgrade；Host/Content-Length 等原样透传
func hopNoTunnel(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "proxy-connection", "expect":
		return true
	}
	return false
}

// rateCounter 分钟速率统计：秒级环形桶，读取近 60 秒总数
type rateCounter struct {
	mu     sync.Mutex
	counts [64]int64
	stamps [64]int64
}

func (r *rateCounter) inc() {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := time.Now().Unix()
	i := int(s & 63)
	if r.stamps[i] != s {
		r.stamps[i] = s
		r.counts[i] = 0
	}
	r.counts[i]++
}

func (r *rateCounter) perMinute() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Unix()
	var c int64
	for j := 0; j < 60; j++ {
		s := now - int64(j)
		i := int(s & 63)
		if r.stamps[i] == s {
			c += r.counts[i]
		}
	}
	return int(c)
}

// peerAddrOf 直连对端地址（host 部分，用于 XFF 追加与统计回退）
func peerAddrOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ==================== 回源 Transport（连接池） ====================

// routeKey 后端路由 key：协议 + scheme + host + port +（免校验 TLS 时附加标记）+ 池参数。
// 回源协议参与取池，使 http1/h2 两条池互不串用；池参数变化即重建（旧池空闲连接自然回收）。
func routeKey(s *Site) string {
	a := s.Adv
	prefix := "http1+"
	if a.BackendH2() {
		prefix = "h2+"
	}
	insecure := ""
	if a.BackendInsecure {
		insecure = "#insecure"
	}
	return prefix + s.Scheme + "://" + s.BackendHost + ":" + strconv.Itoa(s.BackendPort) +
		insecure + "#" + strconv.FormatBool(a.UpstreamKeepalive) +
		"#" + strconv.Itoa(a.UpstreamIdleSec) + "#" + strconv.Itoa(a.UpstreamMaxIdleConns)
}

type transportEntry struct {
	key string
	tr  http.RoundTripper
}

var (
	transportMu sync.Mutex
	transports  = map[int64]*transportEntry{}
)

// transportFor 取站点回源 RoundTripper（按 routeKey 复用，配置变化即重建）
func transportFor(s *Site) http.RoundTripper {
	key := routeKey(s)
	transportMu.Lock()
	defer transportMu.Unlock()
	if e := transports[s.ID]; e != nil && e.key == key {
		return e.tr
	}
	if e := transports[s.ID]; e != nil {
		closeIdle(e.tr) // 配置已变：旧池空闲连接立即释放
	}
	tr := newTransport(s)
	transports[s.ID] = &transportEntry{key: key, tr: tr}
	return tr
}

func newTransport(s *Site) http.RoundTripper {
	a := s.Adv
	connectTimeout := time.Duration(a.ConnectSec) * time.Second
	dialer := &net.Dialer{Timeout: connectTimeout}
	if a.BackendH2() {
		// 回源 HTTP/2：https 经 ALPN 只通告 h2（后端不支持 h2 时明确失败，不静默降级，
		// 对齐 Java backendH2TlsCtx + newH2Parent 判定）；http 走明文 prior-knowledge h2c。
		// 连接/流并发由 x/net/http2 自管（等价 Java h2 池语义）。
		// 本版 http2.Transport 仅有 DialTLSContext（所有拨号均经它）：按站点 scheme 分流。
		httpsBackend := s.Scheme == "https"
		dialTLS := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if !httpsBackend {
				return c, nil // 明文 h2c：不包装 TLS
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			tc := tls.Client(c, &tls.Config{
				ServerName:         host,
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: a.BackendInsecure,
				MinVersion:         tls.VersionTLS12,
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = c.Close()
				return nil, err
			}
			if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" {
				_ = tc.Close()
				return nil, fmt.Errorf("后端未协商 HTTP/2（ALPN=%s）", proto)
			}
			return tc, nil
		}
		return &http2.Transport{
			AllowHTTP:      true, // 明文 scheme=http 时走 prior-knowledge h2c
			DialTLSContext: dialTLS,
		}
	}
	// 回源 HTTP/1.1：池化关闭时每请求短连接（Connection: close 语义），开启时按空闲参数复用
	tr := &http.Transport{
		DisableKeepAlives:     !a.UpstreamKeepalive,
		MaxIdleConnsPerHost:   a.UpstreamMaxIdleConns,
		IdleConnTimeout:       time.Duration(a.UpstreamIdleSec) * time.Second,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: time.Duration(a.IdleSec) * time.Second,
		ExpectContinueTimeout: 0, // 对齐 Java：剥离 Expect，不转发也不代回 100
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: a.BackendInsecure, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
	}
	return tr
}

func closeIdle(tr http.RoundTripper) {
	if c, ok := tr.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func closeIdleTransports() {
	transportMu.Lock()
	defer transportMu.Unlock()
	for id, e := range transports {
		closeIdle(e.tr)
		delete(transports, id)
	}
}
