package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// 请求处理链：与 Java ProxyHandler.startRequest 逐分支对齐（顺序与文案一致）；
// 回源中继与响应回写对齐 BackendRelay.channelRead0（Go 同步模型下即一次 RoundTrip + 流式 copy）。

// serveRequest 单请求入口（https 标记由监听口决定，等价 Java IS_HTTPS 属性）
func serveRequest(w http.ResponseWriter, r *http.Request, https bool) {
	isH2 := r.ProtoMajor == 2
	// 慢速请求体防护：ReadHeaderTimeout 只覆盖头部，半截 body 可长期占住连接（实测 40s 未断）。
	setBodyReadDeadline(w, r)
	hostHdr := r.Host
	if hostHdr == "" {
		hostHdr = r.Header.Get("Host")
	}
	if strings.TrimSpace(hostHdr) == "" {
		sendSimple(w, 400, "缺少 Host 请求头", "", "", false)
		return
	}
	host := hostOnly(hostHdr)
	uri := r.URL.RequestURI()
	if !strings.HasPrefix(uri, "/") {
		sendSimple(w, 400, "仅支持标准请求路径（不支持 CONNECT/绝对 URI）", "", "", false)
		return
	}
	q := strings.IndexByte(uri, '?')
	path := uri
	query := ""
	if q >= 0 {
		path = uri[:q]
		query = uri[q+1:]
	}
	// 路径穿越防护只针对「段级 ..」（/a/../b）：段内含连续点（"a...b"、"..hidden"）不算，
	// 避免误伤 Gitea compare 等合法业务路径。
	// 必须同时检查原始 URI 与解码后的 Path：%2e%2e 这类编码形态在原始 URI 中没有字面量 ".."，
	// 却能由后端或下游框架解码成上跳段（已实测可透传到后端）。
	if hasDotDotSegment(path) || hasDotDotSegment(r.URL.Path) {
		sendSimple(w, 400, "请求路径非法（包含 .. 上跳段）", "", "", false)
		return
	}

	site := routeMatch(host, path)
	if site == nil {
		sendNotFoundPage(w, host, path+joinQuery(query), true)
		return
	}
	st := statsFor(site.ID)
	st.requests.Add(1)
	st.rate.inc()

	adv := site.Adv
	// peerIp：直连对端地址，回源时向下游追加 XFF 链；clientIp：解析后的访客真实 IP
	peerIp := peerAddrOf(r)
	clientIp := resolveClientIp(r, peerIp)
	statsRecord(host, clientIp) // 访问统计：路由命中即计一次（含被访问控制拒绝的请求）

	// 访问控制链：IP 白名单 -> BasicAuth -> 限流 -> 请求体上限
	// 白名单必须按「显式可信代理」解析来源 IP：auto 策略把环回/私网对端默认为可信代理，
	// 内网或本机直连者自带 X-Forwarded-For 即可冒充白名单地址（已实测 403 变 200）。
	guardIp := resolveGuardIP(r, peerIp)
	if len(adv.IPAllow) > 0 && !ipAllowed(guardIp, adv.IPAllow) {
		sendSimple(w, 403, "来源 IP 不在白名单内: "+guardIp, "", "", true)
		return
	}
	if adv.AuthUser != "" {
		// BasicAuth 失败锁定：键为 TCP 对端（不可伪造，转发头与本判定无关），
		// 防止凭据被在线无限爆破（已实测 50 次错误凭据零限速）。锁定期直接 429，
		// 不再给出 WWW-Authenticate 挑战（避免诱导客户端立即重试）。
		if remain := basicAuthLockedMs(peerIp); remain > 0 {
			sendSimple(w, 429, "认证失败次数过多，已临时锁定，请约 "+
				strconv.Itoa(int((remain+59_999)/60_000))+" 分钟后再试",
				"Retry-After", strconv.Itoa(int((remain+999)/1000)), true)
			return
		}
		if !checkBasicAuth(r, adv) {
			baRecordFail(peerIp)
			realm := "Basic realm=\"" + site.Name + "\""
			sendSimple(w, 401, "需要 Basic 认证（"+site.Name+"）", "WWW-Authenticate", realm, true)
			return
		}
		baReset(peerIp)
	}
	if adv.RateLimitRps > 0 && !bucketFor(site).tryAcquire() {
		sendSimple(w, 429, "请求过于频繁（限流 "+gsonFloat(adv.RateLimitRps).String()+" QPS）",
			"Retry-After", "1", true)
		return
	}
	bodyLen := r.ContentLength
	chunkedReq := isChunkedRequest(r)
	if adv.MaxBodyMB > 0 && (bodyLen > int64(adv.MaxBodyMB)*1024*1024 ||
		(bodyLen < 0 && chunkedReq)) {
		// chunked 请求体无声明长度，无法流式限长，直接拒绝（对齐 nginx client_max_body_size 语义）
		sendSimple(w, 413, "请求体超过上限 "+strconv.Itoa(adv.MaxBodyMB)+" MB（chunked 请求体需声明 Content-Length）",
			"", "", false)
		return
	}
	// 强制 HTTPS 跳转（仅明文口）
	if !https && site.ForceHttps {
		hp := boundHttpsPort()
		loc := "https://" + host
		if hp > 0 && hp != 443 {
			loc += ":" + strconv.Itoa(hp)
		}
		loc += uri
		sendSimple(w, 301, "跳转到 "+loc, "Location", loc, true)
		return
	}

	// 静态站点发布：不经后端，直接对外提供站点目录文件（仅 GET/HEAD）
	if site.Mode == ModeStatic {
		serveStatic(w, r, site, path, query, st)
		return
	}

	upath := upstreamPath(site, path, query)

	// WebSocket 等 Upgrade 请求：原始字节隧道（仅 HTTP/1.1）
	if isUpgrade(r) {
		if isH2 {
			sendSimple(w, 400, "HTTP/2 连接不支持协议升级（WebSocket 请经 HTTP/1.1）", "", "", true)
			return
		}
		if adv.BackendH2() {
			// h2 回源无法承载 Upgrade（RFC 7540 8.4）：明确拒绝而不给语义不明的高速源错误
			sendSimple(w, 501, "该站点回源协议为 HTTP/2，不支持 Upgrade/WebSocket，请将回源协议改为 http1", "", "", true)
			return
		}
		startTunnel(w, r, site, upath, peerIp, st, https)
		return
	}
	// gRPC 依赖 trailer 里的 grpc-status：HTTP/1.1 前端无法透传 trailer，明确拒绝
	if adv.BackendH2() && !isH2 && isGrpc(r) {
		sendSimple(w, 501, "gRPC 需经 HTTP/2 前端访问（本连接为 HTTP/1.1，无法透传 grpc-status trailer）", "", "", true)
		return
	}

	// 文件缓存查询（GET、无 Authorization、无 Range、无 Cookie）
	// 缓存键只含 scheme+host+uri，不含请求头；带 Cookie 的响应可能是因人而异的私有内容，
	// 不排除会被写入共享缓存并被匿名访客命中（已实测可复现跨用户数据泄露）。
	mayCache := adv.CacheEnabled && r.Method == http.MethodGet &&
		r.Header.Get("Authorization") == "" && r.Header.Get("Range") == "" &&
		r.Header.Get("Cookie") == ""
	cacheKey := ""
	if mayCache {
		scheme := "http"
		if https {
			scheme = "https"
		}
		cacheKey = cacheBuildKey("GET", scheme+"://"+host+uri)
		if hit := cacheLookup(site.ID, cacheKey, false); hit != nil {
			serveCache(w, r, hit, isH2)
			return
		}
	}

	beginRelay(w, r, site, upath, path+joinQuery(query), peerIp, st, cacheKey,
		r.Method == http.MethodGet, https, isH2)
}

func joinQuery(query string) string {
	if query == "" {
		return ""
	}
	return "?" + query
}

// setBodyReadDeadline 给请求体读取设置截止时间（HTTP/1.1 与 HTTP/2 均由 ResponseController 支持）。
// 预算：30 秒基础 + 1 秒/MB 声明长度，上限 10 分钟；未声明长度按上限处理。
// 不支持时静默忽略（由服务器超时兜底），不影响正常大文件上传。
func setBodyReadDeadline(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return
	}
	budget := 30 * time.Second
	if r.ContentLength > 0 {
		budget += time.Duration(r.ContentLength/(1<<20)) * time.Second
	}
	if budget > 10*time.Minute {
		budget = 10 * time.Minute
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(budget))
}

// beginRelay 消息级中继：改写请求头后回源，响应流式回写；满足条件时旁路 tee 写缓存
func beginRelay(w http.ResponseWriter, r *http.Request, site *Site, upath, pathQuery, peerIp string,
	st *siteStats, cacheKey string, methodGet bool, https, isH2 bool) {
	adv := site.Adv
	st.active.Add(1)
	defer st.active.Add(-1)
	keepAlive := !isH2 && http1KeepAlive(r)

	target := site.Scheme + "://" + net.JoinHostPort(site.BackendHost, strconv.Itoa(site.BackendPort)) + upath
	var body io.Reader
	if r.Body != nil && (r.ContentLength > 0 || (r.ContentLength < 0 && isChunkedRequest(r))) {
		body = r.Body
	}
	fwd, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil { // 方法名含非法字符等（典型为伪造请求）：按内部错误处理
		// 明细（含目标地址解析结果）只入站点错误记录（管理员可见），错误页对访客给通用文案
		noteError(site, "请求构造失败: "+err.Error())
		sendErrorPage(w, 500, "内部错误：无法构造回源请求", "", false)
		return
	}
	fwd.Host = r.Host // 原 Host 透传（对齐 nginx 默认 proxy_set_header Host $http_host）
	copyHeaders(r.Header, fwd.Header)
	// 回源头：剥离逐跳头与 Expect（对齐 nginx：Expect 不转发后端）；
	// h2 回源不写 Connection/TE（RFC 7540 8.1.2.2 属违规头）；
	// h1 未开启池化则维持每请求短连接语义（Connection: close）
	if !adv.BackendH2() && !adv.UpstreamKeepalive {
		fwd.Header.Set("Connection", "close")
	}
	// 上游 chunked / h2 无 CL 的非 GET/HEAD 请求体：Go Transport 依 ContentLength=-1 自动重新
	// 声明 chunked 分帧，无需手工 Transfer-Encoding
	fwd.ContentLength = r.ContentLength
	fwd.Header.Set("X-Forwarded-Proto", protoTag(https))
	fwd.Header.Set("X-Forwarded-Host", r.Host)
	// 来源头一律由本代理重写：客户端自报的 X-Real-IP / Forwarded / CF-Connecting-IP 若原样透传，
	// 上游按「单值真实 IP」取用即可冒充任意来源（绕过上游自己的 IP 白名单、污染审计日志）。
	// 仅当对端是「显式可信代理」（security.trustedProxies 命中或策略 always）时才保留其链路，
	// 否则丢弃客户端链——auto 下环回/私网对端无法区分本机反代与内网直连者，不能作为依据。
	guardIp := resolveGuardIP(r, peerIp)
	fwd.Header.Del("X-Real-IP")
	fwd.Header.Del("Forwarded")
	fwd.Header.Del("CF-Connecting-IP")
	fwd.Header.Del(core.AliyunEsaRealClientIPHeader)
	fwd.Header.Del("X-Forwarded-For")
	fwd.Header.Set("X-Real-IP", guardIp)
	if core.TrustForwardedFromExplicit(peerIp, realIPPolicy) && strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != "" {
		fwd.Header.Set("X-Forwarded-For", r.Header.Get("X-Forwarded-For"))
	} else {
		fwd.Header.Set("X-Forwarded-For", peerIp)
	}
	fwd.Header.Set("X-Forwarded-By", "NexHome")
	applyHeaderOps(adv.ReqHeaders, fwd.Header)

	resp, err := transportFor(site).RoundTrip(fwd)
	if err != nil {
		if r.Context().Err() != nil { // 前端已断开：事务静默收尾
			return
		}
		connectFailed(site, w, err)
		return
	}
	defer resp.Body.Close()

	out := w.Header()
	copyHeaders(resp.Header, out)
	applyHeaderOps(adv.RespHeaders, out)

	status := resp.StatusCode
	// 缓存判定：开启 + GET + 200 + 扩展名命中 + 上游策略允许；
	// 含 Set-Cookie/Authorization/Vary 的响应不缓存（Vary 变体响应缓存 key 无变体维度）
	store := false
	var writer *cacheWriter
	var storeHeaders [][2]string
	var maxItemBytes int64
	var expiresAt int64
	if adv.CacheEnabled && methodGet && cacheKey != "" && status == 200 &&
		resp.Header.Get("Set-Cookie") == "" && resp.Header.Get("Authorization") == "" &&
		resp.Header.Get("Vary") == "" {
		ttl := cacheTtl(resp, adv)
		if ttl > 0 && extCacheable(pathQuery, adv) {
			writer = cacheNewWriter(site.ID, cacheKey, adv)
			if writer != nil {
				store = true
				maxItemBytes = int64(adv.CacheMaxItemMB) * 1024 * 1024
				expiresAt = nowMillis() + int64(ttl)*1000
				storeHeaders = collectStoreHeaders(out)
			}
		}
	}
	if adv.CacheEnabled {
		if store {
			out.Set("X-Cache", "MISS")
		} else {
			out.Set("X-Cache", "BYPASS")
		}
	}
	if !keepAlive {
		out.Set("Connection", "close") // 客户端要求关闭：响应完毕即关（h1）
	}
	// 上游 chunked / close 定界（无 Content-Length）时 Go 响应器自动为下游重新分帧；
	// 1xx/204/205/304 无 body，无需分帧（net/http 语义一致）
	w.WriteHeader(status)

	// 流式回写 + 旁路 tee
	buf := make([]byte, 64*1024)
	readErr := error(nil)
	for {
		n, rdErr := resp.Body.Read(buf)
		if n > 0 {
			if writer != nil {
				writer.Append(buf[:n])
				if writer.written > maxItemBytes { // 单文件超限：放弃缓存，中继不受影响
					writer.Abort()
					writer = nil
				}
			}
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				break // 前端断开：中止中继，不记后端错误
			}
		}
		if rdErr != nil {
			if rdErr != io.EOF {
				readErr = rdErr
			}
			break
		}
	}
	if writer != nil {
		if readErr != nil { // 响应异常/中断：清理临时文件
			writer.Abort()
		} else {
			writer.Finish(status, storeHeaders, expiresAt)
		}
	}
	if readErr != nil && r.Context().Err() == nil {
		// 后端在响应中途关闭连接：头已发出无法补错误页，只记错（对齐 Java channelInactive 有头中断）
		noteError(site, "后端在响应中途关闭连接")
	}
}

func protoTag(https bool) string {
	if https {
		return "https"
	}
	return "http"
}

// connectFailed 回源连接/传输失败：按 Java 阶段语义映射 504/502 并回错误页。
// 对外文案一律通用：err.Error() 含内网后端地址与操作系统错误原文，回显给匿名
// 访客等于免费的内网拓扑测绘（已实测 502 错误页泄露 dial tcp 明细）；
// 原始明细只入站点错误记录（noteError，管理员可见）。
func connectFailed(site *Site, w http.ResponseWriter, err error) {
	msg := err.Error()
	var code int
	var detail string
	var page string
	switch {
	case strings.Contains(msg, "timeout awaiting response headers") || errors.Is(err, context.DeadlineExceeded):
		code = 504
		detail = "后端响应超时（" + strconv.Itoa(site.Adv.IdleSec) + " 秒无响应头）"
		page = "后端响应超时，请稍后重试"
	case strings.Contains(msg, "malformed HTTP"):
		code = 502
		detail = "后端响应报文非法: " + msg
		page = "后端返回了无法解析的响应，请联系站点管理员"
	case strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset"):
		// 后端在响应前关闭连接（EOF/RST 且未收到响应头）；对外同样通用化，
		// 避免「已接受连接但被拒」与「拒绝连接」的差异被用于探测内网端口状态
		noteError(site, "后端在响应前关闭连接")
		sendErrorPage(w, 502, "后端暂时无法访问，请稍后重试", "", false)
		return
	default:
		code = 502
		detail = "后端连接失败: " + msg
		page = "后端暂时无法访问，请稍后重试"
	}
	noteError(site, detail)
	sendErrorPage(w, code, page, "", false)
}

// serveCache 文件缓存命中直出：存头 + Content-Length（按大小）+ 新 Date + X-Cache: HIT
func serveCache(w http.ResponseWriter, r *http.Request, hit *cacheEntry, isH2 bool) {
	keepAlive := !isH2 && http1KeepAlive(r)
	f, err := os.Open(hit.file)
	if err != nil {
		sendErrorPage(w, 500, "缓存文件读取失败: "+err.Error(),
			"请稍后重试，或在代理中心清空该站点的磁盘缓存。", false)
		return
	}
	defer f.Close()
	// 文件比索引记录短：响应头已发出无法改报错误，截断交付（对齐 Java 重置流收尾）
	out := w.Header()
	for _, h := range hit.headers {
		out.Add(h[0], h[1])
	}
	out.Set("Content-Length", strconv.FormatInt(hit.size, 10))
	out.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	out.Set("X-Cache", "HIT")
	if !keepAlive {
		out.Set("Connection", "close")
	}
	w.WriteHeader(hit.status)
	_, _ = io.CopyN(w, f, hit.size)
}

// ==================== 校验与工具 ====================

// hasDotDotSegment 按路径分隔符（/ 与 \，后者兼容 Windows 后端）切分后是否存在恰好等于 ".." 的路径段
func hasDotDotSegment(path string) bool {
	start := 0
	for start <= len(path) {
		slash := strings.IndexAny(path[start:], "/\\")
		end := len(path)
		if slash >= 0 {
			end = start + slash
		}
		if end-start == 2 && path[start] == '.' && path[start+1] == '.' {
			return true
		}
		if slash < 0 {
			break
		}
		start = end + 1
	}
	return false
}

func isUpgrade(r *http.Request) bool {
	up := r.Header.Get("Upgrade")
	conn := r.Header.Get("Connection")
	return strings.TrimSpace(up) != "" && strings.Contains(strings.ToLower(conn), "upgrade")
}

// isGrpc gRPC 请求判定（含 grpc-web 文本帧，均依赖 h2 trailer）
func isGrpc(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(strings.ToLower(ct), "application/grpc")
}

// isChunkedRequest Go 服务器已把上游 chunked 解析为 ContentLength=-1 + TransferEncoding 标记
func isChunkedRequest(r *http.Request) bool {
	for _, te := range r.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			return true
		}
	}
	return false
}

// http1KeepAlive 对齐 Netty HttpUtil.isKeepAlive：1.0 默认关、1.1 默认开，Connection: close 关闭
func http1KeepAlive(r *http.Request) bool {
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		return strings.EqualFold(r.Header.Get("Connection"), "keep-alive")
	}
	return !strings.EqualFold(r.Header.Get("Connection"), "close")
}

// ipAllowed IP 白名单：精确 IP，或显式以点结尾的网段前缀（192.168.1. 匹配 192.168.1.*）
func ipAllowed(ip string, allow []string) bool {
	v := strings.ToLower(ip)
	for _, a := range allow {
		if v == a {
			return true
		}
		if strings.HasSuffix(a, ".") && strings.HasPrefix(v, a) {
			return true // 仅显式前缀段，避免 10.0.0.5 误配 10.0.0.50
		}
	}
	return false
}

func checkBasicAuth(r *http.Request, adv *Advanced) bool {
	hdr := r.Header.Get("Authorization")
	if len(hdr) < 6 || !strings.EqualFold(hdr[:5], "Basic") {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(hdr[5:]))
	if err != nil {
		return false
	}
	i := strings.IndexByte(string(dec), ':')
	if i < 0 {
		return false
	}
	user := subtle.ConstantTimeCompare([]byte(string(dec)[:i]), []byte(adv.AuthUser)) == 1
	pass := subtle.ConstantTimeCompare([]byte(string(dec)[i+1:]), []byte(adv.AuthPass)) == 1
	return user && pass
}

// ==================== BasicAuth 失败锁定 ====================
// BasicAuth 常用于把内网服务经代理暴露到公网，凭据可被在线爆破且此前无任何限速。
// 计数键为 TCP 对端地址（peerAddrOf，转发头与本判定无关、不可伪造），
// 全站共享一个计数桶：对同一访客而言，逐站点尝试等价于逐凭据尝试。

const (
	basicAuthMaxFails    = 10   // 连续失败该次数后锁定该来源
	basicAuthLockMinutes = 15   // 锁定时长
	basicAuthMaxTracked  = 4096 // 计数桶容量上限（防内存放大）
)

type baFailState struct {
	count       int
	lockUntilMs int64
}

var (
	baFailsMu sync.Mutex
	baFails   = map[string]*baFailState{}
)

// basicAuthLockedMs 该来源 BasicAuth 锁定剩余毫秒数，0 表示未锁定（仅回收「锁定已过期」条目，
// 未锁定但仍在计数的活跃条目不得删除，否则失败计数永远无法累加到阈值）。
func basicAuthLockedMs(peer string) int64 {
	if peer == "" {
		return 0
	}
	baFailsMu.Lock()
	defer baFailsMu.Unlock()
	st := baFails[peer]
	if st == nil {
		return 0
	}
	now := nowMillis()
	if st.lockUntilMs > now {
		return st.lockUntilMs - now
	}
	if st.lockUntilMs > 0 {
		delete(baFails, peer) // 锁定已过期：回收
	}
	return 0
}

// baRecordFail 记一次认证失败；累计达阈值进入锁定并写全局日志。
func baRecordFail(peer string) {
	if peer == "" {
		return
	}
	baFailsMu.Lock()
	defer baFailsMu.Unlock()
	now := nowMillis()
	st := baFails[peer]
	if st == nil {
		if len(baFails) >= basicAuthMaxTracked && !purgeBAFailsLocked(now) {
			return // 计数表满且回收无果：丢弃本次计数（优先保证内存安全）
		}
		st = &baFailState{}
		baFails[peer] = st
	}
	if st.lockUntilMs > now {
		return // 已锁定不重复计数
	}
	st.count++
	if st.count < basicAuthMaxFails {
		return
	}
	st.lockUntilMs = now + int64(basicAuthLockMinutes)*60_000
	st.count = 0
	core.LogWarn(core.LogProxy, "BasicAuth 认证连续失败已达上限 (peer="+peer+"，锁定 "+
		strconv.Itoa(basicAuthLockMinutes)+" 分钟)")
}

// baReset 认证成功：清除该来源的失败计数。
func baReset(peer string) {
	if peer == "" {
		return
	}
	baFailsMu.Lock()
	delete(baFails, peer)
	baFailsMu.Unlock()
}

// purgeBAFailsLocked 回收一个未锁定条目（调用方持锁），返回是否腾出空位
func purgeBAFailsLocked(now int64) bool {
	for k, st := range baFails {
		if st.lockUntilMs <= now {
			delete(baFails, k)
			return true
		}
	}
	return false
}

// copyHeaders 头复制：剥离逐跳头与 Expect（含 Connection 头声明的附加逐跳头），保留其余
func copyHeaders(src http.Header, dst http.Header) {
	dynHop := connectionTokens(src)
	for name, vals := range src {
		n := strings.ToLower(name)
		if hopByHop(name) || n == "expect" || strings.HasPrefix(n, "x-http2-") {
			continue // x-http2-* 为流对象编解码器元数据头，不得透传
		}
		if dynHop != nil && dynHop[n] {
			continue
		}
		if n == "host" { // Go 服务器 Host 不在 Header；防御性兼容，避免双 Host
			continue
		}
		for _, v := range vals {
			dst.Add(name, v)
		}
	}
}

// connectionTokens Connection 头中声明的额外逐跳头名（RFC 7230 §6.1，小写；无则返回 nil）
func connectionTokens(h http.Header) map[string]bool {
	vals := h.Values("Connection")
	if len(vals) == 0 {
		vals = h["Connection"]
	}
	if len(vals) == 0 {
		return nil
	}
	var set map[string]bool
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			t := strings.TrimSpace(tok)
			if t == "" || hopByHop(t) {
				continue
			}
			if set == nil {
				set = map[string]bool{}
			}
			set[strings.ToLower(t)] = true
		}
	}
	return set
}

// applyHeaderOps 自定义头改写：delete 移除、set 覆盖
func applyHeaderOps(ops []HeaderOp, h http.Header) {
	for _, op := range ops {
		if op.Op == "delete" {
			h.Del(op.Name)
		} else {
			h.Set(op.Name, op.Value)
		}
	}
}

// cacheTtl 上游 Cache-Control 优先的有效期（秒）；0 = 不缓存
func cacheTtl(resp *http.Response, adv *Advanced) int {
	if !adv.CacheRespectUpstream {
		return adv.CacheTtlSec
	}
	cc := resp.Header.Get("Cache-Control")
	if strings.TrimSpace(cc) == "" {
		return adv.CacheTtlSec
	}
	v := strings.ToLower(cc)
	if strings.Contains(v, "no-store") || strings.Contains(v, "no-cache") || strings.Contains(v, "private") {
		return 0
	}
	if m := maxAgeRe.FindStringSubmatch(v); m != nil {
		if s, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			if s <= 0 {
				return 0
			}
			if s > 2147483647 {
				return 2147483647
			}
			return int(s)
		}
	}
	return adv.CacheTtlSec
}

// extCacheable 扩展名命中判定（未配置清单时缓存全部路径）
func extCacheable(pathAndQuery string, adv *Advanced) bool {
	if len(adv.CacheExtensions) == 0 {
		return true
	}
	ext := extensionOf(pathAndQuery)
	if ext == "" {
		return false
	}
	for _, e := range adv.CacheExtensions {
		if e == ext {
			return true
		}
	}
	return false
}

// collectStoreHeaders 待落盘响应头：剥离 Content-Length/Date/X-Cache（命中直出时重算）
func collectStoreHeaders(h http.Header) [][2]string {
	list := make([][2]string, 0, len(h))
	for name, vals := range h {
		n := strings.ToLower(name)
		if n == "content-length" || n == "date" || n == "x-cache" {
			continue
		}
		for _, v := range vals {
			list = append(list, [2]string{name, v})
		}
	}
	return list
}

func hostHeaderOf(r *http.Request) string {
	if h := r.Header.Get("Host"); h != "" {
		return h
	}
	return r.Host
}
