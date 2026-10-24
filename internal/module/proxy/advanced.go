package proxy

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	"NexHomeGo/internal/core"
)

// 代理站点高级配置（proxy_site.advanced 列的解析结果），字段、默认值、校验文案与键序
// 逐一复刻 Java ProxyAdvanced；JSON 回写供前端预填与「自定义 JSON」页展示。

// HeaderOp 请求/响应头改写操作。
type HeaderOp struct {
	Op    string
	Name  string
	Value string
}

// forbiddenHeaders 禁止改写的头部（逐跳/框架自控头，改写会破坏转发正确性）。
var forbiddenHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true, "content-length": true,
	"host": true, "date": true, "server": true, "x-cache": true,
}

// defaultCacheExtensions 默认缓存扩展名（静态资源类）。
var defaultCacheExtensions = []string{"js", "css", "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "woff", "woff2", "ttf"}

// defaultIndexFiles 静态站点默认首页文件名（按序探测）。
var defaultIndexFiles = []string{"index.html", "index.htm"}

// StaticOpts 静态站点发布选项（mode=STATIC 时生效），JSON 子对象 static。
type StaticOpts struct {
	// IndexFiles 首页文件候选名（目录请求按序探测，命中即返回）。
	IndexFiles []string
	// SPAFallback 前端路由回退：未命中的页面请求（Accept 含 text/html）返回首页文件。
	SPAFallback bool
	// DirListing 允许目录浏览（无首页文件的目录输出文件列表）；否则 404。
	DirListing bool
	// Precompressed 优先使用同名 .br / .gz 预压缩文件（需先自行 gzip/brotli 生成）。
	Precompressed bool
	// CacheControl 附加响应头 Cache-Control（空=不附加，仅靠 ETag/Last-Modified 协商缓存）。
	CacheControl string
}

// Advanced 站点高级配置。
type Advanced struct {
	ReqHeaders  []HeaderOp
	RespHeaders []HeaderOp
	// pathRewrite / stripPrefix 二选一：nil 表示未配置
	PathRewriteFrom *string
	PathRewriteTo   *string
	StripPrefix     *string
	// Static 静态站点发布选项（mode=STATIC 时生效）
	Static          StaticOpts
	ConnectSec      int
	IdleSec         int
	MaxBodyMB       int
	RateLimitRps    float64
	AuthUser        string
	AuthPass        string
	IPAllow         []string
	BackendInsecure bool

	// 回源长连接池（upstream keepalive）
	UpstreamKeepalive    bool
	UpstreamIdleSec      int
	UpstreamMaxIdleConns int

	// 回源 HTTP/2（h2c / ALPN h2）与前端 ALPN 通告
	BackendProtocol        string
	FrontProtocol          string
	H2MaxConcurrentStreams int
	H2MaxConns             int

	// 文件缓存
	CacheEnabled         bool
	CacheTtlSec          int
	CacheInactiveSec     int
	CacheMaxMB           int
	CacheMaxItemMB       int
	CacheRespectUpstream bool
	CacheExtensions      []string
}

func defaults() *Advanced {
	return &Advanced{
		ReqHeaders:             []HeaderOp{},
		RespHeaders:            []HeaderOp{},
		Static:                 StaticOpts{IndexFiles: defaultIndexFiles, Precompressed: true},
		ConnectSec:             10,
		IdleSec:                300,
		MaxBodyMB:              0,
		RateLimitRps:           0,
		IPAllow:                []string{},
		BackendInsecure:        false,
		UpstreamKeepalive:      false,
		UpstreamIdleSec:        60,
		UpstreamMaxIdleConns:   32,
		BackendProtocol:        "http1",
		FrontProtocol:          "h2",
		H2MaxConcurrentStreams: 100,
		H2MaxConns:             4,
		CacheEnabled:           false,
		CacheTtlSec:            3600,
		CacheInactiveSec:       604800,
		CacheMaxMB:             256,
		CacheMaxItemMB:         8,
		CacheRespectUpstream:   true,
		CacheExtensions:        defaultCacheExtensions,
	}
}

// BackendH2 回源是否走 HTTP/2。
func (a *Advanced) BackendH2() bool { return a.BackendProtocol == "h2" }

// FrontH2 前端是否通告 h2（ALPN）。
func (a *Advanced) FrontH2() bool { return a.FrontProtocol != "http1" }

var (
	headerNameRe  = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)
	extRe         = regexp.MustCompile(`^[a-z0-9]{1,10}$`)
	controlCharRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	ipAllowBadRe  = regexp.MustCompile(`[\s,]`)
	maxAgeRe      = regexp.MustCompile(`max-age\s*=\s*(\d+)`)
	// indexFileRe 首页文件名：纯文件名（不含目录分隔符），不得以点开头（避开隐藏文件）。
	indexFileRe = regexp.MustCompile(`^[A-Za-z0-9_$][A-Za-z0-9._$-]{0,63}$`)
)

// parseAdvanced 解析并校验 advanced JSON；非法输入返回 error（文案对齐 Java，由管理接口映射为 400）。
// 严格解析：非法 JSON / 非 JSON 对象一律拒绝，避免坏配置被静默洗白为默认值。
func parseAdvanced(text string) (*Advanced, error) {
	a := defaults()
	if strings.TrimSpace(text) == "" {
		return a, nil
	}
	var raw interface{}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("advanced 不是合法 JSON: %s", err.Error())
	}
	if more := strings.TrimSpace(rest(dec)); more != "" {
		return nil, fmt.Errorf("advanced 不是合法 JSON: trailing %q", more)
	}
	o, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("advanced 必须是 JSON 对象")
	}

	var err error
	if a.ReqHeaders, err = parseHeaderOps(o, "reqHeaders"); err != nil {
		return nil, err
	}
	if a.RespHeaders, err = parseHeaderOps(o, "respHeaders"); err != nil {
		return nil, err
	}

	if el, isNull := objGet(o, "pathRewrite"); el != nil && !isNull {
		pr, ok := el.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("pathRewrite 必须是 JSON 对象")
		}
		from, err2 := requirePath(core.BodyStr(pr, "from"), "pathRewrite.from")
		if err2 != nil {
			return nil, err2
		}
		to, err2 := requirePath(core.BodyStr(pr, "to"), "pathRewrite.to")
		if err2 != nil {
			return nil, err2
		}
		if from == "" || to == "" {
			return nil, fmt.Errorf("pathRewrite 的 from/to 均不能为空")
		}
		a.PathRewriteFrom, a.PathRewriteTo = &from, &to
	}
	if el, isNull := objGet(o, "stripPrefix"); el != nil && !isNull {
		v, err2 := requirePath(core.BodyStr(o, "stripPrefix"), "stripPrefix")
		if err2 != nil {
			return nil, err2
		}
		if v == "" {
			return nil, fmt.Errorf("stripPrefix 不能为空字符串")
		}
		a.StripPrefix = &v
	}
	if has(o, "stripPrefix") && has(o, "pathRewrite") {
		return nil, fmt.Errorf("stripPrefix 与 pathRewrite 只能二选一")
	}

	if el, isNull := objGet(o, "timeout"); el != nil && !isNull {
		t, ok := el.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("timeout 必须是 JSON 对象")
		}
		if a.ConnectSec, err = rangeInt(t, "connectSec", a.ConnectSec, 1, 120, "timeout.connectSec"); err != nil {
			return nil, err
		}
		if a.IdleSec, err = rangeInt(t, "idleSec", a.IdleSec, 5, 86400, "timeout.idleSec"); err != nil {
			return nil, err
		}
	}
	if a.MaxBodyMB, err = rangeInt(o, "maxBodyMB", a.MaxBodyMB, 0, 102400, "maxBodyMB"); err != nil {
		return nil, err
	}
	if a.RateLimitRps, err = rangeDouble(o, "rateLimitRps", a.RateLimitRps, 0, 1000000, "rateLimitRps"); err != nil {
		return nil, err
	}

	if el, isNull := objGet(o, "basicAuth"); el != nil && !isNull {
		ba, ok := el.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("basicAuth 必须是 JSON 对象")
		}
		a.AuthUser = strings.TrimSpace(core.BodyStr(ba, "user"))
		a.AuthPass = core.BodyStr(ba, "pass")
		if a.AuthUser != "" {
			if a.AuthPass == "" {
				return nil, fmt.Errorf("basicAuth 配置了 user 时 pass 不能为空")
			}
			if strings.Contains(a.AuthUser, ":") || controlCharRe.MatchString(a.AuthUser) ||
				controlCharRe.MatchString(a.AuthPass) {
				return nil, fmt.Errorf("basicAuth 的 user 不能含冒号/控制字符")
			}
		}
	}
	if el, isNull := objGet(o, "ipAllow"); el != nil && !isNull {
		arr, ok := el.([]interface{})
		if !ok {
			return nil, fmt.Errorf("ipAllow 必须是 JSON 数组")
		}
		list := []string{}
		for _, e := range arr {
			v := strings.TrimSpace(strOf(e))
			if v == "" {
				return nil, fmt.Errorf("ipAllow 存在空条目")
			}
			if ipAllowBadRe.MatchString(v) || controlCharRe.MatchString(v) {
				return nil, fmt.Errorf("ipAllow 条目非法（应为 IP 或 IP 前缀，不能含空白/逗号）: %s", v)
			}
			list = append(list, strings.ToLower(v))
		}
		a.IPAllow = list
	}
	a.BackendInsecure = core.BodyBool(o, "backendInsecure", a.BackendInsecure)
	if el, isNull := objGet(o, "backendProtocol"); el != nil && !isNull {
		a.BackendProtocol = strings.ToLower(strings.TrimSpace(core.BodyStr(o, "backendProtocol")))
		if a.BackendProtocol != "http1" && a.BackendProtocol != "h2" {
			return nil, fmt.Errorf("backendProtocol 只能是 http1 或 h2: %s", a.BackendProtocol)
		}
	}
	if a.H2MaxConcurrentStreams, err = rangeInt(o, "h2MaxConcurrentStreams", a.H2MaxConcurrentStreams, 1, 1000, "h2MaxConcurrentStreams"); err != nil {
		return nil, err
	}
	if a.H2MaxConns, err = rangeInt(o, "h2MaxConns", a.H2MaxConns, 1, 1024, "h2MaxConns"); err != nil {
		return nil, err
	}
	if el, isNull := objGet(o, "frontProtocol"); el != nil && !isNull {
		a.FrontProtocol = strings.ToLower(strings.TrimSpace(core.BodyStr(o, "frontProtocol")))
		if a.FrontProtocol != "h2" && a.FrontProtocol != "http1" {
			return nil, fmt.Errorf("frontProtocol 只能是 h2 或 http1: %s", a.FrontProtocol)
		}
	}
	a.UpstreamKeepalive = core.BodyBool(o, "upstreamKeepalive", a.UpstreamKeepalive)
	if a.UpstreamIdleSec, err = rangeInt(o, "upstreamIdleSec", a.UpstreamIdleSec, 1, 3600, "upstreamIdleSec"); err != nil {
		return nil, err
	}
	if a.UpstreamMaxIdleConns, err = rangeInt(o, "upstreamMaxIdleConns", a.UpstreamMaxIdleConns, 1, 4096, "upstreamMaxIdleConns"); err != nil {
		return nil, err
	}

	if el, isNull := objGet(o, "static"); el != nil && !isNull {
		s, ok := el.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("static 必须是 JSON 对象")
		}
		if iel, inNull := objGet(s, "indexFiles"); iel != nil && !inNull {
			arr, ok := iel.([]interface{})
			if !ok {
				return nil, fmt.Errorf("static.indexFiles 必须是 JSON 数组")
			}
			idx := []string{}
			for _, e := range arr {
				v := strings.TrimSpace(strOf(e))
				if !indexFileRe.MatchString(v) {
					return nil, fmt.Errorf("static.indexFiles 条目非法（应为纯文件名，如 index.html）: %s", v)
				}
				idx = append(idx, v)
			}
			a.Static.IndexFiles = idx
		}
		a.Static.SPAFallback = core.BodyBool(s, "spaFallback", a.Static.SPAFallback)
		a.Static.DirListing = core.BodyBool(s, "dirListing", a.Static.DirListing)
		a.Static.Precompressed = core.BodyBool(s, "precompressed", a.Static.Precompressed)
		if cc := strings.TrimSpace(core.BodyStr(s, "cacheControl")); cc != "" {
			if strings.ContainsAny(cc, "\r\n") || len(cc) > 200 {
				return nil, fmt.Errorf("static.cacheControl 不能含换行且不超过 200 字符: %s", cc)
			}
			a.Static.CacheControl = cc
		}
	}
	if el, isNull := objGet(o, "cache"); el != nil && !isNull {
		c, ok := el.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("cache 必须是 JSON 对象")
		}
		a.CacheEnabled = core.BodyBool(c, "enabled", a.CacheEnabled)
		if a.CacheTtlSec, err = rangeInt(c, "ttlSec", a.CacheTtlSec, 1, 31536000, "cache.ttlSec"); err != nil {
			return nil, err
		}
		if a.CacheInactiveSec, err = rangeInt(c, "inactiveSec", a.CacheInactiveSec, 60, 31536000, "cache.inactiveSec"); err != nil {
			return nil, err
		}
		if a.CacheMaxMB, err = rangeInt(c, "maxMB", a.CacheMaxMB, 1, 1048576, "cache.maxMB"); err != nil {
			return nil, err
		}
		if a.CacheMaxItemMB, err = rangeInt(c, "maxItemMB", a.CacheMaxItemMB, 1, 1024, "cache.maxItemMB"); err != nil {
			return nil, err
		}
		a.CacheRespectUpstream = core.BodyBool(c, "respectUpstream", a.CacheRespectUpstream)
		if eel, enumNull := objGet(c, "extensions"); eel != nil && !enumNull {
			arr, ok := eel.([]interface{})
			if !ok {
				return nil, fmt.Errorf("cache.extensions 必须是 JSON 数组")
			}
			ext := []string{}
			for _, e := range arr {
				v := strings.ToLower(strings.TrimSpace(strOf(e)))
				if !extRe.MatchString(v) {
					return nil, fmt.Errorf("cache.extensions 条目非法（应为纯扩展名，如 js）: %s", v)
				}
				ext = append(ext, v)
			}
			a.CacheExtensions = ext
		}
	}
	return a, nil
}

// ToJson 回写完整 JSON（含默认值），键序与 Java Gson JsonObject 逐一一致。
func (a *Advanced) ToJson() *core.Row {
	o := core.NewRow()
	o.Set("reqHeaders", headerOpsToJson(a.ReqHeaders))
	o.Set("respHeaders", headerOpsToJson(a.RespHeaders))
	if a.PathRewriteFrom != nil {
		o.Set("pathRewrite", core.NewRow().Set("from", *a.PathRewriteFrom).Set("to", *a.PathRewriteTo))
	} else if a.StripPrefix != nil {
		o.Set("stripPrefix", *a.StripPrefix)
	}
	o.Set("timeout", core.NewRow().Set("connectSec", a.ConnectSec).Set("idleSec", a.IdleSec))
	o.Set("static", core.NewRow().
		Set("indexFiles", stringListJson(a.Static.IndexFiles)).
		Set("spaFallback", a.Static.SPAFallback).
		Set("dirListing", a.Static.DirListing).
		Set("precompressed", a.Static.Precompressed).
		Set("cacheControl", a.Static.CacheControl))
	o.Set("maxBodyMB", a.MaxBodyMB)
	o.Set("rateLimitRps", gsonFloat(a.RateLimitRps))
	o.Set("basicAuth", core.NewRow().Set("user", a.AuthUser).Set("pass", a.AuthPass))
	ip := make([]interface{}, 0, len(a.IPAllow))
	for _, v := range a.IPAllow {
		ip = append(ip, v)
	}
	o.Set("ipAllow", ip)
	o.Set("backendInsecure", a.BackendInsecure)
	o.Set("backendProtocol", a.BackendProtocol)
	o.Set("frontProtocol", a.FrontProtocol)
	o.Set("h2MaxConcurrentStreams", a.H2MaxConcurrentStreams)
	o.Set("h2MaxConns", a.H2MaxConns)
	o.Set("upstreamKeepalive", a.UpstreamKeepalive)
	o.Set("upstreamIdleSec", a.UpstreamIdleSec)
	o.Set("upstreamMaxIdleConns", a.UpstreamMaxIdleConns)
	ext := make([]interface{}, 0, len(a.CacheExtensions))
	for _, v := range a.CacheExtensions {
		ext = append(ext, v)
	}
	o.Set("cache", core.NewRow().
		Set("enabled", a.CacheEnabled).
		Set("ttlSec", a.CacheTtlSec).
		Set("inactiveSec", a.CacheInactiveSec).
		Set("maxMB", a.CacheMaxMB).
		Set("maxItemMB", a.CacheMaxItemMB).
		Set("respectUpstream", a.CacheRespectUpstream).
		Set("extensions", ext))
	return o
}

func headerOpsToJson(ops []HeaderOp) []interface{} {
	arr := make([]interface{}, 0, len(ops))
	for _, h := range ops {
		arr = append(arr, core.NewRow().Set("op", h.Op).Set("name", h.Name).Set("value", h.Value))
	}
	return arr
}

// stringListJson 字符串切片 -> JSON 数组（回写用，空切片输出 [] 而非 null）。
func stringListJson(list []string) []interface{} {
	arr := make([]interface{}, 0, len(list))
	for _, v := range list {
		arr = append(arr, v)
	}
	return arr
}

func parseHeaderOps(o map[string]interface{}, key string) ([]HeaderOp, error) {
	el, isNull := objGet(o, key)
	if el == nil || isNull {
		return []HeaderOp{}, nil
	}
	arr, ok := el.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s 必须是 JSON 数组", key)
	}
	list := []HeaderOp{}
	for _, e := range arr {
		h, ok := e.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s 条目必须是 JSON 对象", key)
		}
		op := strings.ToLower(strings.TrimSpace(core.BodyStr(h, "op")))
		name := strings.TrimSpace(core.BodyStr(h, "name"))
		value := strings.TrimSpace(core.BodyStr(h, "value"))
		if op != "set" && op != "delete" {
			return nil, fmt.Errorf("%s.op 只能是 set 或 delete: %s", key, op)
		}
		if !headerNameRe.MatchString(name) {
			return nil, fmt.Errorf("%s.name 不是合法 HTTP 头名: %s", key, name)
		}
		if forbiddenHeaders[strings.ToLower(name)] {
			return nil, fmt.Errorf("%s 不允许改写头: %s（由代理框架自动控制）", key, name)
		}
		if op == "set" && value != "" && strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("%s.value 不能含换行（头注入风险）: %s", key, name)
		}
		list = append(list, HeaderOp{Op: op, Name: name, Value: value})
	}
	return list, nil
}

func requirePath(v, field string) (string, error) {
	if v != "" && !strings.HasPrefix(v, "/") {
		return "", fmt.Errorf("%s 必须以 / 开头: %s", field, v)
	}
	if strings.ContainsAny(v, " \r\n") {
		return "", fmt.Errorf("%s 不能含空白/换行: %s", field, v)
	}
	return v, nil
}

func rangeInt(o map[string]interface{}, key string, def, min, max int, field string) (int, error) {
	el, isNull := objGet(o, key)
	if el == nil || isNull {
		return def, nil
	}
	n, ok := el.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s 必须是整数", field)
	}
	f, err := n.Float64()
	if err != nil || math.Trunc(f) != f || f < math.MinInt32 || f > math.MaxInt32 {
		return 0, fmt.Errorf("%s 必须是整数", field)
	}
	v := int(f)
	if v < min || v > max {
		return 0, fmt.Errorf("%s 必须在 %d-%d 之间: %d", field, min, max, v)
	}
	return v, nil
}

func rangeDouble(o map[string]interface{}, key string, def, min, max float64, field string) (float64, error) {
	el, isNull := objGet(o, key)
	if el == nil || isNull {
		return def, nil
	}
	n, ok := el.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s 必须是数字", field)
	}
	v, err := n.Float64()
	if err != nil {
		return 0, fmt.Errorf("%s 必须是数字", field)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%s 必须在 %s-%s 之间: %s", field, gsonFloat(min), gsonFloat(max), gsonFloat(v))
	}
	return v, nil
}

// ---------- 小工具 ----------

func has(o map[string]interface{}, k string) bool {
	_, ok := o[k]
	return ok
}

// objGet 取值并标注是否 JSON null（Java o.has(k) && !o.get(k).isJsonNull() 语义）。
func objGet(o map[string]interface{}, k string) (interface{}, bool) {
	v, ok := o[k]
	if !ok {
		return nil, false
	}
	return v, v == nil
}

func strOf(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

// rest 返回 Decoder 未消费的剩余文本（严格拒绝尾部垃圾）。
func rest(dec *json.Decoder) string {
	var extra interface{}
	if err := dec.Decode(&extra); err != nil {
		return ""
	}
	return fmt.Sprint(extra)
}

// gsonFloat Gson/Java double 字符串形态：整值输出 "12.0"（对齐 Java Double.toString）。
func gsonFloat(v float64) json.Number {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return json.Number(fmt.Sprintf("%.1f", v))
	}
	return json.Number(trimNum(v))
}

func trimNum(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return fmt.Sprintf("%d", int64(v))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", v), "0"), ".")
}
