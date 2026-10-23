package proxy

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 反向代理中心管理服务（管理面）。逐一复刻 Java ProxyService：
// 全局开关/端口设置（存 app_config，前缀 proxy.）、站点 CRUD 与校验、
// 状态与证书清单查询、缓存清理；站点/证书变更后触发引擎热更新，
// 端口/开关变更重启监听引擎。转发数据面全部在 engine.go/handler.go。

const (
	keyEnabled   = "proxy.enabled"    // 全局开关（"1"=启用监听），默认关闭：关闭时不绑定任何端口
	keyHTTPPort  = "proxy.http.port"  //
	keyHTTPSPort = "proxy.https.port" //
	// 是否通过代理转发头解析访客真实来源 IP（"0"=关闭，其余含缺省=开启）
	keyTrustRealIp = "proxy.realip.trust_header"
	// 最近一次绑定/降级提示（页头告警条展示），空=正常
	keyLastError = "proxy.last_error"

	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
)

var certModes = map[string]bool{"AUTO": true, "TASK": true, "NONE": true}

// RegisterRoutes 注册 REST 接口。
func RegisterRoutes() {
	web.Route("GET", "/api/proxy/settings", getSettings)
	web.Route("POST", "/api/proxy/settings", saveSettings)
	web.Route("GET", "/api/proxy/sites", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM proxy_site ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(rows) // core.Rows 即 []*core.Row，保序列出
		return nil
	})
	web.Route("POST", "/api/proxy/sites", create)
	web.Route("PUT", "/api/proxy/sites/{id}", update)
	web.Route("DELETE", "/api/proxy/sites/{id}", remove)
	web.Route("POST", "/api/proxy/sites/toggle", toggle)
	// 新建站点表单预填：返回后端默认高级配置（与保存时规范化一致）
	web.Route("GET", "/api/proxy/defaults", func(c *web.Ctx) error {
		c.Ok(core.NewRow().Set("advanced", defaults().ToJson()))
		return nil
	})
	web.Route("GET", "/api/proxy/status", status)
	web.Route("GET", "/api/proxy/certs", func(c *web.Ctx) error {
		c.Ok(sslAPIView())
		return nil
	})
	web.Route("POST", "/api/proxy/certs/reload", func(c *web.Ctx) error {
		sslReload()
		c.Ok(core.NewRow().Set("certs", sslAPIView()))
		return nil
	})
	web.Route("POST", "/api/proxy/cache/purge", purgeCache)
}

// Init 启动接线：初始化文件缓存（重建索引 + 周期清理），并按开关拉起监听。
// 绑定失败不抛出（不拖垮进程），写入 proxy.last_error 供前端展示。
func Init() {
	geoLoad() // IP 归属地离线库（ip2region xdb，外部可覆盖，均缺失时降级留空）
	cacheInit(siteExists)
	statsInit() // 访问记录周期落库（独立于监听开关，关停期间不丢已累积增量）
	// 真实来源 IP 解析开关（默认开启）：读入内存供转发热路径直接取用，避免逐请求查库
	if v, err := core.GetConfig(keyTrustRealIp); err == nil {
		trustRealIp = v != "0"
	}
	if _, err := applyListener(); err != nil {
		core.LogError(core.LogProxy, "启动代理监听失败: "+err.Error())
	}
}

// applyListenerMu 对齐 Java applyListener 的 synchronized（仅串行化「重启监听」这一低频操作）。
var applyListenerMu sync.Mutex

func siteExists(id int64) bool {
	row, err := core.QueryOne("SELECT id FROM proxy_site WHERE id=?", id)
	return err == nil && row != nil
}

// ==================== 全局设置 ====================

func getSettings(c *web.Ctx) error {
	cfg, err := readCfg()
	if err != nil {
		return err
	}
	last, err := core.GetConfig(keyLastError)
	if err != nil {
		return err
	}
	c.Ok(core.NewRow().
		Set("enabled", cfg.enabled).
		Set("httpPort", cfg.httpPort).
		Set("httpsPort", cfg.httpsPort).
		Set("trustRealIp", trustRealIp).
		Set("lastError", orEmpty(last)))
	return nil
}

func saveSettings(c *web.Ctx) error {
	b := c.Body()
	enabled := core.BodyBool(b, "enabled", false)
	httpPort := core.BodyNum(b, "httpPort", defaultHTTPPort)
	httpsPort := core.BodyNum(b, "httpsPort", defaultHTTPSPort)
	if err := validatePorts(enabled, httpPort, httpsPort); err != nil {
		return err
	}
	// 真实来源 IP 解析开关（独立于监听开关，无需重启即生效）
	trust := core.BodyBool(b, "trustRealIp", trustRealIp)
	if err := core.SetConfig(keyTrustRealIp, boolCfg(trust)); err != nil {
		return err
	}
	trustRealIp = trust
	if err := core.SetConfig(keyEnabled, boolCfg(enabled)); err != nil {
		return err
	}
	if err := core.SetConfig(keyHTTPPort, strconv.Itoa(httpPort)); err != nil {
		return err
	}
	if err := core.SetConfig(keyHTTPSPort, strconv.Itoa(httpsPort)); err != nil {
		return err
	}
	warn, err := applyListener()
	if err != nil {
		return err
	}
	core.LogInfo(core.LogProxy, "代理设置已更新: enabled="+strconv.FormatBool(enabled)+
		" HTTP:"+strconv.Itoa(httpPort)+" HTTPS:"+strconv.Itoa(httpsPort))
	last, err := core.GetConfig(keyLastError)
	if err != nil {
		return err
	}
	// 响应 = listenView() 追加 lastError/warning（键序保持一致）
	r := listenView()
	for _, k := range r.Keys() {
		r.Set(k, r.Get(k))
	}
	r.Set("lastError", orEmpty(last))
	r.Set("warning", warn)
	c.Ok(r)
	return nil
}

// validatePorts 端口校验：范围、两代理口不互撞、均不与面板端口冲突（面板端口见 core.Port()）。
func validatePorts(enabled bool, http, https int) error {
	if !enabled {
		return nil // 关闭时不绑定端口，无需校验
	}
	if http < 1 || http > 65535 {
		return core.NewBadRequest("HTTP 端口需在 1-65535 之间")
	}
	if https < 1 || https > 65535 {
		return core.NewBadRequest("HTTPS 端口需在 1-65535 之间")
	}
	if http == https {
		return core.NewBadRequest("HTTP 与 HTTPS 端口不能相同: %d", http)
	}
	panel := core.Port()
	if http == panel || https == panel {
		return core.NewBadRequest("代理端口不能与面板 Web 端口相同: %d", panel)
	}
	return nil
}

// readCfg 读取全局配置快照。
func readCfg() (engineCfg, error) {
	enabled, err := core.GetConfig(keyEnabled)
	if err != nil {
		return engineCfg{}, err
	}
	httpPort, err := intCfg(keyHTTPPort, defaultHTTPPort)
	if err != nil {
		return engineCfg{}, err
	}
	httpsPort, err := intCfg(keyHTTPSPort, defaultHTTPSPort)
	if err != nil {
		return engineCfg{}, err
	}
	return engineCfg{enabled: enabled == "1", httpPort: httpPort, httpsPort: httpsPort}, nil
}

// applyListener 依当前配置重启监听：成功返回降级提示（可能为空串）并刷新 last_error；
// HTTP 绑定失败抛异常（调用方捕获记日志），last_error 写入失败原因。
func applyListener() (string, error) {
	applyListenerMu.Lock()
	defer applyListenerMu.Unlock()
	c, err := readCfg()
	if err != nil {
		return "", err
	}
	warn, err := engineStart(c)
	if err != nil {
		_ = core.SetConfig(keyLastError, err.Error())
		return "", err
	}
	if err := core.SetConfig(keyLastError, warn); err != nil { // warn 空串=正常（Java：null→"" 兜底）
		return "", err
	}
	return warn, nil
}

// ==================== 站点 CRUD ====================

// values 校验后的站点列值（advanced 为规范化后的 JSON 串）。
type values struct {
	name       string
	domains    string
	paths      string
	target     string
	forceHttps bool
	certMode   string
	certTaskId interface{} // nil → 列值 NULL
	advanced   string
	enabled    bool
}

func create(c *web.Ctx) error {
	b := c.Body()
	v, err := validate(b)
	if err != nil {
		return err
	}
	id, err := core.Insert(`INSERT INTO proxy_site(name, domains, paths, target, force_https, cert_mode,
    cert_task_id, advanced, enabled)
VALUES(?,?,?,?,?,?,?,?,?)`,
		v.name, v.domains, v.paths, v.target, boolToInt(v.forceHttps), v.certMode,
		v.certTaskId, v.advanced, boolToInt(v.enabled))
	if err != nil {
		return err
	}
	reloadSites()
	core.LogInfo(core.LogProxy, "新增代理站点: "+v.name+" -> "+v.target)
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

func update(c *web.Ctx) error {
	id := c.ParamLong("id")
	if _, err := mustGet(id); err != nil {
		return err
	}
	b := c.Body()
	v, err := validate(b)
	if err != nil {
		return err
	}
	if _, err = core.Update(`UPDATE proxy_site SET name=?, domains=?, paths=?, target=?, force_https=?,
    cert_mode=?, cert_task_id=?, advanced=?, enabled=? WHERE id=?`,
		v.name, v.domains, v.paths, v.target, boolToInt(v.forceHttps), v.certMode,
		v.certTaskId, v.advanced, boolToInt(v.enabled), id); err != nil {
		return err
	}
	reloadSites()
	core.LogInfo(core.LogProxy, "更新代理站点 #"+strconv.FormatInt(id, 10)+": "+v.name)
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	if _, err = core.Update("DELETE FROM proxy_site WHERE id=?", id); err != nil {
		return err
	}
	cachePurgeSite(id) // 站点删除即清空其磁盘缓存
	dropSiteState(id)  // 释放限流桶与运行统计，避免长期增删站点残留
	reloadSites()
	core.LogInfo(core.LogProxy, "删除代理站点 #"+strconv.FormatInt(id, 10)+": "+rowStr(row, "name"))
	c.Ok("已删除")
	return nil
}

func toggle(c *web.Ctx) error {
	b := c.Body()
	id := bodyInt64(b, "id")
	if id <= 0 {
		return core.NewBadRequest("缺少站点 id")
	}
	enabled := core.BodyBool(b, "enabled", false)
	if _, err := mustGet(id); err != nil {
		return err
	}
	if _, err := core.Update("UPDATE proxy_site SET enabled=? WHERE id=?", boolToInt(enabled), id); err != nil {
		return err
	}
	reloadSites()
	tag := "停用"
	if enabled {
		tag = "启用"
	}
	core.LogInfo(core.LogProxy, tag+"代理站点 #"+strconv.FormatInt(id, 10))
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

// ==================== 状态 / 缓存 ====================

func status(c *web.Ctx) error {
	last, err := core.GetConfig(keyLastError)
	if err != nil {
		return err
	}
	c.Ok(core.NewRow().
		Set("listen", listenView()).
		Set("sites", sitesStatusView()).
		Set("cache", cacheStatusView()).
		Set("lastError", orEmpty(last)))
	return nil
}

func purgeCache(c *web.Ctx) error {
	b := c.Body()
	siteId := bodyInt64(b, "siteId")
	if siteId > 0 {
		cachePurgeSite(siteId)
		core.LogInfo(core.LogProxy, "清理站点 #"+strconv.FormatInt(siteId, 10)+" 缓存")
		c.Ok("已清理该站点缓存")
		return nil
	}
	rows, err := core.Query("SELECT id FROM proxy_site")
	if err != nil {
		return err
	}
	for _, row := range rows {
		cachePurgeSite(int64Val(row.Get("id")))
	}
	core.LogInfo(core.LogProxy, "清理全部代理缓存")
	c.Ok("已清理全部缓存")
	return nil
}

// ==================== 校验 ====================

// validate 站点表单校验（顺序与文案逐字对齐 Java ProxyService.validate）。
func validate(b map[string]interface{}) (*values, error) {
	name := strings.TrimSpace(core.BodyStr(b, "name"))
	if name == "" {
		return nil, core.NewBadRequest("站点名称不能为空")
	}
	domains := strings.TrimSpace(core.BodyStr(b, "domains"))
	if err := validateDomains(domains); err != nil {
		return nil, err
	}
	paths := strings.TrimSpace(core.BodyStr(b, "paths"))
	if _, err := parsePaths(paths); err != nil { // 仅校验格式；空串=整站
		return nil, err
	}
	target := strings.TrimSpace(core.BodyStr(b, "target"))
	if err := validateTarget(target); err != nil {
		return nil, err
	}

	certMode := strings.ToUpper(strings.TrimSpace(fieldStr(b, "certMode", "cert_mode")))
	if certMode == "" {
		certMode = "AUTO"
	}
	var certTaskId interface{} // nil → NULL
	if !certModes[certMode] {
		return nil, core.NewBadRequest("证书模式只能是 AUTO / TASK / NONE: %s", certMode)
	}
	if certMode == "TASK" {
		tid := fieldNum(b, "certTaskId", "cert_task_id", 0)
		if tid <= 0 {
			return nil, core.NewBadRequest("证书模式为 TASK 时必须指定证书任务")
		}
		task, err := core.QueryOne("SELECT status FROM cert_task WHERE id=?", tid)
		if err != nil {
			return nil, err
		}
		if task == nil {
			return nil, core.NewBadRequest("证书任务不存在: #%d", tid)
		}
		// 只要求证书文件可用且未过期：续期失败（ERROR）不影响上次签发的证书继续对外服务
		if _, err := web.ResolveCertFile(int64(tid)); err != nil {
			return nil, err
		}
		certTaskId = tid
	}

	a, err := parseAdvanced(readAdvanced(b))
	if err != nil {
		return nil, err
	}
	advBytes, err := core.MarshalJSON(a.ToJson()) // 校验 + 规范化回写
	if err != nil {
		return nil, err
	}

	forceHttps := fieldBool(b, "forceHttps", "force_https", false)
	if forceHttps && certMode == "NONE" {
		return nil, core.NewBadRequest("强制 HTTPS 需要可用证书，证书模式不能为 NONE")
	}
	enabled := core.BodyBool(b, "enabled", true)
	return &values{name, domains, paths, target, forceHttps, certMode, certTaskId,
		string(advBytes), enabled}, nil
}

// ---------- 字段读取：兼容前端把列表行（DB 列名 snake_case）直接回写的编辑往返 ----------

func fieldStr(b map[string]interface{}, camel, snake string) string {
	if _, ok := b[camel]; ok {
		return core.BodyStr(b, camel)
	}
	return core.BodyStr(b, snake)
}

func fieldBool(b map[string]interface{}, camel, snake string, def bool) bool {
	if _, ok := b[camel]; ok {
		return core.BodyBool(b, camel, def)
	}
	if _, ok := b[snake]; ok {
		return core.BodyBool(b, snake, def)
	}
	return def
}

func fieldNum(b map[string]interface{}, camel, snake string, def int) int {
	if _, ok := b[camel]; ok {
		return core.BodyNum(b, camel, def)
	}
	return core.BodyNum(b, snake, def)
}

// readAdvanced advanced 允许为 JSON 对象或 JSON 字符串，统一取出文本再解析。
func readAdvanced(b map[string]interface{}) string {
	el, ok := b["advanced"]
	if !ok || el == nil {
		return ""
	}
	switch v := el.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case map[string]interface{}, []interface{}: // 对象/数组 → 序列化串（下游解析规范化，键序无关）
		buf, err := core.MarshalJSON(v)
		if err != nil {
			return ""
		}
		return string(buf)
	default: // bool 等原始值：getAsString 形态
		return core.BodyStr(b, "advanced")
	}
}

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM proxy_site WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("代理站点不存在: #%d", id)
	}
	return row, nil
}

func orEmpty(s string) string { return s }

func intCfg(key string, def int) (int, error) {
	v, err := core.GetConfig(key)
	if err != nil {
		return def, err
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	n, cerr := strconv.Atoi(v)
	if cerr != nil {
		return def, nil
	}
	return n, nil
}

// ==================== 关停 / 钩子 / Dashboard ====================

// Shutdown 关停接线：冲刷访问记录、释放离线库与监听资源（供进程退出时调用）。
func Shutdown() {
	engineShutdown()
	statsFlushNow() // 落库最后不足一个周期的访问增量，避免丢失
	geoClose()      // 释放 ip2region 库句柄
}

// OnCertRenewed 供 CertService 续期成功时热加载证书。
func OnCertRenewed() {
	sslReload()
}

// AllSites 站点列表（前端下拉等），仅暴露必要字段。
func AllSites() (core.Rows, error) {
	return core.Query("SELECT id, name, domains, paths, target, enabled FROM proxy_site ORDER BY id")
}

// ListeningStatus 供 Dashboard 注入：代理监听端口是否已绑定（>0）。
func ListeningStatus() bool {
	return boundHttpPort() > 0 || boundHttpsPort() > 0
}

// ---------- 小工具 ----------

func boolCfg(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// bodyInt64 取整型字段为 int64（站点 id 等，避免 int32 平台截断）。
func bodyInt64(b map[string]interface{}, key string) int64 {
	switch v := b[key].(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0
		}
		return n
	case float64:
		return int64(v)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}
