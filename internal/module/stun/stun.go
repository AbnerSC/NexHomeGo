package stun

// STUN 穿透任务管理服务：增删改查 + 启停控制 + 状态持久化（重启自动加载），
// 并提供 ESA（边缘安全加速）站点/解析记录/回源规则的线上列表拉取与手动同步入口。
// 复刻 Java StunService。
//
// 穿透结果有三个可独立启用的联动出口（触发点同一：首次穿透成功、外网映射地址变化）：
// webhook.go（任务内自定义 HTTP 回调）、esa_sync.go（写阿里云 ESA 解析/回源）、
// notify.go（投递到统一告警通知中心，渠道由任务多选勾选）。

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/module/ddns"
	"NexHomeGo/internal/module/provider"
	"NexHomeGo/internal/web"
)

var (
	// runners 任务 id -> 运行中的任务实例
	runnersMu sync.Mutex
	runners   = map[int64]*runner{}
	// taskLocks 任务 id -> 启停互斥锁：并发启动（重复点击/自动恢复重叠）会导致新旧实例竞争同一端口，启停须串行
	locksMu   sync.Mutex
	taskLocks = map[int64]*sync.Mutex{}
)

// RegisterRoutes 注册 REST 接口（路径/方法与 Java StunService.registerRoutes 一致）。
func RegisterRoutes() {
	web.Route("GET", "/api/stun/tasks", listTasks)
	// 单任务流量明细：总量 + 按小时/天/月归档（连接重建不清零，落库+内存实时增量合并）
	web.Route("GET", "/api/stun/tasks/{id}/traffic", func(c *web.Ctx) error {
		c.Ok(trafficDetail(c.ParamLong("id")))
		return nil
	})
	web.Route("POST", "/api/stun/tasks", createTask)
	web.Route("PUT", "/api/stun/tasks/{id}", updateTask)
	web.Route("DELETE", "/api/stun/tasks/{id}", deleteTask)
	web.Route("POST", "/api/stun/tasks/{id}/start", func(c *web.Ctx) error {
		id := c.ParamLong("id")
		if err := startTask(id); err != nil {
			return err
		}
		task, err := mustGet(id)
		if err != nil {
			return err
		}
		c.Ok(task)
		return nil
	})
	web.Route("POST", "/api/stun/tasks/{id}/stop", func(c *web.Ctx) error {
		id := c.ParamLong("id")
		stopTask(id)
		task, err := mustGet(id)
		if err != nil {
			return err
		}
		c.Ok(task)
		return nil
	})
	// 可用性自测：验证外网能否经映射地址主动连入（TCP 连接外网IP:穿透端口，UDP 发探测包）
	web.Route("POST", "/api/stun/tasks/{id}/verify", func(c *web.Ctx) error {
		r := getRunner(c.ParamLong("id"))
		if r == nil {
			return core.NewBadRequest("任务未运行，无法自测")
		}
		row, err := r.verifyNow()
		if err != nil {
			return err
		}
		c.Ok(row)
		return nil
	})
	// 手动立即同步一次 ESA（按当前外网映射地址更新解析记录与回源端口，返回逐条明细）
	web.Route("POST", "/api/stun/tasks/{id}/esa-sync", func(c *web.Ctx) error {
		task, err := mustGet(c.ParamLong("id"))
		if err != nil {
			return err
		}
		c.Ok(esaSyncNow(task))
		return nil
	})
	// 手动试发一次通知：按任务勾选的渠道投递测试通知（异步投递，结果见「通知中心」页发送记录）
	web.Route("POST", "/api/stun/tasks/{id}/notify-test", func(c *web.Ctx) error {
		task, err := mustGet(c.ParamLong("id"))
		if err != nil {
			return err
		}
		n, err := notifyTestSend(task)
		if err != nil {
			return err
		}
		c.Ok("已按 " + strconv.Itoa(n) + " 个勾选渠道投递测试通知，发送结果见「告警通知」页的最近发送记录")
		return nil
	})
	// ESA 站点/解析记录/回源规则列表：供任务表单勾选（只读拉取，不改动云端）
	web.Route("POST", "/api/stun/esa/sites", esaSites)
	web.Route("POST", "/api/stun/esa/records", esaRecords)
	web.Route("POST", "/api/stun/esa/origin-rules", esaOriginRules)
	// 单独探测一次：不启动任务，仅检测 NAT 类型与映射地址（TCP 任务另探测 TCP 映射）
	web.Route("POST", "/api/stun/tasks/{id}/test", testProbe)

	// STUN 服务器维护表路由
	registerServerRoutes()
}

// Init 启动初始化：旧库升级列 + 播种服务器列表 + 拉起流量落库 + 恢复启用的穿透任务。
func Init() {
	ensureColumns()
	initServers()
	initTraffic()
	// 恢复启用的任务放到后台：启动探测会阻塞数秒（STUN 无响应超时），不能拖慢 Web 就绪。
	core.Run(restoreTasks)
}

// StopAll 关停时停止全部任务并释放路由器 UPnP 映射（防止映射条目残留浪费路由器资源）。
func StopAll() {
	runnersMu.Lock()
	for _, r := range runners {
		stopRunnerSilently(r)
	}
	runners = map[int64]*runner{}
	runnersMu.Unlock()
}

// stopRunnerSilently 单个静默停止，异常兜底（等价 Java forEach 内 try/catch）。
func stopRunnerSilently(r *runner) {
	defer func() {
		if rec := recover(); rec != nil {
			core.LogWarn(core.LogStun, "关停停止穿透任务异常: "+fmt.Sprint(rec))
		}
	}()
	r.stopSilently()
}

// FlushTrafficNow 立即落库流量统计（进程关停时调用，保留最后不足一个周期的增量）。
func FlushTrafficNow() { flushTrafficNow() }

// 旧库升级：补充缺失列（新库建表脚本已包含）
func ensureColumns() {
	ensureColumn("peer_addr", "TEXT")
	ensureColumn("punched_at", "TEXT")
	ensureColumn("check_time", "TEXT")
	ensureColumn("check_result", "TEXT")
	ensureColumn("upnp_enabled", "INTEGER NOT NULL DEFAULT 1")
	ensureColumn("webhook_config", "TEXT")
	ensureColumn("webhook_status", "TEXT")
	ensureColumn("esa_sync_enabled", "INTEGER NOT NULL DEFAULT 0")
	ensureColumn("provider_config_id", "INTEGER")
	ensureColumn("esa_site_id", "TEXT")
	ensureColumn("esa_records", "TEXT")
	ensureColumn("esa_rules", "TEXT")
	ensureColumn("esa_sync_status", "TEXT")
	ensureColumn("notify_enabled", "INTEGER NOT NULL DEFAULT 0")
	ensureColumn("notify_channels", "TEXT")
}

func ensureColumn(name, typ string) {
	rows, err := core.Query("PRAGMA table_info(stun_task)")
	if err != nil {
		return
	}
	for _, col := range rows {
		if s, ok := col.Get("name").(string); ok && s == name {
			return
		}
	}
	_, _ = core.Update("ALTER TABLE stun_task ADD COLUMN " + name + " " + typ)
}

// ---------- 启停 ----------

// taskLock 取（或惰性创建）某任务的启停互斥锁。
func taskLock(id int64) *sync.Mutex {
	locksMu.Lock()
	defer locksMu.Unlock()
	l := taskLocks[id]
	if l == nil {
		l = &sync.Mutex{}
		taskLocks[id] = l
	}
	return l
}

func getRunner(id int64) *runner {
	runnersMu.Lock()
	defer runnersMu.Unlock()
	return runners[id]
}

func hasRunner(id int64) bool {
	runnersMu.Lock()
	defer runnersMu.Unlock()
	_, ok := runners[id]
	return ok
}

// startTask 启动任务（同任务串行：并发启动会竞争同一出站/监听端口，是端口冲突启动失败的诱因之一）。
func startTask(id int64) error {
	lock := taskLock(id)
	lock.Lock()
	defer lock.Unlock()
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	stopLocked(id) // 幂等：先停止旧实例（内联调用避免嵌套加锁，逻辑更直白）
	r := newRunner(task)
	if err := r.start(); err != nil {
		return err
	}
	runnersMu.Lock()
	runners[id] = r
	runnersMu.Unlock()
	_, _ = core.Update("UPDATE stun_task SET enabled=1 WHERE id=?", id)
	return nil
}

// stopTask 停止任务（与 startTask 同锁串行，避免停止释放端口与新实例绑定交错）。
func stopTask(id int64) {
	lock := taskLock(id)
	lock.Lock()
	defer lock.Unlock()
	stopLocked(id)
}

// stopLocked 停止本体：调用方必须已持有该任务的启停锁。
func stopLocked(id int64) {
	runnersMu.Lock()
	r := runners[id]
	delete(runners, id)
	runnersMu.Unlock()
	if r != nil {
		r.stop()
	}
	_, _ = core.Update("UPDATE stun_task SET enabled=0, status='STOPPED' WHERE id=?", id)
}

// restoreTasks 启动时自动加载：恢复启用了的穿透任务。
func restoreTasks() {
	rows, err := core.Query("SELECT * FROM stun_task WHERE enabled=1")
	if err != nil {
		return
	}
	for _, row := range rows {
		id := int64(intField(row, "id"))
		if err := startTask(id); err != nil {
			core.LogError(core.LogStun, "自动恢复穿透任务 #"+strconv.FormatInt(id, 10)+" 失败: "+err.Error())
		}
	}
}

// ---------- 增删改 ----------

// listTasks 任务列表：在原始行基础上附带每个任务的累计总流量 total_bytes（含内存未落库增量）。
func listTasks(c *web.Ctx) error {
	rows, err := core.Query("SELECT * FROM stun_task ORDER BY id")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if id, ok := r.Get("id").(int64); ok {
			r.Set("total_bytes", trafficTotalBytes(id))
		}
	}
	c.Ok(rows)
	return nil
}

func createTask(c *web.Ctx) error {
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	id, err := core.Insert(`INSERT INTO stun_task(name, protocol, target_ip, target_port, bind_port,
		stun_host, stun_port, keepalive_sec, peer_addr, upnp_enabled, webhook_config,
		esa_sync_enabled, provider_config_id, esa_site_id, esa_records, esa_rules,
		notify_enabled, notify_channels, enabled)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		core.BodyStr(b, "name"), core.BodyStr(b, "protocol"), core.BodyStr(b, "target_ip"),
		core.BodyNum(b, "target_port", 0), core.BodyNum(b, "bind_port", 0),
		core.BodyStr(b, "stun_host"), core.BodyNum(b, "stun_port", 19302),
		core.BodyNum(b, "keepalive_sec", 25), core.BodyStr(b, "peer_addr"),
		boolToInt(core.BodyBool(b, "upnp_enabled", true)), serializeWebhooks(b),
		boolToInt(core.BodyBool(b, "esa_sync_enabled", false)), providerConfigArg(b),
		strings.TrimSpace(core.BodyStr(b, "esa_site_id")),
		serializePicked(b, "esa_records"), serializePicked(b, "esa_rules"),
		boolToInt(core.BodyBool(b, "notify_enabled", false)), serializeNotifyChannels(b),
		boolToInt(core.BodyBool(b, "enabled", false)))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogStun, "新增穿透任务: "+core.BodyStr(b, "name"))
	// 创建即要求启动的场景：前端传 enabled=1 时自动启动
	if core.BodyBool(b, "enabled", false) {
		if err := startTask(id); err != nil {
			return err
		}
	}
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(task)
	return nil
}

func updateTask(c *web.Ctx) error {
	id := c.ParamLong("id")
	wasRunning := hasRunner(id)
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	if _, err := core.Update(`UPDATE stun_task SET name=?, protocol=?, target_ip=?, target_port=?, bind_port=?,
		stun_host=?, stun_port=?, keepalive_sec=?, peer_addr=?, upnp_enabled=?, webhook_config=?,
		esa_sync_enabled=?, provider_config_id=?, esa_site_id=?, esa_records=?, esa_rules=?,
		notify_enabled=?, notify_channels=? WHERE id=?`,
		core.BodyStr(b, "name"), core.BodyStr(b, "protocol"), core.BodyStr(b, "target_ip"),
		core.BodyNum(b, "target_port", 0), core.BodyNum(b, "bind_port", 0),
		core.BodyStr(b, "stun_host"), core.BodyNum(b, "stun_port", 19302),
		core.BodyNum(b, "keepalive_sec", 25), core.BodyStr(b, "peer_addr"),
		boolToInt(core.BodyBool(b, "upnp_enabled", true)), serializeWebhooks(b),
		boolToInt(core.BodyBool(b, "esa_sync_enabled", false)), providerConfigArg(b),
		strings.TrimSpace(core.BodyStr(b, "esa_site_id")),
		serializePicked(b, "esa_records"), serializePicked(b, "esa_rules"),
		boolToInt(core.BodyBool(b, "notify_enabled", false)), serializeNotifyChannels(b), id); err != nil {
		return err
	}
	core.LogInfo(core.LogStun, "更新穿透任务 #"+strconv.FormatInt(id, 10)+": "+core.BodyStr(b, "name"))
	// 运行中修改配置 -> 重启任务使配置生效
	if wasRunning {
		stopTask(id)
		if err := startTask(id); err != nil {
			return err
		}
	}
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(task)
	return nil
}

func deleteTask(c *web.Ctx) error {
	id := c.ParamLong("id")
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	stopTask(id)
	if _, err := core.Update("DELETE FROM stun_task WHERE id=?", id); err != nil {
		return err
	}
	trafficClear(id) // 清理流量统计（内存计数 + stun_traffic 落库行）
	core.LogInfo(core.LogStun, "删除穿透任务 #"+strconv.FormatInt(id, 10)+": "+strField(task, "name"))
	c.Ok("已删除")
	return nil
}

// ---------- 表单校验 ----------

func validate(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("任务名称不能为空")
	}
	protocol := core.BodyStr(b, "protocol")
	if protocol != "TCP" && protocol != "UDP" {
		return core.NewBadRequest("协议必须为 TCP 或 UDP")
	}
	if strings.TrimSpace(core.BodyStr(b, "target_ip")) == "" {
		return core.NewBadRequest("内网目标 IP 不能为空")
	}
	port := core.BodyNum(b, "target_port", 0)
	if port < 1 || port > 65535 {
		return core.NewBadRequest("内网目标端口需在 1-65535 之间")
	}
	if strings.TrimSpace(core.BodyStr(b, "stun_host")) == "" {
		return core.NewBadRequest("STUN 服务器地址不能为空")
	}
	sp := core.BodyNum(b, "stun_port", 19302)
	if sp < 1 || sp > 65535 {
		return core.NewBadRequest("STUN 端口需在 1-65535 之间")
	}
	bp := core.BodyNum(b, "bind_port", 0)
	if bp < 0 || bp > 65535 {
		return core.NewBadRequest("本地绑定端口需在 0-65535 之间（0=随机）")
	}
	peer := strings.TrimSpace(core.BodyStr(b, "peer_addr"))
	if peer != "" {
		ci := strings.LastIndexByte(peer, ':')
		if ci <= 0 || ci == len(peer)-1 {
			return core.NewBadRequest("对端公网地址格式需为 ip:端口")
		}
		pp, err := strconv.Atoi(peer[ci+1:])
		if err != nil {
			return core.NewBadRequest("对端公网地址端口需为数字")
		}
		if pp < 1 || pp > 65535 {
			return core.NewBadRequest("对端端口需在 1-65535 之间")
		}
	}
	if err := validateWebhooks(b); err != nil {
		return err
	}
	if err := validateEsaSync(b); err != nil {
		return err
	}
	return validateNotify(b)
}

// validateWebhooks Webhook 配置校验：地址须为 http/https，请求方式仅 GET/POST（空地址忽略）。
func validateWebhooks(b map[string]interface{}) error {
	arr, ok := b["webhooks"].([]interface{})
	if !ok {
		return nil
	}
	for _, el := range arr {
		w, ok := el.(map[string]interface{})
		if !ok {
			continue
		}
		url := strings.TrimSpace(core.BodyStr(w, "url"))
		if url == "" {
			continue
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return core.NewBadRequest("Webhook 地址必须以 http:// 或 https:// 开头: %s", url)
		}
		method := strings.ToUpper(strings.TrimSpace(core.BodyStr(w, "method")))
		if method != "" && method != "GET" && method != "POST" {
			return core.NewBadRequest("Webhook 请求方式只能为 GET 或 POST")
		}
	}
	return nil
}

// validateNotify 通知配置校验：启用时必须至少勾选一个渠道，且渠道必须存在。
func validateNotify(b map[string]interface{}) error {
	if !core.BodyBool(b, "notify_enabled", false) {
		return nil
	}
	channels := serializeNotifyChannels(b)
	ids := parseChannelIds(channels)
	if len(ids) == 0 {
		return core.NewBadRequest("启用穿透通知需至少选择一个通知渠道")
	}
	for _, id := range ids {
		row, err := core.QueryOne("SELECT id FROM notify_channel WHERE id=?", id)
		if err != nil {
			return err
		}
		if row == nil {
			return core.NewBadRequest("通知渠道不存在: #%d，请重新选择通知渠道", id)
		}
	}
	return nil
}

// validateEsaSync ESA 同步校验：启用时必须有凭证配置与站点，且至少勾选一条解析记录或回源规则。
func validateEsaSync(b map[string]interface{}) error {
	if !core.BodyBool(b, "esa_sync_enabled", false) {
		return nil
	}
	if _, ok := provider.ParseID(b, "provider_config_id"); !ok {
		return core.NewBadRequest("启用 ESA 同步需选择服务商凭证配置")
	}
	if strings.TrimSpace(core.BodyStr(b, "esa_site_id")) == "" {
		return core.NewBadRequest("启用 ESA 同步需选择 ESA 站点")
	}
	if serializePicked(b, "esa_records") == "" && serializePicked(b, "esa_rules") == "" {
		return core.NewBadRequest("启用 ESA 同步需至少勾选一条解析记录或回源规则")
	}
	return nil
}

// ---------- 序列化（存储用 JSON 串） ----------

// serializeWebhooks 将前端提交的 webhooks 数组规范化为存储用 JSON 串
// （过滤空地址、默认 POST、params 统一为字符串值、保留 body 字段）。
func serializeWebhooks(b map[string]interface{}) string {
	arr, ok := b["webhooks"].([]interface{})
	if !ok {
		return ""
	}
	var out []*core.Row
	for _, el := range arr {
		w, ok := el.(map[string]interface{})
		if !ok {
			continue
		}
		url := strings.TrimSpace(core.BodyStr(w, "url"))
		if url == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(core.BodyStr(w, "method")))
		if method != "GET" {
			method = "POST"
		}
		o := core.NewRow().
			Set("url", url).
			Set("method", method).
			Set("headers", normalizeStringMap(w, "headers")).
			Set("params", normalizeStringMap(w, "params"))
		// 保留用户自定义 JSON 请求体（POST 模式）
		if bv, has := w["body"]; has && bv != nil {
			bodyVal := strings.TrimSpace(fmt.Sprint(bv))
			if bodyVal != "" {
				o.Set("body", bodyVal)
			}
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		return ""
	}
	return marshalStr(out)
}

// serializePicked 将前端勾选的 ESA 记录/规则数组规范化为存储用 JSON 串（元素 {id,name}，无 id 项丢弃）：
// id 为线上 RecordId/ConfigId（定位为主键），name 为名称快照（id 失效时按名称回退）。
func serializePicked(b map[string]interface{}, key string) string {
	arr, ok := b[key].([]interface{})
	if !ok {
		return ""
	}
	var out []*core.Row
	for _, el := range arr {
		o, ok := el.(map[string]interface{})
		if !ok {
			continue
		}
		id, err := strconv.ParseInt(strings.TrimSpace(core.BodyStr(o, "id")), 10, 64)
		if err != nil || id <= 0 {
			continue // 非线上真实 id（如占位项）直接丢弃
		}
		item := core.NewRow().Set("id", id).Set("name", strings.TrimSpace(core.BodyStr(o, "name")))
		out = append(out, item)
	}
	if len(out) == 0 {
		return ""
	}
	return marshalStr(out)
}

// serializeNotifyChannels 将前端勾选的 notify_channels 数组规范化为存储用 JSON 数字串（过滤非法项与重复 id）。
func serializeNotifyChannels(b map[string]interface{}) string {
	arr, ok := b["notify_channels"].([]interface{})
	if !ok {
		return ""
	}
	ids := parseChannelIds(marshalStr(arr))
	if len(ids) == 0 {
		return ""
	}
	return marshalStr(ids)
}

// normalizeStringMap 将 webhook 项内的对象字段（headers/params）规范化为字符串值对象，缺失时返回空对象。
func normalizeStringMap(w map[string]interface{}, key string) map[string]string {
	out := map[string]string{}
	if m, ok := w[key].(map[string]interface{}); ok {
		for k, v := range m {
			if v == nil {
				out[k] = ""
			} else {
				out[k] = fmt.Sprint(v)
			}
		}
	}
	return out
}

// providerConfigArg 凭证配置 id：未选择返回 nil（供插入 NULL），与 cert 模块范式一致。
func providerConfigArg(b map[string]interface{}) interface{} {
	id, ok := provider.ParseID(b, "provider_config_id")
	if !ok {
		return nil
	}
	return id
}

// marshalStr 序列化为 JSON 串（内部辅助，失败返回空串）。
func marshalStr(v interface{}) string {
	bs, err := core.MarshalJSON(v)
	if err != nil {
		return ""
	}
	return string(bs)
}

// ---------- ESA 线上列表拉取 ----------

// esaSites 拉取 ESA 站点列表（表单下拉选择，不手填 SiteId）。
func esaSites(c *web.Ctx) error {
	ak, sk, err := esaCredentials(c.Body())
	if err != nil {
		return err
	}
	online, err := ddns.EsaListSites(ak, sk)
	if err != nil {
		return err
	}
	out := make([]*core.Row, 0, len(online))
	for _, s := range online {
		siteID := ""
		if _, has := s["SiteId"]; has {
			siteID = strconv.FormatInt(esaLong(s, "SiteId"), 10)
		}
		o := core.NewRow().
			Set("site_id", siteID).
			Set("site_name", esaStr(s, "SiteName")).
			Set("status", esaStr(s, "Status"))
		out = append(out, o)
	}
	c.Ok(core.NewRow().Set("sites", out))
	return nil
}

// esaRecords 拉取站点下全部解析记录（含当前记录值，供勾选与回显）。
func esaRecords(c *web.Ctx) error {
	b := c.Body()
	ak, sk, err := esaCredentials(b)
	if err != nil {
		return err
	}
	siteId := strings.TrimSpace(core.BodyStr(b, "site_id"))
	if siteId == "" {
		return core.NewBadRequest("请先选择 ESA 站点")
	}
	online, err := ddns.EsaListAllRecords(ak, sk, siteId)
	if err != nil {
		return err
	}
	out := make([]*core.Row, 0, len(online))
	for _, r := range online {
		recordID := ""
		if _, has := r["RecordId"]; has {
			recordID = strconv.FormatInt(esaLong(r, "RecordId"), 10)
		}
		value := ""
		if data, ok := r["Data"].(map[string]interface{}); ok {
			value = esaStr(data, "Value")
		}
		ttl := ""
		if v, has := r["Ttl"]; has && v != nil {
			ttl = esaStr(r, "Ttl")
		}
		proxied := false
		if v, has := r["Proxied"]; has && v != nil {
			if bv, ok := v.(bool); ok {
				proxied = bv
			}
		}
		o := core.NewRow().
			Set("record_id", recordID).
			Set("record_name", esaStr(r, "RecordName")).
			Set("record_type", esaStr(r, "RecordType")).
			Set("value", value).
			Set("ttl", ttl).
			Set("proxied", proxied).
			Set("comment", esaStr(r, "Comment"))
		out = append(out, o)
	}
	c.Ok(core.NewRow().Set("records", out))
	return nil
}

// esaOriginRules 拉取站点下全部回源规则（含当前回源协议与端口；全局配置由前端过滤不展示）。
func esaOriginRules(c *web.Ctx) error {
	b := c.Body()
	ak, sk, err := esaCredentials(b)
	if err != nil {
		return err
	}
	siteId := strings.TrimSpace(core.BodyStr(b, "site_id"))
	if siteId == "" {
		return core.NewBadRequest("请先选择 ESA 站点")
	}
	online, err := ddns.EsaListOriginRules(ak, sk, siteId)
	if err != nil {
		return err
	}
	out := make([]*core.Row, 0, len(online))
	for _, r := range online {
		configID := ""
		if _, has := r["ConfigId"]; has {
			configID = strconv.FormatInt(esaLong(r, "ConfigId"), 10)
		}
		o := core.NewRow().
			Set("config_id", configID).
			Set("rule_name", esaStr(r, "RuleName")).
			Set("config_type", esaStr(r, "ConfigType")).
			Set("origin_scheme", esaStr(r, "OriginScheme")).
			Set("origin_https_port", esaStr(r, "OriginHttpsPort")).
			Set("origin_http_port", esaStr(r, "OriginHttpPort")).
			Set("rule_enable", esaStr(r, "RuleEnable"))
		out = append(out, o)
	}
	c.Ok(core.NewRow().Set("rules", out))
	return nil
}

// esaCredentials 拉取线上列表用的凭证：ESA 同步只支持引用服务商凭证配置（与 DDNS 的实时读取一致）。
func esaCredentials(b map[string]interface{}) (string, string, error) {
	cfgId, ok := provider.ParseID(b, "provider_config_id")
	if !ok {
		return "", "", core.NewBadRequest("请先选择服务商凭证配置")
	}
	return provider.Credentials(cfgId)
}

// ---------- 单独探测 ----------

// testProbe 单独探测一次：不启动任务，仅检测 NAT 类型与映射地址（TCP 任务另探测 TCP 映射）。
func testProbe(c *web.Ctx) error {
	taskId := c.ParamLong("id")
	task, err := mustGet(taskId)
	if err != nil {
		return err
	}
	r := getRunner(taskId)
	live := r != nil && r.isRunning()
	liveMapped := strField(task, "mapped_addr")
	liveNat := strField(task, "nat_type")

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	// NAT 类型是网络路径属性，新开 socket 探测仍有效；映射地址则不同：临时端口的
	// 映射在对称型 NAT 下与任务端口映射必然不同，任务运行中必须以运行器登记的
	// 实际映射为准，否则探测结果不代表任务通道（误导用户排查方向）
	res := detectNatType(conn, strField(task, "stun_host"), intField(task, "stun_port"), 3000)

	natType := ""
	switch {
	case res == nil || res.mapped == "":
		if strings.TrimSpace(liveNat) == "" {
			natType = "Unknown(STUN服务器无响应)"
		} else {
			natType = liveNat + "(本次探测无响应，取任务记录)"
		}
	default:
		natType = res.natType
	}

	mapped := ""
	tcpMapped := ""
	isTcp := strings.EqualFold(strField(task, "protocol"), "TCP")
	if live {
		mapped = liveMapped // 任务运行中：实际映射（权威）
		if isTcp {
			tcpMapped = liveMapped
		}
	} else {
		if res != nil {
			mapped = res.mapped
		}
		if isTcp && intField(task, "bind_port") > 0 {
			// 仅未运行时才做同端口 TCP 探测：运行中监听与出站链路占用该本地端口，
			// 再从该端口出站是对称型 CGNAT 下的另一条映射（外部端口可能不同），
			// 探测结果不代表任务通道；绑定时才能探测到对入站有效的 TCP 映射，
			// 配置服务器不支持 TCP 时尝试维护列表与内置兜底
			bp := intField(task, "bind_port")
			m := bindOverTcp(strField(task, "stun_host"), intField(task, "stun_port"), bp, 3000)
			// 内置列表按电信 CGNAT 实测可达排序优先，维护列表（历史种子多为被封的 3478 端口）兜底
			fallback := append([][2]string{}, tcpStunServers...)
			fallback = append(fallback, tcpServers()...)
			for i := 0; m == "" && i < len(fallback); i++ {
				port, _ := strconv.Atoi(fallback[i][1])
				m = bindOverTcp(fallback[i][0], port, bp, 3000)
			}
			if m != "" {
				tcpMapped = m
			}
		}
	}

	desc := "无响应"
	if res != nil {
		desc = res.natType + " / " + res.mapped
	}
	if live {
		desc = "任务运行中，取实际映射 " + liveMapped
	}
	if tcpMapped != "" {
		desc += " / TCP映射: " + tcpMapped
	}
	core.LogInfo(core.LogStun, "手动探测任务["+strField(task, "name")+"] 结果: "+desc)

	c.Ok(core.NewRow().
		Set("live", live).
		Set("mapped", mapped).
		Set("natType", natType).
		Set("tcpMapped", tcpMapped))
	return nil
}

// ---------- 查询 ----------

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM stun_task WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("STUN 任务不存在: #%d", id)
	}
	return row, nil
}
