package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/module/provider"
	"NexHomeGo/internal/web"
)

// DDNS 域名同步服务（复刻 Java DdnsService）。
// 负责同步任务的增删改查、定时/手动同步调度，并对接阿里云云解析与 ESA。
// 同步逻辑：解析当前 IP -> 与线上解析记录比对 -> 不一致时调用 OpenAPI 更新 -> 记录状态与日志。
// 调度与 monitor 相同：每任务独立可取消 goroutine，同步串行执行且 SYNCING 防重入兜底。

const syncFirstDelaySec = 5 // 任务启用/编辑后首个同步延迟（秒），等价 Java Tasks.every(5, interval, ...)

var (
	mu        sync.Mutex
	syncing   = map[int64]bool{}               // 正在同步中的任务 id，同一任务同一时刻仅允许一个同步（防并发重复写入）
	schedules = map[int64]context.CancelFunc{} // 任务 id -> 定时句柄，用于增删改时重建调度
)

// RegisterRoutes 注册 REST 接口（路径/方法与 Java DdnsService.registerRoutes 一致）。
func RegisterRoutes() {
	web.Route("GET", "/api/ddns/tasks", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM ddns_task ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
	web.Route("GET", "/api/ddns/nics", func(c *web.Ctx) error {
		nics, err := listNics()
		if err != nil {
			return err
		}
		r := core.NewRow()
		r.Set("nics", nics)
		c.Ok(r)
		return nil
	})
	web.Route("GET", "/api/ddns/public-ip", func(c *web.Ctx) error {
		ip, err := publicIP()
		if err != nil {
			return err
		}
		r := core.NewRow()
		r.Set("ip", ip)
		c.Ok(r)
		return nil
	})
	web.Route("POST", "/api/ddns/preview-ip", func(c *web.Ctx) error {
		b := c.Body()
		ip, err := resolveFields(core.BodyStr(b, "ip_mode"), core.BodyStr(b, "manual_ip"), core.BodyStr(b, "local_nic"))
		if err != nil {
			return err
		}
		r := core.NewRow()
		r.Set("ip", ip)
		c.Ok(r)
		return nil
	})
	// 拉取阿里云 ESA 站点列表：供前端下拉选择；凭证可来自配置或手动填写
	web.Route("POST", "/api/ddns/esa/sites", func(c *web.Ctx) error {
		ak, sk, err := credentialsFrom(c.Body())
		if err != nil {
			return err
		}
		sites, err := esaListSites(ak, sk)
		if err != nil {
			return err
		}
		out := make([]*core.Row, 0, len(sites))
		for _, s := range sites {
			o := core.NewRow()
			if _, has := s["SiteId"]; has {
				o.Set("site_id", numString(s, "SiteId"))
			} else {
				o.Set("site_id", "")
			}
			if _, has := s["SiteName"]; has {
				o.Set("site_name", strAt(s, "SiteName"))
			} else {
				o.Set("site_name", "")
			}
			if _, has := s["Status"]; has {
				o.Set("status", strAt(s, "Status"))
			} else {
				o.Set("status", "")
			}
			out = append(out, o)
		}
		r := core.NewRow()
		r.Set("sites", out)
		c.Ok(r)
		return nil
	})
	web.Route("POST", "/api/ddns/tasks", create)
	web.Route("PUT", "/api/ddns/tasks/{id}", update)
	web.Route("DELETE", "/api/ddns/tasks/{id}", remove)
	web.Route("POST", "/api/ddns/tasks/{id}/sync", func(c *web.Ctx) error {
		id := c.ParamLong("id")
		task, err := mustGet(id)
		if err != nil {
			return err
		}
		if isSyncing(id) {
			c.Ok("该任务正在同步中，请稍候刷新列表查看结果")
			return nil
		}
		core.LogInfo(core.LogDdns, "手动触发同步: "+rowStr(task, "name"))
		core.Run(func() { syncTask(id) })
		c.Ok("已触发同步，请在列表中查看结果")
		return nil
	})
}

// Init 启动时加载全部启用的任务并建立定时调度（重启自动加载）。
func Init() {
	ensureColumn("provider_config_id", "INTEGER") // 旧库升级：引用服务商凭证配置
	rows, err := core.Query("SELECT * FROM ddns_task")
	if err != nil {
		core.LogError(core.LogDdns, "加载 DDNS 任务失败: "+err.Error())
		return
	}
	for _, task := range rows {
		schedule(task)
	}
	mu.Lock()
	n := len(schedules)
	mu.Unlock()
	core.LogInfo(core.LogDdns, "DDNS 任务已加载，共 "+strconv.Itoa(n)+" 个定时任务")
}

// ensureColumn 旧库升级：补充缺失列（新库建表脚本已包含）。
func ensureColumn(name, typ string) {
	rows, err := core.Query("PRAGMA table_info(ddns_task)")
	if err != nil {
		return
	}
	for _, col := range rows {
		if s, ok := col.Get("name").(string); ok && s == name {
			return
		}
	}
	_, _ = core.Update("ALTER TABLE ddns_task ADD COLUMN " + name + " " + typ)
}

// ---------- 增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	if err := validateEsaSiteExists(b); err != nil {
		return err
	}
	id, err := core.Insert(`INSERT INTO ddns_task(name, provider, domain, rr, type, ttl, ip_mode, manual_ip, local_nic,
		provider_config_id, access_key_id, access_key_secret, esa_site_id, interval_sec, enabled)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		core.BodyStr(b, "name"), core.BodyStr(b, "provider"), core.BodyStr(b, "domain"),
		core.BodyStr(b, "rr"), core.BodyStr(b, "type"), core.BodyNum(b, "ttl", 600),
		core.BodyStr(b, "ip_mode"), core.BodyStr(b, "manual_ip"), core.BodyStr(b, "local_nic"),
		providerConfigArg(b), core.BodyStr(b, "access_key_id"), core.BodyStr(b, "access_key_secret"),
		core.BodyStr(b, "esa_site_id"), core.BodyNum(b, "interval_sec", 300),
		boolToInt(core.BodyBool(b, "enabled", true)))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogDdns, "新增同步任务: "+core.BodyStr(b, "name"))
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	schedule(task)
	if rowInt(task, "enabled") == 1 {
		core.Run(func() { syncTask(id) }) // 创建后立即同步一次
	}
	c.Ok(task)
	return nil
}

func update(c *web.Ctx) error {
	id := c.ParamLong("id")
	old, err := mustGet(id)
	if err != nil {
		return err
	}
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	// 仅当 ESA 站点发生变化时回源校验，避免每次开关定时同步都请求阿里云
	if strings.TrimSpace(core.BodyStr(b, "esa_site_id")) != rowStr(old, "esa_site_id") {
		if err := validateEsaSiteExists(b); err != nil {
			return err
		}
	}
	if _, err := core.Update(`UPDATE ddns_task SET name=?, provider=?, domain=?, rr=?, type=?, ttl=?, ip_mode=?,
		manual_ip=?, local_nic=?, provider_config_id=?, access_key_id=?, access_key_secret=?, esa_site_id=?,
		interval_sec=?, enabled=? WHERE id=?`,
		core.BodyStr(b, "name"), core.BodyStr(b, "provider"), core.BodyStr(b, "domain"),
		core.BodyStr(b, "rr"), core.BodyStr(b, "type"), core.BodyNum(b, "ttl", 600),
		core.BodyStr(b, "ip_mode"), core.BodyStr(b, "manual_ip"), core.BodyStr(b, "local_nic"),
		providerConfigArg(b), core.BodyStr(b, "access_key_id"), core.BodyStr(b, "access_key_secret"),
		core.BodyStr(b, "esa_site_id"), core.BodyNum(b, "interval_sec", 300),
		boolToInt(core.BodyBool(b, "enabled", true)), id); err != nil {
		return err
	}
	core.LogInfo(core.LogDdns, "更新同步任务 #"+strconv.FormatInt(id, 10)+": "+core.BodyStr(b, "name"))
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	schedule(task)
	if rowInt(task, "enabled") == 1 {
		core.Run(func() { syncTask(id) }) // 更新后立即同步一次
	}
	c.Ok(task)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	// 默认同步删除远程解析记录，可通过 ?remote=false 仅删除本地任务
	remote := !strings.EqualFold(c.Query("remote"), "false")
	remoteMsg := "（未删除远程解析记录）"
	if remote {
		remoteMsg = deleteRemoteRecord(task)
	}
	cancelSchedule(id)
	if _, err := core.Update("DELETE FROM ddns_task WHERE id=?", id); err != nil {
		return err
	}
	core.LogInfo(core.LogDdns, "删除同步任务 #"+strconv.FormatInt(id, 10)+": "+rowStr(task, "name")+" "+remoteMsg)
	c.Ok("已删除 " + remoteMsg)
	return nil
}

// deleteRemoteRecord 删除任务对应的远程解析记录（尽力而为，失败不阻断本地删除）。
// 优先使用缓存的 RecordId，缺失时回查线上记录；记录已不存在视为删除成功。
// 返回面向用户的删除结果描述。
func deleteRemoteRecord(task *core.Row) string {
	fullDomain := fullRecordName(rowStr(task, "rr"), rowStr(task, "domain"))
	msg, err := tryDeleteRemote(task, fullDomain)
	if err != nil {
		// 记录已不存在（如被手动删除）视为删除成功
		var ae *APIError
		if errors.As(err, &ae) && ae.isNotFound() {
			return "（远程解析记录已不存在）"
		}
		core.LogError(core.LogDdns, "删除远程解析记录失败["+fullDomain+"]: "+err.Error())
		return "（远程解析记录删除失败: " + err.Error() + "）"
	}
	return msg
}

func tryDeleteRemote(task *core.Row, fullDomain string) (string, error) {
	recordId := rowStr(task, "record_id")
	if strings.TrimSpace(recordId) == "" {
		// 缓存缺失（如从未同步成功）：回查线上记录定位 RecordId
		online, err := findOnlineRecord(task, fullDomain)
		if err != nil {
			return "", err
		}
		if online == nil {
			return "（远程无 " + fullDomain + " 解析记录，无需删除）", nil
		}
		recordId = recordIdOf(task, online)
	}
	ak, sk, err := credentials(task)
	if err != nil {
		return "", err
	}
	if rowStr(task, "provider") == "ALIYUN_DNS" {
		if err := dnsDeleteRecord(ak, sk, recordId); err != nil {
			return "", err
		}
	} else {
		if err := esaDeleteRecord(ak, sk, recordId); err != nil {
			return "", err
		}
	}
	return "（已删除远程解析记录 " + fullDomain + "）", nil
}

// validate 表单必填与取值合法性校验（创建与更新时均执行；更新需回传完整表单）。
func validate(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("任务名称不能为空")
	}
	if strings.TrimSpace(core.BodyStr(b, "domain")) == "" {
		return core.NewBadRequest("域名不能为空")
	}
	if strings.TrimSpace(core.BodyStr(b, "rr")) == "" {
		return core.NewBadRequest("主机记录不能为空")
	}
	// 已选择服务商凭证配置时无需手动填写 AccessKey
	if _, ok := provider.ParseID(b, "provider_config_id"); !ok &&
		(strings.TrimSpace(core.BodyStr(b, "access_key_id")) == "" ||
			strings.TrimSpace(core.BodyStr(b, "access_key_secret")) == "") {
		return core.NewBadRequest("请选择阿里云凭证配置，或手动填写 AccessKey ID / Secret")
	}
	if core.BodyStr(b, "provider") == "ALIYUN_ESA" && strings.TrimSpace(core.BodyStr(b, "esa_site_id")) == "" {
		return core.NewBadRequest("ESA 服务商需要填写站点 SiteId")
	}
	if core.BodyStr(b, "ip_mode") == "MANUAL" && strings.TrimSpace(core.BodyStr(b, "manual_ip")) == "" {
		return core.NewBadRequest("手动模式必须填写 IP 地址")
	}
	return nil
}

// credentialsFrom 从请求体解析生效凭证：优先配置引用，否则手动 AccessKey。
func credentialsFrom(b map[string]interface{}) (string, string, error) {
	if id, ok := provider.ParseID(b, "provider_config_id"); ok {
		return provider.Credentials(id)
	}
	return core.BodyStr(b, "access_key_id"), core.BodyStr(b, "access_key_secret"), nil
}

// providerConfigArg 落库参数：未选择凭证配置时写 NULL（等价 Java parseId 返回 null）。
func providerConfigArg(b map[string]interface{}) interface{} {
	if id, ok := provider.ParseID(b, "provider_config_id"); ok {
		return id
	}
	return nil
}

// validateEsaSiteExists ESA 任务：校验所选站点存在于阿里云 ESA 站点列表。
// 不存在（如尚未在阿里云添加站点）时抛出面向用户的提示，引导去控制台添加。
func validateEsaSiteExists(b map[string]interface{}) error {
	if core.BodyStr(b, "provider") != "ALIYUN_ESA" {
		return nil
	}
	siteID := strings.TrimSpace(core.BodyStr(b, "esa_site_id"))
	if siteID == "" {
		return core.NewBadRequest("请选择 ESA 站点")
	}
	ak, sk, err := credentialsFrom(b)
	if err != nil {
		return err
	}
	sites, err := esaListSites(ak, sk)
	if err != nil {
		return err
	}
	for _, s := range sites {
		if _, has := s["SiteId"]; has && numString(s, "SiteId") == siteID {
			return nil
		}
	}
	return core.NewBadRequest("ESA 站点(SiteId=%s) 未在阿里云站点列表中找到，请先到阿里云 ESA 控制台添加该站点后再保存", siteID)
}

// ---------- 同步执行 ----------

// syncTask 执行一次同步：先查询线上记录，再依据查询结果决策新增/更新/跳过。
func syncTask(taskID int64) {
	if !tryEnter(taskID) {
		core.LogInfo(core.LogDdns, "任务 #"+strconv.FormatInt(taskID, 10)+" 正在同步中，本次触发已跳过")
		return
	}
	defer leave(taskID)
	if err := doSync(taskID); err != nil {
		_ = markStatus(taskID, "", false, "FAIL: "+err.Error())
		core.LogError(core.LogDdns, "任务 #"+strconv.FormatInt(taskID, 10)+" 同步失败: "+err.Error())
	}
}

func tryEnter(id int64) bool {
	mu.Lock()
	defer mu.Unlock()
	if syncing[id] {
		return false
	}
	syncing[id] = true
	return true
}

func leave(id int64) {
	mu.Lock()
	delete(syncing, id)
	mu.Unlock()
}

func isSyncing(id int64) bool {
	mu.Lock()
	defer mu.Unlock()
	return syncing[id]
}

func doSync(taskID int64) error {
	task, err := mustGet(taskID)
	if err != nil {
		return err
	}
	fullDomain := fullRecordName(rowStr(task, "rr"), rowStr(task, "domain"))
	ip, err := resolve(task)
	if err != nil {
		return err
	}

	// 先查询：阿里云 DNS/ESA 均提供查询接口，添加前先确认线上状态，避免提交必然失败的请求
	online, err := findOnlineRecord(task, fullDomain)
	if err != nil {
		return err
	}
	onlineIp, has := recordValue(task, online)
	if has && onlineIp == ip {
		_ = markStatus(taskID, ip, true, "SUCCESS(无变化)")
		core.LogInfo(core.LogDdns, "任务["+rowStr(task, "name")+"] IP 无变化: "+ip+"，跳过更新")
		return nil
	}

	if err := writeRecord(taskID, task, fullDomain, ip, online); err != nil {
		return err
	}
	_ = markStatus(taskID, ip, true, "SUCCESS")
	core.LogInfo(core.LogDdns, "任务["+rowStr(task, "name")+"] 已同步 "+fullDomain+" -> "+ip)
	return nil
}

// writeRecord 将解析写入线上：存在则更新，不存在则新增；查询未匹配但缓存过 RecordId 时按 id 兜底更新。
func writeRecord(taskID int64, task *core.Row, fullDomain, ip string, online map[string]interface{}) error {
	if online != nil {
		rid := recordIdOf(task, online)
		if rowStr(task, "record_id") != rid {
			// 缓存回查到的真实 RecordId，避免每次更新前先查询
			_, _ = core.Update("UPDATE ddns_task SET record_id=? WHERE id=?", rid, taskID)
		}
		return updateRecord(task, rid, ip)
	}
	cached := rowStr(task, "record_id")
	if strings.TrimSpace(cached) == "" {
		return addRecord(task, fullDomain, ip) // 查询确认不存在，安全新增
	}
	if err := updateRecord(task, cached, ip); err != nil {
		// 查询未匹配但缓存过 RecordId：按 id 直接更新，规避查询盲区导致的重复新增
		var ae *APIError
		if errors.As(err, &ae) && ae.isNotFound() {
			// 缓存的记录已不存在（如被手动删除）：清除失效缓存后新增
			_, _ = core.Update("UPDATE ddns_task SET record_id=NULL WHERE id=?", taskID)
			return addRecord(task, fullDomain, ip)
		}
		return err
	}
	return nil
}

// findOnlineRecord 查询线上与任务主机记录/类型匹配的解析记录，不存在返回 nil。
func findOnlineRecord(task *core.Row, fullDomain string) (map[string]interface{}, error) {
	rr, typ := rowStr(task, "rr"), rowStr(task, "type")
	ak, sk, err := credentials(task)
	if err != nil {
		return nil, err
	}
	var records []map[string]interface{}
	if rowStr(task, "provider") == "ALIYUN_DNS" {
		records, err = dnsDescribeRecords(ak, sk, rowStr(task, "domain"), rr)
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			if strings.EqualFold(strAt(r, "RR"), rr) && strings.EqualFold(strAt(r, "Type"), typ) {
				return r, nil
			}
		}
	} else {
		// ESA：响应类型字段为 RecordType（地址记录统一为 A/AAAA），按名称 + 类型/地址族匹配
		records, err = esaListRecords(ak, sk, rowStr(task, "esa_site_id"), fullDomain)
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			if _, has := r["RecordName"]; has && strings.EqualFold(strAt(r, "RecordName"), fullDomain) &&
				esaRecordMatches(typ, r) {
				return r, nil
			}
		}
	}
	// 未匹配到目标记录：输出接口返回摘要，便于定位查询盲区
	core.LogInfo(core.LogDdns, "任务["+rowStr(task, "name")+"] 线上未匹配到 "+fullDomain+"/"+typ+
		"（接口返回 "+strconv.Itoa(len(records))+" 条: "+summarize(records)+"）")
	return nil, nil
}

// esaRecordMatches ESA 记录类型匹配：地址类记录线上 RecordType 为合并的 A/AAAA，
// 再按 IP 地址族区分 A 与 AAAA；非地址类型直接比对 RecordType。
func esaRecordMatches(taskType string, r map[string]interface{}) bool {
	rt := ""
	if _, has := r["RecordType"]; has {
		rt = strAt(r, "RecordType")
	} else if _, has := r["Type"]; has {
		rt = strAt(r, "Type")
	}
	addr := strings.EqualFold(taskType, "A") || strings.EqualFold(taskType, "AAAA")
	if !addr {
		return strings.EqualFold(rt, taskType)
	}
	if !strings.EqualFold(rt, "A/AAAA") {
		return false
	}
	val := ""
	if data, ok := r["Data"].(map[string]interface{}); ok {
		if _, has := data["Value"]; has {
			val = strAt(data, "Value")
		}
	}
	v6 := strings.Contains(val, ":")
	return strings.EqualFold(taskType, "AAAA") == v6
}

// summarize 解析记录列表摘要：RR/Type 列表（最多 10 条）。
func summarize(records []map[string]interface{}) string {
	var sb strings.Builder
	i := 0
	for _, r := range records {
		if i >= 10 {
			sb.WriteString(" …")
			break
		}
		i++
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		t := "?"
		if _, has := r["Type"]; has {
			t = strAt(r, "Type")
		} else if _, has := r["RecordType"]; has {
			t = strAt(r, "RecordType")
		}
		name := strAt(r, "RR")
		if _, has := r["RR"]; !has {
			name = strAt(r, "RecordName")
		}
		sb.WriteString(name + "/" + t)
	}
	return sb.String()
}

// recordValue 提取线上记录的解析值，记录为 nil 时 has=false（等价 Java 返回 null）。
func recordValue(task *core.Row, r map[string]interface{}) (string, bool) {
	if r == nil {
		return "", false
	}
	if rowStr(task, "provider") == "ALIYUN_DNS" {
		return strAt(r, "Value"), true
	}
	data, _ := r["Data"].(map[string]interface{})
	return strAt(data, "Value"), true
}

// recordIdOf 提取线上记录的 RecordId（DNS 为字符串；ESA 为数字，转十进制字符串）。
func recordIdOf(task *core.Row, r map[string]interface{}) string {
	if rowStr(task, "provider") == "ALIYUN_DNS" {
		return strAt(r, "RecordId")
	}
	return numString(r, "RecordId")
}

// numString 数字字段取整转十进制字符串（等价 Java String.valueOf(getAsLong)）；
// 响应若以字符串回传数字ID则原样返回。
func numString(r map[string]interface{}, key string) string {
	if v, ok := r[key]; ok {
		if n, ok := v.(json.Number); ok {
			return n.String() // UseNumber 原始字面量精确无损（大整数 id 不可经 float64）
		}
	}
	if f, ok := numAt(r, key); ok {
		return strconv.FormatInt(int64(f), 10)
	}
	return strAt(r, key)
}

// addRecord 新增线上解析记录（仅在查询确认不存在后调用），并缓存 RecordId。
func addRecord(task *core.Row, fullDomain, ip string) error {
	ak, sk, err := credentials(task)
	if err != nil {
		return err
	}
	var newId string
	if rowStr(task, "provider") == "ALIYUN_DNS" {
		newId, err = dnsAddRecord(ak, sk, rowStr(task, "domain"), rowStr(task, "rr"),
			rowStr(task, "type"), ip, rowInt(task, "ttl"))
	} else {
		newId, err = esaCreateRecord(ak, sk, rowStr(task, "esa_site_id"), fullDomain,
			rowStr(task, "type"), ip, rowInt(task, "ttl"))
	}
	if err != nil {
		return err
	}
	_, err = core.Update("UPDATE ddns_task SET record_id=? WHERE id=?", newId, rowInt64(task, "id"))
	return err
}

// updateRecord 更新线上解析记录。
func updateRecord(task *core.Row, recordId, ip string) error {
	ak, sk, err := credentials(task)
	if err != nil {
		return err
	}
	if rowStr(task, "provider") == "ALIYUN_DNS" {
		return dnsUpdateRecord(ak, sk, recordId, rowStr(task, "rr"),
			rowStr(task, "type"), ip, rowInt(task, "ttl"))
	}
	return esaUpdateRecord(ak, sk, recordId, rowStr(task, "type"), ip, rowInt(task, "ttl"))
}

// markStatus 记录同步结果到数据库（失败时 hasIP=false，last_ip 保持原值）。
func markStatus(taskID int64, ip string, hasIP bool, status string) error {
	if !hasIP {
		_, err := core.Update("UPDATE ddns_task SET last_sync=?, last_status=? WHERE id=?",
			core.Now(), status, taskID)
		return err
	}
	_, err := core.Update("UPDATE ddns_task SET last_ip=?, last_sync=?, last_status=? WHERE id=?",
		ip, core.Now(), status, taskID)
	return err
}

// ---------- 调度 ----------

// schedule 根据任务配置建立或重建定时调度：先取消旧句柄，再启用独立 goroutine 触发。
// 同步串行执行于自身 goroutine（不占 core 调度池），SYNCING 防重入兜底手动/定时并发。
func schedule(task *core.Row) {
	id := rowInt64(task, "id")
	cancelSchedule(id)
	if rowInt(task, "enabled") != 1 {
		return
	}
	interval := rowInt(task, "interval_sec")
	if interval < 60 {
		interval = 60
	}
	ctx, cancel := context.WithCancel(context.Background())
	mu.Lock()
	schedules[id] = cancel
	mu.Unlock()
	go func() {
		if !sleepCtx(ctx, time.Duration(syncFirstDelaySec)*time.Second) {
			return
		}
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				syncTask(id)
			}
		}
	}()
}

// cancelSchedule 取消任务定时句柄（任务增删改时重建调度）。
func cancelSchedule(id int64) {
	mu.Lock()
	if cancel, ok := schedules[id]; ok {
		cancel()
		delete(schedules, id)
	}
	mu.Unlock()
}

// ---------- 工具 ----------

// fullRecordName 主机记录 + 域名拼成完整记录名，@ 表示主域名本身。
func fullRecordName(rr, domain string) string {
	if rr == "@" {
		return domain
	}
	return rr + "." + domain
}

// credentials 任务实际生效的阿里云凭证。
// 选择了服务商凭证配置时实时读取（修改配置后所有引用任务自动生效），
// 否则使用任务内手动填写的 AccessKey。
func credentials(task *core.Row) (string, string, error) {
	if n, ok := task.Get("provider_config_id").(int64); ok {
		return provider.Credentials(n)
	}
	return rowStr(task, "access_key_id"), rowStr(task, "access_key_secret"), nil
}

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM ddns_task WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("DDNS 任务不存在: #%d", id)
	}
	return row, nil
}

// ListAll 查询全部任务（供系统信息页统计）。
func ListAll() ([]*core.Row, error) {
	return core.Query("SELECT id, name, provider, domain, rr, enabled, last_status FROM ddns_task")
}

// sleepCtx 可取消睡眠；期间被取消返回 false。0 及以下表示不等待。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func rowStr(row *core.Row, key string) string {
	switch v := row.Get(key).(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func rowInt(row *core.Row, key string) int { return int(rowInt64(row, key)) }

func rowInt64(row *core.Row, key string) int64 {
	switch v := row.Get(key).(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case []byte:
		n, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	default:
		return 0
	}
}
