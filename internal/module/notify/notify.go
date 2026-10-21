package notify

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 统一告警通知中心：集中维护通知渠道（Webhook / Email / 钉钉），
// 各业务模块通过 Broadcast 将事件按启用渠道扇出，或通过 BroadcastTo 只投递到任务自选的若干渠道。
// 路径/方法/响应结构/结果文案逐一复刻 Java NotifyService，保证前端与存量数据零改动。
//
// 渠道配置存于 notify_channel.config（JSON，按类型字段不同）：
//   - WEBHOOK：{"url","method":"GET|POST","headers":{...},"bodyTemplate":"..."}，
//     URL/请求头/bodyTemplate 支持占位符 ${title} ${message} ${event} ${time}
//   - EMAIL：{"host","port","ssl","starttls","username","password","from","to",
//     "saveSent","imapHost","imapPort","imapSsl","imapStarttls","sentFolder"}；
//     saveSent 开启时 SMTP 发送成功后将副本经 IMAP APPEND 存入「已发送」文件夹
//   - DINGTALK：{"webhook":"https://oapi.dingtalk.com/robot/send?access_token=xxx","secret":"加签密钥(可选)"}
//
// 投递在独立单线程队列串行执行，绝不占用 core 调度池（慢 HTTP/SMTP 会拖垮调度），
// 发送失败仅记日志并写 notify_log，不影响调用方主流程。

// 渠道类型
const (
	TypeWebhook  = "WEBHOOK"
	TypeEmail    = "EMAIL"
	TypeDingTalk = "DINGTALK"
)

var placeholderRe = regexp.MustCompile(`\$\{(\w+)\}`)

// queue 独立投递队列（单 worker goroutine，等价 Java 的 nexhome-notify 单线程 executor）。
var (
	queueOnce sync.Once
	queue     = make(chan func(), 1024)
)

func startWorker() {
	queueOnce.Do(func() {
		go func() {
			for job := range queue {
				runJob(job)
			}
		}()
	})
}

// submit 异步排队投递；队列满时丢弃并告警（等价无界队列的极端保护，正常不可能触发）。
func submit(job func()) {
	startWorker()
	select {
	case queue <- job:
	default:
		core.LogWarn(core.LogNotify, "通知投递队列已满，丢弃一条投递")
	}
}

func runJob(job func()) {
	defer func() {
		if r := recover(); r != nil {
			core.LogError(core.LogNotify, "通知投递任务异常")
		}
	}()
	job()
}

// RegisterRoutes 注册 REST 接口。
func RegisterRoutes() {
	web.Route("GET", "/api/notify/channels", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM notify_channel ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
	web.Route("POST", "/api/notify/channels", create)
	web.Route("PUT", "/api/notify/channels/{id}", update)
	web.Route("DELETE", "/api/notify/channels/{id}", remove)
	// 测试已保存渠道（同步投递并写 notify_log，与 Java 一致）
	web.Route("POST", "/api/notify/channels/{id}/test", func(c *web.Ctx) error {
		ch, err := mustGet(c.ParamLong("id"))
		if err != nil {
			return err
		}
		result := dispatch(rowStr(ch, "type"), parseConfig(rowStr(ch, "config")),
			"测试通知", "这是一条来自 NexHome 的测试通知消息。", "notify.test")
		record(rowInt64(ch, "id"), rowStr(ch, "name"), "notify.test", "测试通知", result)
		if strings.HasPrefix(result, "OK") {
			c.Ok("测试发送成功：" + result)
		} else {
			c.Ok(result)
		}
		return nil
	})
	// 测试未保存的草稿（编辑弹窗直接试发，不写 notify_log）
	web.Route("POST", "/api/notify/channels/test", func(c *web.Ctx) error {
		b := c.Body()
		typ := core.BodyStr(b, "type")
		var config map[string]interface{}
		if m, ok := b["config"].(map[string]interface{}); ok {
			config = m
		}
		result := dispatch(typ, config, "测试通知", "这是一条来自 NexHome 的测试通知消息。", "notify.test")
		if strings.HasPrefix(result, "OK") {
			c.Ok("测试发送成功：" + result)
		} else {
			c.Ok("测试发送失败：" + result)
		}
		return nil
	})
	web.Route("GET", "/api/notify/logs", func(c *web.Ctx) error {
		limit := 100
		if q := strings.TrimSpace(c.Query("limit")); q != "" {
			if n, err := strconv.Atoi(q); err == nil {
				if n < 1 {
					n = 1
				}
				if n > 200 {
					n = 200
				}
				limit = n
			}
		}
		rows, err := core.Query("SELECT id, time, channel, event, title, result " +
			"FROM notify_log ORDER BY id DESC LIMIT " + strconv.Itoa(limit))
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
}

// Init 启动时初始化：定期清理过旧通知日志（与 op_log 同策略），保留最近 5000 条；并拉起投递队列。
// 注意：op_log 的清理由 main 中的 core.Every(60,3600,core.TruncateOld) 统一负责（Java 在同一任务里做两件事）。
func Init() {
	startWorker()
	core.Every(60, 3600, func() {
		_, _ = core.Update("DELETE FROM notify_log WHERE id <= (SELECT MAX(id) - 5000 FROM notify_log)")
	})
}

// Broadcast 将事件按全部启用渠道异步扇出。无启用渠道时静默返回；调用方无需等待、不会因异常中断。
// event 事件标识（如 monitor.down / auth.lockout），供渠道模板与过滤使用。
func Broadcast(event, title, message string) {
	channels, err := core.Query("SELECT * FROM notify_channel WHERE enabled=1 ORDER BY id")
	if err != nil {
		core.LogError(core.LogNotify, "查询通知渠道失败: "+err.Error())
		return
	}
	if len(channels) == 0 {
		return
	}
	for _, ch := range channels {
		typ := rowStr(ch, "type")
		config := parseConfig(rowStr(ch, "config"))
		id := rowInt64(ch, "id")
		name := rowStr(ch, "name")
		submit(func() {
			result := dispatch(typ, config, title, message, event)
			record(id, name, event, title, result)
		})
	}
}

// BroadcastTo 将事件按指定渠道异步扇出（供各模块做「按任务自选渠道」的通知投递，
// 与 Broadcast 的区别只在于渠道由调用方给定而非「全部启用渠道」）。
// 渠道 id 的存在性与启用状态在投递队列内逐条核对：已被删除的渠道记告警跳过，
// 已停用的渠道同样跳过（停用即全局静默，不因任务勾选而绕过）；每次投递仍写 notify_log。
func BroadcastTo(channelIDs []int64, event, title, message string) {
	// 去重且保持顺序（等价 LinkedHashSet）
	seen := map[int64]bool{}
	ids := make([]int64, 0, len(channelIDs))
	for _, id := range channelIDs {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	// 查询也放到投递队列：调用方多为保活/接收线程，不该为通知承担数据库锁等待
	submit(func() {
		for _, cid := range ids {
			ch, err := core.QueryOne("SELECT * FROM notify_channel WHERE id=?", cid)
			if err != nil {
				core.LogError(core.LogNotify, "查询通知渠道 #"+strconv.FormatInt(cid, 10)+" 失败: "+err.Error())
				continue
			}
			if ch == nil {
				core.LogWarn(core.LogNotify, "通知渠道已删除，跳过事件 "+event+": #"+strconv.FormatInt(cid, 10))
				continue
			}
			if rowInt64(ch, "enabled") != 1 {
				core.LogInfo(core.LogNotify, "通知渠道["+rowStr(ch, "name")+"] 已停用，跳过事件 "+event)
				continue
			}
			result := dispatch(rowStr(ch, "type"), parseConfig(rowStr(ch, "config")), title, message, event)
			record(rowInt64(ch, "id"), rowStr(ch, "name"), event, title, result)
		}
	})
}

// ---------- 渠道增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	typ, err := normalizeType(core.BodyStr(b, "type"))
	if err != nil {
		return err
	}
	cfg := configOf(b)
	if err := validate(typ, cfg); err != nil {
		return err
	}
	id, err := core.Insert("INSERT INTO notify_channel(name, type, enabled, config) VALUES(?,?,?,?)",
		core.BodyStr(b, "name"), typ, boolToInt(core.BodyBool(b, "enabled", true)), configRaw(c.BodyText()))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogNotify, "新增通知渠道: "+core.BodyStr(b, "name")+"("+typ+")")
	ch, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(ch)
	return nil
}

func update(c *web.Ctx) error {
	id := c.ParamLong("id")
	if _, err := mustGet(id); err != nil {
		return err
	}
	b := c.Body()
	typ, err := normalizeType(core.BodyStr(b, "type"))
	if err != nil {
		return err
	}
	cfg := configOf(b)
	if err := validate(typ, cfg); err != nil {
		return err
	}
	if _, err := core.Update("UPDATE notify_channel SET name=?, type=?, enabled=?, config=? WHERE id=?",
		core.BodyStr(b, "name"), typ, boolToInt(core.BodyBool(b, "enabled", true)), configRaw(c.BodyText()), id); err != nil {
		return err
	}
	core.LogInfo(core.LogNotify, "更新通知渠道 #"+strconv.FormatInt(id, 10)+": "+core.BodyStr(b, "name"))
	ch, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(ch)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	ch, err := mustGet(id)
	if err != nil {
		return err
	}
	if _, err := core.Update("DELETE FROM notify_channel WHERE id=?", id); err != nil {
		return err
	}
	core.LogInfo(core.LogNotify, "删除通知渠道 #"+strconv.FormatInt(id, 10)+": "+rowStr(ch, "name"))
	c.Ok("已删除")
	return nil
}

// configOf 请求体里的 config 对象（前端统一以 config 字段提交各类型表单），缺失返回空对象。
func configOf(b map[string]interface{}) map[string]interface{} {
	if m, ok := b["config"].(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

// configRaw 从请求体原文提取 config 对象的紧凑 JSON（保持键的提交顺序，等价 Gson JsonObject.toString）。
// config 缺失或非对象时返回 "{}"。
func configRaw(bodyText string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bodyText), &m); err != nil {
		return "{}"
	}
	raw, ok := m["config"]
	if !ok || len(raw) == 0 || raw[0] != '{' {
		return "{}"
	}
	var sb bytes.Buffer
	if err := json.Compact(&sb, raw); err != nil {
		return "{}"
	}
	return sb.String()
}

func normalizeType(typeStr string) (string, error) {
	t := strings.ToUpper(strings.TrimSpace(typeStr))
	switch t {
	case TypeWebhook, TypeEmail, TypeDingTalk:
		return t, nil
	}
	return "", core.NewBadRequest("不支持的通知渠道类型: %s", typeStr)
}

func validate(typ string, cfg map[string]interface{}) error {
	switch typ {
	case TypeWebhook:
		if strings.TrimSpace(core.BodyStr(cfg, "url")) == "" {
			return core.NewBadRequest("Webhook 地址不能为空")
		}
	case TypeEmail:
		if strings.TrimSpace(core.BodyStr(cfg, "host")) == "" {
			return core.NewBadRequest("SMTP 服务器不能为空")
		}
		if strings.TrimSpace(core.BodyStr(cfg, "to")) == "" {
			return core.NewBadRequest("收件人不能为空")
		}
		if core.BodyBool(cfg, "saveSent", false) &&
			strings.TrimSpace(core.BodyStr(cfg, "username")) == "" {
			return core.NewBadRequest("开启已发送存档需填写用户名（IMAP 以该账号登录）")
		}
	case TypeDingTalk:
		if strings.TrimSpace(core.BodyStr(cfg, "webhook")) == "" {
			return core.NewBadRequest("钉钉机器人 Webhook 不能为空")
		}
	default:
		return core.NewBadRequest("未知渠道类型: %s", typ)
	}
	return nil
}

// ---------- 分发投递 ----------

// dispatch 按类型投递一条通知，返回结果文案（OK... / FAIL(...)），不抛出。
func dispatch(typ string, cfg map[string]interface{}, title, message, event string) (result string) {
	defer func() {
		if r := recover(); r != nil {
			result = "FAIL(" + toString(r) + ")"
		}
	}()
	var (
		r   string
		err error
	)
	switch typ {
	case TypeWebhook:
		r, err = sendWebhook(cfg, title, message, event)
	case TypeEmail:
		r, err = sendEmail(cfg, title, message, event)
	case TypeDingTalk:
		r, err = sendDingTalk(cfg, title, message)
	default:
		return "FAIL(未知渠道类型 " + typ + ")"
	}
	if err != nil {
		return "FAIL(" + err.Error() + ")"
	}
	return r
}

// ---------- 记录与工具 ----------

// record 写一条发送记录到 notify_log（等价 Java record）。
func record(channelID int64, channelName, event, title, result string) {
	ok := strings.HasPrefix(result, "OK")
	if ok {
		core.LogInfo(core.LogNotify, "通知["+channelName+"] "+event+" 发送成功: "+result)
	} else {
		core.LogWarn(core.LogNotify, "通知["+channelName+"] "+event+" 发送失败: "+result)
	}
	_, _ = core.Insert("INSERT INTO notify_log(time, channel_id, channel, event, title, result) "+
		"VALUES(?,?,?,?,?,?)", core.Now(), channelID, channelName, event, title, result)
}

func parseConfig(s string) map[string]interface{} {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return map[string]interface{}{}
	}
	return m
}

// replace 占位符替换：${key} → data[key]，未知键替换为空串（等价 Java replace）。
func replace(text string, data map[string]string) string {
	if !strings.Contains(text, "${") {
		return text
	}
	return placeholderRe.ReplaceAllStringFunc(text, func(mt string) string {
		key := placeholderRe.FindStringSubmatch(mt)[1]
		return data[key] // 缺失键 → 空串（getOrDefault 语义）
	})
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM notify_channel WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("通知渠道不存在: #%d", id)
	}
	return row, nil
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

func rowInt64(row *core.Row, key string) int64 {
	switch v := row.Get(key).(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func toString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return ""
	}
}
