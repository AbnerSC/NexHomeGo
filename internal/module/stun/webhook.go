package stun

// STUN 穿透结果 Webhook 推送：穿透成功 / 外网映射地址变化时，将结果按任务配置的
// 多个 webhook 异步推送到其他系统。支持 GET / POST 两种请求方式与自定义参数。
// 复刻 Java StunWebhook。
//
// 配置存于 stun_task.webhook_config（JSON 数组），每项：
//
//	{"url":"https://...","method":"POST","headers":{"Authorization":"Bearer xxx"},"params":{"token":"xxx","addr":"${mapped_addr}"}}
//
// 占位符 ${字段} 取任务结果列值（event/id/name/protocol/target_ip/target_port/
// mapped_addr/nat_type/punched_at/check_result/status 等），URL、请求头与自定义参数值均支持。
//   - POST：以 application/json 发送「结果字段 + 自定义参数」合并的请求体（Content-Type 可被自定义头覆盖）
//   - GET：将「结果字段 + 自定义参数」URL 编码后拼为查询串
//
// 每条 webhook 的最近一次调用时间与结果（成功/失败原因）写回 stun_task.webhook_status
// （JSON 对象，url -> {time,result}），供前端展示。推送失败仅记日志，不影响穿透主流程；
// 异步在独立串行线程执行，避免占用全局调度池拖慢保活
// （与公网入站验证同理：调度池被慢 HTTP 占用会延迟保活导致 CGNAT 映射超时回收——穿透静默失效的直接诱因）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// webhookFields 结果字段：作为 POST 请求体 / GET 查询串的内容，同时供 ${字段} 占位符引用
var webhookFields = []string{
	"id", "name", "protocol", "target_ip", "target_port", "bind_port",
	"stun_host", "stun_port", "peer_addr", "mapped_addr", "mapped_ip", "mapped_port",
	"nat_type", "punched_at", "check_time", "check_result", "status",
}

// kvSeq 保序键值对（等价 Java LinkedHashMap 语义：headers/params 的推送顺序影响
// GET 查询串与默认 POST 体的字段顺序，须与配置 JSON 中的书写顺序一致）
type kvSeq struct {
	keys []string
	m    map[string]string
}

func newKVSeq() *kvSeq { return &kvSeq{m: map[string]string{}} }

func (s *kvSeq) put(k, v string) {
	if _, has := s.m[k]; !has {
		s.keys = append(s.keys, k)
	}
	s.m[k] = v
}

var webhookPlaceholder = regexp.MustCompile(`\$\{(\w+)\}`)

// 独立推送串行队列：webhook HTTP 可能耗时较久，不能占用全局调度池
var webhookExec = newSerialExec("stun-webhook")

// webhookHTTP 连接超时 10s（等价 Java HttpClient.connectTimeout），单次请求整体 20s 超时由 context 控制
var webhookHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConns:        16,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// pushWebhook 按任务配置推送穿透结果（event 为 stun.punched / stun.mapped_changed）；无配置时静默返回
func pushWebhook(task *core.Row, event string) {
	config := strings.TrimSpace(strField(task, "webhook_config"))
	if config == "" {
		return
	}
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(config), &arr); err != nil {
		core.LogWarn(core.LogStun, "解析 webhook 配置失败: "+err.Error())
		return
	}
	taskId := int64(intField(task, "id"))
	data := buildWebhookData(task, event)
	name := strField(task, "name")
	for _, el := range arr {
		var w map[string]json.RawMessage
		if json.Unmarshal(el, &w) != nil || w == nil {
			continue // 非对象项跳过
		}
		u := strings.TrimSpace(rawStr(w, "url"))
		if u == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(rawStr(w, "method")))
		if method != "GET" {
			method = "POST"
		}
		headers := readWebhookMap(w, "headers", data)
		params := readWebhookMap(w, "params", data)
		bodyTpl := ""
		if bv, has := w["body"]; has {
			if s, ok := jsonStr(bv); ok {
				bodyTpl = replaceWebhook(s, data)
			}
		}
		target := replaceWebhook(u, data)
		verb, key := method, u // 状态以配置的原始 URL（含占位符）为键，与前端 webhook_config 一致便于回显
		webhookExec.submit(func() {
			recordWebhookResult(taskId, key, sendWebhook(name, target, verb, data, params, headers, bodyTpl))
		})
	}
}

// sendWebhook 执行一次 webhook 推送，返回调用结果文案（OK(HTTP xxx) / FAIL(...)），仅记日志不抛出
func sendWebhook(taskName, target, method string, data *webhookData,
	params, headers *kvSeq, bodyTpl string) (ret string) {
	defer func() {
		if rec := recover(); rec != nil {
			ret = "FAIL(" + fmt.Sprint(rec) + ")"
		}
	}()
	rawURL := target
	if method == "GET" {
		var qs strings.Builder
		appendQs := func(k, v string) {
			if qs.Len() > 0 {
				qs.WriteByte('&')
			}
			qs.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(v))
		}
		for _, k := range data.keys {
			appendQs(k, data.vals[k])
		}
		for _, k := range params.keys {
			appendQs(k, params.m[k])
		}
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		target = rawURL + sep + qs.String()
	}

	var payload string
	if method == "GET" {
		payload = ""
	} else if strings.TrimSpace(bodyTpl) != "" {
		// 用户自定义 JSON 请求体（已做占位符替换）
		payload = bodyTpl
	} else {
		// 兼容旧模式：结果字段 + 自定义参数合并为 JSON（保序）
		o := core.NewRow()
		for _, k := range data.keys {
			o.Set(k, data.vals[k])
		}
		for _, k := range params.keys {
			o.Set(k, params.m[k])
		}
		b, err := json.Marshal(o)
		if err != nil {
			return "FAIL(" + err.Error() + ")"
		}
		payload = string(b)
	}

	var req *http.Request
	var err error
	if method == "GET" {
		req, err = http.NewRequest(http.MethodGet, target, nil)
	} else {
		req, err = http.NewRequest(http.MethodPost, target, strings.NewReader(payload))
	}
	if err != nil {
		core.LogWarn(core.LogStun, "任务["+taskName+"] 推送 webhook 失败("+rawURL+"): "+err.Error())
		return "FAIL(" + err.Error() + ")"
	}
	req.Header.Set("User-Agent", "NexHome-STUN")
	hasContentType := false
	for _, k := range headers.keys {
		v := headers.m[k]
		if strings.EqualFold(k, "Content-Type") {
			hasContentType = true
		}
		// Go 侧无 Java 的受限头异常；Host 由 req.Host 表达，其余头直接设置
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	if method != "GET" && !hasContentType {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := webhookHTTP.Do(req.WithContext(ctx))
	if err != nil {
		core.LogWarn(core.LogStun, "任务["+taskName+"] 推送 webhook 失败("+rawURL+"): "+err.Error())
		return "FAIL(" + err.Error() + ")"
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		core.LogInfo(core.LogStun, "任务["+taskName+"] 穿透结果已推送 webhook("+method+"): "+rawURL+
			" HTTP "+strconv.Itoa(code))
		return "OK(HTTP " + strconv.Itoa(code) + ")"
	}
	r := "FAIL(HTTP " + strconv.Itoa(code) + " " + truncateStr(string(body)) + ")"
	core.LogWarn(core.LogStun, "任务["+taskName+"] 推送 webhook 返回非 2xx: "+r)
	return r
}

// webhookData 结果字段值表（保序）：event + 各任务列
type webhookData struct {
	keys []string
	vals map[string]string
}

func (d *webhookData) put(k, v string) {
	if _, has := d.vals[k]; !has {
		d.keys = append(d.keys, k)
	}
	d.vals[k] = v
}

// readWebhookMap 读取 webhook 项内的对象字段（headers/params）并对值做占位符替换。
// 配置以 map[string]json.RawMessage 接收（值保留原始文本），orderedJSONEntries 恢复键序
func readWebhookMap(w map[string]json.RawMessage, key string, data *webhookData) *kvSeq {
	m := newKVSeq()
	sub, ok := w[key]
	if !ok {
		return m
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(sub, &obj) != nil || obj == nil {
		return m // 非对象（缺失/null）：空表
	}
	for _, e := range orderedJSONEntries(string(sub)) {
		s := ""
		if ss, isStr := jsonStr(e.value); isStr {
			s = ss
		} else if e.value != nil {
			s = string(e.value)
		}
		m.put(e.key, replaceWebhook(s, data))
	}
	return m
}

// recordWebhookResult 将某条 webhook 最近一次调用时间与结果写回 stun_task.webhook_status
// （url -> {time,result}）；推送在串行队列执行无需加锁
func recordWebhookResult(taskId int64, urlKey, result string) {
	if taskId <= 0 {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			core.LogWarn(core.LogStun, "记录 webhook 调用结果失败(task#"+strconv.FormatInt(taskId, 10)+"): "+fmt.Sprint(rec))
		}
	}()
	row, err := core.QueryOne("SELECT webhook_status FROM stun_task WHERE id=?", taskId)
	if err != nil || row == nil {
		return
	}
	status := core.NewRow()
	text := strings.TrimSpace(strField(row, "webhook_status"))
	if text != "" {
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &m) == nil {
			for _, e := range orderedJSONEntries(text) {
				status.Set(e.key, e.value)
			}
		}
	}
	status.Set(urlKey, core.NewRow().Set("time", core.Now()).Set("result", result))
	b, merr := json.Marshal(status)
	if merr != nil {
		return
	}
	if _, err = core.Update("UPDATE stun_task SET webhook_status=? WHERE id=?", string(b), taskId); err != nil {
		core.LogWarn(core.LogStun, "记录 webhook 调用结果失败(task#"+strconv.FormatInt(taskId, 10)+"): "+err.Error())
	}
}

// buildWebhookData 结果字段值表：event + 各任务列（缺失列以空串占位，保证占位符可解析）
func buildWebhookData(task *core.Row, event string) *webhookData {
	d := &webhookData{vals: map[string]string{}}
	d.put("event", event)
	for _, f := range webhookFields {
		d.put(f, strField(task, f))
	}
	// 从 mapped_addr (如 "1.2.3.4:5678") 拆分出独立的 mapped_ip 和 mapped_port（覆盖列值）；
	// mapped_addr 无冒号时保留 FIELDS 循环已写入的 mapped_ip/mapped_port 列值（等价 Java putIfAbsent）
	mappedAddr := d.vals["mapped_addr"]
	if idx := strings.LastIndex(mappedAddr, ":"); mappedAddr != "" && idx > 0 {
		d.put("mapped_ip", mappedAddr[:idx])
		d.put("mapped_port", mappedAddr[idx+1:])
	}
	return d
}

// replaceWebhook 将文本中的 ${字段} 占位符替换为结果字段值（未知字段替换为空串）
func replaceWebhook(text string, data *webhookData) string {
	if text == "" || !strings.Contains(text, "${") {
		return text
	}
	return webhookPlaceholder.ReplaceAllStringFunc(text, func(m string) string {
		key := webhookPlaceholder.FindStringSubmatch(m)[1]
		return data.vals[key] // 未知字段为空串
	})
}

// truncateStr webhook 失败响应体截断（超 200 字符保留前 200 + 省略号）
func truncateStr(s string) string {
	if s != "" && len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
