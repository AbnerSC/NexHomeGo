package stun

// STUN 穿透结果同步阿里云 ESA（边缘安全加速）：把外网映射 IP 写入站点解析记录的记录值、
// 把映射端口写入回源规则的回源 HTTPS 端口（等价于独立小工具 stun2esa 的 ESAUtil，改造为
// 凭证引用服务商配置 provider_config、记录与规则由前端从线上列表勾选、只更新不新增）。复刻 Java StunEsaSync。
//
// 配置存于 stun_task：esa_sync_enabled（开关）、provider_config_id（AK/SK 来源）、esa_site_id（站点）、
// esa_records/esa_rules（勾选快照 JSON 数组，元素 {"id":123,"name":"*.edge.example.com"}）。
//
// 定位策略：按 id 为主，id 在线上已不存在（记录被删除重建）时按名称回退匹配并刷新存储的 id；
// 名称也匹配不到则该项记失败——本功能只更新已有配置，绝不新增或删除云端记录。
//
// 写云端的最小化原则：UpdateRecord 把线上 Type/Ttl/Proxied 原样回传，只改 Data.Value；
// UpdateOriginRule 的 OriginScheme 沿用规则现值，只改 OriginHttpsPort；现值已与目标一致时跳过写入
// （省配额、避免站点配置反复变更）。UDP 任务的映射端口对 HTTPS 回源无意义，故只同步解析记录、不动回源规则。
//
// 同步失败仅记日志与 esa_sync_status（供前端展示与手动重试），不影响穿透主流程；
// 在独立串行线程执行，避免占用全局调度池拖慢保活导致 CGNAT 映射超时回收。

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/module/ddns"
	"NexHomeGo/internal/module/provider"
)

// esaRetryDelayMS 写操作失败后的重试间隔（毫秒），共尝试 2 次
const esaRetryDelayMS = 3_000

// 独立同步串行队列：ESA HTTP 调用可能耗时数秒到数十秒，不能占用全局调度池
var esaSyncExec = newSerialExec("stun-esa-sync")

// esaSyncTriggerAsync 穿透成功 / 映射地址变化后的异步同步（任务未启用 ESA 同步时静默返回）
func esaSyncTriggerAsync(task *core.Row) {
	if intField(task, "esa_sync_enabled") != 1 {
		return
	}
	name := strField(task, "name")
	esaSyncExec.submit(func() {
		status := esaSync(task)
		result := strField(status, "result")
		if strings.HasPrefix(result, "FAIL") {
			core.LogWarn(core.LogStun, "任务["+name+"] ESA 同步失败: "+result)
		} else {
			core.LogInfo(core.LogStun, "任务["+name+"] ESA 同步 "+result+" "+esaItemsBrief(status))
		}
	})
}

// esaSyncNow 立即同步一次（手动触发，同步执行以便调用方直接拿到明细结果）
func esaSyncNow(task *core.Row) *core.Row {
	return esaSync(task)
}

// esaPicked 勾选快照项（{id,name}）
type esaPicked struct {
	id   int64
	name string
}

// esaSync 执行一次同步并把结果写回 stun_task.esa_sync_status，返回结果对象（time/result/mapped_addr/items）
func esaSync(task *core.Row) *core.Row {
	taskId := int64(intField(task, "id"))
	taskName := strField(task, "name")
	items := core.NewRowList()
	var result string
	// 整体中断（凭证错误/列表拉取失败等）：已有明细时按部分成功上报，便于定位是哪一项之后断的
	if msg, fail := func() (msg string, fail bool) {
		defer func() {
			if rec := recover(); rec != nil {
				fail = true
				msg = fmt.Sprint(rec)
			}
		}()
		mapped := strings.TrimSpace(strField(task, "mapped_addr"))
		ci := strings.LastIndex(mapped, ":")
		if mapped == "" || ci <= 0 || ci == len(mapped)-1 {
			return "无外网映射地址，请先启动穿透任务", true
		}
		ip := mapped[:ci]
		port := mapped[ci+1:]
		siteId := strings.TrimSpace(strField(task, "esa_site_id"))
		if siteId == "" {
			return "未选择 ESA 站点", true
		}
		cfgId := int64(intField(task, "provider_config_id"))
		if cfgId <= 0 {
			return "未选择服务商凭证配置，请在任务表单中重新选择", true
		}
		ak, sk, err := provider.Credentials(cfgId)
		if err != nil {
			return err.Error(), true
		}
		if strings.TrimSpace(ak) == "" || strings.TrimSpace(sk) == "" {
			return "凭证配置的 AccessKey 为空", true
		}
		pickedRecords := parseEsaPicked(strField(task, "esa_records"))
		pickedRules := parseEsaPicked(strField(task, "esa_rules"))
		if len(pickedRecords) == 0 && len(pickedRules) == 0 {
			return "未勾选任何解析记录或回源规则", true
		}
		if len(pickedRecords) > 0 {
			if m, f := esaSyncRecords(taskId, ak, sk, siteId, pickedRecords, ip, items); f {
				return m, true
			}
		}
		if len(pickedRules) > 0 {
			if strings.EqualFold(strField(task, "protocol"), "UDP") {
				// UDP 任务的映射端口对 HTTPS 回源无意义，未改动回源规则
				items.Append(esaItem("rule", strconv.Itoa(len(pickedRules))+" 条回源规则", "", port, "SKIP",
					"UDP 任务的映射端口对 HTTPS 回源无意义，未改动回源规则"))
			} else {
				if m, f := esaSyncRules(taskId, ak, sk, siteId, pickedRules, port, items); f {
					return m, true
				}
			}
		}
		result = esaSummarize(items)
		return "", false
	}(); fail {
		if items.Len() > 0 {
			result = "PARTIAL(中断: " + msg + ")"
		} else {
			result = "FAIL(" + msg + ")"
		}
		core.LogWarn(core.LogStun, "任务["+taskName+"] ESA 同步中断: "+msg)
	}
	status := core.NewRow()
	status.Set("time", core.Now())
	status.Set("result", result)
	status.Set("mapped_addr", strField(task, "mapped_addr"))
	status.Set("items", items)
	esaSaveStatus(taskId, status)
	return status
}

// esaSyncRecords 把映射 IP 写入勾选的 ESA 解析记录（仅 A/AAAA，单值、同地址族才覆盖，其余跳过并说明）。
// 返回 (错误消息, 是否整体中断)：列表拉取失败视为整体中断。
func esaSyncRecords(taskId int64, ak, sk, siteId string, picked []esaPicked, ip string, items *core.RowList) (string, bool) {
	online, err := ddns.EsaListAllRecords(ak, sk, siteId)
	if err != nil {
		return err.Error(), true
	}
	for _, p := range picked {
		rec := esaLocate(online, p.id, p.name, "RecordId", "RecordName")
		if rec == nil {
			items.Append(esaItem("record", p.name, "", ip, "FAIL", "线上未找到该解析记录（本功能只更新不新增）"))
			continue
		}
		recordId := strconv.FormatInt(esaLong(rec, "RecordId"), 10)
		recType := esaStr(rec, "RecordType")
		current := esaValueOf(rec)
		if recType != "" && !strings.EqualFold(recType, "A/AAAA") &&
			!strings.EqualFold(recType, "A") && !strings.EqualFold(recType, "AAAA") {
			items.Append(esaItem("record", p.name, current, ip, "SKIP", "记录类型为 "+recType+"，非地址记录不改"))
			continue
		}
		if strings.Contains(current, ",") {
			items.Append(esaItem("record", p.name, current, ip, "SKIP", "线上为多值记录，整体覆盖会丢失其余地址，请手工处理"))
			continue
		}
		if strings.Contains(current, ":") != strings.Contains(ip, ":") {
			items.Append(esaItem("record", p.name, current, ip, "FAIL", "地址族不匹配（线上 "+
				esaFam(current)+"，映射 "+esaFam(ip)+"）"))
			continue
		}
		if ip == current {
			items.Append(esaItem("record", p.name, current, ip, "SKIP", "记录值无变化"))
			continue
		}
		ttl := esaInt(rec, "Ttl", 1) // 线上缺失时按“自动”（1）传参
		proxied := core.BodyBool(rec, "Proxied", false)
		writeType := recType
		if writeType == "" {
			writeType = "A/AAAA"
		}
		last := esaWrite(taskId, "esa_records", p.name, "RecordId", online, recordId, func(id string) error {
			return ddns.EsaUpdateRecordValue(ak, sk, id, writeType, ip, ttl, proxied)
		})
		if last == nil {
			items.Append(esaItem("record", p.name, current, ip, "OK", "记录值已更新"))
		} else {
			items.Append(esaItem("record", p.name, current, ip, "FAIL", errDesc(last)))
		}
	}
	return "", false
}

// esaSyncRules 把映射端口写入勾选的 ESA 回源规则 HTTPS 端口（跳过全局配置，协议沿用规则现值）
func esaSyncRules(taskId int64, ak, sk, siteId string, picked []esaPicked, port string, items *core.RowList) (string, bool) {
	online, err := ddns.EsaListOriginRules(ak, sk, siteId)
	if err != nil {
		return err.Error(), true
	}
	for _, p := range picked {
		cfg := esaLocate(online, p.id, p.name, "ConfigId", "RuleName")
		if cfg == nil {
			items.Append(esaItem("rule", p.name, "", port, "FAIL", "线上未找到该回源规则"))
			continue
		}
		if strings.EqualFold(esaStr(cfg, "ConfigType"), "global") {
			items.Append(esaItem("rule", p.name, "", port, "SKIP", "全局回源配置不适用规则端口同步"))
			continue
		}
		configId := strconv.FormatInt(esaLong(cfg, "ConfigId"), 10)
		current := esaStr(cfg, "OriginHttpsPort")
		if port == current {
			items.Append(esaItem("rule", p.name, current, port, "SKIP", "回源端口无变化"))
			continue
		}
		scheme := esaStr(cfg, "OriginScheme")
		if scheme == "" {
			scheme = "https" // 线上未返回协议时按本功能的语义固定 HTTPS，避免被改回默认值
		}
		last := esaWrite(taskId, "esa_rules", p.name, "ConfigId", online, configId, func(id string) error {
			return ddns.EsaUpdateOriginRulePort(ak, sk, siteId, id, scheme, port)
		})
		if last == nil {
			items.Append(esaItem("rule", p.name, current, port, "OK", "回源 HTTPS 端口已更新"))
		} else {
			items.Append(esaItem("rule", p.name, current, port, "FAIL", errDesc(last)))
		}
	}
	return "", false
}

// esaWriteOp 写操作：入参为本次实际使用的配置 id（解析记录 RecordId / 回源规则 ConfigId）
type esaWriteOp func(id string) error

// esaWrite 执行一次写操作并在失败时重试（共 2 次）：首轮失败后按名称回退重定位（记录被删除重建会使
// 快照 id 失效，换用新 id 重试并写回任务配置），等待 esaRetryDelayMS 再试一次。返回 nil 表示成功，否则末次错误。
func esaWrite(taskId int64, column, name, idField string, online []map[string]interface{}, id string, op esaWriteOp) error {
	currentId := id
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			// 名称回退：id 在线上已失效（删除重建）时换用新 id 重试，并把新 id 写回任务勾选快照
			byName := esaLocate(online, 0, name, idField, esaNameField(idField))
			if byName != nil {
				freshId := strconv.FormatInt(esaLong(byName, idField), 10)
				if freshId != currentId {
					currentId = freshId
					esaRefreshId(taskId, column, name, freshId)
				}
			}
		}
		err := op(currentId)
		if err == nil {
			return nil
		}
		last = err
		if attempt == 0 {
			core.LogWarn(core.LogStun, "ESA 写入失败("+name+")，"+
				strconv.Itoa(esaRetryDelayMS/1000)+" 秒后重试: "+errDesc(err))
			time.Sleep(esaRetryDelayMS * time.Millisecond)
		}
	}
	return last
}

// parseEsaPicked 解析勾选快照列（JSON 数组，元素 {id,name}），缺失或非法时返回空表
func parseEsaPicked(text string) []esaPicked {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var arr []map[string]interface{}
	// UseNumber：勾选快照里的 id 可能为大整数（与响应层同语义精确解析，不可经 float64 丢精度）
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if dec.Decode(&arr) != nil {
		core.LogWarn(core.LogStun, "解析 ESA 勾选配置失败: text="+text)
		return nil
	}
	var out []esaPicked
	for _, o := range arr {
		if o == nil {
			continue
		}
		out = append(out, esaPicked{id: esaLong(o, "id"), name: core.BodyStr(o, "name")})
	}
	return out
}

// esaLocate 按 id 定位线上配置，id 未命中时按名称回退（应对记录删除重建后的 id 漂移）
func esaLocate(online []map[string]interface{}, id int64, name, idField, nameField string) map[string]interface{} {
	if id > 0 {
		for _, o := range online {
			if o != nil && esaLong(o, idField) == id {
				return o
			}
		}
	}
	if name != "" {
		for _, o := range online {
			if o != nil && strings.EqualFold(esaStr(o, nameField), name) {
				return o
			}
		}
	}
	return nil
}

// esaNameField 由 id 字段名推名称字段名（RecordId -> RecordName，ConfigId -> RuleName）
func esaNameField(idField string) string {
	if idField == "ConfigId" {
		return "RuleName"
	}
	return "RecordName"
}

// esaValueOf 取解析记录的当前记录值（ESA 的 Data.Value）
func esaValueOf(rec map[string]interface{}) string {
	if data, ok := rec["Data"].(map[string]interface{}); ok {
		return core.BodyStr(data, "Value")
	}
	return ""
}

// esaRefreshId 把回退定位到的新 id 写回任务勾选快照，下次同步直接按新 id 命中
func esaRefreshId(taskId int64, column, name, newId string) {
	defer func() { recover() }()
	row, err := core.QueryOne("SELECT "+column+" FROM stun_task WHERE id=?", taskId)
	if err != nil || row == nil {
		return
	}
	picked := parseEsaPicked(strField(row, column))
	changed := false
	newIdNum := strings.TrimSpace(newId)
	for i := range picked {
		if strings.EqualFold(picked[i].name, name) {
			picked[i].id, _ = strconv.ParseInt(newIdNum, 10, 64)
			changed = true
		}
	}
	if !changed {
		return
	}
	arr := core.NewRowList()
	for _, p := range picked {
		arr.Append(core.NewRow().Set("id", p.id).Set("name", p.name))
	}
	b, merr := json.Marshal(arr)
	if merr != nil {
		return
	}
	if _, err = core.Update("UPDATE stun_task SET "+column+"=? WHERE id=?", string(b), taskId); err != nil {
		core.LogWarn(core.LogStun, "刷新 ESA 配置 id 失败("+name+"): "+err.Error())
		return
	}
	core.LogInfo(core.LogStun, "ESA 配置 id 已刷新("+name+" -> "+newId+")")
}

// esaSummarize 汇总明细为结果文案：全部跳过=无变化，有写入=更新项数，有失败=PARTIAL/FAIL
func esaSummarize(items *core.RowList) string {
	ok, fail := 0, 0
	for _, it := range items.Items() {
		switch strField(it, "state") {
		case "OK":
			ok++
		case "FAIL":
			fail++
		}
	}
	total := items.Len()
	if total == 0 {
		return "FAIL(无可同步项)"
	}
	if fail == 0 {
		if ok > 0 {
			return "OK(更新 " + strconv.Itoa(ok) + " 项)"
		}
		return "OK(无变化)"
	}
	if ok+fail < total || ok > 0 {
		return "PARTIAL(成功 " + strconv.Itoa(total-fail) + "/" + strconv.Itoa(total) + ")"
	}
	return "FAIL(" + strconv.Itoa(total) + " 项全部失败)"
}

// esaItemsBrief 明细的一行摘要（写日志用，避免整段 JSON 刷屏）
func esaItemsBrief(status *core.Row) string {
	var sb strings.Builder
	list, _ := status.Get("items").(*core.RowList)
	if list == nil {
		return "(无明细)"
	}
	for _, o := range list.Items() {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(strField(o, "kind") + ":" + strField(o, "name") + "=" + strField(o, "state"))
	}
	if sb.Len() == 0 {
		return "(无明细)"
	}
	return sb.String()
}

// esaItem 单条同步明细：kind=record|rule，state=OK|SKIP|FAIL
func esaItem(kind, name, from, to, state, msg string) *core.Row {
	return core.NewRow().
		Set("kind", kind).Set("name", name).Set("from", from).
		Set("to", to).Set("state", state).Set("msg", msg)
}

func esaSaveStatus(taskId int64, status *core.Row) {
	if taskId <= 0 {
		return
	}
	b, err := json.Marshal(status)
	if err != nil {
		return
	}
	if _, err = core.Update("UPDATE stun_task SET esa_sync_status=? WHERE id=?", string(b), taskId); err != nil {
		core.LogError(core.LogStun, "记录 ESA 同步结果失败(task#"+strconv.FormatInt(taskId, 10)+"): "+err.Error())
	}
}

// esaFam 地址族描述（含冒号为 IPv6，否则 IPv4）
func esaFam(s string) string {
	if strings.Contains(s, ":") {
		return "IPv6"
	}
	return "IPv4"
}

// esaStr 从线上对象取字符串字段（等价 Java JsonUtils.str(JsonObject)：数字转字符串）
func esaStr(o map[string]interface{}, k string) string {
	return core.BodyStr(o, k)
}

// errDesc 错误描述（Message 为空时退回 Error 串，等价 Java e.getMessage()==null?e.toString():getMessage）
func errDesc(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// esaLong 从线上对象取整型字段（数字/数字字符串，缺失/非法返回 0，等价 Java longOf）。
// json.Number 按原始字面量精确解析（ESA RecordId/ConfigId 可达 18 位，不可经 float64）
func esaLong(o map[string]interface{}, k string) int64 {
	switch v := o[k].(type) {
	case json.Number:
		n, _ := strconv.ParseInt(v.String(), 10, 64)
		return n
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	}
	return 0
}

// esaInt 从线上对象取整型字段带默认值（等价 Java intOf）
func esaInt(o map[string]interface{}, k string, def int) int {
	v, ok := o[k]
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.Atoi(strings.TrimSpace(x.String())); err == nil {
			return n
		}
		return def
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return def
}
