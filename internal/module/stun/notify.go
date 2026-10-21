package stun

// STUN 穿透结果通知：穿透成功 / 外网映射地址变化 / 可用性自测确认失效（FAIL）时，把结果按任务勾选的渠道投递到
// 统一告警通知中心（渠道在「告警通知」页集中维护，任务只选择用哪些渠道，可多选）。复刻 Java StunNotify。
//
// 配置存于 stun_task：notify_enabled（开关）、notify_channels（勾选的渠道 id JSON 数组，如 [1,3]）。
//
// 触发点与 webhook 推送、ESA 同步完全一致（runner 的映射地址落库联动），事件标识为
// stun.punched / stun.mapped_changed（手动试发为 stun.notify_test），可在通知渠道的 Webhook
// 模板中以 ${event} 引用。此外，周期巡检自测首次确认通道失效（FAIL）时额外推送 stun.verify_failed
// 告警（仅通知中心，不触发 webhook/ESA）：按失效边沿触发，恢复后再次失效才会重新告警，避免连续失败周期刷屏。
// 投递在通知中心的独立线程串行执行，渠道被删除或停用时跳过并记日志，不影响穿透与保活；
// 每次投递写入 notify_log，可在「告警通知」页的最近发送记录中查看结果。

import (
	"encoding/json"
	"strconv"
	"strings"

	"NexHomeGo/internal/core"
	gonotify "NexHomeGo/internal/module/notify"
)

// 事件标识（与 webhook 推送的事件保持一致；verify_failed 仅通知中心）
const (
	eventChanged      = "stun.mapped_changed"
	eventTest         = "stun.notify_test"
	eventVerifyFailed = "stun.verify_failed"
)

// notifyTrigger 按任务勾选的渠道推送穿透结果；未启用或未勾选渠道时静默返回
func notifyTrigger(task *core.Row, event string) {
	if intField(task, "notify_enabled") != 1 {
		return
	}
	name := strField(task, "name")
	ids := parseChannelIds(strField(task, "notify_channels"))
	if len(ids) == 0 {
		core.LogWarn(core.LogStun, "任务["+name+"] 已启用穿透通知但未选择通知渠道，本次未投递")
		return
	}
	gonotify.BroadcastTo(ids, event, notifyTitle(event, name), notifyMessage(task, event))
}

// notifyTestSend 手动试发一次（任务列表操作列的「通知」按钮）：按当前勾选渠道投递一条测试通知，返回投递渠道数。
// 投递在通知中心的独立线程异步执行，本函数只做勾选校验，结果由调用方提示用户去「告警通知」页查看发送记录。
func notifyTestSend(task *core.Row) (int, error) {
	ids := parseChannelIds(strField(task, "notify_channels"))
	if len(ids) == 0 {
		return 0, core.NewBadRequest("任务未勾选通知渠道，请先在编辑表单中勾选至少一个渠道")
	}
	name := strField(task, "name")
	gonotify.BroadcastTo(ids, eventTest, notifyTitle(eventTest, name), notifyMessage(task, eventTest))
	return len(ids), nil
}

func notifyTitle(event, taskName string) string {
	switch event {
	case eventChanged:
		return "穿透映射地址变化：" + taskName
	case eventVerifyFailed:
		return "穿透通道自测失败：" + taskName
	case eventTest:
		return "穿透通知测试：" + taskName
	}
	return "穿透成功：" + taskName
}

// notifyMessage 正文按「字段: 值」逐行组织，邮件渠道会渲染为对齐的两列表格（见通知中心）
func notifyMessage(task *core.Row, event string) string {
	mapped := strField(task, "mapped_addr")
	if mapped == "" {
		mapped = "无"
	}
	var sb strings.Builder
	sb.WriteString("任务: " + strField(task, "name") + "\n")
	sb.WriteString("协议: " + strField(task, "protocol") + "\n")
	sb.WriteString("内网目标: " + strField(task, "target_ip") + ":" + strField(task, "target_port") + "\n")
	sb.WriteString("外网映射地址: " + mapped + "\n")
	if nat := strField(task, "nat_type"); nat != "" {
		sb.WriteString("NAT类型: " + nat + "\n")
	}
	if punchedAt := strField(task, "punched_at"); punchedAt != "" {
		sb.WriteString("穿透时间: " + punchedAt + "\n")
	}
	eventDesc := "首次穿透成功"
	switch event {
	case eventChanged:
		eventDesc = "外网映射地址已变更，后续外网访问请以此地址为准"
	case eventVerifyFailed:
		eventDesc = "可用性自测发现穿透通道不可用（FAIL），保活链路已触发重建，请检查网络或上层 NAT/防火墙"
	case eventTest:
		eventDesc = "这是一条测试通知，渠道勾选与投递链路均正常"
	}
	sb.WriteString("事件: " + eventDesc + "\n")
	if detail := strField(task, "verify_detail"); detail != "" {
		sb.WriteString("自测结果: " + detail + "\n")
	}
	sb.WriteString("时间: " + core.Now())
	return sb.String()
}

// parseChannelIds 解析渠道 id 列表（存储为 JSON 数字数组，如 [1,3]；非法项丢弃，不影响其余渠道）
func parseChannelIds(text string) []int64 {
	var ids []int64
	text = strings.TrimSpace(text)
	if text == "" {
		return ids
	}
	var arr []interface{}
	if err := json.Unmarshal([]byte(text), &arr); err != nil {
		core.LogWarn(core.LogStun, "解析穿透通知渠道配置失败: "+err.Error())
		return ids
	}
	for _, item := range arr {
		var id int64
		switch v := item.(type) {
		case float64:
			id = int64(v)
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				continue // 非数字项丢弃
			}
			id = n
		default:
			continue // 对象/空值等非数字项丢弃
		}
		if id > 0 {
			dup := false
			for _, x := range ids {
				if x == id {
					dup = true
					break
				}
			}
			if !dup {
				ids = append(ids, id)
			}
		}
	}
	return ids
}
