package stun

// STUN 服务器维护：常用服务器列表增删改查，穿透任务新增/编辑时下拉选择。
// 复刻 Java StunServerService。
//
// tcp_support 标记服务器是否支持 STUN-over-TCP：TCP 穿透任务必须借助支持 TCP 的
// 服务器出站，才能在运营商 CGNAT 上建立真实 TCP 映射；配置的服务器不支持时，
// 运行器按本表 tcp_support=1 的列表依次兜底。

import (
	"strconv"
	"strings"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// registerServerRoutes 注册 STUN 服务器维护 REST 接口
func registerServerRoutes() {
	web.Route("GET", "/api/stun/servers", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM stun_server ORDER BY sort_order, id")
		if err != nil {
			return err
		}
		c.Ok(rows)
		return nil
	})
	web.Route("POST", "/api/stun/servers", serverCreate)
	web.Route("POST", "/api/stun/servers/probe-tcp", serverProbeTcp)
	web.Route("POST", "/api/stun/servers/{id}/move", serverMove)
	web.Route("PUT", "/api/stun/servers/{id}", serverUpdate)
	web.Route("DELETE", "/api/stun/servers/{id}", serverDelete)
}

// seedServers 常用公共 STUN 服务器（name, host, port, tcp_support），按展示顺序播种。
// tcp_support 为运行期探测依据：实测支持 TCP 的标 1（Twilio TURN 在电信 CGNAT 下 443/80 实测可达）；
// 部分运营商 CGNAT 封锁 3478/TCP 出站，此类候选探测自动跳过，不影响其余流程
var seedServers = [][4]string{
	{"谷歌", "stun.l.google.com", "19302", "0"},
	{"Cloudflare", "stun.cloudflare.com", "3478", "0"},
	{"小米路由器(境内)", "stun.miwifi.com", "3478", "1"},
	{"芒果TV(境内)", "stun.hitv.com", "3478", "1"},
	{"哔哩哔哩(境内)", "stun.chat.bilibili.com", "3478", "1"},
	{"华为云裸(社区)", "124.70.180.79", "3478", "1"},
	{"Twilio", "global.stun.twilio.com", "3478", "0"},
	{"TwilioTURN(TCP)", "global.turn.twilio.com", "443", "1"},
	{"TwilioTURN(TCP-80)", "global.turn.twilio.com", "80", "1"},
	{"VoipStunt", "stun.voipstunt.com", "3478", "0"},
	{"Antisip(TCP)", "stun.antisip.com", "3478", "1"},
	{"Nextcloud(TCP)", "stun.nextcloud.com", "443", "1"},
	{"CloudflareTURN(TCP)", "turn.cloudflare.com", "3478", "1"},
	{"FreeSwitch(TCP)", "stun.freeswitch.org", "3478", "1"},
}

// legacySeedRows 旧版本内置默认服务器（已停服/不支持TCP/被实测取代），升级时自动清除对应默认行
var legacySeedRows = [][4]string{
	{"小米", "stun.miwifi.com", "3478", "0"},
	{"谷歌", "stun.l.google.com", "19302", "0"},
	{"Antisip", "stun.antisip.com", "3478", "1"},
	{"STUNProtocol", "stun.stunprotocol.org", "3478", "1"},
	{"Sipgate", "stun.sipgate.net", "3478", "1"},
	// Nextcloud TCP 实测仅 443 可用（3478 被本类运营商封锁），旧种子行清除后由新种子 443 行补入
	{"Nextcloud(TCP)", "stun.nextcloud.com", "3478", "1"},
}

// initServers 启动播种/刷新：旧库补充排序列；清除旧版停服默认服务器；补入实测可用列表。
// 仅删除与旧默认（name/host/port/tcp_support）完全一致的默认行，用户改动过的行保留。
func initServers() {
	ensureServerColumn("sort_order", "INTEGER NOT NULL DEFAULT 0")
	for _, l := range legacySeedRows {
		port, _ := strconv.Atoi(l[2])
		tcp, _ := strconv.Atoi(l[3])
		_, _ = core.Update("DELETE FROM stun_server WHERE name=? AND host=? AND port=? AND tcp_support=?",
			l[0], l[1], port, tcp)
	}
	maxOrder := int64(0)
	if v, err := core.Scalar("SELECT COALESCE(MAX(sort_order), 0) FROM stun_server"); err == nil {
		if n, ok := v.(int64); ok {
			maxOrder = n
		}
	}
	for _, s := range seedServers {
		port, _ := strconv.Atoi(s[2])
		tcp, _ := strconv.Atoi(s[3])
		row, _ := core.QueryOne("SELECT id FROM stun_server WHERE host=? AND port=?", s[1], port)
		if row == nil {
			maxOrder++
			_, _ = core.Update("INSERT INTO stun_server(name, host, port, tcp_support, sort_order) VALUES(?,?,?,?,?)",
				s[0], s[1], port, tcp, maxOrder)
		} else {
			// 已存在（用户/历史数据）：保留用户顺序与名称，仅校正 tcp_support 实测标记
			if id, ok := row.Get("id").(int64); ok {
				_, _ = core.Update("UPDATE stun_server SET tcp_support=? WHERE id=?", tcp, id)
			}
		}
	}
	core.LogInfo(core.LogStun, "STUN 服务器列表已刷新（清除停服默认项，补入实测可用服务器）")
}

// ensureServerColumn 旧库升级：补充缺失列（新库建表脚本已包含）
func ensureServerColumn(name, typ string) {
	rows, err := core.Query("PRAGMA table_info(stun_server)")
	if err != nil {
		return
	}
	for _, col := range rows {
		if s, ok := col.Get("name").(string); ok && s == name {
			return
		}
	}
	_, _ = core.Update("ALTER TABLE stun_server ADD COLUMN " + name + " " + typ)
}

// tcpServers 支持 STUN-over-TCP 的服务器列表（host/port），供 TCP 映射探测兜底
func tcpServers() [][2]string {
	list, err := queryServerPairs("SELECT host, port FROM stun_server WHERE tcp_support=1 ORDER BY sort_order, id")
	if err != nil {
		return nil
	}
	return list
}

// allServers 全部 STUN 服务器（host/port，按维护排序），供 UDP/TCP 保活候选兜底
func allServers() [][2]string {
	list, err := queryServerPairs("SELECT host, port FROM stun_server ORDER BY sort_order, id")
	if err != nil {
		return nil
	}
	return list
}

func queryServerPairs(query string) ([][2]string, error) {
	rows, err := core.Query(query)
	if err != nil {
		return nil, err
	}
	list := make([][2]string, 0, len(rows))
	for _, m := range rows {
		host, _ := m.Get("host").(string)
		port := ""
		switch p := m.Get("port").(type) {
		case int64:
			port = strconv.FormatInt(p, 10)
		case string:
			port = p
		}
		list = append(list, [2]string{host, port})
	}
	return list, nil
}

// ---------- 增删改 ----------

func serverCreate(c *web.Ctx) error {
	b := c.Body()
	if err := validateServer(b); err != nil {
		return err
	}
	id, err := core.Insert(`INSERT INTO stun_server(name, host, port, tcp_support, sort_order)
		VALUES(?,?,?,?,(SELECT COALESCE(MAX(sort_order),0)+1 FROM stun_server))`,
		core.BodyStr(b, "name"), core.BodyStr(b, "host"), core.BodyNum(b, "port", 3478),
		boolToInt(core.BodyBool(b, "tcp_support", false)))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogStun, "新增STUN服务器: "+core.BodyStr(b, "name"))
	row, err := serverMustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

func serverUpdate(c *web.Ctx) error {
	id := c.ParamLong("id")
	b := c.Body()
	if err := validateServer(b); err != nil {
		return err
	}
	if _, err := core.Update("UPDATE stun_server SET name=?, host=?, port=?, tcp_support=? WHERE id=?",
		core.BodyStr(b, "name"), core.BodyStr(b, "host"), core.BodyNum(b, "port", 3478),
		boolToInt(core.BodyBool(b, "tcp_support", false)), id); err != nil {
		return err
	}
	core.LogInfo(core.LogStun, "更新STUN服务器 #"+strconv.FormatInt(id, 10)+": "+core.BodyStr(b, "name"))
	row, err := serverMustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

func serverDelete(c *web.Ctx) error {
	id := c.ParamLong("id")
	if _, err := core.Update("DELETE FROM stun_server WHERE id=?", id); err != nil {
		return err
	}
	core.LogInfo(core.LogStun, "删除STUN服务器 #"+strconv.FormatInt(id, 10))
	c.Ok("已删除")
	return nil
}

// serverMove 上移/下移调整顺序（交换相邻行，先按当前顺序归一化序号再交换）
func serverMove(c *web.Ctx) error {
	id := c.ParamLong("id")
	dir := core.BodyStr(c.Body(), "dir")
	ordered, err := core.Query("SELECT id FROM stun_server ORDER BY sort_order, id")
	if err != nil {
		return err
	}
	idx := -1
	for i, m := range ordered {
		if v, ok := m.Get("id").(int64); ok && v == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return core.NewBadRequest("STUN 服务器不存在: #%d", id)
	}
	swap := idx + 1
	if dir == "up" {
		swap = idx - 1
	}
	if swap < 0 || swap >= len(ordered) {
		c.Ok(core.NewRow().Set("moved", false)) // 已到边界
		return nil
	}
	// 归一化：避免多行 sort_order 相同导致交换无效
	for i, m := range ordered {
		v, _ := m.Get("id").(int64)
		_, _ = core.Update("UPDATE stun_server SET sort_order=? WHERE id=?", i, v)
	}
	otherID, _ := ordered[swap].Get("id").(int64)
	_, _ = core.Update("UPDATE stun_server SET sort_order=? WHERE id=?", swap, id)
	_, _ = core.Update("UPDATE stun_server SET sort_order=? WHERE id=?", idx, otherID)
	c.Ok(core.NewRow().Set("moved", true))
	return nil
}

// serverProbeTcp 手动探测服务器是否支持 STUN-over-TCP（新增/编辑表单「探测」按钮）
func serverProbeTcp(c *web.Ctx) error {
	b := c.Body()
	host := strings.TrimSpace(core.BodyStr(b, "host"))
	port := core.BodyNum(b, "port", 3478)
	if host == "" {
		return core.NewBadRequest("服务器地址不能为空")
	}
	if port < 1 || port > 65535 {
		return core.NewBadRequest("端口需在 1-65535 之间")
	}
	p := probeOverTcp(host, port, "", 0, 3000)
	mapped := ""
	if p != nil {
		mapped = p.mapped
		_ = p.conn.Close() // 手动探测仅验证支持性，用后即闭（长期保活由任务运行器管理）
	}
	core.LogInfo(core.LogStun, "探测 STUN-over-TCP "+host+":"+strconv.Itoa(port)+" -> "+
		supportedText(p != nil, mapped))
	res := core.NewRow().
		Set("supported", p != nil).
		Set("mapped", mapped)
	c.Ok(res)
	return nil
}

func supportedText(supported bool, mapped string) string {
	if supported {
		return "支持，映射地址 " + mapped
	}
	return "不支持/无响应"
}

// validateServer 表单校验
func validateServer(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("服务器名称不能为空")
	}
	if strings.TrimSpace(core.BodyStr(b, "host")) == "" {
		return core.NewBadRequest("服务器地址不能为空")
	}
	port := core.BodyNum(b, "port", 3478)
	if port < 1 || port > 65535 {
		return core.NewBadRequest("端口需在 1-65535 之间")
	}
	return nil
}

func serverMustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM stun_server WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("STUN 服务器不存在: #%d", id)
	}
	return row, nil
}

// boolToInt Java JsonUtils.bool→0/1 布尔列形态
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
