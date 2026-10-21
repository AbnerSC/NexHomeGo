package wol

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// WOL（Wake-on-LAN）网络唤醒服务。
// 底层：向目标广播地址发送 UDP 魔术包（Magic Packet）：6 字节 0xFF + 目标 MAC 重复 16 遍，连续 3 次提高成功率。
// 多网口设备可配多个 MAC（逗号/分号/空白含换行分隔），唤醒时逐个 MAC 各发 3 次。
// 路径、方法、响应结构与 Java WolService 逐一对应，前端零改动。

var macRe = regexp.MustCompile(`^[0-9a-fA-F]{12}$`)

// RegisterRoutes 注册 WOL 接口（由主程序在 Web 启动前调用）。
func RegisterRoutes() {
	web.Route("GET", "/api/wol/devices", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM wol_device ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})

	web.Route("POST", "/api/wol/devices", create)
	web.Route("PUT", "/api/wol/devices/{id}", update)
	web.Route("DELETE", "/api/wol/devices/{id}", remove)

	// 单台唤醒
	web.Route("POST", "/api/wol/devices/{id}/wake", func(c *web.Ctx) error {
		if err := Wake(c.ParamLong("id")); err != nil {
			return err
		}
		c.Ok("唤醒魔术包已发送")
		return nil
	})

	// 批量唤醒
	web.Route("POST", "/api/wol/wake-batch", func(c *web.Ctx) error {
		b := c.Body()
		results := []string{}
		if arr, ok := b["ids"].([]interface{}); ok {
			for _, e := range arr {
				id := toInt64(e)
				if err := Wake(id); err != nil {
					results = append(results, fmt.Sprintf("#%d 失败: %s", id, err.Error()))
				} else {
					results = append(results, fmt.Sprintf("#%d 已发送", id))
				}
			}
		}
		c.Ok(core.NewRow().Set("results", results))
		return nil
	})
}

// ---------- 增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	name := core.BodyStr(b, "name")
	mac := core.BodyStr(b, "mac")
	broadcast := core.BodyStr(b, "broadcast")
	port := core.BodyNum(b, "port", 9)
	if err := validate(name, mac, broadcast); err != nil {
		return err
	}
	id, err := core.Insert("INSERT INTO wol_device(name, mac, broadcast, port) VALUES(?,?,?,?)",
		name, normalizeMacs(mac), broadcast, port)
	if err != nil {
		return err
	}
	core.LogInfo(core.LogWol, "新增唤醒设备: "+name)
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
	name := core.BodyStr(b, "name")
	mac := core.BodyStr(b, "mac")
	broadcast := core.BodyStr(b, "broadcast")
	port := core.BodyNum(b, "port", 9)
	if err := validate(name, mac, broadcast); err != nil {
		return err
	}
	if _, err := core.Update("UPDATE wol_device SET name=?, mac=?, broadcast=?, port=? WHERE id=?",
		name, normalizeMacs(mac), broadcast, port, id); err != nil {
		return err
	}
	core.LogInfo(core.LogWol, "更新唤醒设备 #"+strconv.FormatInt(id, 10)+": "+name)
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	dev, err := mustGet(id)
	if err != nil {
		return err
	}
	if _, err := core.Update("DELETE FROM wol_device WHERE id=?", id); err != nil {
		return err
	}
	core.LogInfo(core.LogWol, "删除唤醒设备 #"+strconv.FormatInt(id, 10)+": "+str(dev.Get("name")))
	c.Ok("已删除")
	return nil
}

// ---------- 唤醒 ----------

// Wake 向指定设备发送魔术包唤醒。
func Wake(deviceID int64) error {
	dev, err := mustGet(deviceID)
	if err != nil {
		return err
	}
	name := str(dev.Get("name"))
	macs := macList(str(dev.Get("mac")))
	broadcast := str(dev.Get("broadcast"))
	port := int(toInt64(dev.Get("port")))

	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(broadcast, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	conn, err := newBroadcastConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	// 多网口设备逐个 MAC 发送，每个 MAC 连发 3 次，应对 UDP 丢包。
	for _, mac := range macs {
		mb, err := parseMac(mac)
		if err != nil {
			return err
		}
		packet := buildMagicPacket(mb)
		for i := 0; i < 3; i++ {
			if _, err := conn.WriteTo(packet, addr); err != nil {
				return err
			}
		}
	}
	core.LogInfo(core.LogWol, "唤醒魔术包已发送 -> "+name+" (MAC="+strings.Join(macs, ",")+
		", 广播="+broadcast+":"+strconv.Itoa(port)+")")
	return nil
}

// buildMagicPacket 6 字节 0xFF + MAC 重复 16 次，共 102 字节。
func buildMagicPacket(mac []byte) []byte {
	packet := make([]byte, 102)
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], mac)
	}
	return packet
}

// ---------- 校验与工具 ----------

func validate(name, mac, broadcast string) error {
	if strings.TrimSpace(name) == "" {
		return core.NewBadRequest("设备名称不能为空")
	}
	if _, err := macListErr(mac); err != nil {
		return err
	}
	if strings.TrimSpace(broadcast) == "" {
		return core.NewBadRequest("广播地址不能为空，常用 255.255.255.255 或子网广播地址")
	}
	return nil
}

// macList 拆分 MAC 字段为地址列表并逐个校验格式（逗号/分号/空白含换行分隔）。
func macList(mac string) []string {
	list, _ := macListErr(mac)
	return list
}

func macListErr(mac string) ([]string, error) {
	list := make([]string, 0)
	for _, part := range splitOnSeparators(mac) {
		if part == "" {
			continue
		}
		hex := removeChars(part, ":-")
		if len(hex) != 12 || !macRe.MatchString(hex) {
			return nil, core.NewBadRequest("MAC 地址格式不正确: %s（多网口可用逗号/分号/换行分隔多个 MAC，例如 00:11:22:33:44:55）", part)
		}
		list = append(list, part)
	}
	if len(list) == 0 {
		return nil, core.NewBadRequest("MAC 地址不能为空")
	}
	return list, nil
}

// normalizeMacs 统一每个 MAC 为冒号分隔小写，多个以逗号连接存储。
func normalizeMacs(mac string) string {
	var out []string
	for _, m := range macList(mac) {
		h := strings.ToLower(removeChars(m, ":-"))
		var sb strings.Builder
		for i := 0; i < 6; i++ {
			if i > 0 {
				sb.WriteByte(':')
			}
			sb.WriteString(h[i*2 : i*2+2])
		}
		out = append(out, sb.String())
	}
	return strings.Join(out, ",")
}

func parseMac(mac string) ([]byte, error) {
	h := removeChars(mac, ":-")
	if len(h) != 12 {
		return nil, core.NewBadRequest("MAC 地址格式不正确: %s", mac)
	}
	b := make([]byte, 6)
	for i := 0; i < 6; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, core.NewBadRequest("MAC 地址格式不正确: %s", mac)
		}
		b[i] = byte(v)
	}
	return b, nil
}

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM wol_device WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("唤醒设备不存在: #%d", id)
	}
	return row, nil
}

// splitOnSeparators 按 逗号/分号/空白（含换行/制表）拆分。
func splitOnSeparators(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	return fields
}

func removeChars(s string, cut string) string {
	for _, c := range cut {
		s = strings.ReplaceAll(s, string(c), "")
	}
	return s
}

func str(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

func toInt64(v interface{}) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}
