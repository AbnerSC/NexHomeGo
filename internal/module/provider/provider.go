package provider

import (
	"strconv"
	"strings"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 服务商凭证配置：集中维护阿里云 AccessKey，供 DDNS 同步、SSL 证书（DNS01）、STUN 穿透按名称引用，
// 避免每个任务重复填写。任务通过 provider_config_id 引用本表；删除配置时把当前凭证回填到引用任务，
// 保证继续可用。路径/方法/响应结构逐一复刻 Java ProviderConfigService。

// types 支持的服务商类型（code -> 显示名，保持登记顺序）。
var providerTypes = []struct{ code, name string }{
	{"ALIYUN", "阿里云（云解析 / ESA）"},
}

func typeSupported(code string) bool {
	for _, t := range providerTypes {
		if t.code == code {
			return true
		}
	}
	return false
}

// Init 启动初始化：旧库补充 provider_type 列（存量配置默认阿里云）。
func Init() { ensureColumn("provider_type", "TEXT NOT NULL DEFAULT 'ALIYUN'") }

func ensureColumn(name, typ string) {
	rows, err := core.Query("PRAGMA table_info(provider_config)")
	if err != nil {
		return
	}
	for _, col := range rows {
		if s, ok := col.Get("name").(string); ok && s == name {
			return
		}
	}
	_, _ = core.Update("ALTER TABLE provider_config ADD COLUMN " + name + " " + typ)
}

// RegisterRoutes 注册服务商接口。
func RegisterRoutes() {
	web.Route("GET", "/api/provider/types", func(c *web.Ctx) error {
		m := core.NewRow()
		for _, t := range providerTypes {
			m.Set(t.code, t.name)
		}
		c.Ok(m)
		return nil
	})
	web.Route("GET", "/api/provider/configs", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM provider_config ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
	web.Route("POST", "/api/provider/configs", create)
	web.Route("PUT", "/api/provider/configs/{id}", update)
	web.Route("DELETE", "/api/provider/configs/{id}", remove)
}

// ---------- 供其他模块调用的工具 ----------

// ParseID 从请求体解析可选的配置 id（未选择/空/非法返回 0,false）。
func ParseID(b map[string]interface{}, key string) (int64, bool) {
	s := strings.TrimSpace(core.BodyStr(b, key))
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Credentials 读取配置的阿里云凭证 (accessKeyId, accessKeySecret)，配置不存在时返回错误。
func Credentials(id int64) (string, string, error) {
	c := mustGetRow(id)
	if c == nil {
		return "", "", core.NewBadRequest("服务商凭证配置不存在: #%d，请重新选择凭证配置", id)
	}
	return str(c.Get("access_key_id")), str(c.Get("access_key_secret")), nil
}

// ESASiteID 读取配置的 ESA 站点 SiteId（未填写返回空串）。
func ESASiteID(id int64) (string, error) {
	row, err := core.QueryOne("SELECT esa_site_id FROM provider_config WHERE id=?", id)
	if err != nil {
		return "", err
	}
	if row == nil {
		return "", core.NewBadRequest("服务商凭证配置不存在: #%d，请重新选择凭证配置", id)
	}
	return str(row.Get("esa_site_id")), nil
}

// ---------- 增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	pt, err := providerType(b)
	if err != nil {
		return err
	}
	id, err := core.Insert("INSERT INTO provider_config(name, provider_type, access_key_id, access_key_secret, esa_site_id) VALUES(?,?,?,?,?)",
		core.BodyStr(b, "name"), pt, core.BodyStr(b, "access_key_id"),
		core.BodyStr(b, "access_key_secret"), core.BodyStr(b, "esa_site_id"))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogProvider, "新增服务商凭证配置["+pt+"]: "+core.BodyStr(b, "name"))
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
	if err := validate(b); err != nil {
		return err
	}
	pt, err := providerType(b)
	if err != nil {
		return err
	}
	if _, err := core.Update("UPDATE provider_config SET name=?, provider_type=?, access_key_id=?, access_key_secret=?, esa_site_id=? WHERE id=?",
		core.BodyStr(b, "name"), pt, core.BodyStr(b, "access_key_id"),
		core.BodyStr(b, "access_key_secret"), core.BodyStr(b, "esa_site_id"), id); err != nil {
		return err
	}
	core.LogInfo(core.LogProvider, "更新服务商凭证配置 #"+strconv.FormatInt(id, 10)+"["+pt+"]: "+core.BodyStr(b, "name"))
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

// remove 删除配置：引用该配置的 DDNS 任务回填当前凭证转为任务内手动凭证；
// 证书任务解除引用；STUN 穿透任务停用 ESA 同步并解除引用。
func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	cfg, err := mustGet(id)
	if err != nil {
		return err
	}
	if _, err := core.Update("UPDATE ddns_task SET provider_config_id=NULL, access_key_id=?, access_key_secret=? WHERE provider_config_id=?",
		cfg.Get("access_key_id"), cfg.Get("access_key_secret"), id); err != nil {
		return err
	}
	if _, err := core.Update("UPDATE cert_task SET provider_config_id=NULL WHERE provider_config_id=?", id); err != nil {
		return err
	}
	stunOff, err := core.Update("UPDATE stun_task SET esa_sync_enabled=0, provider_config_id=NULL WHERE provider_config_id=?", id)
	if err != nil {
		return err
	}
	if _, err := core.Update("DELETE FROM provider_config WHERE id=?", id); err != nil {
		return err
	}
	msg := "删除服务商凭证配置 #" + strconv.FormatInt(id, 10) + ": " + str(cfg.Get("name")) + "（引用任务已回填凭证"
	if stunOff > 0 {
		msg += "；" + itoa(int(stunOff)) + " 个穿透任务已停用 ESA 同步，需重新选择凭证配置"
	}
	msg += "）"
	core.LogInfo(core.LogProvider, msg)
	c.Ok("已删除，引用该配置的任务已回填当前凭证")
	return nil
}

func validate(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("配置名称不能为空")
	}
	if strings.TrimSpace(core.BodyStr(b, "access_key_id")) == "" ||
		strings.TrimSpace(core.BodyStr(b, "access_key_secret")) == "" {
		return core.NewBadRequest("AccessKey ID / Secret 不能为空")
	}
	return nil
}

// providerType 服务商类型（缺省阿里云，兼容旧表单；必须在支持清单内）。
func providerType(b map[string]interface{}) (string, error) {
	t := core.BodyStr(b, "provider_type")
	if strings.TrimSpace(t) == "" {
		t = "ALIYUN"
	}
	if !typeSupported(t) {
		return "", core.NewBadRequest("不支持的服务商类型: %s", t)
	}
	return t, nil
}

func mustGet(id int64) (*core.Row, error) {
	row := mustGetRow(id)
	if row == nil {
		return nil, core.NewBadRequest("服务商凭证配置不存在: #%d", id)
	}
	return row, nil
}

func mustGetRow(id int64) *core.Row {
	row, err := core.QueryOne("SELECT * FROM provider_config WHERE id=?", id)
	if err != nil {
		return nil
	}
	return row
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
		return ""
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
