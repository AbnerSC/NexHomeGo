package nav

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 网站导航服务。每个条目至少配置内网或外网地址之一（可都填），前端按访问来源智能选择、缺失自动回退。
// 排序使用权重字段（拖拽后批量回传新顺序）。路径/方法/响应结构逐一复刻 Java NavService。

const (
	keyLanProbeURL = "nav.lan_probe_url"
	keyBGURL       = "nav.bg_url"
)

// 本地图片文件名白名单：字母/数字/中文/._- + 小写图片扩展名（与 Java IMG_NAME 逐字节一致，不含路径分隔符以防穿越）。
var imgNameRe = regexp.MustCompile(`^[0-9A-Za-z_.\-\p{Han}]+\.(png|jpe?g|gif|webp|svg|ico)$`)

func imgDir() string { return filepath.Join(core.DataDir(), "images") }

// RegisterRoutes 注册导航接口。
func RegisterRoutes() {
	web.Route("GET", "/api/nav/items", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM nav_item ORDER BY weight DESC, id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
	web.Route("POST", "/api/nav/items", create)
	web.Route("PUT", "/api/nav/items/{id}", update)
	web.Route("DELETE", "/api/nav/items/{id}", remove)

	// 本地图标上传（multipart），返回相对 URL 回填 icon_url
	web.Route("POST", "/api/nav/icons", uploadIcon)

	// 图标展示：位于 /api/** 之外故免登录，供 <img> 直接加载
	web.Route("GET", "/nav-icons/{file}", serveIconRoute)

	// 拖拽排序：按新顺序提交 id 数组，权重从大到小赋值
	web.Route("PUT", "/api/nav/reorder", func(c *web.Ctx) error {
		b := c.Body()
		ids := toSlice(b["ids"])
		weight := len(ids) * 10
		for _, e := range ids {
			if _, err := core.Update("UPDATE nav_item SET weight=? WHERE id=?", weight, toInt64(e)); err != nil {
				return err
			}
			weight -= 10
		}
		core.LogInfo(core.LogNav, "更新导航排序，共 "+itoa(len(ids))+" 项")
		c.Ok("排序已保存")
		return nil
	})

	// 内网探测链接 + 背景图配置
	web.Route("GET", "/api/nav/settings", func(c *web.Ctx) error {
		probe, _ := core.GetConfig(keyLanProbeURL)
		bg, _ := core.GetConfig(keyBGURL)
		c.Ok(core.NewRow().Set("lanProbeUrl", probe).Set("bgUrl", bg))
		return nil
	})
	web.Route("PUT", "/api/nav/settings", func(c *web.Ctx) error {
		b := c.Body()
		if _, has := b["lanProbeUrl"]; has {
			url := strings.TrimSpace(core.BodyStr(b, "lanProbeUrl"))
			if url != "" && !isURL(url) {
				return core.NewBadRequest("内网探测链接需以 http:// 或 https:// 开头")
			}
			if err := core.SetConfig(keyLanProbeURL, url); err != nil {
				return err
			}
			if url == "" {
				core.LogInfo(core.LogNav, "已清空内网探测链接")
			} else {
				core.LogInfo(core.LogNav, "内网探测链接已设置: "+url)
			}
		}
		if _, has := b["bgUrl"]; has {
			bg := strings.TrimSpace(core.BodyStr(b, "bgUrl"))
			if bg != "" && !isURL(bg) && !strings.HasPrefix(bg, "/") {
				return core.NewBadRequest("背景图需为 / 开头的系统内路径或 http(s) 地址")
			}
			if err := core.SetConfig(keyBGURL, bg); err != nil {
				return err
			}
			if bg == "" {
				core.LogInfo(core.LogNav, "已清空导航背景图")
			} else {
				core.LogInfo(core.LogNav, "导航背景图已设置: "+bg)
			}
		}
		c.Ok("已保存")
		return nil
	})

	// 图片管理：列出本地图标（附引用它的导航名）
	web.Route("GET", "/api/nav/images", func(c *web.Ctx) error {
		imgs := listImages()
		refs := map[string][]string{}
		if rows, err := core.Query("SELECT name, icon_url FROM nav_item"); err == nil {
			for _, r := range rows {
				u := str(r.Get("icon_url"))
				if u != "" {
					refs[u] = append(refs[u], str(r.Get("name")))
				}
			}
		}
		for _, item := range imgs.Items() {
			url := str(item.Get("url"))
			names := refs[url]
			if names == nil {
				names = []string{}
			}
			item.Set("refs", names)
		}
		c.Ok(core.NewRow().Set("images", imgs))
		return nil
	})

	// 图片管理手动删除（先做引用校验）
	web.Route("DELETE", "/api/nav/images/{file}", func(c *web.Ctx) error {
		file := c.Param("file")
		url := URLPrefix + file
		names := []string{}
		if rows, err := core.Query("SELECT name FROM nav_item WHERE icon_url=?", url); err == nil {
			for _, r := range rows {
				names = append(names, str(r.Get("name")))
			}
		}
		if len(names) > 0 {
			return core.NewBadRequest("图片正被导航「%s」引用，请先更换图标再删除", strings.Join(names, "、"))
		}
		if bg, _ := core.GetConfig(keyBGURL); bg == url {
			return core.NewBadRequest("图片当前用作导航背景，请先更换背景再删除")
		}
		ok, err := deleteImage(file)
		if err != nil {
			return err
		}
		if !ok {
			return core.NewBadRequest("图片不存在或已删除")
		}
		core.LogInfo(core.LogNav, "删除导航图片: "+url)
		c.Ok("已删除")
		return nil
	})

	// 本地图片目录展示（data/images，免登录供背景 CSS 加载）
	web.Route("GET", "/images/{file}", serveLocalImage)
}

// Init 启动维护：清理上传后取消表单遗留的孤儿图标文件。
func Init() { cleanOrphans() }

// ---------- 增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	id, err := core.Insert("INSERT INTO nav_item(name, icon_url, description, lan_url, wan_url, weight, enabled) VALUES(?,?,?,?,?,?,?)",
		core.BodyStr(b, "name"), core.BodyStr(b, "icon_url"), core.BodyStr(b, "description"),
		core.BodyStr(b, "lan_url"), core.BodyStr(b, "wan_url"),
		core.BodyNum(b, "weight", 0), boolToInt(core.BodyBool(b, "enabled", true)))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogNav, "新增导航: "+core.BodyStr(b, "name"))
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
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
	if _, err := core.Update("UPDATE nav_item SET name=?, icon_url=?, description=?, lan_url=?, wan_url=?, weight=?, enabled=? WHERE id=?",
		core.BodyStr(b, "name"), core.BodyStr(b, "icon_url"), core.BodyStr(b, "description"),
		core.BodyStr(b, "lan_url"), core.BodyStr(b, "wan_url"),
		core.BodyNum(b, "weight", 0), boolToInt(core.BodyBool(b, "enabled", true)), id); err != nil {
		return err
	}
	deleteIfUnreferenced(str(old.Get("icon_url")))
	core.LogInfo(core.LogNav, "更新导航 #"+strconv.FormatInt(id, 10)+": "+core.BodyStr(b, "name"))
	row, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(row)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	item, err := mustGet(id)
	if err != nil {
		return err
	}
	if _, err := core.Update("DELETE FROM nav_item WHERE id=?", id); err != nil {
		return err
	}
	deleteIfUnreferenced(str(item.Get("icon_url")))
	core.LogInfo(core.LogNav, "删除导航 #"+strconv.FormatInt(id, 10)+": "+str(item.Get("name")))
	c.Ok("已删除")
	return nil
}

// ---------- 上传 / 展示 ----------

func uploadIcon(c *web.Ctx) error {
	r := c.Request()
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return core.NewBadRequest("请选择要上传的图标文件")
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return core.NewBadRequest("请选择要上传的图标文件")
	}
	defer file.Close()
	bytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	url, err := saveIcon(header.Filename, bytes)
	if err != nil {
		return err
	}
	core.LogInfo(core.LogNav, "上传导航图标: "+url)
	c.Ok(core.NewRow().Set("url", url))
	return nil
}

func serveIconRoute(c *web.Ctx) error {
	data, ctype, ok := serveIcon(c.Param("file"))
	if !ok {
		c.Fail(http.StatusNotFound, "图标不存在")
		return nil
	}
	setUploadHeaders(c)
	c.SetHeader("Cache-Control", "public, max-age=604800")
	c.Raw(http.StatusOK, data, ctype)
	return nil
}

func serveLocalImage(c *web.Ctx) error {
	file := c.Param("file")
	if file == "" || !imgNameRe.MatchString(file) {
		c.Fail(http.StatusNotFound, "图片不存在")
		return nil
	}
	p := filepath.Join(imgDir(), file)
	if !withinDir(p, imgDir()) {
		c.Fail(http.StatusNotFound, "图片不存在")
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		c.Fail(http.StatusNotFound, "图片不存在")
		return nil
	}
	c.SetHeader("Cache-Control", "public, max-age=3600")
	setUploadHeaders(c)
	c.Raw(http.StatusOK, data, iconTypeOf(file))
	return nil
}

// setUploadHeaders 用户上传文件直出时的安全头：
// 图标/图片与面板同源，SVG 内嵌脚本可直接在本面板域内执行（存储型 XSS），
// 因此禁止 MIME 猜测（nosniff）并用 CSP sandbox 剥离脚本能力（仅保留内联样式以正常渲染）。
// 这些响应都作为 <img> 资源嵌入页面，sandbox 不影响图片正常显示。
func setUploadHeaders(c *web.Ctx) {
	c.SetHeader("X-Content-Type-Options", "nosniff")
	c.SetHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
}

// ---------- 校验与工具 ----------

func validate(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("网站名称不能为空")
	}
	lan := core.BodyStr(b, "lan_url")
	wan := core.BodyStr(b, "wan_url")
	if strings.TrimSpace(lan) == "" && strings.TrimSpace(wan) == "" {
		return core.NewBadRequest("内网地址与外网地址至少填写一个")
	}
	if (lan != "" && !isURL(lan)) || (wan != "" && !isURL(wan)) {
		return core.NewBadRequest("访问地址需以 http:// 或 https:// 开头")
	}
	icon := core.BodyStr(b, "icon_url")
	if icon != "" && !isURL(icon) && !strings.HasPrefix(icon, URLPrefix) {
		return core.NewBadRequest("图标需为上传后的本地路径或以 http(s):// 开头的外部地址")
	}
	return nil
}

func mustGet(id int64) (*core.Row, error) {
	row, err := core.QueryOne("SELECT * FROM nav_item WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.NewBadRequest("导航条目不存在: #%d", id)
	}
	return row, nil
}

func isURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func toSlice(v interface{}) []interface{} {
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
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

func itoa(i int) string { return strconv.Itoa(i) }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
