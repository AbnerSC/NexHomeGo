package nav

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"NexHomeGo/internal/core"
)

// 导航图标本地存储：上传图标落盘 data/nav-icons/（与数据库同目录，沿用现有备份策略），
// 文件名为随机 UUID + 白名单扩展名，nav_item.icon_url 存相对 URL /nav-icons/xxx.png。
// 展示路由位于 /api/** 之外故免登录（<img> 无法带 X-Token），文件名不可猜且图标不敏感，安全可接受。
// 决策⑤：全部落在 data 目录内。

// URLPrefix 本地图标 URL 前缀。
const URLPrefix = "/nav-icons/"

const maxIconSize = 2 * 1024 * 1024

var iconTypes = map[string]string{
	"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
	"gif": "image/gif", "webp": "image/webp", "svg": "image/svg+xml",
	"ico": "image/x-icon",
}

var iconNameRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.(png|jpg|jpeg|gif|webp|svg|ico)$`)

func iconDir() string { return filepath.Join(core.DataDir(), "nav-icons") }

// saveIcon 保存上传字节为本地图标，返回存入 icon_url 的相对 URL。
func saveIcon(originalName string, bytes []byte) (string, error) {
	if len(bytes) == 0 {
		return "", core.NewBadRequest("图标文件内容为空")
	}
	if len(bytes) > maxIconSize {
		return "", core.NewBadRequest("图标文件不能超过 2MB")
	}
	ext := extOf(originalName)
	if _, ok := iconTypes[ext]; !ok {
		return "", core.NewBadRequest("不支持的图标格式，仅支持 png/jpg/gif/webp/svg/ico")
	}
	dir := iconDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := newUUID() + "." + ext
	if err := os.WriteFile(filepath.Join(dir, name), bytes, 0o644); err != nil {
		return "", err
	}
	return URLPrefix + name, nil
}

// serveIcon 图标展示（免登录）：文件名白名单 + 目录穿越防护，命中长缓存。返回 (字节, Content-Type, 是否存在)。
func serveIcon(file string) ([]byte, string, bool) {
	if file == "" || !iconNameRe.MatchString(file) {
		return nil, "", false
	}
	p := filepath.Join(iconDir(), file)
	if !withinDir(p, iconDir()) {
		return nil, "", false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, "", false
	}
	return data, iconTypes[extOf(file)], true
}

// deleteIfUnreferenced 仅当本地图标 URL 不再被任何导航条目引用时删除对应文件（避免误删共享图标）。
func deleteIfUnreferenced(iconURL string) {
	if !strings.HasPrefix(iconURL, URLPrefix) {
		return
	}
	name := iconURL[len(URLPrefix):]
	if !iconNameRe.MatchString(name) {
		return
	}
	v, err := core.Scalar("SELECT COUNT(*) FROM nav_item WHERE icon_url=?", iconURL)
	if err != nil {
		return
	}
	if toInt64(v) > 0 {
		return
	}
	_ = os.Remove(filepath.Join(iconDir(), name))
}

// listImages 图片管理：目录内全部图片元数据（url/size/mtime），按修改时间倒序。
func listImages() *core.RowList {
	out := core.NewRowList()
	dir := iconDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	type item struct {
		url   string
		size  int64
		mtime int64
	}
	items := make([]item, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{
			url:   URLPrefix + e.Name(),
			size:  fi.Size(),
			mtime: fi.ModTime().UnixMilli(),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mtime > items[j].mtime })
	for _, it := range items {
		r := core.NewRow()
		r.Set("url", it.url)
		r.Set("size", it.size)
		r.Set("mtime", it.mtime)
		out.Append(r)
	}
	return out
}

// deleteImage 图片管理手动删除（引用校验由路由层负责），返回是否实际删除。
func deleteImage(file string) (bool, error) {
	if !iconNameRe.MatchString(file) {
		return false, core.NewBadRequest("图片不存在: %s", file)
	}
	p := filepath.Join(iconDir(), file)
	if !withinDir(p, iconDir()) {
		return false, core.NewBadRequest("图片不存在: %s", file)
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// iconTypeOf 扩展名 → Content-Type（图片展示路由共用），未知回退二进制流。
func iconTypeOf(name string) string {
	if t, ok := iconTypes[extOf(name)]; ok {
		return t
	}
	return "application/octet-stream"
}

// cleanOrphans 启动维护：清理目录中未被任何导航条目引用的残留文件（如上传后取消表单遗留）。
func cleanOrphans() {
	dir := iconDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	referenced := map[string]bool{}
	if rows, err := core.Query("SELECT icon_url FROM nav_item"); err == nil {
		for _, r := range rows {
			if v := r.Get("icon_url"); v != nil {
				referenced[str(v)] = true
			}
		}
	}
	cleaned := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		url := URLPrefix + e.Name()
		if !referenced[url] {
			if os.Remove(filepath.Join(dir, e.Name())) == nil {
				cleaned++
			}
		}
	}
	if cleaned > 0 {
		core.LogInfo(core.LogNav, "清理孤儿导航图标 "+itoa(cleaned)+" 个")
	}
}

func extOf(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

// withinDir 判断目标路径是否仍在 base 目录内（防目录穿越）。
func withinDir(target, base string) bool {
	absT, err1 := filepath.Abs(target)
	absB, err2 := filepath.Abs(base)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(absB, absT)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "."
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[pos] = '-'
			pos++
		}
		out[pos] = hex[b[i]>>4]
		out[pos+1] = hex[b[i]&0x0f]
		pos += 2
	}
	return string(out)
}
