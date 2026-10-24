package proxy

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 静态站点发布的文件存储（决策⑤：运行期文件全部落在 data 目录内）：
//
//	data/html/{站点ID}   每个静态站点的默认站点目录（容器内即 /app/data/html/{id}），保存时自动创建
//	data/html/temp/      zip 上传临时目录：保存前压缩包先落这里，解压到站点目录后立即删除
//
// 因此「发布静态网站」不再需要宿主机预置目录：新增站点时留空站点目录即可，
// 上传 zip -> 保存 -> 自动解压到 data/html/{id}，删除站点时一并清理该默认目录。
// 用户也可以继续手填任意绝对路径（如只读挂载的 /srv/www），此时不参与自动管理。

const (
	// maxUploadBytes 单个 zip 上传上限（解压前）。
	maxUploadBytes = 512 << 20
	// uploadTTL 上传临时文件保留时长：超时未保存的压缩包由周期任务清理。
	uploadTTL = time.Hour
)

// defaultZipLimits 解压限制（zip bomb 防护）：文件数、总解压大小、单文件大小。
var defaultZipLimits = zipLimits{MaxFiles: 20000, MaxBytes: 2 << 30, MaxFile: 512 << 20}

// uploadTokenRe 上传凭据格式：16 字节随机数的 hex（32 位小写），直接作为临时文件名，
// 必须先过白名单拼接，避免路径注入。
var uploadTokenRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// zipLimits 解压限制。
type zipLimits struct {
	MaxFiles int
	MaxBytes int64
	MaxFile  int64
}

// zipStats 解压统计（写日志与响应）。
type zipStats struct {
	Files   int
	Dirs    int
	Bytes   int64
	Skipped int
}

// htmlRoot 静态站点发布根目录：data/html（容器内 /app/data/html）。
func htmlRoot() string { return filepath.Join(core.DataDir(), "html") }

// htmlTempRoot zip 上传临时目录：data/html/temp。
func htmlTempRoot() string { return filepath.Join(htmlRoot(), "temp") }

// siteDirFor 站点默认目录：data/html/{id}。
func siteDirFor(id int64) string { return filepath.Join(htmlRoot(), strconv.FormatInt(id, 10)) }

// ensureHtmlDirs 创建 data/html 与 data/html/temp（幂等）。
func ensureHtmlDirs() error { return os.MkdirAll(htmlTempRoot(), 0o755) }

// defaultSiteDir 返回并创建站点默认目录（data/html/{id}），以正斜杠形态返回。
func defaultSiteDir(id int64) (string, error) {
	dir := siteDirFor(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return staticRootDir(filepath.ToSlash(dir), true)
}

// resolveStaticSiteDir 解析静态站点目录：留空=默认目录（自动创建），否则用用户指定目录（须存在）。
func resolveStaticSiteDir(id int64, target string) (string, error) {
	if strings.TrimSpace(target) == "" {
		return defaultSiteDir(id)
	}
	return staticRootDir(target, true)
}

// removeSiteDir 递归删除站点默认目录 data/html/{id}（调用方负责判断是否应当删除）。
func removeSiteDir(id int64) {
	dir := siteDirFor(id)
	if err := os.RemoveAll(dir); err != nil {
		core.LogWarn(core.LogProxy, "删除静态站点目录失败: "+filepath.ToSlash(dir)+"（"+err.Error()+"）")
		return
	}
	core.LogInfo(core.LogProxy, "已删除静态站点目录: "+filepath.ToSlash(dir))
}

// isDefaultSiteDir 站点目录是否正是默认目录 data/html/{id}。
func isDefaultSiteDir(id int64, target string) bool {
	def, err := filepath.Abs(siteDirFor(id))
	if err != nil {
		return false
	}
	cur, err := filepath.Abs(filepath.FromSlash(strings.TrimSpace(target)))
	if err != nil {
		return false
	}
	return strings.EqualFold(cur, def)
}

// removeDefaultSiteDir 删除站点时清理默认目录：仅当站点目录正是 data/html/{id} 时递归删除，
// 用户自填的目录（可能是只读挂载或共享目录）一律不动。
func removeDefaultSiteDir(id int64, target string) {
	if !isDefaultSiteDir(id, target) {
		return
	}
	removeSiteDir(id)
}

// cleanUploadTemp 清理超时未保存的上传压缩包（启动时与每小时执行）。
func cleanUploadTemp() {
	dir := htmlTempRoot()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	deadline := time.Now().Add(-uploadTTL)
	cleaned := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || !info.ModTime().Before(deadline) {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			cleaned++
		}
	}
	if cleaned > 0 {
		core.LogInfo(core.LogProxy, "清理过期上传压缩包 "+strconv.Itoa(cleaned)+" 个")
	}
}

// uploadTempPath 上传凭据 -> 临时压缩包绝对路径（凭据白名单 + 目录包含性双校验）。
func uploadTempPath(token string) (string, bool) {
	if !uploadTokenRe.MatchString(token) {
		return "", false
	}
	p := filepath.Join(htmlTempRoot(), token+".zip")
	if !staticWithin(filepath.Clean(htmlTempRoot()), filepath.Clean(p)) {
		return "", false
	}
	return p, true
}

// newUploadToken 生成 16 字节随机凭据（hex）。
func newUploadToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// uploadZip 接收 zip 压缩包并落到 data/html/temp/{token}.zip，返回保存凭据。
// 用 MultipartReader 流式落盘（不进内存、不落系统临时目录），保存站点时再解压。
func uploadZip(c *web.Ctx) error {
	if err := ensureHtmlDirs(); err != nil {
		return err
	}
	mr, err := c.Request().MultipartReader()
	if err != nil {
		return core.NewBadRequest("请选择要上传的 .zip 压缩包")
	}
	var part *multipart.Part
	for {
		p, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			return core.NewBadRequest("上传数据解析失败: %s", perr.Error())
		}
		if p.FormName() == "file" {
			part = p
			break
		}
		_ = p.Close()
	}
	if part == nil {
		return core.NewBadRequest("请选择要上传的 .zip 压缩包")
	}
	defer part.Close()

	name := part.FileName()
	if !strings.EqualFold(path.Ext(name), ".zip") {
		return core.NewBadRequest("仅支持 .zip 压缩包（当前文件: %s）", name)
	}
	// zip 魔数校验：文件头 "PK\x03\x04"（空包为 "PK\x05\x06"），避免把任意文件当压缩包上传
	head := make([]byte, 4)
	if _, err := io.ReadFull(part, head); err != nil {
		return core.NewBadRequest("压缩包内容为空或读取失败")
	}
	if string(head[:2]) != "PK" {
		return core.NewBadRequest("文件内容不是有效的 zip 压缩包")
	}
	token, err := newUploadToken()
	if err != nil {
		return err
	}
	dst := filepath.Join(htmlTempRoot(), token+".zip")
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	written, cerr := io.Copy(f, io.LimitReader(io.MultiReader(bytes.NewReader(head), part), maxUploadBytes+1))
	serr := f.Close()
	if cerr != nil || serr != nil {
		_ = os.Remove(dst)
		return core.NewBadRequest("压缩包写入失败，请重试")
	}
	if written > maxUploadBytes {
		_ = os.Remove(dst)
		return core.NewBadRequest("压缩包不能超过 %d MB", maxUploadBytes>>20)
	}
	if written < 22 { // zip 最小结构（仅中央目录结尾记录）为 22 字节
		_ = os.Remove(dst)
		return core.NewBadRequest("压缩包内容为空或已损坏")
	}
	// 提前校验可解析性：坏包在保存前就报错，避免用户白等一次保存
	zr, zerr := zip.OpenReader(dst)
	if zerr != nil {
		_ = os.Remove(dst)
		return core.NewBadRequest("压缩包无法解析: %s", zerr.Error())
	}
	_ = zr.Close()

	core.LogInfo(core.LogProxy, "静态站点压缩包已上传: "+name+"（"+staticSize(written)+"）")
	c.Ok(core.NewRow().Set("token", token).Set("name", name).Set("size", written))
	return nil
}

// applyUpload 把临时压缩包解压到站点目录并删除临时文件（无论成功失败都不留 zip）。
func applyUpload(token, destDir, siteName string) error {
	zipPath, ok := uploadTempPath(token)
	if !ok {
		return core.NewBadRequest("上传凭据无效，请重新上传压缩包")
	}
	if _, err := os.Stat(zipPath); err != nil {
		return core.NewBadRequest("上传的压缩包已过期或不存在，请重新上传")
	}
	st, err := unzipInto(zipPath, destDir, defaultZipLimits)
	_ = os.Remove(zipPath) // 解压后即删：压缩包只是传输载体
	if err != nil {
		core.LogWarn(core.LogProxy, "静态站点解压失败["+siteName+"]: "+err.Error())
		return core.NewBadRequest("解压失败: %s", err.Error())
	}
	core.LogInfo(core.LogProxy, fmt.Sprintf("静态站点解压完成[%s]: %s（文件 %d，目录 %d，共 %s）",
		siteName, filepath.ToSlash(destDir), st.Files, st.Dirs, staticSize(st.Bytes)))
	return nil
}

// unzipInto 解压 zip 到 destDir。安全边界：
//   - 拒绝绝对路径、盘符、上跳段（zip-slip）、控制字符与符号链接条目；
//   - 目标路径必须仍在站点目录内（拼接后再做包含性复核）；
//   - 文件数 / 单文件 / 总解压大小三重上限（zip bomb）；
//   - 跳过 macOS 打包垃圾（__MACOSX、.DS_Store、._*）；
//   - 全部条目同属一个顶层目录时自动剥离该层（常见于「压缩 dist 文件夹」）。
//
// 同名文件覆盖，其余既有文件保留（便于增量发布）。
func unzipInto(zipPath, destDir string, lim zipLimits) (zipStats, error) {
	var st zipStats
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return st, fmt.Errorf("压缩包无法解析: %v", err)
	}
	defer zr.Close()
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return st, err
	}
	root, err := filepath.Abs(filepath.FromSlash(destDir))
	if err != nil {
		return st, err
	}
	prefix := zipCommonPrefix(zr.File)
	for _, f := range zr.File {
		rel, skip, rerr := zipEntryRel(f.Name, prefix)
		if rerr != nil {
			return st, rerr
		}
		if skip {
			st.Skipped++
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(rel))
		if !staticWithin(root, target) {
			return st, fmt.Errorf("压缩包条目越出站点目录: %s", f.Name)
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(strings.ReplaceAll(f.Name, "\\", "/"), "/") {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return st, err
			}
			st.Dirs++
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return st, fmt.Errorf("压缩包包含符号链接条目，已拒绝: %s", f.Name)
		}
		if st.Files >= lim.MaxFiles {
			return st, fmt.Errorf("压缩包文件数超过上限 %d", lim.MaxFiles)
		}
		if f.UncompressedSize64 > uint64(lim.MaxFile) {
			return st, fmt.Errorf("压缩包内单文件超过上限 %s: %s", staticSize(lim.MaxFile), f.Name)
		}
		if st.Bytes+int64(f.UncompressedSize64) > lim.MaxBytes {
			return st, fmt.Errorf("解压后总大小超过上限 %s", staticSize(lim.MaxBytes))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return st, err
		}
		n, werr := extractZipEntry(f, target, lim.MaxFile)
		if werr != nil {
			return st, fmt.Errorf("写入 %s 失败: %v", rel, werr)
		}
		st.Files++
		st.Bytes += n
	}
	return st, nil
}

// extractZipEntry 写单个文件；用 LimitReader 兜住「声明大小造假」的压缩包。
func extractZipEntry(f *zip.File, target string, maxFile int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	n, cerr := io.Copy(out, io.LimitReader(rc, maxFile+1))
	serr := out.Close()
	if cerr != nil {
		return n, cerr
	}
	if serr != nil {
		return n, serr
	}
	if n > maxFile {
		return n, fmt.Errorf("解压后单文件超过上限 %s", staticSize(maxFile))
	}
	return n, nil
}

// zipEntryRel 条目名 -> 站点内相对路径。返回 (相对路径, 是否跳过, 错误)。
func zipEntryRel(rawName, prefix string) (string, bool, error) {
	name := strings.TrimSuffix(strings.ReplaceAll(rawName, "\\", "/"), "/")
	if name == "" {
		return "", true, nil
	}
	if strings.HasPrefix(name, "/") || (len(name) >= 2 && name[1] == ':') {
		return "", false, fmt.Errorf("压缩包包含绝对路径条目，已拒绝: %s", rawName)
	}
	if controlCharRe.MatchString(name) {
		return "", false, fmt.Errorf("压缩包包含非法字符条目: %s", rawName)
	}
	if zipMacJunk(name) {
		return "", true, nil
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", false, fmt.Errorf("压缩包包含上跳路径（..），已拒绝: %s", rawName)
		}
	}
	if prefix != "" {
		// 顶层目录自身（如 "dist/"）直接跳过，否则会解出一个多余的空目录
		if name == prefix {
			return "", true, nil
		}
		name = strings.TrimPrefix(name, prefix+"/")
	}
	if name == "" {
		return "", true, nil
	}
	return name, false, nil
}

// zipCommonPrefix 识别「全部条目共有的顶层目录」：仅当每个有效条目都位于同一个顶层目录下
// （且没有根级文件）时返回该目录名，否则返回空（不剥离）。
func zipCommonPrefix(files []*zip.File) string {
	prefix := ""
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(strings.ReplaceAll(f.Name, "\\", "/"), "/"), "/")
		if name == "" || zipMacJunk(name) {
			continue
		}
		i := strings.IndexByte(name, '/')
		if i <= 0 {
			// 顶层目录自身条目（如 "dist/"）不代表存在根级文件，不参与判定；
			// 真正的根级文件则放弃剥离（保持原结构）。
			if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
				continue
			}
			return ""
		}
		seg := name[:i]
		if prefix == "" {
			prefix = seg
		} else if prefix != seg {
			return ""
		}
	}
	return prefix
}

// zipMacJunk macOS 打包垃圾：__MACOSX 目录、.DS_Store、AppleDouble（._ 前缀）。
func zipMacJunk(name string) bool {
	if name == "__MACOSX" || strings.HasPrefix(name, "__MACOSX/") {
		return true
	}
	base := path.Base(name)
	return base == ".DS_Store" || strings.HasPrefix(base, "._")
}
