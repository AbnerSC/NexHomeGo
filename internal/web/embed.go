package web

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"NexHomeGo/internal/core"
)

// 前端静态资源（原生 JS/HTML/CSS，无构建步骤）随镜像内嵌交付，路径与内容与 Java jar 内 /web 完全一致。
//
//go:embed all:web
var webEmbed embed.FS

const webRoot = "web"

// staticRead 读取静态资源：外部目录（server.web.dir，开发热更新）优先，否则读内嵌资源。
// relPath 为相对 web 根的路径（不含前导斜杠），空表示 index.html。返回 (内容, 是否存在)。
func staticRead(relPath string) ([]byte, bool) {
	if relPath == "" || strings.HasSuffix(relPath, "/") {
		relPath += "index.html"
	}
	// 目录穿越防护：拒绝 .. / 绝对路径 / 盘符 / 反斜杠。
	if strings.Contains(relPath, "..") || strings.HasPrefix(relPath, "/") ||
		strings.Contains(relPath, ":") || strings.Contains(relPath, "\\") {
		return nil, false
	}
	if dir := core.WebDir(); dir != "" {
		if data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(relPath))); err == nil {
			return data, true
		}
		return nil, false
	}
	data, err := webEmbed.ReadFile(webRoot + "/" + relPath)
	if err != nil {
		return nil, false
	}
	return data, true
}

// webEmbedFS 内嵌 web 根，供未来 fs.FS 消费者使用。
func webEmbedFS() fs.FS {
	sub, err := fs.Sub(webEmbed, webRoot)
	if err != nil {
		return nil
	}
	return sub
}

// contentType 按扩展名推断 Content-Type（与 Java WebServer.contentType 一致）。
func contentType(file string) string {
	f := strings.ToLower(file)
	switch {
	case strings.HasSuffix(f, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(f, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(f, ".js"), strings.HasSuffix(f, ".mjs"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(f, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(f, ".png"):
		return "image/png"
	case strings.HasSuffix(f, ".jpg"), strings.HasSuffix(f, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(f, ".gif"):
		return "image/gif"
	case strings.HasSuffix(f, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(f, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(f, ".webp"):
		return "image/webp"
	case strings.HasSuffix(f, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(f, ".woff"):
		return "font/woff"
	case strings.HasSuffix(f, ".ttf"):
		return "font/ttf"
	case strings.HasSuffix(f, ".txt"):
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// readFileBytes 读取磁盘文件（供下载类响应，如证书打包/配置备份）。
func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// writeFileAll 原子性写文件（父目录不存在自动创建），供证书/图标等落盘收敛到 data 下使用。
func writeFileAll(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
