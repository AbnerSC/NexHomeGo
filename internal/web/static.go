package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// 面板静态资源响应策略：弱 ETag 协商（304）+ gzip 压缩结果缓存。
//
// 背景：前端拆成十余个独立 js 由 index.html 同步加载，链路往返延迟较高时
// 每个资源都要各付一次 TTFB。启用协商缓存后，未变更的资源只回 304（无响应体）；
// 压缩则把 HTML/CSS/JS 体积压到约三分之一。
//
// 压缩结果按「资源路径 + ETag」缓存：embed 资源进程内不变，命中即直接写出；
// 外部目录（server.web.dir，开发热更新）内容变化后 ETag 随之变化，条目自动重建。

// gzipMinBytes 低于此体积不做压缩（gzip 头部开销可能反超收益）。
const gzipMinBytes = 1024

type gzipEntry struct {
	etag string
	body []byte
}

var gzipCache sync.Map // 资源路径 -> *gzipEntry

// serveIndex 响应面板首页（index.html）。
func serveIndex(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, r, "index.html")
}

// serveStatic 响应面板静态资源，rel 为相对 web 根的路径（允许带前导斜杠）。
func serveStatic(w http.ResponseWriter, r *http.Request, rel string) {
	serveAsset(w, r, strings.TrimPrefix(rel, "/"))
}

// serveAsset 统一的静态资源出口：ETag 协商 + 可选 gzip。
func serveAsset(w http.ResponseWriter, r *http.Request, rel string) {
	data, ok := staticRead(rel)
	if !ok {
		notFoundPlain(w)
		return
	}
	etag := assetETag(data)
	h := w.Header()
	// no-cache 语义为「可缓存但每次须验证」：配合 ETag，未变更时只回 304。
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", etag)
	// 响应体随 Accept-Encoding 变化，提示中间缓存按编码分桶。
	h.Set("Vary", "Accept-Encoding")
	if etagMatched(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	ct := contentType(rel)
	body := data
	if acceptsGzip(r) && compressible(ct) && len(data) >= gzipMinBytes {
		if gz := gzipCached(rel, etag, data); gz != nil {
			body = gz
			h.Set("Content-Encoding", "gzip")
		}
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

// assetETag 内容指纹（弱校验）：gzip 与明文是同一资源的两种编码，用弱 ETag 共享校验值。
func assetETag(data []byte) string {
	sum := sha256.Sum256(data)
	return `W/"` + hex.EncodeToString(sum[:8]) + `"`
}

// etagMatched If-None-Match 与当前 ETag 的弱比较（支持 * 与逗号分隔多值）。
func etagMatched(header, etag string) bool {
	if header == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" {
			return true
		}
		if strings.TrimPrefix(part, "W/") == want {
			return true
		}
	}
	return false
}

// compressible 仅对文本类资源压缩（图片/字体本身已压缩，再压无收益）。
func compressible(ct string) bool {
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml")
}

// acceptsGzip 解析 Accept-Encoding，支持 q 权重（q=0 视为拒绝，* 通配）。
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		p := strings.TrimSpace(strings.ToLower(part))
		if p == "" {
			continue
		}
		name, q := p, 1.0
		if i := strings.IndexByte(p, ';'); i >= 0 {
			name = strings.TrimSpace(p[:i])
			if j := strings.Index(p[i:], "q="); j >= 0 {
				if v, err := strconv.ParseFloat(strings.TrimSpace(p[i+j+2:]), 64); err == nil {
					q = v
				}
			}
		}
		if (name == "gzip" || name == "*") && q > 0 {
			return true
		}
	}
	return false
}

// gzipCached 返回压缩后字节（按路径命中缓存；ETag 变化即重建）。
func gzipCached(rel, etag string, data []byte) []byte {
	if v, ok := gzipCache.Load(rel); ok {
		if e := v.(*gzipEntry); e.etag == etag {
			return e.body
		}
	}
	var buf bytes.Buffer
	buf.Grow(len(data) / 2)
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil
	}
	if _, err := zw.Write(data); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}
	body := buf.Bytes()
	gzipCache.Store(rel, &gzipEntry{etag: etag, body: body})
	return body
}
