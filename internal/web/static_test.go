package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// 静态资源出口的行为约束：gzip 只在客户端接受时启用、ETag 协商命中即 304。
func TestServeAssetGzipAndETag(t *testing.T) {
	raw, ok := staticRead("js/dashboard.js")
	if !ok {
		t.Fatal("内嵌资源 js/dashboard.js 缺失")
	}

	// 1) 接受 gzip：压缩写出，解压后与原内容一致。
	req := httptest.NewRequest(http.MethodGet, "/js/dashboard.js", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	rec := httptest.NewRecorder()
	serveStatic(rec, req, "/js/dashboard.js")
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("首次请求状态码 = %d, 期望 200", res.StatusCode)
	}
	if enc := res.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, 期望 gzip", enc)
	}
	if res.Header.Get("Vary") != "Accept-Encoding" {
		t.Fatalf("Vary = %q, 期望 Accept-Encoding", res.Header.Get("Vary"))
	}
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("缺少 ETag 响应头")
	}
	if got := res.Header.Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("Content-Length = %q 与实际压缩后长度 %d 不一致", got, rec.Body.Len())
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("响应体不是合法 gzip: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("读取 gzip 响应体失败: %v", err)
	}
	if !bytes.Equal(plain, raw) {
		t.Fatal("解压后的内容与内嵌资源不一致")
	}

	// 2) 携带同一 ETag：304 且无响应体。
	req2 := httptest.NewRequest(http.MethodGet, "/js/dashboard.js", nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	serveStatic(rec2, req2, "/js/dashboard.js")
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("协商命中状态码 = %d, 期望 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Fatalf("304 响应体应为空，实际 %d 字节", rec2.Body.Len())
	}

	// 3) 客户端不接受 gzip：原样写出，且沿用同一 ETag（弱校验）。
	req3 := httptest.NewRequest(http.MethodGet, "/js/dashboard.js", nil)
	rec3 := httptest.NewRecorder()
	serveStatic(rec3, req3, "/js/dashboard.js")
	if enc := rec3.Result().Header.Get("Content-Encoding"); enc != "" {
		t.Fatalf("未声明 gzip 时不应压缩，实际 Content-Encoding=%q", enc)
	}
	if !bytes.Equal(rec3.Body.Bytes(), raw) {
		t.Fatal("未压缩响应体与内嵌资源不一致")
	}
	if got := rec3.Result().Header.Get("ETag"); got != etag {
		t.Fatalf("压缩与明文应共享弱 ETag，%q != %q", got, etag)
	}

	// 4) 不存在的资源：404 纯文本。
	rec4 := httptest.NewRecorder()
	serveStatic(rec4, httptest.NewRequest(http.MethodGet, "/no-such.js", nil), "/no-such.js")
	if rec4.Code != http.StatusNotFound {
		t.Fatalf("不存在资源状态码 = %d, 期望 404", rec4.Code)
	}
}
