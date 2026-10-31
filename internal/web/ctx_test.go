package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"NexHomeGo/internal/core"
)

// TestBodyTextCachedAcrossReads 请求体是单向流：同一处理内先 Body() 解析字段、
// 再 BodyText() 取原文（通知渠道把 config 原样入库就是这种用法）时，
// 第二次读取不得拿到空串，否则保存下来的 config 会变成 {}。
func TestBodyTextCachedAcrossReads(t *testing.T) {
	payload := `{"name":"ch","type":"WEBHOOK","config":{"url":"http://127.0.0.1:9/hook"}}`
	r := httptest.NewRequest("POST", "/api/notify/channels", strings.NewReader(payload))
	c := newCtx(httptest.NewRecorder(), r, nil)

	body := c.Body()
	if got, _ := body["name"].(string); got != "ch" {
		t.Fatalf("Body() 应解析出 name=ch，实际 %q", got)
	}
	if got := c.BodyText(); got != payload {
		t.Fatalf("二次 BodyText() 应返回完整原文，实际 %q", got)
	}
	if got := c.Body(); got["type"] != "WEBHOOK" {
		t.Fatalf("Body() 重复调用应保持可用，实际 %v", got)
	}
}

// TestBodyTextEmptyBody 无请求体时不得 panic，且多次调用一致。
func TestBodyTextEmptyBody(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/proxy/sites", nil)
	// httptest 在 body 为 nil 时给的是 http.NoBody（非 nil），显式置 nil 才能真正走 Ctx 的判空分支。
	r.Body = nil
	c := newCtx(httptest.NewRecorder(), r, nil)

	if got := c.BodyText(); got != "" {
		t.Fatalf("空请求体应返回空串，实际 %q", got)
	}
	if got := c.Body(); len(got) != 0 {
		t.Fatalf("空请求体解析结果应为空对象，实际 %v", got)
	}
}

// TestBodyTextTooLargeMapsTo413 请求体超出上限时正文被截断，由此产生的「字段为空」等
// 解析失败必须由 mapError 改报 413（而不是误导用户去改表单内容的 400）。
func TestBodyTextTooLargeMapsTo413(t *testing.T) {
	const limit = int64(8 << 10)
	payload := `{"name":"` + strings.Repeat("a", 32<<10) + `","domains":"a.example.com"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/proxy/sites", strings.NewReader(payload))
	r.Body = http.MaxBytesReader(w, r.Body, limit) // 模拟 serveHTTP 的套壳（上限缩小便于构造）
	c := newCtx(w, r, nil)

	got := c.BodyText()
	if len(got) == 0 || len(got) > int(limit) {
		t.Fatalf("超限请求应只读到被截断的部分，实际 %d 字节（上限 %d）", len(got), limit)
	}
	if again := c.BodyText(); again != got {
		t.Fatalf("截断结果应被缓存，二次读取实际 %d 字节", len(again))
	}
	// 半截 JSON 解析出的字段必然缺失，模拟 handler 因此返回的误导性校验错误
	mapError(c, core.NewBadRequest("站点名称不能为空"))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限请求应返回 413，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "请求体过大") {
		t.Fatalf("响应应说明请求体过大，实际 %q", w.Body.String())
	}
}
