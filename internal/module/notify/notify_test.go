package notify

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// ---------- 基础工具 ----------

func TestReplace(t *testing.T) {
	data := map[string]string{"title": "T", "message": "M", "event": "E", "time": "2026-10-21 00:00:00"}
	if got := replace("${title}|${event}|${unknown}|end", data); got != "T|E||end" {
		t.Errorf("未知占位符应替换为空串: %q", got)
	}
	if got := replace("no placeholder", data); got != "no placeholder" {
		t.Errorf("无占位符应原样: %q", got)
	}
	// $ 与特殊字符按字面输出（等价 Matcher.quoteReplacement）
	if got := replace("${title}", map[string]string{"title": "$1&x"}); got != "$1&x" {
		t.Errorf("特殊字符字面量: %q", got)
	}
}

func TestNormalizeTypeAndValidate(t *testing.T) {
	for _, s := range []string{"webhook", " WEBHOOK ", "Email"} {
		if got, err := normalizeType(s); err != nil || got != strings.ToUpper(strings.TrimSpace(s)) {
			t.Errorf("normalizeType(%q) = %q,%v", s, got, err)
		}
	}
	if _, err := normalizeType("SMS"); err == nil {
		t.Error("不支持的类型应报错")
	}
	if err := validate(TypeWebhook, map[string]interface{}{"url": " "}); err == nil {
		t.Error("Webhook 空地址应报错")
	}
	if err := validate(TypeEmail, map[string]interface{}{"host": "h"}); err == nil {
		t.Error("缺收件人应报错")
	}
	if err := validate(TypeEmail, map[string]interface{}{"host": "h", "to": "a@b", "saveSent": true, "username": ""}); err == nil {
		t.Error("saveSent 无用户名应报错")
	}
	if err := validate(TypeDingTalk, map[string]interface{}{"webhook": "https://oapi.dingtalk.com"}); err != nil {
		t.Errorf("合法钉钉配置应通过: %v", err)
	}
	if err := validate("SMTP", nil); err == nil {
		t.Error("未知类型应报错")
	}
}

func TestConfigRaw(t *testing.T) {
	// 保持提交顺序的紧凑 JSON（等价 Gson JsonObject.toString）
	got := configRaw(`{"name":"n","config":{"url":"http://x","zz":1,"aa":2}}`)
	if got != `{"url":"http://x","zz":1,"aa":2}` {
		t.Errorf("configRaw 应保序紧凑: %s", got)
	}
	if got := configRaw(`{"name":"n"}`); got != "{}" {
		t.Errorf("config 缺失应为 {}: %s", got)
	}
	if got := configRaw(`{"config":"not-object"}`); got != "{}" {
		t.Errorf("config 非对象应为 {}: %s", got)
	}
}

func TestTruncate(t *testing.T) {
	long := strings.Repeat("a", 250)
	if got := truncate(long); len(got) != 203 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncate 200+... 异常: len=%d", len(got))
	}
	if got := truncate(""); got != "" {
		t.Errorf("空串: %q", got)
	}
}

// ---------- Webhook / 钉钉 ----------

func TestSendWebhookPostDefaultBody(t *testing.T) {
	var mu sync.Mutex
	var gotBody, gotCT, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = string(b)
		gotCT = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result, err := sendWebhook(map[string]interface{}{"url": srv.URL}, "标题", "正文", "monitor.down")
	if err != nil {
		t.Fatal(err)
	}
	if result != "OK(HTTP 200)" {
		t.Errorf("result = %q", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotCT != "application/json; charset=utf-8" || gotUA != "NexHome-Notify" {
		t.Errorf("默认头不符: CT=%q UA=%q", gotCT, gotUA)
	}
	// 默认 JSON 字段顺序与 Java Gson 一致
	if !strings.HasPrefix(gotBody, `{"source":"NexHome","event":"monitor.down","title":"标题","message":"正文","time":`) {
		t.Errorf("默认 body 键序/内容不符: %s", gotBody)
	}
}

func TestSendWebhookGetQueryOrder(t *testing.T) {
	var mu sync.Mutex
	var gotQuery, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotQuery = r.URL.RawQuery
		gotMethod = r.Method
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := map[string]interface{}{"url": srv.URL + "/hook?k=1", "method": "get"}
	result, err := sendWebhook(cfg, "T i", "M", "E")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result, "OK") {
		t.Errorf("result = %q", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotMethod != "GET" {
		t.Errorf("method = %q", gotMethod)
	}
	// 顺序 title,message,event,time + 空格加号编码（对齐 Java URLEncoder）
	if !strings.HasPrefix(gotQuery, "k=1&title=T+i&message=M&event=E&time=") {
		t.Errorf("GET 查询串不符: %s", gotQuery)
	}
}

func TestSendWebhookTemplateAndHeaders(t *testing.T) {
	var mu sync.Mutex
	var gotBody, gotToken, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = string(b)
		gotToken = r.Header.Get("X-Token")
		gotCT = r.Header.Get("Content-Type")
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := map[string]interface{}{
		"url":          srv.URL,
		"method":       "POST",
		"bodyTemplate": "${event}/${title}",
		"headers": map[string]interface{}{
			"X-Token":      "tok-${event}",
			"Content-Type": "text/plain; charset=utf-8",
		},
	}
	result, err := sendWebhook(cfg, "T", "M", "E")
	if err != nil {
		t.Fatal(err)
	}
	if result != "OK(HTTP 200)" {
		t.Errorf("result = %q", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotBody != "E/T" || gotToken != "tok-E" || gotCT != "text/plain; charset=utf-8" {
		t.Errorf("模板/头不符: body=%q token=%q ct=%q", gotBody, gotToken, gotCT)
	}
}

func TestSendWebhookFailBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	result, err := sendWebhook(map[string]interface{}{"url": srv.URL}, "T", "M", "E")
	if err != nil {
		t.Fatal(err)
	}
	if result != "FAIL(HTTP 500 boom)" {
		t.Errorf("result = %q", result)
	}
}

func TestSendDingTalk(t *testing.T) {
	// errcode=0 成功
	var mu sync.Mutex
	var gotSign, gotTs, gotContent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTs = r.URL.Query().Get("timestamp")
		gotSign = r.URL.Query().Get("sign")
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotContent = string(b)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	secret := "SECabc123"
	cfg := map[string]interface{}{"webhook": srv.URL + "?access_token=x", "secret": secret}
	result, err := sendDingTalk(cfg, "T", "M")
	if err != nil {
		t.Fatal(err)
	}
	if result != "OK(HTTP 200)" {
		t.Errorf("result = %q", result)
	}
	mu.Lock()
	defer mu.Unlock()
	ts, _ := strconv.ParseInt(gotTs, 10, 64)
	// 服务端收到的是 URL 解码后的原值，重新计算未转义的 base64 签名比对
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "\n" + secret))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if gotSign != want {
		t.Errorf("加签不匹配: got=%s want=%s", gotSign, want)
	}
	if !strings.Contains(gotContent, `"msgtype":"text"`) || !strings.Contains(gotContent, "[NexHome] T") {
		t.Errorf("钉钉报文体不符: %s", gotContent)
	}

	// HTTP 200 但 errcode!=0（关键词不匹配等）
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"keywords not match"}`))
	}))
	defer srv2.Close()
	result, err = sendDingTalk(map[string]interface{}{"webhook": srv2.URL}, "T", "M")
	if err != nil {
		t.Fatal(err)
	}
	if result != "FAIL(errcode=310000 keywords not match)" {
		t.Errorf("result = %q", result)
	}
}

func TestDispatchUnknownType(t *testing.T) {
	if got := dispatch("SMS", nil, "T", "M", "E"); got != "FAIL(未知渠道类型 SMS)" {
		t.Errorf("dispatch = %q", got)
	}
}

// ---------- 扇出（真 SQLite + 队列 worker） ----------

func setupTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := core.InitDB(dir + "/test.db"); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

func insertChannel(t *testing.T, name, typ string, enabled int, config string) int64 {
	t.Helper()
	id, err := core.Insert("INSERT INTO notify_channel(name, type, enabled, config) VALUES(?,?,?,?)",
		name, typ, enabled, config)
	if err != nil {
		t.Fatalf("insert channel: %v", err)
	}
	return id
}

func waitNotifyLog(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		v, err := core.Scalar("SELECT COUNT(*) FROM notify_log")
		if err == nil {
			if c, ok := v.(int64); ok && c >= int64(n) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待 notify_log >= %d 超时", n)
}

func TestBroadcastFanout(t *testing.T) {
	setupTestDB(t)
	var mu sync.Mutex
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = string(b)
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	insertChannel(t, "本地钩子", TypeWebhook, 1,
		fmt.Sprintf(`{"url":%q}`, srv.URL))

	Broadcast("monitor.down", "监控告警", "目标: x")
	waitNotifyLog(t, 1)

	mu.Lock()
	body := gotBody
	mu.Unlock()
	if !strings.Contains(body, `"event":"monitor.down"`) {
		t.Errorf("扇出内容不符: %s", body)
	}
	row, err := core.QueryOne("SELECT channel, event, result FROM notify_log ORDER BY id DESC LIMIT 1")
	if err != nil || row == nil {
		t.Fatalf("查询 notify_log: %v", err)
	}
	if rowStr(row, "channel") != "本地钩子" || rowStr(row, "event") != "monitor.down" ||
		!strings.HasPrefix(rowStr(row, "result"), "OK") {
		t.Errorf("notify_log 记录不符: %+v", row)
	}
}

func TestBroadcastSkipsWhenNoChannel(t *testing.T) {
	setupTestDB(t)
	Broadcast("e", "t", "m") // 无渠道静默返回，不panic即通过
}

func TestBroadcastToSelectSkipDisabledAndDeleted(t *testing.T) {
	setupTestDB(t)
	var hits int64
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"url":%q}`, srv.URL)
	enabledID := insertChannel(t, "启用", TypeWebhook, 1, cfg)
	disabledID := insertChannel(t, "停用", TypeWebhook, 0, cfg)

	BroadcastTo([]int64{enabledID, disabledID, 9999, 0}, "stun.lost", "标题", "正文")
	waitNotifyLog(t, 1)
	// 再等一点时间确认停用/不存在渠道没有被投递
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("只应投递启用渠道: hits=%d", hits)
	}
	n, err := core.Scalar("SELECT COUNT(*) FROM notify_log")
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := n.(int64); c != 1 {
		t.Errorf("notify_log 应仅 1 条: %v", n)
	}
}

// ---------- Email：MIME / HTML / 工具 ----------

func TestEncodeSubject(t *testing.T) {
	if got := encodeSubject("ASCII Subject"); got != "ASCII Subject" {
		t.Errorf("纯 ASCII 不编码: %q", got)
	}
	got := encodeSubject("中文")
	if !strings.HasPrefix(got, "=?UTF-8?B?") || !strings.HasSuffix(got, "?=") {
		t.Errorf("非 ASCII 应 RFC2047 Base64: %q", got)
	}
}

func TestSplitRecipients(t *testing.T) {
	got := splitRecipients("a@x.com, b@y.com;c@z.com")
	if len(got) != 3 || got[0] != "a@x.com" || got[2] != "c@z.com" {
		t.Errorf("收件人拆分不符: %v", got)
	}
}

func TestDotStuff(t *testing.T) {
	got := dotStuff("hello\r\n.hidden\r\nend")
	if got != "hello\r\n..hidden\r\nend" {
		t.Errorf("dot-stuffing 不符: %q", got)
	}
}

func TestIMapQuote(t *testing.T) {
	if got := imapQuote(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("imapQuote = %s", got)
	}
	if s, ok := imapUnquote(`"a\"b"`); !ok || s != `a"b` {
		t.Errorf("imapUnquote = %q,%v", s, ok)
	}
}

func TestBuildEmailHtml(t *testing.T) {
	msg := "目标: https://a.b\n类型: HTTP\n自由文本 <x> & \"引号\"\n\n时间: 2026-10-21 00:00:00"
	html := buildEmailHtml("监控告警：x 不可用", msg, "monitor.down")
	if !strings.Contains(html, "#e5484d") || !strings.Contains(html, ">告警<") {
		t.Error("down/告警事件应红色配色")
	}
	if !strings.Contains(html, "<td colspan=\"2\"") {
		t.Error("非 KV 行应整行渲染")
	}
	if strings.Contains(html, "<x>") {
		t.Error("应 HTML 转义")
	}
	if strings.Contains(html, "时间: <") || !strings.Contains(html, "2026-10-21 00:00:00") {
		t.Error("KV 行值应渲染")
	}
	up := buildEmailHtml("监控恢复：x 已恢复", msg, "monitor.up")
	if !strings.Contains(up, "#2fb344") || !strings.Contains(up, ">恢复<") {
		t.Error("up/恢复事件应绿色配色")
	}
	other := buildEmailHtml("信息", msg, "auth.lockout")
	if !strings.Contains(other, "#3b82f6") || !strings.Contains(other, ">通知<") {
		t.Error("其他事件默认蓝色配色")
	}
}

func TestBuildMimeMessage(t *testing.T) {
	msg := buildMimeMessage("from@x.com", "a@y.com, b@z.com", "告警T", "plain body", "<b>html</b>")
	s := string(msg)
	for _, want := range []string{
		"From: from@x.com\r\n",
		"To: a@y.com, b@z.com\r\n",
		"Subject: =?UTF-8?B?",
		"MIME-Version: 1.0\r\n",
		"Content-Type: multipart/alternative; boundary=\"nexhome_",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("MIME 缺少 %q", want)
		}
	}
	if !strings.HasSuffix(s, "--\r\n") {
		t.Error("MIME 应以结束 boundary-- 收尾")
	}
}

// ---------- SMTP（进程内 fake 服务器，验证 CRAM-MD5 + 投递对话） ----------

// startFakeSMTP 启动单连接 fake SMTP 服务器。authMechs 为空表示不通告 AUTH；
// 通告 CRAM-MD5 时按 RFC2195 校验 "user hex(hmac-md5(pass, challenge))"。
func startFakeSMTP(t *testing.T, authMechs, cramUser, cramPass string) (host string, port int, dataCh chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	dataCh = make(chan string, 4)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		w := func(s string) { _, _ = conn.Write([]byte(s)) }
		r := bufio.NewReader(conn)
		line := func() string {
			l, err := r.ReadString('\n')
			if err != nil {
				return ""
			}
			return strings.TrimRight(l, "\r\n")
		}
		w("220 fake SMTP\r\n")
		challenge := "12345@fake"
		for {
			l := line()
			if l == "" {
				return
			}
			up := strings.ToUpper(l)
			switch {
			case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
				resp := "250-fake\r\n250"
				if authMechs != "" {
					resp += " AUTH " + authMechs
				}
				w(resp + "\r\n")
			case strings.HasPrefix(up, "AUTH CRAM-MD5"):
				w("334 " + base64.StdEncoding.EncodeToString([]byte(challenge)) + "\r\n")
				respB64 := line()
				dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(respB64))
				ok := false
				if err == nil {
					parts := strings.Fields(string(dec))
					if len(parts) == 2 && parts[0] == cramUser {
						mac := hmac.New(md5.New, []byte(cramPass))
						mac.Write([]byte(challenge))
						want := fmt.Sprintf("%x", mac.Sum(nil))
						ok = hmac.Equal([]byte(want), []byte(parts[1]))
					}
				}
				if ok {
					w("235 authenticated\r\n")
				} else {
					w("535 auth failed\r\n")
				}
			case strings.HasPrefix(up, "MAIL FROM"):
				w("250 ok\r\n")
			case strings.HasPrefix(up, "RCPT TO"):
				w("250 ok\r\n")
			case up == "DATA":
				w("354 go ahead\r\n")
				var sb strings.Builder
				for {
					d := line()
					if d == "." {
						break
					}
					sb.WriteString(d + "\r\n")
				}
				dataCh <- sb.String()
				w("250 queued\r\n")
			case up == "QUIT":
				w("221 bye\r\n")
				return
			default:
				w("250 ok\r\n")
			}
		}
	}()
	return h, port, dataCh
}

func TestSmtpSendCramMd5(t *testing.T) {
	host, port, dataCh := startFakeSMTP(t, "PLAIN LOGIN CRAM-MD5", "u@x.com", "secret")
	msg := buildMimeMessage("u@x.com", "a@y.com", "告警T", "plain", "<b>h</b>")
	err := smtpSend(smtpOptions{
		Host: host, Port: port,
		Username: "u@x.com", Password: "secret",
		From: "u@x.com", To: []string{"a@y.com"}, Data: msg,
	})
	if err != nil {
		t.Fatalf("smtpSend: %v", err)
	}
	select {
	case data := <-dataCh:
		if !strings.Contains(data, "Subject: =?UTF-8?B?") {
			t.Errorf("DATA 内容缺少头: %s", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 DATA 内容")
	}
}

func TestSmtpSendNoUsableMech(t *testing.T) {
	host, port, _ := startFakeSMTP(t, "PLAIN LOGIN", "u", "p") // 明文链路不通告 CRAM-MD5 可用
	err := smtpSend(smtpOptions{
		Host: host, Port: port, Username: "u", Password: "p",
		From: "u@x.com", To: []string{"a@y.com"}, Data: []byte("x\r\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "不支持任何可用认证方式") {
		t.Errorf("明文链路应拒绝 PLAIN/LOGIN: %v", err)
	}
}

func TestSendEmailEndToEnd(t *testing.T) {
	host, port, dataCh := startFakeSMTP(t, "CRAM-MD5", "notify@x.com", "secret")
	cfg := map[string]interface{}{
		"host": host, "port": float64(port), "ssl": false,
		"username": "notify@x.com", "password": "secret",
		"from": "notify@x.com", "to": "a@y.com, b@y.com",
	}
	result, err := sendEmail(cfg, "标题", "正文行", "monitor.down")
	if err != nil {
		t.Fatal(err)
	}
	if result != "OK(已发送)" {
		t.Errorf("result = %q", result)
	}
	select {
	case data := <-dataCh:
		if !strings.Contains(data, "Content-Type: multipart/alternative") {
			t.Errorf("应 multipart: %s", data[:min(len(data), 200)])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 DATA")
	}
}
func TestSendEmailArchiveFailureNote(t *testing.T) {
	setupTestDB(t) // 存档失败会写 LogWarn，需要可用数据库
	// saveSent 开启但 IMAP 不可达：投递成功事实不变，结果附注存档失败
	host, port, _ := startFakeSMTP(t, "CRAM-MD5", "notify@x.com", "secret")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, imapPortStr, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close() // 关闭端口，制造连接失败
	imapPort, _ := strconv.Atoi(imapPortStr)

	cfg := map[string]interface{}{
		"host": host, "port": float64(port), "ssl": false,
		"username": "notify@x.com", "password": "secret",
		"to": "a@y.com", "saveSent": true,
		"imapHost": "127.0.0.1", "imapPort": float64(imapPort), "imapSsl": false,
	}
	result, err := sendEmail(cfg, "T", "M", "monitor.up")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result, "OK(已发送，IMAP 存档失败:") || !strings.HasSuffix(result, ")") {
		t.Errorf("存档失败应降级为结果附注: %q", result)
	}
}

// ---------- IMAP：已发送文件夹探测 ----------

// fakeIMAP 极简 IMAP 服务端，按 Dovecot（mailu）的写法回报 LIST：
// 纯 ASCII 名字不带引号（atom），含空格才加引号，\Sent 直接写在属性列表里。
// hidden 里的邮箱存在但不在 LIST 出现，用于验证 CREATE 报 already exists 时的兜底。
type fakeIMAP struct {
	boxes      []string
	hidden     []string
	sent       string
	denyCreate bool
}

func startFakeIMAP(t *testing.T, srv fakeIMAP) (host string, port int, appended chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	appended = make(chan string, 4)
	t.Cleanup(func() { _ = ln.Close() })

	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	// listName 模拟 Dovecot：名字可作 atom 就不加引号
	listName := func(name string) string {
		for i := 0; i < len(name); i++ {
			c := name[i]
			if c <= 0x20 || c >= 0x7f || strings.ContainsRune("(){%*\"\\", rune(c)) {
				return imapQuote(name)
			}
		}
		return name
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		w := func(s string) { _, _ = conn.Write([]byte(s)) }
		r := bufio.NewReader(conn)
		line := func() string {
			l, err := r.ReadString('\n')
			if err != nil {
				return ""
			}
			return strings.TrimRight(l, "\r\n")
		}
		w("* OK [CAPABILITY IMAP4rev1 SPECIAL-USE] fake Dovecot ready\r\n")
		for {
			tag, cmd, ok := strings.Cut(line(), " ")
			if !ok {
				return
			}
			upper := strings.ToUpper(cmd)
			switch {
			case strings.HasPrefix(upper, "LOGIN "):
				w(tag + " OK Logged in\r\n")
			case strings.HasPrefix(upper, "LIST"):
				for _, b := range srv.boxes {
					flags := "\\HasNoChildren"
					if b == srv.sent {
						flags += " \\Sent"
					}
					w("* LIST (" + flags + ") \"/\" " + listName(b) + "\r\n")
				}
				w(tag + " OK List completed\r\n")
			case strings.HasPrefix(upper, "CREATE "):
				name, _, _ := takeAstring(strings.TrimSpace(cmd[len("CREATE "):]))
				switch {
				case srv.denyCreate:
					w(tag + " NO CREATE failed: Permission denied\r\n")
				case has(srv.boxes, name) || has(srv.hidden, name):
					w(tag + " NO [ALREADYEXISTS] Mailbox already exists\r\n")
				default:
					srv.boxes = append(srv.boxes, name)
					w(tag + " OK Create completed\r\n")
				}
			case strings.HasPrefix(upper, "SUBSCRIBE"):
				w(tag + " OK Subscribe completed\r\n")
			case strings.HasPrefix(upper, "APPEND "):
				name, tail, _ := takeAstring(strings.TrimSpace(cmd[len("APPEND "):]))
				n := 0
				if i := strings.IndexByte(tail, '{'); i >= 0 {
					if j := strings.IndexByte(tail[i:], '}'); j > 0 {
						n, _ = strconv.Atoi(tail[i+1 : i+j])
					}
				}
				w("+ Ready for literal data\r\n")
				if n > 0 {
					if _, err := io.ReadFull(r, make([]byte, n+2)); err != nil { // 报文 + CRLF
						return
					}
				}
				appended <- name
				w(tag + " OK Append completed\r\n")
			case strings.HasPrefix(upper, "LOGOUT"):
				w("* BYE\r\n")
				w(tag + " OK Logout completed\r\n")
				return
			default:
				w(tag + " OK done\r\n")
			}
		}
	}()
	return h, port, appended
}

// archiveTo 发起一次 IMAP 存档（imapSsl 关，直连假服务端）。
func archiveTo(host string, port int, extra map[string]interface{}) string {
	cfg := map[string]interface{}{
		"imapHost": host, "imapPort": float64(port), "imapSsl": false,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return archiveToSent(cfg, host, "notify@x.com", "secret", []byte("Subject: t\r\n\r\nbody\r\n"))
}

// mailu/Dovecot 实测写法：纯字母名字在 LIST 中是无引号 atom，且带 \Sent 标记，
// 旧实现只认带引号名字，会把已存在的 Sent 判成不存在。
func TestImapArchiveDovecotUnquotedAtom(t *testing.T) {
	setupTestDB(t)
	host, port, appended := startFakeIMAP(t, fakeIMAP{
		boxes: []string{"INBOX", "Drafts", "Sent", "Trash"}, sent: "Sent",
	})
	if result := archiveTo(host, port, nil); result != "已存档至已发送[Sent]" {
		t.Fatalf("result = %q", result)
	}
	if got := <-appended; got != "Sent" {
		t.Errorf("APPEND 目标 = %q", got)
	}
}

// 名字含空格必须带引号（旧实现的 LastIndex(" ") 会把 "Sent Messages" 打成 "Messages\"）。
func TestImapArchiveQuotedFolderWithSpace(t *testing.T) {
	setupTestDB(t)
	host, port, appended := startFakeIMAP(t, fakeIMAP{
		boxes: []string{"INBOX", "Sent Messages"}, sent: "Sent Messages",
	})
	if result := archiveTo(host, port, nil); result != "已存档至已发送[Sent Messages]" {
		t.Fatalf("result = %q", result)
	}
	if got := <-appended; got != "Sent Messages" {
		t.Errorf("APPEND 目标 = %q", got)
	}
}

// 手动指定的中文文件夹名：LIST 回来是 modified UTF-7，需解码后才能与配置值匹配，
// APPEND 又要用编码后的线上名回发。
func TestImapArchiveChineseFolderUtf7(t *testing.T) {
	setupTestDB(t)
	wire := imapUtf7Encode("已发送")
	host, port, appended := startFakeIMAP(t, fakeIMAP{boxes: []string{"INBOX", wire}})
	if result := archiveTo(host, port, map[string]interface{}{"sentFolder": "已发送"}); result != "已存档至已发送[已发送]" {
		t.Fatalf("result = %q", result)
	}
	if got := <-appended; got != wire {
		t.Errorf("APPEND 目标 = %q，应为线上编码名 %q", got, wire)
	}
}

// 服务端确实没有已发送文件夹：自动 CREATE Sent 后再 APPEND。
func TestImapArchiveCreatesMissingFolder(t *testing.T) {
	setupTestDB(t)
	host, port, appended := startFakeIMAP(t, fakeIMAP{boxes: []string{"INBOX"}})
	if result := archiveTo(host, port, nil); result != "已存档至已发送[Sent]" {
		t.Fatalf("result = %q", result)
	}
	if got := <-appended; got != "Sent" {
		t.Errorf("APPEND 目标 = %q", got)
	}
}

// LIST 漏报但文件夹实际已存在（mailbox_list_index 滱后）：CREATE 回 already exists 不能当失败。
func TestImapArchiveCreateAlreadyExists(t *testing.T) {
	setupTestDB(t)
	host, port, appended := startFakeIMAP(t, fakeIMAP{boxes: []string{"INBOX"}, hidden: []string{"Sent"}})
	if result := archiveTo(host, port, nil); result != "已存档至已发送[Sent]" {
		t.Fatalf("result = %q", result)
	}
	if got := <-appended; got != "Sent" {
		t.Errorf("APPEND 目标 = %q", got)
	}
}

// 建不了文件夹时把服务器原话带回结果（旧实现只给一句「未探测到」）。
func TestImapArchiveCreateDenied(t *testing.T) {
	setupTestDB(t)
	host, port, _ := startFakeIMAP(t, fakeIMAP{boxes: []string{"INBOX"}, denyCreate: true})
	result := archiveTo(host, port, nil)
	if !strings.Contains(result, "Permission denied") || !strings.Contains(result, "请在渠道配置中手动指定文件夹名") {
		t.Errorf("失败原因应带回服务器响应: %q", result)
	}
}

func TestImapUtf7RoundTrip(t *testing.T) {
	for _, s := range []string{"Sent", "已发送", "已发送邮件", "日本語", "a&b", "Sent/2026"} {
		if got := imapUtf7Decode(imapUtf7Encode(s)); got != s {
			t.Errorf("round trip %q = %q", s, got)
		}
	}
	if got := imapUtf7Encode("已发送"); got != "&XfJT0ZAB-" {
		t.Errorf("已发送 编码 = %q", got)
	}
	if got := imapUtf7Decode("&XfJT0ZAB-"); got != "已发送" {
		t.Errorf("&XfJT0ZAB- 解码 = %q", got)
	}
	// 纯 ASCII 名不编码，保留用户手填的 &...- 形式
	if got := imapEncodeName("&XfJT0ZAB-"); got != "&XfJT0ZAB-" {
		t.Errorf("imapEncodeName = %q", got)
	}
}
