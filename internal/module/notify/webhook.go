package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// Webhook / 钉钉渠道投递。HTTP 客户端连接超时 10s、单请求 20s，与 Java HttpClient 配置一致。

var webhookHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// requestCtx 单请求 20s 超时（等价 Java HttpRequest.timeout）。
func requestCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 20*time.Second)
}

func placeholderPairs(title, message, event string) (pairs [][2]string, data map[string]string) {
	now := core.Now()
	pairs = [][2]string{
		{"title", title},
		{"message", message},
		{"event", event},
		{"time", now},
	}
	data = make(map[string]string, 4)
	for _, p := range pairs {
		data[p[0]] = p[1]
	}
	return
}

func sendWebhook(cfg map[string]interface{}, title, message, event string) (string, error) {
	pairs, data := placeholderPairs(title, message, event)
	u := strings.TrimSpace(core.BodyStr(cfg, "url"))
	method := strings.ToUpper(strings.TrimSpace(core.BodyStr(cfg, "method")))
	if method != "GET" {
		method = "POST"
	}

	body := ""
	if method == "GET" {
		qs := make([]string, 0, len(pairs))
		for _, p := range pairs {
			qs = append(qs, url.QueryEscape(p[0])+"="+url.QueryEscape(p[1]))
		}
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u = u + sep + strings.Join(qs, "&")
	} else {
		body = buildWebhookBody(cfg, data, title, message, event)
	}

	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	ctx, cancel := requestCtx()
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "NexHome-Notify")

	hasContentType := false
	if headers, ok := cfg["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if strings.EqualFold(k, "Content-Type") {
				hasContentType = true
			}
			req.Header.Set(k, replace(toString(v), data))
		}
	}
	if method == "POST" && !hasContentType {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	resp, err := webhookHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return "OK(HTTP " + strconv.Itoa(code) + ")", nil
	}
	return "FAIL(HTTP " + strconv.Itoa(code) + " " + truncate(string(b)) + ")", nil
}

// buildWebhookBody webhook 请求体：优先用户模板（占位符替换），否则默认 JSON
// （字段顺序 source/event/title/message/time 与 Java Gson JsonObject 一致）。
func buildWebhookBody(cfg map[string]interface{}, data map[string]string, title, message, event string) string {
	template := core.BodyStr(cfg, "bodyTemplate")
	if strings.TrimSpace(template) != "" {
		return replace(template, data)
	}
	payload := core.NewRow().
		Set("source", "NexHome").
		Set("event", event).
		Set("title", title).
		Set("message", message).
		Set("time", core.Now())
	b, err := core.MarshalJSON(payload)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// sendDingTalk 钉钉自定义机器人：HTTP 200 仍可能 errcode!=0（加签错误、关键词不匹配），需二次判定。
func sendDingTalk(cfg map[string]interface{}, title, message string) (string, error) {
	webhook := strings.TrimSpace(core.BodyStr(cfg, "webhook"))
	secret := strings.TrimSpace(core.BodyStr(cfg, "secret"))
	u := webhook
	if secret != "" {
		ts := time.Now().UnixMilli()
		sign, err := dingTalkSign(ts, secret)
		if err != nil {
			return "", err
		}
		sep := "?"
		if strings.Contains(webhook, "?") {
			sep = "&"
		}
		u = webhook + sep + "timestamp=" + strconv.FormatInt(ts, 10) + "&sign=" + sign
	}
	payload := core.NewRow().
		Set("msgtype", "text").
		Set("text", core.NewRow().Set("content", "[NexHome] "+title+"\n"+message+"\n"+core.Now()))
	body, err := core.MarshalJSON(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", u, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	ctx, cancel := requestCtx()
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := webhookHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	code := resp.StatusCode
	if code < 200 || code >= 300 {
		return "FAIL(HTTP " + strconv.Itoa(code) + " " + truncate(string(b)) + ")", nil
	}
	var rj map[string]interface{}
	_ = json.Unmarshal(b, &rj)
	errcode := int64(0)
	if v, ok := rj["errcode"].(float64); ok {
		errcode = int64(v)
	}
	if errcode == 0 {
		return "OK(HTTP " + strconv.Itoa(code) + ")", nil
	}
	return "FAIL(errcode=" + strconv.FormatInt(errcode, 10) + " " + core.BodyStr(rj, "errmsg") + ")", nil
}

// dingTalkSign 钉钉加签：sign = urlencode(base64(HmacSHA256(timestamp + "\n" + secret, secret)))。
// url.QueryEscape 与 Java URLEncoder.encode 对 base64 字符集（A-Za-z0-9+/=）的转义结果一致。
func dingTalkSign(timestamp int64, secret string) (string, error) {
	stringToSign := strconv.FormatInt(timestamp, 10) + "\n" + secret
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign)) // hash.Hash.Write 不会失败
	return url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil))), nil
}
