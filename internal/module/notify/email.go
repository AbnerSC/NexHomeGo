package notify

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// Email 渠道：SMTP/SMTPS 发送 multipart/alternative（纯文本兜底 + HTML 美化版），
// saveSent 开启时副本经 IMAP APPEND 存入「已发送」文件夹。
// 等价复刻 Java MailSession + jakarta.mail 行为；按决策⑥用标准库手写最小 SMTP/IMAP 客户端，不引第三方。

// emailKV 邮件正文里的 "key: value" 明细行（key 较短且不含冒号），渲染为对齐的两列表格。
// 锚定 ^$ 以对齐 Java Matcher.matches() 的全行匹配语义（否则行中间冒号会误判）。
var emailKV = regexp.MustCompile(`^([^:：]{1,16})[:：]\s*(.+)$`)

func sendEmail(cfg map[string]interface{}, title, message, event string) (string, error) {
	host := strings.TrimSpace(core.BodyStr(cfg, "host"))
	port := core.BodyNum(cfg, "port", 465)
	ssl := core.BodyBool(cfg, "ssl", true)
	starttls := core.BodyBool(cfg, "starttls", false)
	username := strings.TrimSpace(core.BodyStr(cfg, "username"))
	password := core.BodyStr(cfg, "password")
	from := strings.TrimSpace(core.BodyStr(cfg, "from"))
	if from == "" {
		from = username
	}
	to := strings.TrimSpace(core.BodyStr(cfg, "to"))
	saveSent := core.BodyBool(cfg, "saveSent", false)

	msg := buildMimeMessage(from, to, title,
		title+"\n\n"+message+"\n\n-- "+core.Now(),
		buildEmailHtml(title, message, event))

	if err := smtpSend(smtpOptions{
		Host: host, Port: port, SSL: ssl, StartTLS: starttls,
		Username: username, Password: password,
		From: from, To: splitRecipients(to), Data: msg,
	}); err != nil {
		return "", err
	}
	// SMTP 协议只负责投递不落箱，mailu 等自建邮箱的网页客户端看不到已发邮件；
	// 开启存档则将副本经 IMAP APPEND 写入「已发送」文件夹，存档失败不影响投递结果（仅结果附注）
	if !saveSent || username == "" {
		return "OK(已发送)", nil
	}
	return "OK(已发送，" + archiveToSent(cfg, host, username, password, msg) + ")", nil
}

// splitRecipients 收件人拆分（逗号/分号/空白分隔，等价 InternetAddress.parse）。
func splitRecipients(to string) []string {
	fields := strings.FieldsFunc(to, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// buildMimeMessage 生成完整 RFC822 报文（头齐全，供投递与 IMAP 存档共用同一份副本）。
func buildMimeMessage(from, to, subject, plain, html string) []byte {
	boundary := "nexhome_" + randHex(12)
	now := time.Now()
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + strings.Join(splitRecipients(to), ", ") + "\r\n")
	sb.WriteString("Subject: " + encodeSubject(subject) + "\r\n")
	sb.WriteString("Date: " + now.Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	sb.WriteString("Message-ID: <" + randHex(8) + "." + fmt.Sprintf("%d", now.UnixNano()) + "@nexhome>\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n")
	sb.WriteString("\r\n")
	writeMimePart(&sb, boundary, "text/plain; charset=UTF-8", plain)
	writeMimePart(&sb, boundary, "text/html; charset=UTF-8", html)
	sb.WriteString("--" + boundary + "--\r\n")
	return []byte(sb.String())
}

func writeMimePart(sb *strings.Builder, boundary, contentType, content string) {
	sb.WriteString("--" + boundary + "\r\n")
	sb.WriteString("Content-Type: " + contentType + "\r\n")
	sb.WriteString("Content-Transfer-Encoding: base64\r\n")
	sb.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		sb.WriteString(enc[i:end] + "\r\n")
	}
}

// encodeSubject 非 ASCII 主题按 RFC2047 Base64 编码（等价 JavaMail 自动编码行为）。
func encodeSubject(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

// buildEmailHtml 邮件 HTML 正文：卡片式布局 + 内联样式（邮件客户端不支持 <style>/外链 CSS），按事件自动配色。
// HTML 结构与 Java buildEmailHtml 逐字节一致。
func buildEmailHtml(title, message, event string) string {
	joined := (event) + " " + (title)
	accent := "#3b82f6"
	badgeText := "通知"
	if strings.Contains(joined, "down") || strings.Contains(joined, "告警") ||
		strings.Contains(joined, "不可用") || strings.Contains(joined, "失败") {
		accent = "#e5484d"
		badgeText = "告警"
	} else if strings.Contains(joined, "up") || strings.Contains(joined, "恢复") {
		accent = "#2fb344"
		badgeText = "恢复"
	}

	var rows strings.Builder
	for _, line := range strings.Split(message, "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		if m := emailKV.FindStringSubmatch(text); m != nil {
			rows.WriteString("<tr>")
			rows.WriteString("<td style=\"padding:7px 0;color:#8a94a6;font-size:13px;white-space:nowrap;vertical-align:top;\">")
			rows.WriteString(htmlEscape(m[1]) + "</td>")
			rows.WriteString("<td style=\"padding:7px 0;color:#2c3444;font-size:14px;word-break:break-all;\">")
			rows.WriteString(htmlEscape(m[2]) + "</td></tr>")
		} else {
			rows.WriteString("<tr><td colspan=\"2\" style=\"padding:7px 0;color:#2c3444;font-size:14px;word-break:break-all;\">")
			rows.WriteString(htmlEscape(text) + "</td></tr>")
		}
	}

	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>" +
		"<body style=\"margin:0;padding:0;\">" +
		"<div style=\"margin:0;padding:24px 12px;background:#f2f4f7;" +
		"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;\">" +
		"<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" " +
		"style=\"max-width:560px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;\">" +
		"<tr><td style=\"height:6px;line-height:6px;font-size:0;background:" + accent + ";\"></td></tr>" +
		"<tr><td style=\"padding:20px 28px 0;\">" +
		"<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>" +
		"<td style=\"font-size:12px;color:#8a94a6;letter-spacing:2px;\">NEXHOME · 事件通知</td>" +
		"<td align=\"right\"><span style=\"display:inline-block;padding:3px 12px;border-radius:999px;" +
		"font-size:12px;color:#ffffff;background:" + accent + ";\">" + badgeText + "</span></td>" +
		"</tr></table></td></tr>" +
		"<tr><td style=\"padding:12px 28px 14px;font-size:18px;font-weight:600;color:#111827;line-height:1.5;\">" +
		htmlEscape(title) + "</td></tr>" +
		"<tr><td style=\"padding:0 28px 20px;\">" +
		"<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" " +
		"style=\"border-top:1px solid #eef1f5;\">" + rows.String() + "</table></td></tr>" +
		"<tr><td style=\"padding:13px 28px;background:#fafbfc;border-top:1px solid #eef1f5;" +
		"font-size:12px;color:#a4adc0;\">由 NexHome 自动发送 · " + htmlEscape(core.Now()) + "</td></tr>" +
		"</table></div></body></html>"
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())[:n*2]
	}
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(hexDigits[x>>4])
		sb.WriteByte(hexDigits[x&0x0F])
	}
	return sb.String()
}
