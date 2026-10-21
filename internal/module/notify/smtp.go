package notify

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// 最小 SMTP 客户端（决策⑥：优先标准库，不引第三方）。支持 SMTPS(465 隐式 TLS)、STARTTLS、
// AUTH PLAIN / CRAM-MD5 / LOGIN（按服务器通告与链路安全选择，明文链路不用明文口令机制，
// 对齐 JavaMail plainRequiresTLS 默认行为）。报文正文已 base64 编码为纯 ASCII，无需 8BITMIME 协商。
// 连接与每步 IO 超时 15s，与 Java mail.*.connectiontimeout/timeout 一致。

type smtpOptions struct {
	Host     string
	Port     int
	SSL      bool
	StartTLS bool

	Username string
	Password string

	From string
	To   []string
	Data []byte
}

const smtpIOTimeout = 15 * time.Second

type smtpConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func smtpSend(o smtpOptions) error {
	addr := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	d := net.Dialer{Timeout: smtpIOTimeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("SMTP 连接失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpIOTimeout))

	c := &smtpConn{conn: conn, r: bufio.NewReader(conn)}
	secure := o.SSL
	if secure {
		if err := c.upgradeTLS(o.Host); err != nil {
			return err
		}
	}

	if err := c.expect(220); err != nil { // 服务就绪
		return err
	}
	features, err := c.ehlo()
	if err != nil {
		return err
	}
	// STARTTLS 升级（明文且服务器支持时），升级后按协议要求重新 EHLO
	if !secure && o.StartTLS && hasFeature(features, "STARTTLS") {
		if err := c.cmd("STARTTLS", 220); err != nil {
			return err
		}
		if err := c.upgradeTLS(o.Host); err != nil {
			return err
		}
		secure = true
		features, err = c.ehlo()
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(o.Username) != "" {
		if err := c.auth(features, o, secure); err != nil {
			return err
		}
	}

	if err := c.cmd("MAIL FROM:<"+o.From+">", 250); err != nil {
		return err
	}
	for _, rcpt := range o.To {
		if err := c.cmd("RCPT TO:<"+rcpt+">", 250, 251); err != nil {
			return err
		}
	}
	if err := c.cmd("DATA", 354); err != nil {
		return err
	}
	// 报文行首单句点需转义双句点（dot-stuffing，RFC5321）
	payload := dotStuff(string(o.Data))
	if !strings.HasSuffix(payload, "\r\n") {
		payload += "\r\n"
	}
	if _, err := c.conn.Write([]byte(payload + ".\r\n")); err != nil {
		return fmt.Errorf("SMTP 发送数据失败: %w", err)
	}
	if err := c.expect(250, 251); err != nil {
		return err
	}
	_ = c.cmd("QUIT", 221) // 退出失败不影响投递结果
	return nil
}

func (c *smtpConn) upgradeTLS(host string) error {
	_ = c.conn.SetDeadline(time.Now().Add(smtpIOTimeout))
	tconn := tls.Client(c.conn, &tls.Config{ServerName: host})
	if err := tconn.Handshake(); err != nil {
		return fmt.Errorf("SMTP TLS 握手失败: %w", err)
	}
	c.conn = tconn
	c.r = bufio.NewReader(tconn)
	return nil
}

func (c *smtpConn) ehlo() ([]string, error) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "nexhome.local"
	}
	lines, err := c.replyAfter("EHLO " + hostname)
	if err != nil {
		return nil, err
	}
	if code := statusOf(lines[len(lines)-1]); code != 250 {
		return nil, fmt.Errorf("SMTP EHLO 失败: %s", strings.Join(lines, " / "))
	}
	return lines, nil
}

// auth 按链路安全选择认证机制：TLS 下 PLAIN → CRAM-MD5 → LOGIN；明文仅 CRAM-MD5
// （避免明文链路发送口令，对齐 JavaMail plainRequiresTLS 默认）。
func (c *smtpConn) auth(features []string, o smtpOptions, secure bool) error {
	order := []string{"CRAM-MD5"}
	if secure {
		order = []string{"PLAIN", "CRAM-MD5", "LOGIN"}
	}
	for _, mech := range order {
		if !hasAuthMech(features, mech) {
			continue
		}
		switch mech {
		case "PLAIN":
			chall := base64.StdEncoding.EncodeToString(
				[]byte("\x00" + o.Username + "\x00" + o.Password))
			return c.cmd("AUTH PLAIN "+chall, 235)
		case "CRAM-MD5":
			lines, err := c.replyAfter("AUTH CRAM-MD5")
			if err != nil {
				return err
			}
			last := lines[len(lines)-1]
			if statusOf(last) != 334 {
				return fmt.Errorf("SMTP CRAM-MD5 质询异常: %s", strings.Join(lines, " / "))
			}
			chal, err := base64.StdEncoding.DecodeString(strings.TrimSpace(last[3:]))
			if err != nil {
				return fmt.Errorf("SMTP CRAM-MD5 质询解码失败: %w", err)
			}
			mac := hmac.New(md5.New, []byte(o.Password))
			mac.Write(chal)
			resp := o.Username + " " + fmt.Sprintf("%x", mac.Sum(nil))
			return c.cmd(base64.StdEncoding.EncodeToString([]byte(resp)), 235)
		case "LOGIN":
			if err := c.cmd("AUTH LOGIN", 334); err != nil {
				return err
			}
			if err := c.cmd(base64.StdEncoding.EncodeToString([]byte(o.Username)), 334); err != nil {
				return err
			}
			return c.cmd(base64.StdEncoding.EncodeToString([]byte(o.Password)), 235)
		}
	}
	return fmt.Errorf("SMTP 服务器不支持任何可用认证方式（PLAIN/CRAM-MD5/LOGIN）")
}

// cmd 发送一条命令并校验响应码。
func (c *smtpConn) cmd(line string, codes ...int) error {
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		return fmt.Errorf("SMTP 写入失败: %w", err)
	}
	_ = c.conn.SetDeadline(time.Now().Add(smtpIOTimeout))
	return c.expect(codes...)
}

func (c *smtpConn) expect(codes ...int) error {
	lines, err := c.replyAfter("")
	if err != nil {
		return err
	}
	last := lines[len(lines)-1]
	code := statusOf(last)
	for _, want := range codes {
		if code == want {
			return nil
		}
	}
	return fmt.Errorf("SMTP 命令失败: %s", strings.Join(lines, " / "))
}

// replyAfter 发送命令（cmdText 为空表示不发送）并收集连续响应行（多行响应用 250- 形式）。
func (c *smtpConn) replyAfter(cmdText string) ([]string, error) {
	if cmdText != "" {
		if _, err := c.conn.Write([]byte(cmdText + "\r\n")); err != nil {
			return nil, fmt.Errorf("SMTP 写入失败: %w", err)
		}
	}
	_ = c.conn.SetDeadline(time.Now().Add(smtpIOTimeout))
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("SMTP 读取失败: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines, nil
		}
	}
}

// statusOf 提取响应行 3 位状态码，非法返回 0。
func statusOf(line string) int {
	if len(line) < 3 {
		return 0
	}
	n, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0
	}
	return n
}

func hasFeature(features []string, verb string) bool {
	for _, f := range features {
		if len(f) > 4 && f[3] == '-' || len(f) > 3 && f[3] == ' ' {
			if strings.EqualFold(firstToken(f[4:]), verb) {
				return true
			}
		}
	}
	return false
}

// hasAuthMech 解析 EHLO 通告行 "250-AUTH PLAIN LOGIN CRAM-MD5" 的机制参数列表。
func hasAuthMech(features []string, mech string) bool {
	for _, f := range features {
		if len(f) <= 4 || (f[3] != '-' && f[3] != ' ') {
			continue
		}
		params := strings.Fields(f[4:])
		if len(params) == 0 || !strings.EqualFold(params[0], "AUTH") {
			continue
		}
		for _, m := range params[1:] {
			if strings.EqualFold(m, mech) {
				return true
			}
		}
	}
	return false
}

func firstToken(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// dotStuff 报文每行行首的 "." 转义为 ".."（RFC5321 透明传输要求）。
func dotStuff(msg string) string {
	lines := strings.Split(msg, "\r\n")
	for i, l := range lines {
		if strings.HasPrefix(l, ".") {
			lines[i] = "." + l
		}
	}
	return strings.Join(lines, "\r\n")
}
