package notify

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// 最小 IMAP 客户端：仅实现「已发送」存档所需指令（LOGIN / LIST / CREATE / APPEND），
// 决策⑥不引第三方库。SMTP 发送成功后副本经 APPEND 写入「已发送」文件夹
// （mailu 等自建邮箱的网页客户端即可看到已发邮件；IMAP 以 SMTP 同账号登录，
// imapHost/imapPort 留空默认同 SMTP 主机/993 SSL，sentFolder 留空自动探测）。
// Java 侧 appendMessages 后另行补 \Seen 去除未读角标，这里直接在 APPEND 时带 (\Seen) 标志，效果等价。

// 常见「已发送」文件夹名：mailu/Dovecot 为 Sent，中文客户端环境可能是本地化名称
var sentFolderCandidates = []string{"Sent", "Sent Messages", "Sent Items", "已发送", "已发送邮件", "INBOX.Sent"}

const imapIOTimeout = 15 * time.Second

func archiveToSent(cfg map[string]interface{}, smtpHost, username, password string, msg []byte) string {
	imapHost := strings.TrimSpace(core.BodyStr(cfg, "imapHost"))
	if imapHost == "" {
		imapHost = smtpHost
	}
	port := core.BodyNum(cfg, "imapPort", 993)
	ssl := core.BodyBool(cfg, "imapSsl", true)
	starttls := core.BodyBool(cfg, "imapStarttls", false)
	preferred := strings.TrimSpace(core.BodyStr(cfg, "sentFolder"))

	folder, err := imapAppend(imapHost, port, ssl, starttls, username, password, preferred, msg)
	if err != nil {
		core.LogWarn(core.LogNotify, "邮件 IMAP 存档失败: "+err.Error())
		return "IMAP 存档失败: " + err.Error()
	}
	return "已存档至已发送[" + folder + "]"
}

func imapAppend(host string, port int, ssl, starttls bool, username, password, preferred string, msg []byte) (string, error) {
	d := net.Dialer{Timeout: imapIOTimeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", fmt.Errorf("IMAP 连接失败: %w", err)
	}
	defer conn.Close()
	i := &imapConn{conn: conn}
	i.reset()
	if ssl {
		if err := i.upgradeTLS(host); err != nil {
			return "", err
		}
	}
	// 服务端握手 * OK greeting
	if err := i.expectUntaggedOK(); err != nil {
		return "", err
	}
	if !ssl && starttls {
		if _, err := i.command("STARTTLS"); err != nil {
			return "", err
		}
		if err := i.upgradeTLS(host); err != nil {
			return "", err
		}
	}
	if _, err := i.command("LOGIN " + imapQuote(username) + " " + imapQuote(password)); err != nil {
		return "", err
	}
	folder, err := findSentFolder(i, preferred)
	if err != nil {
		_ = i.logout()
		return "", err
	}
	// APPEND 直接带 (\Seen)，避免网页客户端「已发送」出现未读角标
	appendCmd := "APPEND " + imapQuote(folder) + " (\\Seen) {" + strconv.Itoa(len(msg)) + "}"
	if err := i.commandWithLiteral(appendCmd, msg); err != nil {
		_ = i.logout()
		return "", fmt.Errorf("IMAP APPEND 失败: %w", err)
	}
	_ = i.logout()
	return folder, nil
}

// findSentFolder 定位「已发送」文件夹：优先用户指定名，否则按常见候选探测，都不存在则尝试创建 Sent。
func findSentFolder(i *imapConn, preferred string) (string, error) {
	if preferred != "" {
		ok, err := i.listHasEntry(preferred)
		if err != nil {
			return "", err
		}
		if ok {
			return preferred, nil
		}
		if _, err := i.command("CREATE " + imapQuote(preferred)); err != nil {
			return "", fmt.Errorf("已发送文件夹[%s]不存在且无法创建", preferred)
		}
		return preferred, nil
	}
	for _, name := range sentFolderCandidates {
		ok, err := i.listHasEntry(name)
		if err != nil {
			return "", err
		}
		if ok {
			return name, nil
		}
	}
	if _, err := i.command("CREATE " + imapQuote("Sent")); err == nil {
		return "Sent", nil
	}
	return "", fmt.Errorf("未探测到已发送文件夹，请在渠道配置中手动指定文件夹名")
}

type imapConn struct {
	conn net.Conn
	r    *bufio.Reader
	tag  int
}

func (i *imapConn) reset() {
	i.r = bufio.NewReader(i.conn)
	_ = i.conn.SetDeadline(time.Now().Add(imapIOTimeout))
}

func (i *imapConn) upgradeTLS(host string) error {
	tconn := tls.Client(i.conn, &tls.Config{ServerName: host})
	if err := tconn.Handshake(); err != nil {
		return fmt.Errorf("IMAP TLS 握手失败: %w", err)
	}
	i.conn = tconn
	i.reset()
	return nil
}

// command 发送带标签命令并等待 tagged OK（自动吃掉中间 untagged 行）。
func (i *imapConn) command(line string) (string, error) {
	i.tag++
	tag := "a" + strconv.Itoa(i.tag)
	if _, err := i.conn.Write([]byte(tag + " " + line + "\r\n")); err != nil {
		return "", fmt.Errorf("IMAP 写入失败: %w", err)
	}
	_ = i.conn.SetDeadline(time.Now().Add(imapIOTimeout))
	for {
		resp, err := i.r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("IMAP 读取失败: %w", err)
		}
		resp = strings.TrimRight(resp, "\r\n")
		if strings.HasPrefix(resp, tag+" ") {
			rest := resp[len(tag)+1:]
			if strings.HasPrefix(rest, "OK") {
				return rest, nil
			}
			return "", fmt.Errorf("IMAP %s 失败: %s", line, resp)
		}
		// untagged（* ...）与续行（+ ...）继续读
	}
}

// commandWithLiteral 处理字面量追加：命令以 {N} 结尾，服务器回 "+" 后写入原始字节再等 tagged 响应。
func (i *imapConn) commandWithLiteral(line string, literal []byte) error {
	i.tag++
	tag := "a" + strconv.Itoa(i.tag)
	if _, err := i.conn.Write([]byte(tag + " " + line + "\r\n")); err != nil {
		return fmt.Errorf("IMAP 写入失败: %w", err)
	}
	_ = i.conn.SetDeadline(time.Now().Add(imapIOTimeout))
	for {
		resp, err := i.r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("IMAP 读取失败: %w", err)
		}
		resp = strings.TrimRight(resp, "\r\n")
		if strings.HasPrefix(resp, "+") {
			if _, err := i.conn.Write(append(literal, '\r', '\n')); err != nil {
				return fmt.Errorf("IMAP 写入字面量失败: %w", err)
			}
			continue
		}
		if strings.HasPrefix(resp, tag+" ") {
			if strings.HasPrefix(resp[len(tag)+1:], "OK") {
				return nil
			}
			return fmt.Errorf("IMAP %s", resp)
		}
	}
}

// listHasEntry 通过 LIST 精确探测文件夹是否存在。
func (i *imapConn) listHasEntry(name string) (bool, error) {
	i.tag++
	tag := "a" + strconv.Itoa(i.tag)
	line := tag + " LIST " + imapQuote("") + " " + imapQuote(name) + "\r\n"
	if _, err := i.conn.Write([]byte(line)); err != nil {
		return false, fmt.Errorf("IMAP 写入失败: %w", err)
	}
	_ = i.conn.SetDeadline(time.Now().Add(imapIOTimeout))
	found := false
	for {
		resp, err := i.r.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("IMAP 读取失败: %w", err)
		}
		resp = strings.TrimRight(resp, "\r\n")
		if strings.HasPrefix(resp, "* LIST") {
			// 精确匹配末尾带引号的文件夹名（避免大小写前缀误判）
			if idx := strings.LastIndex(resp, " "); idx >= 0 {
				q := resp[idx+1:]
				unquoted, ok := imapUnquote(q)
				if ok && unquoted == name {
					found = true
				}
			}
			continue
		}
		if strings.HasPrefix(resp, tag+" ") {
			return found, nil
		}
	}
}

func (i *imapConn) expectUntaggedOK() error {
	_ = i.conn.SetDeadline(time.Now().Add(imapIOTimeout))
	resp, err := i.r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("IMAP 读取握手失败: %w", err)
	}
	resp = strings.TrimRight(resp, "\r\n")
	if strings.HasPrefix(resp, "* OK") || strings.HasPrefix(resp, "* PREAUTH") {
		return nil
	}
	return fmt.Errorf("IMAP 服务器拒绝连接: %s", resp)
}

func (i *imapConn) logout() error {
	_, err := i.command("LOGOUT")
	return err
}

// imapQuote 带引号字符串（转义 \ 与 "）。
func imapQuote(s string) string {
	return "\"" + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + "\""
}

func imapUnquote(q string) (string, bool) {
	if len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
		return "", false
	}
	inner := q[1 : len(q)-1]
	return strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(inner), true
}
