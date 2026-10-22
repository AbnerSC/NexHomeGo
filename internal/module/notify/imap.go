package notify

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"NexHomeGo/internal/core"
)

// 最小 IMAP 客户端：仅实现「已发送」存档所需指令（LOGIN / LIST / CREATE / SUBSCRIBE / APPEND），
// 决策⑥不引第三方库。SMTP 发送成功后副本经 APPEND 写入「已发送」文件夹
// （mailu 等自建邮箱的网页客户端即可看到已发邮件；IMAP 以 SMTP 同账号登录，
// imapHost/imapPort 留空默认同 SMTP 主机/993 SSL，sentFolder 留空自动探测）。
// Java 侧 appendMessages 后另行补 \Seen 去除未读角标，这里直接在 APPEND 时带 (\Seen) 标志，效果等价。
//
// 探测靠 LIST "" "*" 全量枚举：先认 \Sent 特殊用途标志，再按名字匹配。Dovecot（mailu）的 LIST
// 响应把纯 ASCII 名字写成无引号 atom（* LIST (\HasNoChildren \Sent) "/" Sent），名字非 ASCII 时
// 用 modified UTF-7（RFC 3501 5.1.3）编码；两种写法都必须能解析，否则会把已存在的 Sent 判成不存在，
// 随后的 CREATE 又被服务器以 already exists 拒绝，最终误报「未探测到已发送文件夹」。

// 常见「已发送」文件夹名：mailu/Dovecot 为 Sent，中文客户端环境可能是本地化名称。
// 比较时忽略大小写，并允许「INBOX.Sent」这类带层级前缀的写法与「Sent」互相匹配。
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
	appendCmd := "APPEND " + imapQuote(folder.wire) + " (\\Seen) {" + strconv.Itoa(len(msg)) + "}"
	if err := i.commandWithLiteral(appendCmd, msg); err != nil {
		_ = i.logout()
		return "", fmt.Errorf("IMAP APPEND 失败: %w", err)
	}
	_ = i.logout()
	return folder.name, nil
}

// imapFolder 邮件文件夹：wire 为线上名（modified UTF-7，CREATE/APPEND 用），name 为解码后的展示名。
type imapFolder struct {
	wire string
	name string
}

// imapMailbox LIST 返回的邮箱及其属性（\Sent / \Noselect / \HasNoChildren ...）。
type imapMailbox struct {
	wire  string
	name  string
	flags []string
}

func (m imapMailbox) folder() imapFolder { return imapFolder{wire: m.wire, name: m.name} }

func (m imapMailbox) hasFlag(flag string) bool {
	for _, f := range m.flags {
		if strings.EqualFold(f, flag) {
			return true
		}
	}
	return false
}

// findSentFolder 定位「已发送」文件夹：优先用户指定名，其次 \Sent 特殊用途标志，再按常见候选名匹配；
// 都不存在则创建（优先用指定名，否则 Sent）。
func findSentFolder(i *imapConn, preferred string) (imapFolder, error) {
	boxes, err := i.listMailboxes()
	if err != nil {
		return imapFolder{}, err
	}
	if preferred != "" {
		if mb, ok := pickMailbox(boxes, preferred); ok {
			return mb.folder(), nil
		}
		// 指定名不存在：按该名创建，失败时把服务器原话带回，便于用户改配置
		return createSentFolder(i, preferred)
	}
	if mb, ok := pickSpecialUse(boxes, "\\Sent"); ok {
		return mb.folder(), nil
	}
	for _, name := range sentFolderCandidates {
		if mb, ok := pickMailbox(boxes, name); ok {
			return mb.folder(), nil
		}
	}
	return createSentFolder(i, "Sent")
}

// createSentFolder 创建（并尽力订阅）「已发送」文件夹。
// 服务器回报 already exists 时视为可用：LIST 可能因 mailbox_list_index 滞后而漏报。
func createSentFolder(i *imapConn, name string) (imapFolder, error) {
	wire := imapEncodeName(name)
	if _, err := i.command("CREATE " + imapQuote(wire)); err != nil {
		if !isAlreadyExists(err) {
			return imapFolder{}, fmt.Errorf("未探测到已发送文件夹，且创建[%s]失败(%s)；请在渠道配置中手动指定文件夹名", name, err.Error())
		}
	} else if _, err := i.command("SUBSCRIBE " + imapQuote(wire)); err != nil {
		// 订阅只影响网页客户端的订阅列表，失败不阻断存档
		core.LogWarn(core.LogNotify, "IMAP 订阅["+name+"]失败: "+err.Error())
	}
	return imapFolder{wire: wire, name: name}, nil
}

// isAlreadyExists 判断 CREATE 是否只是「已存在」（Dovecot：NO [ALREADYEXISTS] Mailbox already exists）。
func isAlreadyExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exist") || strings.Contains(msg, "[alreadyexists]")
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
	_, rest, err := i.collect(line)
	return rest, err
}

// collect 发送带标签命令，返回全部 untagged（* ...）行与 tagged 响应正文。
func (i *imapConn) collect(line string) ([]string, string, error) {
	i.tag++
	tag := "a" + strconv.Itoa(i.tag)
	if _, err := i.conn.Write([]byte(tag + " " + line + "\r\n")); err != nil {
		return nil, "", fmt.Errorf("IMAP 写入失败: %w", err)
	}
	_ = i.conn.SetDeadline(time.Now().Add(imapIOTimeout))
	var untagged []string
	for {
		resp, err := i.r.ReadString('\n')
		if err != nil {
			return untagged, "", fmt.Errorf("IMAP 读取失败: %w", err)
		}
		resp = strings.TrimRight(resp, "\r\n")
		if strings.HasPrefix(resp, tag+" ") {
			rest := resp[len(tag)+1:]
			if strings.HasPrefix(rest, "OK") {
				return untagged, rest, nil
			}
			return untagged, "", fmt.Errorf("IMAP %s 失败: %s", line, resp)
		}
		if strings.HasPrefix(resp, "* ") {
			untagged = append(untagged, resp)
		}
		// 续行（+ ...）继续读
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

// listMailboxes 一次 LIST "" "*" 枚举全部邮箱（含 \Sent 等 SPECIAL-USE 属性）。
func (i *imapConn) listMailboxes() ([]imapMailbox, error) {
	lines, _, err := i.collect("LIST " + imapQuote("") + " " + imapQuote("*"))
	if err != nil {
		return nil, err
	}
	boxes := make([]imapMailbox, 0, len(lines))
	for _, line := range lines {
		if mb, ok := parseListLine(line); ok {
			boxes = append(boxes, mb)
		}
	}
	return boxes, nil
}

// parseListLine 解析一条 untagged LIST 响应，兼容三种写法：
//   * LIST (\HasNoChildren \Sent) "/" Sent          （Dovecot：无引号 atom）
//   * LIST (\HasNoChildren) "/" "Sent Messages"     （含空格：带引号）
//   * LIST (\HasNoChildren) "." "INBOX"             （层级分隔符为 . ）
func parseListLine(line string) (imapMailbox, bool) {
	rest, ok := cutPrefixFold(line, "* LIST ")
	if !ok {
		return imapMailbox{}, false
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "(") {
		return imapMailbox{}, false
	}
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return imapMailbox{}, false
	}
	mb := imapMailbox{flags: strings.Fields(rest[1:end])}
	// 括号内是属性，其后是层级分隔符（"x" 或 NIL），末尾是文件夹名
	if _, rest, ok = takeAstring(strings.TrimSpace(rest[end+1:])); !ok {
		return imapMailbox{}, false
	}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "{") {
		return imapMailbox{}, false // 字面量写法极少见于 LIST，不支持
	}
	if mb.wire, _, ok = takeAstring(rest); !ok || mb.wire == "" {
		return imapMailbox{}, false
	}
	mb.name = imapUtf7Decode(mb.wire)
	return mb, true
}

// pickMailbox 按名字挑邮箱：忽略大小写与层级前缀；\Noselect（不可选占位）命中排后。
func pickMailbox(boxes []imapMailbox, name string) (imapMailbox, bool) {
	for _, skipNoSelect := range []bool{true, false} {
		for _, mb := range boxes {
			if skipNoSelect && mb.hasFlag("\\Noselect") {
				continue
			}
			if mailboxNameEq(mb.name, name) {
				return mb, true
			}
		}
	}
	return imapMailbox{}, false
}

// pickSpecialUse 按 SPECIAL-USE 标志挑邮箱（如 \Sent），同样让 \Noselect 命中排后。
func pickSpecialUse(boxes []imapMailbox, flag string) (imapMailbox, bool) {
	for _, skipNoSelect := range []bool{true, false} {
		for _, mb := range boxes {
			if skipNoSelect && mb.hasFlag("\\Noselect") {
				continue
			}
			if mb.hasFlag(flag) {
				return mb, true
			}
		}
	}
	return imapMailbox{}, false
}

// mailboxNameEq 名字比较：忽略大小写，按 / 与 . 取末级后比较（INBOX.Sent ≈ Sent）。
func mailboxNameEq(name, want string) bool {
	if strings.EqualFold(name, want) {
		return true
	}
	for _, sep := range []string{"/", "."} {
		if idx := strings.LastIndex(name, sep); idx >= 0 && strings.EqualFold(name[idx+1:], want) {
			return true
		}
	}
	return false
}

// takeAstring 取行首一个 IMAP astring（带引号字符串或 atom），返回取值与剩余内容。
func takeAstring(s string) (string, string, bool) {
	if s == "" {
		return "", s, false
	}
	if s[0] != '"' {
		if i := strings.IndexByte(s, ' '); i >= 0 {
			return s[:i], strings.TrimSpace(s[i+1:]), true
		}
		return s, "", true
	}
	escaped := false
	for i := 1; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch s[i] {
		case '\\':
			escaped = true
		case '"':
			val, ok := imapUnquote(s[:i+1])
			return val, strings.TrimSpace(s[i+1:]), ok
		}
	}
	return "", s, false
}

// cutPrefixFold 忽略大小写去掉前缀（服务器可能小写回报 * list）。
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
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

// imapEncodeName 待创建名转线上名：纯 ASCII 原样返回（保留用户手填的 &...- 编码名），
// 含非 ASCII 时才转 modified UTF-7，避免 CREATE/APPEND 直接发 UTF-8 被服务器判为非法邮箱名。
func imapEncodeName(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return imapUtf7Encode(s)
		}
	}
	return s
}

// imapUtf7Encode UTF-8 → modified UTF-7（RFC 3501 5.1.3）：& → &-，其余非可打印 ASCII 按 UTF-16BE 的 base64 编码，
// base64 的 / 换成 ,（mailu/Roundcube 建的中文文件夹在线上就是这个样子）。
func imapUtf7Encode(s string) string {
	var sb strings.Builder
	var buf []rune
	flush := func() {
		if len(buf) == 0 {
			return
		}
		raw := make([]byte, 0, len(buf)*2)
		for _, r := range buf {
			if r > 0xFFFF {
				r -= 0x10000
				hi := uint16(0xD800 + (r >> 10))
				lo := uint16(0xDC00 + (r & 0x3FF))
				raw = append(raw, byte(hi>>8), byte(hi), byte(lo>>8), byte(lo))
				continue
			}
			raw = append(raw, byte(r>>8), byte(r))
		}
		enc := base64.RawStdEncoding.EncodeToString(raw)
		sb.WriteByte('&')
		sb.WriteString(strings.ReplaceAll(enc, "/", ","))
		sb.WriteByte('-')
		buf = buf[:0]
	}
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			flush()
			if r == '&' {
				sb.WriteString("&-")
			} else {
				sb.WriteByte(byte(r))
			}
			continue
		}
		buf = append(buf, r)
	}
	flush()
	return sb.String()
}

// imapUtf7Decode modified UTF-7 → UTF-8，供 LIST 回来的名字与配置/候选名比较。
func imapUtf7Decode(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			sb.WriteByte(s[i])
			continue
		}
		end := strings.IndexByte(s[i+1:], '-')
		if end < 0 {
			sb.WriteByte(s[i])
			continue
		}
		enc := s[i+1 : i+1+end]
		i += end + 1
		if enc == "" {
			sb.WriteByte('&')
			continue
		}
		raw, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(enc, ",", "/"))
		if err != nil || len(raw)%2 != 0 {
			sb.WriteString("&" + enc + "-") // 残缺编码原样保留
			continue
		}
		u16 := make([]uint16, 0, len(raw)/2)
		for j := 0; j+1 < len(raw); j += 2 {
			u16 = append(u16, uint16(raw[j])<<8|uint16(raw[j+1]))
		}
		sb.WriteString(string(utf16.Decode(u16)))
	}
	return sb.String()
}
