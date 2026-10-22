package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebSocket / Upgrade 隧道：原始字节回源（仅 HTTP/1.1 且回源 http1）。
// 复刻 Java startTunnel + UpgradeBridge + RawRelay：序列化回源请求头（保留 Upgrade、
// Connection 归一为 upgrade）→ 嗅探后端状态行 → 101 转双向原始泵；非 101/超长/半途关闭回 502。

const (
	tunnelIdleSec   = 300 // 隧道空闲回收（对齐 Java 前端 IdleStateHandler 300s）
	tunnelHeadLimit = 65536
)

var crlfcrlf = []byte("\r\n\r\n")

// startTunnel Upgrade 请求入口（handler 已确认：非 h2、回源 http1）
func startTunnel(w http.ResponseWriter, r *http.Request, site *Site, upath, peerIp string, st *siteStats, https bool) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		// 理论不可达：隧道只在 h1 连接触发，h1 ResponseWriter 必支持 Hijack
		noteError(site, "隧道建立失败: 响应器不支持连接接管")
		sendErrorPage(w, 502, "协议升级失败: 响应器不支持连接接管",
			"WebSocket / 协议升级需后端支持，请确认该站点的后端与回源协议配置。", false)
		return
	}
	front, bufin, err := hj.Hijack()
	if err != nil {
		noteError(site, "隧道建立失败: 连接接管失败: "+err.Error())
		return
	}
	defer front.Close()

	st.active.Add(1)
	defer st.active.Add(-1)

	// 原始序列化回源请求头（保留 Upgrade，Connection 归一为 upgrade）
	head := serializeTunnelHead(r, upath, peerIp, https, site)

	backend, err := dialTunnelBackend(site)
	if err != nil {
		tunnelFail(front, site, "后端连接失败: "+err.Error())
		return
	}
	defer backend.Close()

	if _, err = backend.Write([]byte(head)); err != nil {
		tunnelFail(front, site, "后端连接失败: "+err.Error())
		return
	}

	// 嗅探响应状态行：101 才转泵
	_ = backend.SetReadDeadline(time.Now().Add(tunnelIdleDuration()))
	br := bufio.NewReader(backend)
	respHead, err := sniffUpgradeHead(br)
	if err != nil {
		if err.Error() == "升级响应头超长" {
			tunnelFail(front, site, err.Error())
		} else {
			tunnelFail(front, site, "后端在升级确认前关闭连接")
		}
		return
	}
	code := parseStatus(respHead)
	if code != 101 {
		tunnelFail(front, site, "后端未确认协议升级（HTTP "+strconv.Itoa(code)+"），WebSocket/升级请求需后端支持")
		return
	}

	// 101：把已嗅探的响应头（含 101 后抢跑到达的帧数据）原样写回前端，随后恢复读取进入原始泵
	if _, err = front.Write(respHead); err != nil {
		return
	}
	pumpTunnel(front, bufin, backend)
}

func tunnelIdleDuration() time.Duration { return time.Duration(tunnelIdleSec) * time.Second }

// serializeTunnelHead 序列化回源请求行与头部（对齐 Java startTunnel 的 StringBuilder 流程）
func serializeTunnelHead(r *http.Request, upath, peerIp string, https bool, site *Site) string {
	var sb strings.Builder
	sb.Grow(512)
	sb.WriteString(r.Method)
	sb.WriteByte(' ')
	sb.WriteString(upath)
	sb.WriteString(" HTTP/1.1\r\n")
	// Go 服务器已从 Header 移除 Host/Content-Length/Transfer-Encoding：按原请求语义补回
	sb.WriteString("Host: ")
	sb.WriteString(r.Host)
	sb.WriteString("\r\n")
	if r.ContentLength >= 0 {
		sb.WriteString("Content-Length: ")
		sb.WriteString(strconv.FormatInt(r.ContentLength, 10))
		sb.WriteString("\r\n")
	}
	for name, vals := range r.Header {
		if hopNoTunnel(name) || strings.EqualFold(name, "Host") {
			continue
		}
		for _, v := range vals {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\r\n")
		}
	}
	if https {
		sb.WriteString("X-Forwarded-Proto: https-tunnel\r\n")
	} else {
		sb.WriteString("X-Forwarded-Proto: http-tunnel\r\n")
	}
	xff := r.Header.Get("X-Forwarded-For")
	if strings.TrimSpace(xff) == "" {
		sb.WriteString("X-Forwarded-For: " + peerIp + "\r\n")
	} else {
		sb.WriteString("X-Forwarded-For: " + xff + ", " + peerIp + "\r\n")
	}
	sb.WriteString("X-Forwarded-By: NexHome\r\n")
	applyTunnelOps(&sb, site.Adv.ReqHeaders)
	sb.WriteString("Connection: upgrade\r\n\r\n")
	return sb.String()
}

// applyTunnelOps 隧道模式自定义头改写：直接作用于序列化文本（简单可靠，头名已由配置校验）
func applyTunnelOps(sb *strings.Builder, ops []HeaderOp) {
	for _, op := range ops {
		n := op.Name
		if n != "" && !hopNoTunnel(n) && !strings.EqualFold(n, "upgrade") {
			// delete：移除该头行；set：先删后追加
			p := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(n) + `:.*\r?\n`)
			removed := p.ReplaceAllString(sb.String(), "")
			sb.Reset()
			sb.WriteString(removed)
			if op.Op == "set" {
				sb.WriteString(n)
				sb.WriteString(": ")
				sb.WriteString(op.Value)
				sb.WriteString("\r\n")
			}
		}
	}
}

// dialTunnelBackend 建立回源原始连接（TCP + 可选 TLS，连接超时对齐 connectSec）
func dialTunnelBackend(site *Site) (net.Conn, error) {
	addr := net.JoinHostPort(site.BackendHost, strconv.Itoa(site.BackendPort))
	d := &net.Dialer{Timeout: time.Duration(site.Adv.ConnectSec) * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if site.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{
			ServerName:         site.BackendHost,
			InsecureSkipVerify: site.Adv.BackendInsecure,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		return tc, nil
	}
	return conn, nil
}

// sniffUpgradeHead 累积读取后端响应头直至头部结束；超 64KB 报错（对齐 UpgradeBridge 嗅探）
func sniffUpgradeHead(br *bufio.Reader) ([]byte, error) {
	acc := make([]byte, 0, 512)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err // 头未收满即断：后端在升级确认前关闭连接
		}
		acc = append(acc, b)
		if len(acc) > tunnelHeadLimit {
			return nil, &overflowErr{}
		}
		if len(acc) >= 4 && bytes.Equal(acc[len(acc)-4:], crlfcrlf) {
			break
		}
	}
	// 头部之后已抢跑到达的帧数据一并带走（写回前端后进入原始泵）
	for br.Buffered() > 0 {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		acc = append(acc, b)
	}
	return acc, nil
}

type overflowErr struct{}

func (e *overflowErr) Error() string { return "升级响应头超长" }

// parseStatus 状态行 "HTTP/1.x 101 ..." 解析
func parseStatus(head []byte) int {
	line := string(head)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "HTTP/") {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			return code
		}
	}
	return 0
}

// tunnelFail 隧道建立失败：记错 + 向前端写 502 页 + 关闭两端（对齐 Java UpgradeBridge.fail）
func tunnelFail(front net.Conn, site *Site, reason string) {
	noteError(site, "隧道建立失败: "+reason)
	writeErrorPageTo(front, 502, "协议升级失败: "+reason,
		"WebSocket / 协议升级需后端支持，请确认该站点的后端与回源协议配置。")
	front.Close()
}

// pumpTunnel 双向原始泵：一端活跃则转发，任一端结束即关两端；空闲 300 秒回收（对齐 RawRelay）
func pumpTunnel(front net.Conn, bufin *bufio.ReadWriter, backend net.Conn) {
	var wg sync.WaitGroup
	idle := tunnelIdleDuration()
	src := &bufferedConn{Conn: front, rd: bufin.Reader}
	pump := func(dst net.Conn, from *bufferedConn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			_ = from.SetReadDeadline(time.Now().Add(idle))
			n, err := from.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		backend.SetDeadline(time.Now())
		front.SetDeadline(time.Now())
		backend.Close()
	}
	wg.Add(2)
	go pump(backend, src)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			_ = backend.SetReadDeadline(time.Now().Add(idle))
			n, err := backend.Read(buf)
			if n > 0 {
				if _, werr := front.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		backend.SetDeadline(time.Now())
		front.SetDeadline(time.Now())
		front.Close()
	}()
	wg.Wait()
}

// bufferedConn 优先消费 hijack 时已缓冲的字节，再读底层连接（Hijack 语义要求：
// bufin 中可能有随请求尾部的残余字节，直接读 conn 会丢）
type bufferedConn struct {
	net.Conn
	rd *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.rd != nil && c.rd.Buffered() > 0 {
		return c.rd.Read(p)
	}
	return c.Conn.Read(p)
}

// 保证 io 导入被使用（bufferedConn 语义与 io.Reader 一致）
var _ io.Reader = (*bufferedConn)(nil)
