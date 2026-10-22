package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 极简 Docker Engine API 客户端（仅本服务所需的读写请求）。
// 默认经 Unix socket /var/run/docker.sock 通信（容器部署时挂载即可），
// 也支持环境变量 DOCKER_HOST 指定 unix:///path/to/docker.sock 或 tcp://host:2375。
// Java 版基于 SocketChannel 手写 HTTP/1.1；Go 版改用 net/http + 自定义拨号（Unix/TCP），
// 状态码校验、错误信息提取、多路复用解帧等行为与 Java 版逐一对齐。

// connectTimeout 连接超时：端口不通时快速失败。
const connectTimeout = 3 * time.Second

type dockerClient struct {
	network  string // "unix" / "tcp"
	addr     string
	describe string
	// broken 非空表示 DOCKER_HOST 配置无效，所有请求直接失败（不拖垮应用启动）
	broken string
	hc     *http.Client
}

var winDriveRe = regexp.MustCompile(`^/[A-Za-z]:.*`)

// newDockerClient 从环境变量 DOCKER_HOST 构建客户端，未配置时默认 unix:///var/run/docker.sock。
func newDockerClient() *dockerClient {
	host := strings.TrimSpace(os.Getenv("DOCKER_HOST"))
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	c := &dockerClient{}
	if strings.HasPrefix(host, "tcp://") {
		hp := host[len("tcp://"):]
		h, p := "127.0.0.1", 2375
		if i := strings.LastIndex(hp, ":"); i > 0 {
			h = hp[:i]
			if n, err := strconv.Atoi(hp[i+1:]); err == nil {
				p = n
			}
		}
		c.network = "tcp"
		c.addr = net.JoinHostPort(h, strconv.Itoa(p))
		c.describe = host
	} else {
		path := strings.TrimPrefix(host, "unix://")
		// Windows 盘符路径兼容：unix:///C:/x.sock 去掉多余前导斜杠
		if winDriveRe.MatchString(path) {
			path = path[1:]
		}
		if path == "" {
			c.broken = "DOCKER_HOST 配置无效（" + host + "）: socket 路径为空"
			c.describe = host
		} else {
			c.network = "unix"
			c.addr = path
			c.describe = "unix://" + path
		}
	}
	d := &net.Dialer{Timeout: connectTimeout}
	c.hc = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, c.network, c.addr)
		},
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   true, // 等价 Java 的 Connection: close
		MaxIdleConnsPerHost: -1,
	}}
	return c
}

// get GET 请求返回响应体；非 2xx 抛出携带状态码与 Daemon 错误信息的异常。
func (c *dockerClient) get(pathAndQuery string) (string, error) {
	return c.exchange("GET", pathAndQuery, false, false)
}

// post POST 请求（容器起停/清理等写操作）；接受 2xx 与 304（容器已处于目标状态）。
func (c *dockerClient) post(pathAndQuery string) (string, error) {
	return c.exchange("POST", pathAndQuery, true, false)
}

// logs 读取容器日志：非 TTY 响应为 Docker 多路复用帧，解帧后按序拼接返回。
func (c *dockerClient) logs(pathAndQuery string) (string, error) {
	return c.exchange("GET", pathAndQuery, false, true)
}

func (c *dockerClient) exchange(method, pathAndQuery string, lenientOk, demux bool) (string, error) {
	if c.broken != "" {
		return "", errors.New(c.broken)
	}
	req, err := http.NewRequest(method, "http://docker"+pathAndQuery, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	code := resp.StatusCode
	ok := code >= 200 && code < 300
	if !ok && lenientOk && code == 304 {
		ok = true
	}
	if !ok {
		text := strings.TrimSpace(string(body))
		// Daemon 错误体形如 {"message":"..."}，提取后更友好
		message := ""
		if o, e := parseJSON(text); e == nil {
			message = o.str("message")
		}
		if message == "" {
			message = text
		}
		return "", fmt.Errorf("Docker API %d: %s", code, message)
	}
	if demux {
		body = demultiplex(body)
	}
	return string(body), nil
}

// demultiplex Docker 多路复用流解帧：每帧 8 字节头 = [流类型 1][零 3][大端长度 4]。
// 非帧格式（TTY 容器日志原始字节流，首字节不会是 1/2）时原样返回。
func demultiplex(data []byte) []byte {
	var out []byte
	pos := 0
	framed := false
	for pos+8 <= len(data) {
		typ := data[pos]
		if typ != 1 && typ != 2 {
			break // 非 stdout/stderr 帧头，判定为原始流
		}
		l := int(data[pos+4])<<24 | int(data[pos+5])<<16 | int(data[pos+6])<<8 | int(data[pos+7])
		from := pos + 8
		to := from + l
		if to > len(data) {
			to = len(data)
		}
		out = append(out, data[from:to]...)
		pos = to
		framed = true
	}
	if !framed {
		return data // 未解出任何帧：TTY 原始日志，直接返回
	}
	return out
}
