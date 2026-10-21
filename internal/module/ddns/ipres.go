package ddns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// DDNS IP 来源解析器（复刻 Java IpResolver），支持三种模式：
//   - LOCAL  - 读取本机网卡 IP（可指定网卡名，缺省取第一个 IPv4 内网地址）
//   - MANUAL - 用户手动输入的 IP
//   - PUBLIC - 调用公网接口获取本机出口公网 IP（多接口容错）

// 公网 IP 查询接口（逐个尝试，任一成功即返回）
var publicIPURLs = []string{
	"https://ddns.oray.com/checkip",
	"http://v4.66666.host:66/ip",
	"https://myip.ipip.net",
	"http://v4.666666.host:66/ip",
	"https://4.ipw.cn",
	"https://ip.3322.net",
}

var publicIPHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

var ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// resolve 根据任务行解析应同步的 IP（同步流程入口）。
func resolve(task *core.Row) (string, error) {
	return resolveFields(rowStr(task, "ip_mode"), rowStr(task, "manual_ip"), rowStr(task, "local_nic"))
}

// resolveFields 按模式解析 IP（preview-ip 端点直接以表单三字段调用）。
func resolveFields(mode, manualIP, nic string) (string, error) {
	switch mode {
	case "MANUAL":
		if strings.TrimSpace(manualIP) == "" {
			return "", core.NewBadRequest("手动模式未填写 IP 地址")
		}
		return manualIP, nil
	case "LOCAL":
		return localIP(nic)
	default:
		return publicIP()
	}
}

// isVirtualIface 近似 Java NetworkInterface.isVirtual()：Linux 子接口形如 eth0:1 / docker0:1。
// Go 无 virtual 概念，Java 侧判定的主要是此类冒号子接口（docker0 等网桥在 Java 侧同样不被过滤）。
func isVirtualIface(name string) bool { return strings.Contains(name, ":") }

// usableNic 网卡是否可用作 LOCAL 模式来源（up、非回环、非虚拟子接口）。
func usableNic(nic net.Interface) bool {
	return nic.Flags&net.FlagUp != 0 && nic.Flags&net.FlagLoopback == 0 && !isVirtualIface(nic.Name)
}

// localIP 读取本机网卡 IPv4 地址（nicName 为空时取第一个可用网卡的私有 IPv4）。
func localIP(nicName string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, nic := range ifaces {
		if !usableNic(nic) {
			continue
		}
		if nicName != "" && nic.Name != nicName {
			continue
		}
		addrs, err := nic.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			// IsPrivate 覆盖 RFC1918 三段（10/8、172.16/12、192.168/16），
			// 与 Java Inet4Address.isSiteLocalAddress 判定一致
			if ip != nil && ip.To4() != nil && ip.IsPrivate() {
				return ip.String(), nil
			}
		}
	}
	if strings.TrimSpace(nicName) == "" {
		return "", errors.New("未找到可用的本机网卡 IPv4 地址")
	}
	return "", errors.New("网卡 " + nicName + " 未找到可用 IPv4 地址")
}

// listNics 列出本机所有可用网卡名（供前端下拉选择）。
func listNics() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0)
	for _, nic := range ifaces {
		if usableNic(nic) {
			names = append(names, nic.Name)
		}
	}
	return names, nil
}

// publicIP 调用公网接口获取出口公网 IP（任一接口 200 且响应体为纯 IPv4 即成功）。
func publicIP() (string, error) {
	lastMsg := ""
	hasLast := false
	for _, u := range publicIPURLs {
		ip, err := fetchPublicIP(u)
		if err != nil {
			// 与 Java 一致：仅请求异常记录 last，状态码/格式不符静默尝试下一个接口
			lastMsg, hasLast = err.Error(), true
			continue
		}
		if ip != "" {
			return ip, nil
		}
	}
	if hasLast {
		core.LogWarn(core.LogDdns, "所有公网 IP 查询接口均失败: "+lastMsg)
	} else {
		core.LogWarn(core.LogDdns, "所有公网 IP 查询接口均失败")
	}
	return "", errors.New("获取公网 IP 失败，请检查网络或改用手动/本地网卡模式")
}

// fetchPublicIP 请求单个查询接口；返回空串表示响应可用但内容不是纯 IPv4（不计为失败）。
func fetchPublicIP(u string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := publicIPHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if resp.StatusCode == 200 && ipv4Re.MatchString(ip) {
		return ip, nil
	}
	return "", nil
}
