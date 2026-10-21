package stun

// UPnP IGD 端口映射客户端：SSDP 发现路由器网关，
// 经 WANIPConnection / WANPPPConnection 服务 SOAP 调用添加/删除 WAN->LAN 端口映射。
// 复刻 Java UpnpClient：纯标准库实现（net + encoding/xml + regexp），不依赖第三方库。
//
// 与 STUN 穿透配合使用：STUN 负责探测 NAT 类型与外网映射地址，UPnP 在路由器上
// 显式开放入站端口，对称型/受限型 NAT 下外网也能主动连入，显著提升穿透成功率。

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// gateway SSDP 发现结果：SOAP 控制地址 + 服务类型
type gateway struct {
	controlUrl  string
	serviceType string
}

var upnpSearchTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"upnp:rootdevice",
}

// discoverUpnp 发现局域网 UPnP 网关并定位 WAN 连接控制地址，未发现返回 nil
func discoverUpnp(timeoutMs int) *gateway {
	for _, location := range ssdpSearch(timeoutMs) {
		g, err := parseDescription(location)
		if err != nil {
			// 该设备描述解析失败，尝试下一个
			continue
		}
		if g != nil {
			core.LogInfo(core.LogStun, "UPnP 网关发现: "+g.serviceType+" @ "+g.controlUrl)
			return g
		}
	}
	return nil
}

// upnpAddPortMapping 添加端口映射（外网端口 -> 内网客户端，租期 86400=1天），失败返回 false
func upnpAddPortMapping(g *gateway, protocol string, externalPort, internalPort int,
	internalClient, description string) bool {
	body := "<NewRemoteHost></NewRemoteHost>" +
		"<NewExternalPort>" + strconv.Itoa(externalPort) + "</NewExternalPort>" +
		"<NewProtocol>" + protocol + "</NewProtocol>" +
		"<NewInternalPort>" + strconv.Itoa(internalPort) + "</NewInternalPort>" +
		"<NewInternalClient>" + internalClient + "</NewInternalClient>" +
		"<NewEnabled>1</NewEnabled>" +
		"<NewPortMappingDescription>" + description + "</NewPortMappingDescription>" +
		"<NewLeaseDuration>86400</NewLeaseDuration>"
	if _, err := upnpSoap(g, "AddPortMapping", body); err != nil {
		core.LogWarn(core.LogStun, "UPnP AddPortMapping 失败: "+err.Error())
		return false
	}
	return true
}

// upnpDeletePortMapping 删除端口映射（停止任务时释放路由器映射）；
// 映射不存在或网关离线时静默忽略
func upnpDeletePortMapping(g *gateway, protocol string, externalPort int) {
	body := "<NewRemoteHost></NewRemoteHost>" +
		"<NewExternalPort>" + strconv.Itoa(externalPort) + "</NewExternalPort>" +
		"<NewProtocol>" + protocol + "</NewProtocol>"
	_, _ = upnpSoap(g, "DeletePortMapping", body)
}

// upnpExternalIp 查询路由器 WAN 口 IP，失败返回空串
func upnpExternalIp(g *gateway) string {
	resp, err := upnpSoap(g, "GetExternalIPAddress", "")
	if err != nil {
		return ""
	}
	s := strings.Index(resp, "<NewExternalIPAddress>")
	e := strings.Index(resp, "</NewExternalIPAddress>")
	if s >= 0 && e > s {
		return strings.TrimSpace(resp[s+len("<NewExternalIPAddress>"):e])
	}
	return ""
}

// ---------- SSDP 发现 ----------

// ssdpSearch SSDP M-SEARCH 发现：逐块合格网卡绑定发送发现包
// （Windows 多网卡/WSL/Hyper-V 环境下默认组播路由可能走虚拟网卡，路由器收不到发现包），
// 并持续收集响应直到超时（设备响应延迟在 MX 内随机，不能因单次超前提前退出）。
func ssdpSearch(timeoutMs int) []string {
	var locations []string
	seen := map[string]bool{}
	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	lc := net.ListenConfig{}
	ifaces := eligibleInterfaces()
	var sockets []*net.UDPConn
	for _, ni := range ifaces {
		ms, err := ssdpSocket(&lc, &ni)
		if err != nil {
			// 该网卡创建 socket 失败，跳过
			continue
		}
		sockets = append(sockets, ms)
	}
	if len(sockets) == 0 {
		ms, err := ssdpSocket(&lc, nil)
		if err == nil {
			sockets = append(sockets, ms)
		}
	}
	var names []string
	for _, ni := range ifaces {
		names = append(names, ni.Name)
	}
	core.LogInfo(core.LogStun, "UPnP SSDP 发现网卡: ["+strings.Join(names, ", ")+"]")
	for _, ms := range sockets {
		_ = ms.SetWriteDeadline(time.Now().Add(2 * time.Second))
		for round := 0; round < 2; round++ { // UDP 可能丢包，发两轮
			for _, st := range upnpSearchTargets {
				_, _ = ms.WriteToUDP([]byte(ssdpMsearch(st)), group)
			}
		}
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		for _, ms := range sockets {
			_ = ms.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, _, err := ms.ReadFromUDP(buf)
			if err != nil {
				// 该 socket 暂无响应（超时或 socket 关闭），继续等待其他 socket / 下一轮
				continue
			}
			collectSsdpLocation(buf[:n], &locations, seen)
		}
	}
	for _, ms := range sockets {
		_ = ms.Close()
	}
	return locations
}

// collectSsdpLocation 从 SSDP 响应中提取 LOCATION 描述地址（保序去重）
func collectSsdpLocation(data []byte, out *[]string, seen map[string]bool) {
	resp := string(data)
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) >= 9 && strings.EqualFold(line[:9], "LOCATION:") {
			loc := strings.TrimSpace(line[9:])
			if loc != "" && !seen[loc] {
				seen[loc] = true
				*out = append(*out, loc)
			}
		}
	}
}

func ssdpMsearch(st string) string {
	return "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: " + st + "\r\n\r\n"
}

// eligibleInterfaces 枚举可发送发现包的网卡：已启用、支持组播、有 IPv4 地址（排除环回）
func eligibleInterfaces() []net.Interface {
	var list []net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ni := range ifaces {
		if ni.Flags&net.FlagLoopback != 0 || ni.Flags&net.FlagUp == 0 || ni.Flags&net.FlagMulticast == 0 {
			continue
		}
		if ifaceIPv4(ni) != nil {
			list = append(list, ni)
		}
	}
	return list
}

// ifaceIPv4 取网卡首个 IPv4 单播地址
func ifaceIPv4(ni net.Interface) net.IP {
	addrs, err := ni.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
			return ipnet.IP.To4()
		}
	}
	return nil
}

// ssdpSocket SSDP 发现 socket：绑定到指定网卡的 IPv4 地址，确保发现包走正确的局域网
// （内核按源地址选路，绑定即指定出口网卡；Go 标准库无组播 TTL 设置入口（在 x/net/ipv4），
// SSDP 为链路本地范围组播，默认 TTL=1 足以直达同网段路由器，Java 的 TTL=4 属冗余保险，可接受差异）
func ssdpSocket(lc *net.ListenConfig, ni *net.Interface) (*net.UDPConn, error) {
	var local *net.UDPAddr
	if ni != nil {
		ip := ifaceIPv4(*ni)
		if ip == nil {
			return nil, fmt.Errorf("no ipv4")
		}
		local = &net.UDPAddr{IP: ip, Port: 0}
	} else {
		local = &net.UDPAddr{Port: 0}
	}
	pc, err := lc.ListenPacket(nil, "udp4", local.String())
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("not udp conn")
	}
	return uc, nil
}

// ---------- 设备描述解析 ----------

// xmlDevice 设备描述 XML 结构（root/device 可嵌套 deviceList，逐层收集 service）
type xmlDevice struct {
	Services []xmlService `xml:"serviceList>service"`
	Devices  []xmlDevice  `xml:"deviceList>device"`
}

type xmlService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type xmlRoot struct {
	Device xmlDevice `xml:"device"`
}

// parseDescription 拉取设备描述 XML，定位 WANIPConnection / WANPPPConnection 服务的控制地址；
// 未找到返回 nil
func parseDescription(location string) (*gateway, error) {
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var root xmlRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	for _, svc := range collectServices(root.Device) {
		if strings.Contains(svc.ServiceType, "WANIPConnection") || strings.Contains(svc.ServiceType, "WANPPPConnection") {
			control, err := resolveControlUrl(location, svc.ControlURL)
			if err != nil {
				return nil, err
			}
			return &gateway{controlUrl: control, serviceType: svc.ServiceType}, nil
		}
	}
	return nil, nil
}

// collectServices 按文档序（深度优先）展开设备树中的服务，等价 Java getElementsByTagName("service")
func collectServices(dev xmlDevice) []xmlService {
	var out []xmlService
	out = append(out, dev.Services...)
	for _, sub := range dev.Devices {
		out = append(out, collectServices(sub)...)
	}
	return out
}

// resolveControlUrl controlURL 可能为相对路径，按描述地址的 scheme/host/port 解析为绝对地址
func resolveControlUrl(location, control string) (string, error) {
	base, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	root, err := url.Parse(base.Scheme + "://" + base.Host)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(control)
	if err != nil {
		return "", err
	}
	return root.ResolveReference(ref).String(), nil
}

// ---------- SOAP 调用 ----------

// upnpSoap 发送 SOAP 请求，非 200 返回带 UPnP 错误码的 error
func upnpSoap(g *gateway, action, bodyInner string) (string, error) {
	env := "<?xml version=\"1.0\"?>\r\n" +
		"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
		"<s:Body><u:" + action + " xmlns:u=\"" + g.serviceType + "\">" +
		bodyInner + "</u:" + action + "></s:Body></s:Envelope>"
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest("POST", g.controlUrl, strings.NewReader(env))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", "\""+g.serviceType+"#"+action+"\"")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	body := string(data)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("UPnP %s 失败(HTTP %d): %s", action, resp.StatusCode, upnpExtractError(body))
	}
	return body, nil
}

var upnpErrPattern = regexp.MustCompile(`(?s)<errorCode>(\d+)</errorCode>\s*<errorDescription>([^<]*)</errorDescription>`)

// upnpExtractError 提取 UPnP SOAP 错误码与描述，便于日志定位（如 718=映射条目冲突）
func upnpExtractError(resp string) string {
	m := upnpErrPattern.FindStringSubmatch(resp)
	if m != nil {
		return "错误" + m[1] + "(" + strings.TrimSpace(m[2]) + ")"
	}
	return "响应非200"
}
