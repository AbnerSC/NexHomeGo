package proxy

import (
	"embed"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"NexHomeGo/internal/core"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// 客户端 IP 归属地解析（代理访问记录用）：基于 ip2region 的 xdb 库文件离线解析，无在线接口依赖。
// 库文件加载优先级：数据目录外部文件（data/ip2region_v4.xdb、data/ip2region_v6.xdb，便于自行更新库）
// > 程序内置资源（db/ 下随二进制打包）；v4 / v6 两个库独立可选。
// Go 侧统一采用整库内存缓冲（等价 Java BufferCache，xdb 官方标注该绑定仅 BufferCache 并发只读安全）。
// 设计要点与 Java 一致：同步即时返回（内存检索微秒级 + 结果缓存）、库缺失降级恒返回 null 不影响转发、
// 地区口径：国内记录到省/市，外国仅国家，内网本机判定「局域网」。

type Region struct {
	Country  string
	Province string
	City     string
}

var regionLAN = &Region{Country: "局域网"}

// geoCacheLimit 缓存容量上限：达到上限后仅检索不缓存，防止异常流量撑爆内存
const geoCacheLimit = 5000

//go:embed db/ip2region_v4.xdb db/ip2region_v6.xdb
var geoDB embed.FS

var (
	geoMu     sync.RWMutex
	geoBuffV4 []byte // 整库缓冲；nil = 该侧不可用
	geoBuffV6 []byte
	geoCache  = map[string]*Region{} // IP -> 归属地；nil 值 = 检索无记录（哨兵）
	geoCached int
)

// geoLoad 由代理启动流程调用：加载 xdb 库（失败降级，不抛异常）
func geoLoad() {
	geoBuffV4 = geoLoadSide(true)
	geoBuffV6 = geoLoadSide(false)
	if geoBuffV4 == nil && geoBuffV6 == nil {
		core.LogWarn(core.LogProxy, "未加载到任何 IP 归属地库文件（data/ip2region_v4.xdb 或 v6），归属地留空")
		return
	}
	core.LogInfo(core.LogProxy, "IP 归属地库已加载: v4="+boolWord(geoBuffV4 != nil)+", v6="+boolWord(geoBuffV6 != nil))
}

func geoClose() {
	geoMu.Lock()
	defer geoMu.Unlock()
	geoBuffV4, geoBuffV6 = nil, nil
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// geoLoadSide 加载单侧库：优先数据目录外部文件（可自行更新库），缺失时回退内置资源，均不可用返回 nil（该侧跳过）。
func geoLoadSide(v4 bool) []byte {
	tag := "v6"
	name := "ip2region_v6.xdb"
	builtin := "db/ip2region_v6.xdb"
	if v4 {
		tag = "v4"
		name = "ip2region_v4.xdb"
		builtin = "db/ip2region_v4.xdb"
	}
	extPath := core.DataDir() + "/" + name
	if b, err := os.ReadFile(extPath); err == nil {
		core.LogInfo(core.LogProxy, tag+" IP 归属地库已加载: "+extPath)
		return b
	}
	b, err := xdb.LoadContentFromFS(geoDB, builtin)
	if err != nil {
		core.LogWarn(core.LogProxy, tag+" IP 归属地库既无外部文件也无内置资源 "+builtin+"，"+tag+" 归属地留空")
		return nil
	}
	core.LogInfo(core.LogProxy, tag+" IP 归属地库已加载: classpath:"+builtin)
	return b
}

// geoRegionOf 查询 IP 归属地（同步即时返回）：内网即时判定；其余命中缓存直接返回；
// 未命中做一次本地 xdb 检索并缓存。库不可用或无记录时返回 nil。
func geoRegionOf(ip string) *Region {
	if isLan(ip) {
		return regionLAN
	}
	if ip == "" || strings.TrimSpace(ip) == "" {
		return nil
	}
	geoMu.RLock()
	buffV4, buffV6 := geoBuffV4, geoBuffV6
	key := strings.TrimSpace(ip)
	if r, ok := geoCache[key]; ok {
		geoMu.RUnlock()
		return r // nil 哨兵 = 检索无记录
	}
	geoMu.RUnlock()

	if buffV4 == nil && buffV6 == nil {
		return nil
	}
	r := geoSearch(key, buffV4, buffV6)

	geoMu.Lock()
	if geoCached < geoCacheLimit {
		if _, dup := geoCache[key]; !dup {
			geoCache[key] = r
			geoCached++
		}
	}
	geoMu.Unlock()
	return r
}

// geoSearch xdb 检索并归一化口径：国内保留省/市，外国仅国家；非法地址/无记录返回 nil
func geoSearch(ip string, buffV4, buffV6 []byte) *Region {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil // 非法地址按无记录处理
	}
	var version *xdb.Version
	var buff []byte
	if parsed.To4() != nil {
		version, buff = xdb.IPv4, buffV4
	} else {
		version, buff = xdb.IPv6, buffV6
	}
	if buff == nil {
		return nil // 该侧库未加载
	}
	// buffer 模式检索器仅持有只读缓冲引用，每次新建结构体成本可忽略（官方绑定非并发安全）
	s, err := xdb.NewWithBuffer(version, buff)
	if err != nil {
		return nil
	}
	region, err := s.Search(ip)
	if err != nil || strings.TrimSpace(region) == "" {
		return nil
	}
	parts := strings.Split(region, "|")
	country := cleanPart(parts, 0)
	if country == "" {
		return nil
	}
	if country == "中国" {
		return &Region{Country: "中国", Province: cleanPart(parts, 2), City: cleanPart(parts, 3)}
	}
	return &Region{Country: country}
}

// cleanPart 取分段值并过滤空串与 "0" 占位符
func cleanPart(parts []string, idx int) string {
	if idx >= len(parts) {
		return ""
	}
	v := strings.TrimSpace(parts[idx])
	if v == "" || v == "0" {
		return ""
	}
	return v
}

// isLan 内网/非公网判定：IPv4 私有段、回环、链路本地、CGNAT；IPv6 回环、链路本地、ULA
func isLan(ip string) bool {
	if ip == "" {
		return true
	}
	v := ip
	if strings.HasPrefix(v, "::ffff:") && strings.ContainsRune(v[7:], '.') {
		v = v[7:] // IPv4-mapped IPv6
	}
	if strings.ContainsRune(v, ':') {
		lower := strings.ToLower(v)
		return lower == "::1" || strings.HasPrefix(lower, "fe80:") ||
			strings.HasPrefix(lower, "fc") || strings.HasPrefix(lower, "fd")
	}
	p := strings.Split(v, ".")
	if len(p) != 4 {
		return true // 非法格式不检索
	}
	a, err1 := strconv.Atoi(p[0])
	b, err2 := strconv.Atoi(p[1])
	if err1 != nil || err2 != nil {
		return true
	}
	return a == 10 || a == 127 || a == 192 && b == 168 ||
		a == 172 && b >= 16 && b <= 31 ||
		a == 169 && b == 254 ||
		a == 100 && b >= 64 && b <= 127
}

func readFileIfExists(path string) ([]byte, error) {
	return os.ReadFile(path)
}
