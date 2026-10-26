package proxy

import (
	"embed"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"NexHomeGo/internal/core"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// 客户端 IP 归属地解析（代理访问记录用）：基于 ip2region 的 xdb 库文件离线解析，无在线接口依赖。
// 库文件只随二进制内置（db/ 下打包），不支持数据目录外置替换；v4 / v6 两个库独立可选。
//
// 内存策略：不整库进内存、也不落盘。整库缓冲的代价是 v4 约 10.6 MB、v6 约 35.6 MB 常驻堆，
// 会让进程 RSS 从约 15 MB 涨到 60 MB 以上，而归属地只是访问记录的附属信息。
// 改为「向量索引常驻 + 正文按需从内置资源读」：只把 512 KB 向量索引
// （VectorIndexRows*Cols*Size）读进堆，检索时的少量字节直接从二进制内的 embed 数据读取
// （embed 数据是只读 .rodata 映射页，按需分页，不进 Go 堆，也不需要复制到数据目录）。
// 设计要点与 Java 一致：同步即时返回（索引内存检索 + 结果缓存）、库缺失降级恒返回 null 不影响转发、
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

// geoLib 单侧库：常驻向量索引（512 KB），正文按需从内置资源读取，不落盘。
// 一个实例持有一个只读句柄，Searcher 内部会 Seek，必须串行检索。
type geoLib struct {
	searcher *xdb.Searcher
	mu       sync.Mutex
}

var (
	geoMu     sync.RWMutex
	geoV4     *geoLib // nil = 该侧不可用
	geoV6     *geoLib
	geoCache  = map[string]*Region{} // IP -> 归属地；nil 值 = 检索无记录（哨兵）
	geoCached int
)

// geoLoad 由代理启动流程调用：打开 xdb 库（失败降级，不抛异常）
func geoLoad() {
	geoV4 = geoLoadSide(true)
	geoV6 = geoLoadSide(false)
	if geoV4 == nil && geoV6 == nil {
		core.LogWarn(core.LogProxy, "内置 IP 归属地库不可用（v4/v6 均未打开），归属地留空")
		return
	}
	core.LogInfo(core.LogProxy, "IP 归属地库已就绪（向量索引常驻 + 正文按需读内置资源）: v4="+
		boolWord(geoV4 != nil)+", v6="+boolWord(geoV6 != nil))
}

func geoClose() {
	geoMu.Lock()
	v4, v6 := geoV4, geoV6
	geoV4, geoV6 = nil, nil
	geoMu.Unlock()
	closeGeoLib(v4)
	closeGeoLib(v6)
}

func closeGeoLib(l *geoLib) {
	if l != nil && l.searcher != nil {
		l.searcher.Close()
	}
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// embedReadSeekCloser 把内置资源句柄适配成 xdb 需要的 io.ReadSeekCloser：
// embed.FS 的 Open 结果本身实现 Seek，只是 fs.File 接口没声明。
type embedReadSeekCloser struct {
	io.ReadSeeker
	io.Closer
}

// geoLoadSide 加载单侧库：只把向量索引读进内存，正文后续从同一个内置句柄按需 Seek+Read。
// 不落盘、不整库进堆；任何一步失败都返回 nil（该侧跳过），不影响代理转发。
func geoLoadSide(v4 bool) *geoLib {
	tag := "v6"
	builtin := "db/ip2region_v6.xdb"
	version := xdb.IPv6
	if v4 {
		tag = "v4"
		builtin = "db/ip2region_v4.xdb"
		version = xdb.IPv4
	}
	f, err := geoDB.Open(builtin)
	if err != nil {
		core.LogWarn(core.LogProxy, tag+" 内置归属地库缺失 "+builtin+"，"+tag+" 归属地留空: "+err.Error())
		return nil
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		_ = f.Close()
		core.LogWarn(core.LogProxy, tag+" 内置归属地库不支持随机读取，"+tag+" 归属地留空")
		return nil
	}
	index, err := xdb.LoadVectorIndex(rs)
	if err != nil {
		_ = f.Close()
		core.LogWarn(core.LogProxy, tag+" 归属地库向量索引加载失败，"+tag+" 归属地留空: "+err.Error())
		return nil
	}
	s := xdb.INewSearcher(version, embedReadSeekCloser{rs, f}, index, nil)
	core.LogInfo(core.LogProxy, fmt.Sprintf("%s 归属地库已就绪：索引 %d KB，正文按需读内置资源（不落盘）",
		tag, len(index)/1024))
	return &geoLib{searcher: s}
}

// geoRegionOf 查询 IP 归属地（同步即时返回）：内网即时判定；其余命中缓存直接返回；
// 未命中做一次本地 xdb 检索并缓存。库不可用或无记录时返回 nil。
func geoRegionOf(ip string) *Region {
	if isLan(ip) {
		return regionLAN
	}
	key := strings.TrimSpace(ip)
	if key == "" {
		return nil
	}
	geoMu.RLock()
	if r, ok := geoCache[key]; ok {
		geoMu.RUnlock()
		return r // nil 哨兵 = 检索无记录
	}
	v4, v6 := geoV4, geoV6
	geoMu.RUnlock()

	if v4 == nil && v6 == nil {
		return nil
	}
	r := geoSearch(key, v4, v6)

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
func geoSearch(ip string, v4, v6 *geoLib) *Region {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil // 非法地址按无记录处理
	}
	// 注意：net.IP 是定义类型 type IP []byte，直接传给 Search 会落到它的 default 分支
	// （报 invalid ip value type），必须显式转成 []byte。
	lib := v4
	ipBytes := []byte(parsed.To4())
	if ipBytes == nil {
		lib, ipBytes = v6, []byte(parsed.To16())
	}
	if lib == nil || lib.searcher == nil || ipBytes == nil {
		return nil // 该侧库未加载
	}
	// 文件模式检索器内部 Seek，非并发安全：同侧串行检索（结果缓存覆盖绝大多数请求）
	lib.mu.Lock()
	region, err := lib.searcher.Search(ipBytes)
	lib.mu.Unlock()
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
