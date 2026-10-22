package web

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// Go 原生系统信息采集：替代 Java 的 OperatingSystemMXBean / Runtime 内存读数。
// 生产目标为 Linux 容器，优先读 /proc；本地非 Linux 环境优雅降级（返回 -1 / 0）。
// 决策①：内存诊断页按 Go 特性重做，这里的采集同时服务于 /api/system/metrics 与 /api/diag/*。

var procBase = "/proc"

// ---------- CPU ----------

type cpuSnap struct {
	total uint64
	idle  uint64
	at    time.Time
}

var (
	cpuMu   sync.Mutex
	cpuPrev *cpuSnap
)

// CPUPct 返回整体 CPU 使用率百分比（保留 1 位小数）。基于 /proc/stat 相邻两次采样的增量；
// 首次采样或无法读取时返回 -1（与 Java「未就绪返回 -1」语义一致）。
func CPUPct() float64 {
	cur, ok := readCPUStat()
	if !ok {
		return -1
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	prev := cpuPrev
	cpuPrev = cur
	if prev == nil {
		return -1
	}
	dTotal := float64(cur.total - prev.total)
	dIdle := float64(cur.idle - prev.idle)
	if cur.total <= prev.total || dTotal <= 0 {
		return -1
	}
	load := (dTotal - dIdle) / dTotal * 100.0
	if load < 0 {
		load = 0
	}
	return round1(load)
}

func readCPUStat() (*cpuSnap, bool) {
	b, err := os.ReadFile(procBase + "/stat")
	if err != nil {
		return nil, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)[1:]
		if len(f) < 5 {
			return nil, false
		}
		var total, idle uint64
		for i, s := range f {
			v, e := strconv.ParseUint(s, 10, 64)
			if e != nil {
				continue
			}
			total += v
			if i == 3 || i == 4 { // idle + iowait
				idle += v
			}
		}
		return &cpuSnap{total: total, idle: idle, at: time.Now()}, true
	}
	return nil, false
}

// ---------- 物理内存 / Swap ----------

type memInfo struct {
	totalKB     uint64
	availableKB uint64
	swapTotalKB uint64
	swapFreeKB  uint64
}

func readMemInfo() (memInfo, bool) {
	var m memInfo
	b, err := os.ReadFile(procBase + "/meminfo")
	if err != nil {
		return m, false
	}
	seen := false
	for _, line := range strings.Split(string(b), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		rest := strings.TrimSpace(line[colon+1:])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		kb, e := strconv.ParseUint(fields[0], 10, 64)
		if e != nil {
			continue
		}
		switch key {
		case "MemTotal":
			m.totalKB, seen = kb, true
		case "MemAvailable":
			m.availableKB = kb
		case "SwapTotal":
			m.swapTotalKB = kb
		case "SwapFree":
			m.swapFreeKB = kb
		}
	}
	return m, seen
}

// ---------- 进程 RSS ----------

// RSSBytes 进程常驻物理内存（字节）。优先 /proc/self/status 的 VmRSS；不可用返回 -1。
func RSSBytes() int64 { return procStatusKB("VmRSS:") }

// RSSPeakBytes 进程 RSS 峰值（VmHWM，内核单调记录、不回落，重启后归零）；不可用返回 -1。
// 与 RSS 一起对照：若峰值远小于容器 cgroup 记账的历史高位，说明两者不是同一个进程。
func RSSPeakBytes() int64 { return procStatusKB("VmHWM:") }

// procStatusKB 从 /proc/self/status 取以 kB 计的单值字段（如 VmRSS/VmHWM），转为字节。
func procStatusKB(field string) int64 {
	b, err := os.ReadFile(procBase + "/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, field) {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 2 {
				if kb, e := strconv.ParseInt(f[1], 10, 64); e == nil {
					return kb * 1024
				}
			}
		}
	}
	return -1
}

// ---------- 容器内存上限 / 用量（cgroup v2 / v1） ----------

// cgroupRef 解析 /proc/self/cgroup，返回 (版本, 本进程所属 memory 层级路径)。
// v2 行形如 "0::/system.slice/docker-<id>.scope"；v1 行形如 "12:memory:/docker/<id>"。
// 必要性：cgroup v1 下 Docker 默认 cgroupns=host，容器内 /sys/fs/cgroup 仍是宿主机视图，
// 固定路径 /sys/fs/cgroup/memory/memory.limit_in_bytes 读到的是根/上层 cgroup 的限制
// （数字与容器无关），必须按本进程路径拼出容器自己的限制文件。
func cgroupRef() (ver int, path string) {
	b, err := os.ReadFile(procBase + "/self/cgroup")
	if err != nil {
		return 0, "/"
	}
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "0::") { // unified 层级优先
			return 2, orRoot(strings.TrimPrefix(s, "0::"))
		}
		if f := strings.SplitN(s, ":", 3); len(f) == 3 && f[1] == "memory" {
			ver, path = 1, f[2]
		}
	}
	return ver, orRoot(path)
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// ContainerCgroupPath 本进程 cgroup 的可读描述（诊断页自证身份用）；不可读返回 ""。
func ContainerCgroupPath() string {
	ver, path := cgroupRef()
	if ver == 0 {
		return ""
	}
	return fmt.Sprintf("v%d %s", ver, path)
}

// HostName 本机主机名（容器内即容器 ID 短串）；不可读返回 "-"。
// 与 PID 一起用于区分「页面到底由哪个进程应答」。
func HostName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "-"
}

// containerCgroupFile 拼出本进程 cgroup 下某文件的绝对路径（v2/v1 文件名不同）。
func containerCgroupFile(ver int, path, v2Name, v1Name string) string {
	if ver == 2 {
		return filepath.Join("/sys/fs/cgroup", path, v2Name)
	}
	return filepath.Join("/sys/fs/cgroup/memory", path, v1Name)
}

// ContainerMemLimitBytes 容器可用内存上限（字节）；无限制或不可读返回 -1。
func ContainerMemLimitBytes() int64 {
	if ver, path := cgroupRef(); ver != 0 {
		if v, ok := readCgroupInt(containerCgroupFile(ver, path, "memory.max", "memory.limit_in_bytes")); ok {
			return v
		}
		return -1
	}
	// /proc/self/cgroup 不可读：退回固定路径猜测（cgroupns 私有时恰好指向容器自身层级）。
	if v, ok := readCgroupInt("/sys/fs/cgroup/memory.max"); ok {
		return v
	}
	if v, ok := readCgroupInt("/sys/fs/cgroup/memory/memory.limit_in_bytes"); ok {
		return v
	}
	return -1
}

// ContainerMemUsageBytes 容器 cgroup 当前内存记账值（字节，含可回收 page cache）；
// 与 docker stats 的 MEM USAGE 同口径，可与进程 RSS 对照。不可读返回 -1。
func ContainerMemUsageBytes() int64 {
	if ver, path := cgroupRef(); ver != 0 {
		if v, ok := readCgroupInt(containerCgroupFile(ver, path, "memory.current", "memory.usage_in_bytes")); ok {
			return v
		}
		return -1
	}
	if v, ok := readCgroupInt("/sys/fs/cgroup/memory.current"); ok {
		return v
	}
	if v, ok := readCgroupInt("/sys/fs/cgroup/memory/memory.usage_in_bytes"); ok {
		return v
	}
	return -1
}

// readCgroupInt 读取单值 cgroup 文件；空、"max"、解析失败或非正值返回 false。
// cgroup v1 的「无限制」是接近 int64 上限的天文数字，一并按不可用处理。
func readCgroupInt(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0, false
	}
	v, e := strconv.ParseInt(s, 10, 64)
	if e != nil || v <= 0 || v > 1<<62 {
		return 0, false
	}
	return v, true
}

// ---------- 按容器上限约束 Go 运行时 ----------

// applyContainerMemoryLimit 启动时让 Go 运行时尊重容器内存上限：
// 未显式设置 GOMEMLIMIT（环境变量）且能读到 cgroup 上限时，把软内存上限设为 cgroup 上限的 75%，
// 促使 GC 在接近容器硬限前提前收缩。否则一旦堆涨过 mem_limit，内核会直接 OOM kill，进程无任何日志。
// 若代码/环境已给出更严格的软上限，则不放松。
func applyContainerMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return // 已由环境变量指定，尊重用户配置
	}
	lim := ContainerMemLimitBytes()
	if lim <= 0 {
		return // 无限制或不可读，保持 Go 默认行为
	}
	target := lim / 4 * 3
	if target < 64<<20 {
		target = 64 << 20 // 过小的上限会导致 GC 抖动，设下限 64 MB
	}
	if cur := debug.SetMemoryLimit(-1); cur < target {
		return // 已有更严格的软上限，不放松
	}
	debug.SetMemoryLimit(target)
	core.LogInfo(core.LogSys, fmt.Sprintf(
		"已按容器内存上限启用 Go 软内存限制: %.0f MB（cgroup 上限 %.0f MB，可用 GOMEMLIMIT 环境变量覆盖）",
		bytesToMB(target), bytesToMB(lim)))
}

// ---------- 操作系统展示名（缓存） ----------

var (
	osOnce   sync.Once
	osName   string
	osArch   string
	osPretty string
)

// OSDisplay Linux 优先 /etc/os-release 的 PRETTY_NAME，否则回退 "os 名 arch"（与 Java detectOsDisplay 一致）。
func OSDisplay() string {
	osOnce.Do(func() {
		osName = runtime.GOOS
		osArch = runtime.GOARCH
		if osName != "linux" {
			return
		}
		f, err := os.Open("/etc/os-release")
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			s := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(s, "PRETTY_NAME=") {
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(s, "PRETTY_NAME="))
			if len(name) >= 2 && (name[0] == '"' || name[0] == '\'') && name[len(name)-1] == name[0] {
				name = name[1 : len(name)-1]
			}
			if name = strings.TrimSpace(name); name != "" {
				osPretty = name
			}
			return
		}
	})
	if osPretty != "" {
		return osPretty
	}
	return osName + " " + osArch
}

// ---------- 私有网判定（访问来源识别） ----------

// IsPrivateSource 环回/私网/链路本地/组播及 CGNAT(100.64.0.0/10) 视为内网，其余公网。
func IsPrivateSource(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	if strings.HasPrefix(ip, "127.") || ip == "::1" || strings.HasPrefix(ip, "localhost") {
		return true
	}
	// IPv6 链路本地 fe80::/10、ULA fc00::/7
	if strings.Contains(ip, ":") {
		l := strings.ToLower(ip)
		return strings.HasPrefix(l, "fe80:") || strings.HasPrefix(l, "fc") || strings.HasPrefix(l, "fd")
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	a, _ := strconv.Atoi(parts[0])
	b, _ := strconv.Atoi(parts[1])
	switch a {
	case 10:
		return true
	case 172:
		return b >= 16 && b <= 31
	case 192:
		return b == 168
	case 169:
		return b == 254
	case 100:
		return b >= 64 && b <= 127 // CGNAT
	case 224, 239, 255:
		return true // 组播/保留
	}
	return false
}

// ---------- 数值工具 ----------

func round1(v float64) float64 { return float64(int64(v*10+sign(v)*0.5)) / 10 }

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}

func bytesToMB(b int64) float64 {
	if b < 0 {
		return -1
	}
	return round1(float64(b) / 104857.6)
}

func kbToMB(kb uint64) float64 { return round1(float64(kb) / 1024.0) }

// MemTotalMB / MemUsedMB：供 /api/system/metrics（容器内以 /proc/meminfo 为准）。
func memMetrics() (cores int, cpu float64, memTotalMB, memUsedMB, swapTotalMB, swapUsedMB float64) {
	cores = runtime.NumCPU()
	cpu = CPUPct()
	m, ok := readMemInfo()
	if ok {
		usedKB := uint64(0)
		if m.totalKB >= m.availableKB {
			usedKB = m.totalKB - m.availableKB
		}
		memTotalMB = kbToMB(m.totalKB)
		memUsedMB = kbToMB(usedKB)
		swapUsed := uint64(0)
		if m.swapTotalKB >= m.swapFreeKB {
			swapUsed = m.swapTotalKB - m.swapFreeKB
		}
		swapTotalMB = kbToMB(m.swapTotalKB)
		swapUsedMB = kbToMB(swapUsed)
	} else {
		memTotalMB, memUsedMB, swapTotalMB, swapUsedMB = -1, -1, -1, -1
	}
	return
}

// procEnabled 判断当前是否可读 /proc（用于诊断页在本地开发环境标注数据源）。
func procEnabled() bool {
	if _, err := os.Stat(procBase); err != nil {
		return false
	}
	_ = core.Version // 保持 core 依赖引用（诊断与版本联动展示）
	return true
}
