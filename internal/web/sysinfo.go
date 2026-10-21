package web

import (
	"bufio"
	"os"
	"runtime"
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
	cpuMu  sync.Mutex
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
func RSSBytes() int64 {
	b, err := os.ReadFile(procBase + "/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
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

// ---------- 容器内存上限（cgroup v2 / v1） ----------

// ContainerMemLimitBytes 容器可用内存上限（字节）；无限制或不可读返回 -1。
// 优先 cgroup v2（/sys/fs/cgroup/memory.max），回退 v1（memory.limit_in_bytes，超大值视为无限制）。
func ContainerMemLimitBytes() int64 {
	if v, ok := readMemLimitFile("/sys/fs/cgroup/memory.max"); ok {
		return v
	}
	if v, ok := readMemLimitFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); ok {
		// v1 无限制时给出接近 int64 上限的天文数字，超过物理内存即视为无限制。
		if v > 1<<62 {
			return -1
		}
		return v
	}
	return -1
}

func readMemLimitFile(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0, false
	}
	v, e := strconv.ParseInt(s, 10, 64)
	if e != nil || v <= 0 {
		return 0, false
	}
	return v, true
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
