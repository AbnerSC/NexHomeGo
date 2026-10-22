package web

import (
	"runtime"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// 内存诊断服务（决策①：按 Go 特性重做）。
// 轻量周期采样本进程内存（runtime.MemStats + 进程 RSS），构建时间线环形缓冲，
// 并联动 op_log 做「内存跳变点 ↔ 日志事件」的时间线关联分析。
// 本页只反映本系统自身占用；宿主机整体内存由顶栏资源监控（/api/system/metrics）展示。
//
// 与 Java DiagService 的差异：
//   - 去掉 JVM 专有概念（Metaspace/CodeHeap/GC 分代/NMT 原生内存跟踪）；
//   - 堆/栈/GC/协程数改由 runtime.MemStats、runtime.NumGoroutine 提供；
//   - 进程 RSS 复用 sysinfo.go 的 /proc 读取，非 Linux 环境优雅降级。
//
// 保持不变的：采样间隔(10s)/环形缓冲容量(1080≈3h)/关联分析日志窗口(120s)/接口路径与响应结构骨架，
// 以及「内存跳变 ↔ op_log 事件」定位能力。diag.js 随之按新字段渲染。

const (
	diagIntervalSec  = 10
	diagCapacity     = 1080
	diagLogWindowSec = 120
)

var (
	diagMu     sync.Mutex
	diagHist   []*core.Row
	diagLatest *core.Row
)

// ProxyCacheProvider 由反向代理模块注入，返回 (条目数, 字节数)；未注入时计 0。
var ProxyCacheProvider func() (entries int, bytes int64)

// RegisterDiagRoutes 注册诊断接口。
func RegisterDiagRoutes() {
	Route("GET", "/api/diag/snapshot", func(c *Ctx) error {
		c.Ok(diagSnapshot())
		return nil
	})
	Route("GET", "/api/diag/analysis", func(c *Ctx) error {
		c.Ok(diagAnalysis(c.Query("metric")))
		return nil
	})
}

// InitDiag 启动周期采样（先立即采一次，保证进页面即有数据）。
func InitDiag() {
	diagSample()
	core.Every(diagIntervalSec, diagIntervalSec, diagSample)
	core.LogInfo(core.LogSys, "内存诊断采样已启动：间隔 10 秒，保留 1080 个样本")
}

// ---------- 采样 ----------

func diagSample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	rss := RSSBytes()

	var cacheN int
	var cacheMB float64 = -1
	if ProxyCacheProvider != nil {
		entries, bytes := ProxyCacheProvider()
		cacheN = entries
		cacheMB = bytesToMB(bytes)
	}

	now := time.Now()
	s := core.NewRow()
	s.Set("t", now.UnixMilli())
	s.Set("time", now.Format("2006-01-02 15:04:05"))
	s.Set("heap", bytesToMB(int64(ms.HeapAlloc)))
	s.Set("heapSys", bytesToMB(int64(ms.HeapSys)))
	s.Set("heapObj", int64(ms.HeapObjects))
	s.Set("stack", bytesToMB(int64(ms.StackInuse)))
	s.Set("sys", bytesToMB(int64(ms.Sys)))
	s.Set("gc", int64(ms.NumGC))
	s.Set("gcMs", int64(ms.PauseTotalNs/1e6))
	s.Set("thr", runtime.NumGoroutine())
	s.Set("rss", bytesToMB(rss))
	s.Set("cacheN", cacheN)
	s.Set("cacheMB", cacheMB)

	diagMu.Lock()
	diagLatest = s
	diagHist = append(diagHist, s)
	if len(diagHist) > diagCapacity {
		diagHist = diagHist[len(diagHist)-diagCapacity:]
	}
	diagMu.Unlock()
}

// ---------- 接口数据 ----------

func diagSnapshot() *core.Row {
	diagMu.Lock()
	hist := make([]*core.Row, len(diagHist))
	copy(hist, diagHist)
	latest := diagLatest
	diagMu.Unlock()
	if latest == nil {
		latest = core.NewRow()
	}
	out := core.NewRow()
	out.Set("intervalSec", diagIntervalSec)
	out.Set("capacity", diagCapacity)
	out.Set("count", len(hist))
	out.Set("latest", latest)
	out.Set("history", core.Rows(hist))
	out.Set("go", diagRuntimeInfo())
	return out
}

func diagRuntimeInfo() *core.Row {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m := core.NewRow()
	m.Set("version", runtime.Version())
	m.Set("numCpu", runtime.NumCPU())
	m.Set("goroutine", runtime.NumGoroutine())
	m.Set("uptimeSec", int64(time.Since(bootTime).Seconds()))
	m.Set("maxHeapMB", bytesToMB(int64(ms.HeapSys)))
	m.Set("proc", procEnabled())
	if lim := ContainerMemLimitBytes(); lim > 0 {
		m.Set("containerLimitMB", bytesToMB(lim))
	} else {
		m.Set("containerLimitMB", -1)
	}
	return m
}

// diagAnalysis 关联分析：定位时间线中的最大内存跳变，并取该时刻前后窗口的 op_log 事件。
func diagAnalysis(metric string) *core.Row {
	byHeap := metric == "heap"
	key := "rss"
	if byHeap {
		key = "heap"
	}
	diagMu.Lock()
	hist := make([]*core.Row, len(diagHist))
	copy(hist, diagHist)
	diagMu.Unlock()

	out := core.NewRow()
	metricName := "rss"
	metricLabel := "进程 RSS"
	if byHeap {
		metricName = "heap"
		metricLabel = "Go 堆"
	}
	out.Set("metric", metricName)
	out.Set("metricLabel", metricLabel)
	out.Set("count", len(hist))

	var jump *core.Row
	if len(hist) >= 2 {
		first := rowNum(hist[0], key)
		last := rowNum(hist[len(hist)-1], key)
		out.Set("firstMB", round1(first))
		out.Set("lastMB", round1(last))
		out.Set("growthMB", round1(last-first))
		var maxDelta float64
		maxIdx := -1
		for i := 1; i < len(hist); i++ {
			d := rowNum(hist[i], key) - rowNum(hist[i-1], key)
			if d > maxDelta {
				maxDelta = d
				maxIdx = i
			}
		}
		if maxIdx > 0 && maxDelta > 0 {
			jump = core.NewRow()
			jump.Set("time", hist[maxIdx].Get("time"))
			jump.Set("ts", hist[maxIdx].Get("t"))
			jump.Set("fromMB", round1(rowNum(hist[maxIdx-1], key)))
			jump.Set("toMB", round1(rowNum(hist[maxIdx], key)))
			jump.Set("deltaMB", round1(maxDelta))
		}
	}
	out.Set("jump", jump)

	start := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05")
	if len(hist) > 0 {
		start = str(hist[0].Get("time"))
	}
	density, _ := core.Query(
		"SELECT substr(time,1,16) AS minute, COUNT(*) AS c FROM op_log "+
			"WHERE time>=? GROUP BY minute ORDER BY minute", start)
	out.Set("density", core.Rows(density))

	if jump != nil {
		ts := toInt64(jump.Get("ts"))
		from := time.UnixMilli(ts - int64(diagLogWindowSec)*1000).Format("2006-01-02 15:04:05")
		to := time.UnixMilli(ts + int64(diagLogWindowSec)*1000).Format("2006-01-02 15:04:05")
		logsAround, _ := core.Query(
			"SELECT time, module, level, message FROM op_log "+
				"WHERE time BETWEEN ? AND ? ORDER BY time LIMIT 300", from, to)
		out.Set("logsAround", core.Rows(logsAround))
	} else {
		out.Set("logsAround", core.NewRowList())
	}

	notable, _ := core.Query(
		"SELECT time, module, message FROM op_log WHERE " +
			"message LIKE '%缓存已加载%' OR message LIKE '%启动完成%' " +
			"OR message LIKE '%即将重启%' OR message LIKE '%重启并应用%' " +
			"OR message LIKE '%监听已启动%' ORDER BY id DESC LIMIT 50")
	out.Set("notable", core.Rows(notable))
	return out
}

func rowNum(r *core.Row, k string) float64 {
	if r == nil {
		return 0
	}
	switch v := r.Get(k).(type) {
	case int64:
		return float64(v)
	case float64:
		return v
	default:
		return 0
	}
}
