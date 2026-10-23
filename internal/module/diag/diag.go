package diag

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// 内存诊断模块（按 Go 特性重做，独立成模块）。
// 只做两件事：
//  1. 当前实时内存使用情况（本进程 Go 运行时 + 进程 RSS，请求时现采，不依赖采样周期）；
//  2. 内存时间线——最近 24 小时曲线（每 60 秒采样入库，页面只取 24 小时窗口）。
//
// 数据落库（diag_memory 表，见 core/schema.sql），保留 7 天后由每分钟一次的清理任务删除，
// 因此进程重启不会丢失时间线。宿主机整体资源由顶栏 /api/system/metrics 展示，本页只反映本系统自身占用。

const (
	intervalSec   = 60 // 采样间隔（秒）
	windowHours   = 24 // 时间线展示窗口（小时）
	retentionDays = 7  // 数据保留天数（入库后超过即清理）
)

// RegisterRoutes 注册内存诊断接口。
func RegisterRoutes() {
	web.Route("GET", "/api/diag/memory", func(c *web.Ctx) error {
		c.Ok(snapshot())
		return nil
	})
}

// Init 启动周期采样：立即采一次保证进页面即有数据，之后每 60 秒入库；
// 每小时清理超过 7 天的历史样本（另在启动时先清一次）。
func Init() {
	migrateUnitScale()
	prune()
	sample()
	core.Every(intervalSec, intervalSec, sample)
	core.Every(60, 3600, prune)
	core.LogInfo(core.LogSys, "内存诊断采样已启动：每 60 秒入库，保留 7 天（页面展示最近 24 小时）")
}

// ---------- 采样与清理 ----------

// memSample 一次采样的原始读数（内存均以字节计，-1 表示不可读）。
type memSample struct {
	at      time.Time
	rss     int64
	heap    int64
	heapSys int64
	heapObj int64
	stack   int64
	sys     int64
	thr     int64
	gc      int64
	gcMs    int64
}

// readMem 读取当前进程内存（实时值；时间线采样与接口实时区共用同一口径）。
func readMem() memSample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return memSample{
		at:      time.Now(),
		rss:     web.RSSBytes(),
		heap:    int64(ms.HeapAlloc),
		heapSys: int64(ms.HeapSys),
		heapObj: int64(ms.HeapObjects),
		stack:   int64(ms.StackInuse),
		sys:     int64(ms.Sys),
		thr:     int64(runtime.NumGoroutine()),
		gc:      int64(ms.NumGC),
		gcMs:    int64(ms.PauseTotalNs / 1e6),
	}
}

// unitFixKey app_config 中的口径修复标记（见 migrateUnitScale）。
const unitFixKey = "diag.memUnitFix"

// migrateUnitScale 一次性清理「旧口径」历史样本：
// 早期版本 bytesToMB 用 104857.6 作除数（正确的 1 MB = 1048576 字节的 1/10），
// 使所有入库字节数被放大 10 倍再显示；这些样本与修复后的样本混绘会出现 10 倍断层，
// 且单位错值无法反查真值精度，故首次升级时清空一次，由新采样重建时间线。
func migrateUnitScale() {
	if v, _ := core.GetConfig(unitFixKey); v == "2" {
		return
	}
	n, err := core.Update("DELETE FROM diag_memory")
	if err != nil {
		core.LogError(core.LogSys, "内存诊断旧口径样本清理失败: "+err.Error())
		return
	}
	if err := core.SetConfig(unitFixKey, "2"); err != nil {
		core.LogError(core.LogSys, "内存诊断口径标记写入失败: "+err.Error())
		return
	}
	core.LogInfo(core.LogSys, fmt.Sprintf("内存诊断 MB 口径已修正为 1 MB = 1048576 字节，清理旧口径样本 %d 条", n))
}

// sample 采集一次并入库。
func sample() {
	s := readMem()
	if _, err := core.Insert(`INSERT INTO diag_memory(ts, time, rss, heap, heap_sys, heap_obj, stack, sys, thr, gc, gc_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		s.at.UnixMilli(), s.at.Format("2006-01-02 15:04:05"),
		s.rss, s.heap, s.heapSys, s.heapObj, s.stack, s.sys, s.thr, s.gc, s.gcMs); err != nil {
		core.LogError(core.LogSys, "内存诊断采样入库失败: "+err.Error())
	}
}

// prune 删除超过保留期的历史样本（7 天前的数据不再需要）。
func prune() {
	cutoff := time.Now().Add(-retentionDays * 24 * time.Hour).UnixMilli()
	n, err := core.Update("DELETE FROM diag_memory WHERE ts < ?", cutoff)
	if err != nil {
		core.LogError(core.LogSys, "内存诊断过期数据清理失败: "+err.Error())
		return
	}
	if n > 0 {
		core.LogInfo(core.LogSys, fmt.Sprintf("内存诊断数据已清理：删除 %d 条超过 %d 天的样本", n, retentionDays))
	}
}

// ---------- 接口数据 ----------

// snapshot 返回实时内存 + 最近 24 小时时间线。
func snapshot() *core.Row {
	live := readMem()

	hist := core.NewRowList()
	from := time.Now().Add(-windowHours * time.Hour).UnixMilli()
	rows, err := core.Query(`SELECT ts, time, rss, heap, heap_sys, heap_obj, stack, sys, thr, gc, gc_ms
		FROM diag_memory WHERE ts >= ? ORDER BY ts`, from)
	if err != nil {
		core.LogError(core.LogSys, "读取内存诊断时间线失败: "+err.Error())
	}
	for _, r := range rows {
		hist.Append(core.NewRow().
			Set("t", rowInt64(r, "ts")).
			Set("time", rowStr(r, "time")).
			Set("rss", bytesToMB(rowInt64(r, "rss"))).
			Set("heap", bytesToMB(rowInt64(r, "heap"))).
			Set("heapSys", bytesToMB(rowInt64(r, "heap_sys"))).
			Set("heapObj", rowInt64(r, "heap_obj")).
			Set("stack", bytesToMB(rowInt64(r, "stack"))).
			Set("sys", bytesToMB(rowInt64(r, "sys"))).
			Set("thr", rowInt64(r, "thr")).
			Set("gc", rowInt64(r, "gc")).
			Set("gcMs", rowInt64(r, "gc_ms")))
	}

	out := core.NewRow()
	out.Set("intervalSec", intervalSec)
	out.Set("windowHours", windowHours)
	out.Set("retentionDays", retentionDays)
	out.Set("count", hist.Len())
	out.Set("latest", liveRow(live))
	out.Set("history", hist)
	out.Set("runtime", runtimeInfo())
	return out
}

// liveRow 实时读数 -> 响应行（与时间线样本同字段，前端可复用同一套渲染）。
func liveRow(s memSample) *core.Row {
	r := core.NewRow()
	r.Set("t", s.at.UnixMilli())
	r.Set("time", s.at.Format("2006-01-02 15:04:05"))
	r.Set("rss", bytesToMB(s.rss))
	r.Set("heap", bytesToMB(s.heap))
	r.Set("heapSys", bytesToMB(s.heapSys))
	r.Set("heapObj", s.heapObj)
	r.Set("stack", bytesToMB(s.stack))
	r.Set("sys", bytesToMB(s.sys))
	r.Set("thr", s.thr)
	r.Set("gc", s.gc)
	r.Set("gcMs", s.gcMs)
	// memLimit：容器内存上限（MB，cgroup 读不到或无限制为 -1），供页面把进程 RSS 与硬限并列对照。
	r.Set("memLimit", bytesToMB(web.ContainerMemLimitBytes()))
	return r
}

// runtimeInfo 进程与 Go 运行时基础信息，供实时区头部展示。
func runtimeInfo() *core.Row {
	m := core.NewRow()
	m.Set("version", runtime.Version())
	m.Set("numCpu", runtime.NumCPU())
	m.Set("goroutine", runtime.NumGoroutine())
	m.Set("uptimeSec", int64(time.Since(bootTime).Seconds()))
	m.Set("pid", os.Getpid())
	m.Set("hostname", hostName())
	m.Set("proc", procAvailable())
	return m
}

// ---------- 工具 ----------

// bootTime 进程启动时刻，用于 uptimeSec。
var bootTime = time.Now()

func hostName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "-"
}

func procAvailable() bool {
	_, err := os.Stat("/proc/self/status")
	return err == nil
}

// bytesToMB 字节 -> MB。1 MB = 1024*1024 = 1048576 字节，必须与 /proc 的 kB、
// 系统设置页 processMemoryMB 的 rss/1024/1024 保持同一口径，否则读数会被放大 10 倍
// （历史缺陷：除数写成 104857.6，导致进程 RSS 显示值超过容器内存上限）。
func bytesToMB(b int64) float64 {
	if b < 0 {
		return -1
	}
	return round1(float64(b) / 1048576)
}

func round1(v float64) float64 {
	s := 1.0
	if v < 0 {
		s = -1.0
	}
	return float64(int64(v*10+s*0.5)) / 10
}

func rowStr(r *core.Row, key string) string {
	switch v := r.Get(key).(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func rowInt64(r *core.Row, key string) int64 {
	switch v := r.Get(key).(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}
