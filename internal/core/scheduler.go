package core

import (
	"context"
	"sync/atomic"
	"time"
)

// Tasks：全局轻量任务调度器（DDNS 定时同步、证书续期检查、监控探测、日志清理等周期任务）。
// 分层语义与 Java Tasks 一致：
//   - Every 注册的周期任务保证串行：上一次执行未结束时本周期直接跳过（不排队），避免状态机型任务并发重入；
//   - 任务体运行在独立 goroutine，阻塞 IO 不占用调度触发；
//   - 异常仅记日志，不终止周期任务。
var (
	schedCtx    context.Context
	schedCancel context.CancelFunc
)

func init() {
	schedCtx, schedCancel = context.WithCancel(context.Background())
}

// Every 周期性任务：先延迟 initialDelaySec 秒，之后每 periodSec 秒触发一次；同任务串行、跳过重叠周期。
func Every(initialDelaySec, periodSec int, job func()) {
	var running int32
	go func() {
		if !sleepCtx(time.Duration(initialDelaySec)*time.Second) {
			return
		}
		ticker := time.NewTicker(time.Duration(periodSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-schedCtx.Done():
				return
			case <-ticker.C:
				if atomic.CompareAndSwapInt32(&running, 0, 1) {
					go func() {
						defer atomic.StoreInt32(&running, 0)
						safeRun(job)
					}()
				}
			}
		}
	}()
}

// Delay 延迟一次性任务（delaySec 秒后执行）。
func Delay(delaySec int, job func()) {
	go func() {
		if sleepCtx(time.Duration(delaySec)*time.Second) {
			safeRun(job)
		}
	}()
}

// Run 异步执行一次（不阻塞 HTTP 线程）。
func Run(job func()) {
	go safeRun(job)
}

// ShutdownTasks 关停调度器（进程退出钩子调用）。
func ShutdownTasks() {
	schedCancel()
}

// sleepCtx 睡眠给定时长，若期间调度器被取消则提前返回 false。0 表示不等待直接返回 true。
func sleepCtx(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-schedCtx.Done():
		return false
	case <-t.C:
		return true
	}
}

// safeRun 包裹任务，异常只记录日志，避免周期任务因 panic 终止。
func safeRun(job func()) {
	defer func() {
		if r := recover(); r != nil {
			LogError(LogSys, "调度任务异常")
		}
	}()
	job()
}
