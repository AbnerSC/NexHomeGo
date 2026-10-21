package web

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/auth"
	"NexHomeGo/internal/core"
)

// 系统级 REST 接口：登录鉴权、全局日志分页、系统信息/资源监控、访问与安全设置、
// 配置备份、统一仪表盘、网络测速、访问来源识别。路径、方法、响应结构逐一复刻 Java SystemRoutes，
// 保证前端零改动。内存相关读数按决策①改用 Go runtime + /proc。

// bootTime 进程启动时刻，用于 uptimeSec。
var bootTime = time.Now()

// ---------- 测速负载块（1MB 随机数据，只读复用） ----------

var speedBlock = func() []byte {
	b := make([]byte, 1<<20)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rnd.Read(b)
	return b
}()

const (
	speedTestDefaultMs   = int64(10_000)
	speedDownMaxMs       = int64(60_000)
	speedDownMaxBytes    = int64(16) << 30
	speedDownMaxFixed    = int64(32) << 20
	speedUpMaxMs         = int64(60_000)
	speedLogWindowSec    = 120
)

var pingBody = []byte{'P'}

// RegisterSystemRoutes 注册系统级路由（由主程序在 Web 启动前调用）。
func RegisterSystemRoutes() {
	registerAuthRoutes()
	registerSystemRoutes()
	registerSpeedTestRoutes()
}

// ---------- 鉴权 ----------

func registerAuthRoutes() {
	Route("POST", "/api/auth/login", func(c *Ctx) error {
		b := c.Body()
		password := core.BodyStr(b, "password")
		if strings.TrimSpace(password) == "" {
			return core.NewBadRequest("密码不能为空")
		}
		ip := c.ClientIP()
		if remain := auth.LockRemainingMs(ip); remain > 0 {
			minutes := (remain + 59_999) / 60_000
			c.Fail(http.StatusTooManyRequests, fmt.Sprintf("尝试过于频繁，已临时锁定，请约 %d 分钟后再试", minutes))
			return nil
		}
		token, err := auth.Login(password, ip)
		if err != nil {
			return err
		}
		if token == "" {
			c.Fail(http.StatusUnauthorized, "密码错误")
			return nil
		}
		c.Ok(core.NewRow().Set("token", token))
		return nil
	})

	Route("GET", "/api/auth/check", func(c *Ctx) error {
		token := c.Header("X-Token")
		if token == "" {
			token = c.Query("token")
		}
		c.Ok(core.NewRow().Set("loggedIn", auth.Check(token)))
		return nil
	})

	Route("POST", "/api/auth/logout", func(c *Ctx) error {
		auth.Logout(c.Header("X-Token"))
		c.Ok("已退出")
		return nil
	})

	Route("POST", "/api/auth/change-password", func(c *Ctx) error {
		b := c.Body()
		oldPwd := core.BodyStr(b, "old_password")
		newPwd := core.BodyStr(b, "new_password")
		if len(newPwd) < 12 {
			return core.NewBadRequest("新密码长度至少 12 位")
		}
		ok, err := auth.ChangePassword(oldPwd, newPwd)
		if err != nil {
			return err
		}
		if !ok {
			c.Fail(http.StatusBadRequest, "原密码不正确")
			return nil
		}
		c.Ok("密码已修改，请重新登录")
		return nil
	})

	Route("GET", "/api/auth/security", func(c *Ctx) error {
		maxFails, _ := auth.GetMaxFails()
		lockMinutes, _ := auth.GetLockMinutes()
		c.Ok(core.NewRow().Set("maxFails", maxFails).Set("lockMinutes", lockMinutes))
		return nil
	})

	Route("PUT", "/api/auth/security", func(c *Ctx) error {
		b := c.Body()
		if err := auth.SetSecurity(core.BodyNum(b, "maxFails", 3), core.BodyNum(b, "lockMinutes", 30)); err != nil {
			return err
		}
		mf, _ := auth.GetMaxFails()
		lm, _ := auth.GetLockMinutes()
		core.LogInfo(core.LogAuth, fmt.Sprintf("登录安全参数已更新：最大失败 %d 次，锁定 %d 分钟", mf, lm))
		c.Ok("已保存登录安全设置")
		return nil
	})
}

// ---------- 系统信息 / 日志 / 设置 / 备份 / 仪表盘 / 来源 ----------

func registerSystemRoutes() {
	// 全局日志（分页 + 模块过滤）
	Route("GET", "/api/logs", func(c *Ctx) error {
		page := parseIntDefault(c.Query("page"))
		size := parseIntDefault(c.Query("size"))
		if size == 0 {
			size = 50
		}
		r, err := core.LogPage(page, size, c.Query("module"))
		if err != nil {
			return err
		}
		c.Ok(r)
		return nil
	})

	// 系统信息：内存读数改用 Go runtime（usedMemoryMB=进程 RSS，maxMemoryMB=容器上限/物理内存）
	Route("GET", "/api/system/info", func(c *Ctx) error {
		usedMB, maxMB := processMemoryMB()
		info := core.NewRow()
		info.Set("name", "NexHome 联枢")
		info.Set("version", core.Version)
		info.Set("javaVersion", "go"+strings.TrimPrefix(runtime.Version(), "go"))
		info.Set("os", OSDisplay())
		info.Set("port", HTTPPort())
		info.Set("httpsEnabled", HTTPSActive())
		info.Set("uptimeSec", int64(time.Since(bootTime).Seconds()))
		info.Set("usedMemoryMB", usedMB)
		info.Set("maxMemoryMB", maxMB)
		c.Ok(info)
		return nil
	})

	// 系统资源监控（CPU / 物理内存 / 虚拟内存，供顶栏实时展示）
	Route("GET", "/api/system/metrics", func(c *Ctx) error {
		cores, cpu, memTotal, memUsed, swapTotal, swapUsed := memMetrics()
		m := core.NewRow()
		m.Set("cores", cores)
		m.Set("cpuLoad", cpu)
		m.Set("memTotalMB", memTotal)
		m.Set("memUsedMB", memUsed)
		m.Set("swapTotalMB", swapTotal)
		m.Set("swapUsedMB", swapUsed)
		c.Ok(m)
		return nil
	})

	// 访问与安全设置（保存后进程内重启生效）
	Route("GET", "/api/system/web-settings", func(c *Ctx) error {
		v, err := AccessConfigApiView()
		if err != nil {
			return err
		}
		c.Ok(v)
		return nil
	})
	Route("PUT", "/api/system/web-settings", func(c *Ctx) error {
		if _, err := ApplyAccessConfig(c.Body()); err != nil {
			return err
		}
		core.LogInfo(core.LogSys, "访问配置已更新，服务即将重启应用新配置")
		ScheduleRestart(1)
		c.Ok("已保存，服务正在以新配置重启")
		return nil
	})

	// 配置备份：VACUUM INTO 一致性快照后下载。
	// 决策⑤：快照必须落在 data 目录内（data/tmp），不得使用系统临时目录；下载后即删并限制残留。
	Route("GET", "/api/system/backup", func(c *Ctx) error {
		stamp := time.Now().Format("20060102-150405")
		tmpDir := filepath.Join(core.DataDir(), "tmp")
		if err := os.MkdirAll(tmpDir, 0o755); err != nil {
			return err
		}
		tmp := filepath.Join(tmpDir, "nexhome-backup-"+stamp+"-"+strconv.Itoa(int(time.Now().UnixNano()))+".db")
		_ = os.Remove(tmp) // VACUUM INTO 要求目标不存在
		target := filepath.ToSlash(tmp)
		if err := core.BackupTo(target); err != nil {
			return err
		}
		defer func() { _ = os.Remove(tmp) }()
		name := "nexhome-" + stamp + ".db"
		if err := c.File(tmp, name); err != nil {
			return err
		}
		core.LogInfo(core.LogSys, "配置备份已导出: "+name)
		return nil
	})

	// 统一状态仪表盘（聚合各模块关键状态；各业务模块通过 RegisterDashboardSection 注册自己的分区）
	Route("GET", "/api/dashboard", func(c *Ctx) error {
		c.Ok(DashboardSummary())
		return nil
	})

	// 访问来源识别（首页导航内外网智能切换依据）
	Route("GET", "/api/net/source", func(c *Ctx) error {
		ip := c.ClientIP()
		c.Ok(core.NewRow().Set("lan", IsPrivateSource(ip)).Set("ip", ip))
		return nil
	})
}

// ---------- 网络测速 ----------

func registerSpeedTestRoutes() {
	Route("GET", "/api/system/speedtest/ping", func(c *Ctx) error {
		c.Raw(http.StatusOK, pingBody, "application/octet-stream")
		return nil
	})

	Route("GET", "/api/system/speedtest/down", func(c *Ctx) error {
		fixed := clampInt64(parseLongDefault(c.Query("bytes"), 0), 0, speedDownMaxFixed)
		ms := clampInt64(parseLongDefault(c.Query("ms"), speedTestDefaultMs), 500, speedDownMaxMs)
		w := c.Writer()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		if fixed > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(fixed, 10))
		}
		if !c.wroteHdr {
			w.WriteHeader(http.StatusOK)
			c.wroteHdr = true
		}
		speedWrite(w, fixed, ms)
		return nil
	})

	Route("POST", "/api/system/speedtest/up", func(c *Ctx) error {
		req := c.Request()
		var total int64
		deadline := time.Now().Add(time.Duration(speedUpMaxMs) * time.Millisecond)
		buf := make([]byte, 256*1024)
		if req.Body != nil {
			defer req.Body.Close()
			for time.Now().Before(deadline) {
				n, err := req.Body.Read(buf)
				if n > 0 {
					total += int64(n)
				}
				if err != nil {
					break
				}
			}
		}
		c.Ok(core.NewRow().Set("bytes", total))
		return nil
	})
}

// speedWrite 持续写出高熵负载：fixed>0 写满即收尾（预热）；否则写到 ms 超时或字节兜底上限。
// 逐块 Flush，让浏览器到点中断时服务端下一次写出即感知；客户端断连静默收尾。
func speedWrite(w http.ResponseWriter, fixed, maxMs int64) {
	var capBytes int64 = speedDownMaxBytes
	if fixed > 0 {
		capBytes = fixed
	}
	deadline := time.Now().Add(time.Duration(maxMs) * time.Millisecond)
	flusher, _ := w.(http.Flusher)
	var sent int64
	for sent < capBytes && (fixed > 0 || time.Now().Before(deadline)) {
		n := int64(len(speedBlock))
		if capBytes-sent < n {
			n = capBytes - sent
		}
		if _, err := w.Write(speedBlock[:n]); err != nil {
			return // 客户端断连：静默收尾
		}
		sent += n
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ---------- 辅助 ----------

// processMemoryMB 返回 (usedMB, maxMB)：used 取进程 RSS（读不到回退 Go 堆占用），
// max 取容器内存上限（读不到回退物理内存总量）。
func processMemoryMB() (usedMB, maxMB int64) {
	rss := RSSBytes()
	if rss >= 0 {
		usedMB = rss / 1024 / 1024
	} else {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		usedMB = int64(ms.HeapAlloc / 1024 / 1024)
	}
	if lim := ContainerMemLimitBytes(); lim > 0 {
		maxMB = lim / 1024 / 1024
		return
	}
	if m, ok := readMemInfo(); ok {
		maxMB = int64(m.totalKB / 1024)
	}
	return
}

func parseIntDefault(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func parseLongDefault(s string, def int64) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func clampInt64(v, min, max int64) int64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
