package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	// SQLite 驱动（cgo）：mattn/go-sqlite3，与 Java 侧 SQLite 二进制格式互操作。
	// 空导入仅在此 cmd 层发生，internal/** 只用 database/sql 泛化 API，
	// 使内部包在无 C 工具链的环境也能 go vet 编译校验。
	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/auth"
	"NexHomeGo/internal/core"
	"NexHomeGo/internal/module/cert"
	"NexHomeGo/internal/module/ddns"
	"NexHomeGo/internal/module/monitor"
	"NexHomeGo/internal/module/nav"
	"NexHomeGo/internal/module/notify"
	"NexHomeGo/internal/module/provider"
	"NexHomeGo/internal/module/stun"
	"NexHomeGo/internal/module/wol"
	"NexHomeGo/internal/web"
)

// NexHome 主入口。启动顺序与 Java NexHomeApp 一致：
// 配置加载 → 数据库初始化 → 鉴权初始化 → 路由注册 → Web 启动 → 后台任务 → 等待退出信号。
func main() {
	// 1) 基础配置（解析 WORK_DIR/DATA_DIR，生成或读取 nexhome.properties）
	if err := core.LoadConfig(); err != nil {
		fatal("加载配置失败", err)
	}

	// 2) 数据库（打开 data/nexhome.db，WAL + 外键，执行 schema.sql 建表）
	dbPath := filepath.Join(core.DataDir(), "nexhome.db")
	if err := core.InitDB(dbPath); err != nil {
		fatal("初始化数据库失败", err)
	}
	defer core.CloseDB()

	// 决策⑤：备份快照等临时文件全部落在 data/tmp；启动时清理上次进程遗留的残留（下载即删的兜底）。
	cleanTmp()

	// 3) 鉴权初始化（首次启动生成随机初始密码并打印控制台）
	if err := auth.Init(); err != nil {
		fatal("初始化鉴权失败", err)
	}

	// 旧库升级：服务商表补充 provider_type 列（新库建表脚本已含）
	provider.Init()

	// 4) 路由注册（须在 Web 启动前；各模块启动前经 web.Route 声明）
	web.RegisterSystemRoutes()
	web.RegisterDiagRoutes()
	wol.RegisterRoutes()
	nav.RegisterRoutes()
	provider.RegisterRoutes()
	monitor.RegisterRoutes()
	notify.RegisterRoutes()
	ddns.RegisterRoutes()
	cert.RegisterRoutes() // 含 /.well-known/acme-challenge/{token} 应答路由（免登录）
	stun.RegisterRoutes()

	// 通知钩子接线（解耦：auth/monitor 不直接依赖 notify 包，启动时注入广播入口）
	monitor.NotifyBroadcast = notify.Broadcast
	auth.NotifyBroadcast = notify.Broadcast

	// 5) Web 服务启动（读取数据库访问配置，带端口自愈）
	if err := web.Start(); err != nil {
		fatal("Web 服务启动失败", err)
	}

	// 6) 后台周期任务
	web.InitDiag()
	nav.Init()
	monitor.Init()                         // 加载启用任务并建立周期探测调度
	notify.Init()                          // 拉起投递队列 + 定期清理 notify_log
	ddns.Init()                            // 加载启用的 DDNS 任务并建立定时同步调度
	cert.Init()                            // 证书模块：旧库升级列 + 重置中断签发状态 + 每小时自动续期检查
	stun.Init()                            // 穿透模块：升级列 + 播种服务器 + 流量落库 + 恢复启用的穿透任务
	core.Every(60, 3600, core.TruncateOld) // 每小时清理过期日志，保留最近 20000 条

	core.LogInfo(core.LogSys, "NexHome(Go) 启动完成，版本 "+core.Version)

	// 7) 等待退出信号，优雅关停（顺序对齐 Java NexHomeApp 关停钩子）
	waitShutdown()
	core.LogInfo(core.LogSys, "收到退出信号，正在关闭...")
	// 停止全部穿透任务并释放路由器 UPnP 映射 → 落库最后不足一周期的流量增量 → 关停后台调度任务。
	// （须在 defer core.CloseDB() 生效前完成，确保 DB 句柄仍可用）
	stun.StopAll()
	stun.FlushTrafficNow()
	core.ShutdownTasks()
}

// cleanTmp 删除 data/tmp 下的残留备份文件（决策⑤：运行期文件收敛到 data 内，且不留垃圾）。
func cleanTmp() {
	dir := filepath.Join(core.DataDir(), "tmp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) >= 16 && name[:16] == "nexhome-backup-" {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

func waitShutdown() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

func fatal(msg string, err error) {
	if core.DataDir() != "" {
		core.LogError(core.LogSys, msg+": "+err.Error())
	}
	println("FATAL: " + msg + ": " + err.Error())
	os.Exit(1)
}
