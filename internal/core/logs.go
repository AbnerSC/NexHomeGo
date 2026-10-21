package core

import "fmt"

// Logs 全局操作日志：所有模块统一写入，同时输出控制台与 SQLite op_log 表，Web 端分页查询。
// 模块常量保证日志可按模块过滤（值与 Java Logs 完全一致）。
const (
	LogSys     = "SYSTEM"
	LogAuth    = "AUTH"
	LogDdns    = "DDNS"
	LogStun    = "STUN"
	LogWol     = "WOL"
	LogCert    = "CERT"
	LogNav     = "NAV"
	LogDocker  = "DOCKER"
	LogProvider = "PROVIDER"
	LogNotify  = "NOTIFY"
	LogMonitor = "MONITOR"
	LogProxy   = "PROXY"
)

func LogInfo(module, message string) { writeLog(module, "INFO", message) }
func LogWarn(module, message string) { writeLog(module, "WARN", message) }
func LogError(module, message string) { writeLog(module, "ERROR", message) }

func writeLog(module, level, message string) {
	t := Now()
	// 控制台格式与 Java 完全一致：[time] [module] [level] message
	fmt.Printf("[%s] [%s] [%s] %s\n", t, module, level, message)
	// 日志落库失败不影响业务，仅输出到控制台（等价 Java 行为）。
	if _, err := Insert("INSERT INTO op_log(time, module, level, message) VALUES(?,?,?,?)",
		t, module, level, message); err != nil {
		fmt.Printf("写入日志表失败: %s\n", err.Error())
	}
}

// LogPage 分页查询日志：page 从 1 开始，size 越界回退 50，module 空表示全部。
// 返回 {list,total,page,size}（字段名与 Java Logs.page 一致）。
func LogPage(page, size int, module string) (*Row, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	offset := (page - 1) * size
	where := ""
	var args []interface{}
	var countArgs []interface{}
	if module != "" {
		where = " WHERE module=?"
		args = append(args, module)
		countArgs = append(countArgs, module)
	}
	args = append(args, size, offset)
	rows, err := Query("SELECT id, time, module, level, message FROM op_log"+where+
		" ORDER BY id DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, err
	}
	total, err := Scalar("SELECT COUNT(*) FROM op_log"+where, countArgs...)
	if err != nil {
		return nil, err
	}
	if total == nil {
		total = int64(0)
	}
	r := NewRow()
	r.Set("list", rows)
	r.Set("total", total)
	r.Set("page", page)
	r.Set("size", size)
	return r, nil
}

// TruncateOld 清理过期日志，保留最近 20000 条，防止表无限增长。
func TruncateOld() {
	_, _ = Update("DELETE FROM op_log WHERE id <= (SELECT MAX(id) - 20000 FROM op_log)")
}
