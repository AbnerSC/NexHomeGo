package core

import (
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"
)

//go:embed schema.sql
var schemaSQL string

// 数据访问层：SQLite，单连接（等价 Java「单连接 + 方法级同步」的单写者模型），
// 所有模块通过本层静态式方法访问数据库。驱动（mattn/go-sqlite3）的空导入隔离在 cmd 层，
// 使 internal 包在无 C 工具链的环境也能编译校验。
var (
	db     *sql.DB
	timeLayout = "2006-01-02 15:04:05"
)

// InitDB 打开 data/nexhome.db（WAL + 外键 + busy_timeout）并执行建表脚本。
// dsnFile 由调用方给出（生产为 DataDir()/nexhome.db；测试可注入夹具路径）。
func InitDB(dsnFile string) error {
	d := strings.ReplaceAll(dsnFile, "\\", "/")
	var err error
	db, err = sql.Open("sqlite3", d)
	if err != nil {
		return err
	}
	// 单连接串行化写入，规避 SQLITE_BUSY（与 Java 单连接模型一致）。
	db.SetMaxOpenConns(1)
	st := []string{
		"PRAGMA busy_timeout=10000",
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range st {
		if _, err := db.Exec(p); err != nil {
			return err
		}
	}
	return ExecScript(schemaSQL)
}

// CloseDB 关闭数据库连接。
func CloseDB() {
	if db != nil {
		_ = db.Close()
		db = nil
	}
}

// DB 暴露底层连接池（供个别需要原生 API 的场景，如备份/事务细节）。
func DB() *sql.DB { return db }

// ExecScript 执行建表脚本：按分号拆分逐条执行（忽略注释行与空语句），等价 Java Database.execScript。
func ExecScript(script string) error {
	for _, part := range strings.Split(script, ";") {
		var sb strings.Builder
		for _, line := range strings.Split(part, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
		sqlText := strings.TrimSpace(sb.String())
		if sqlText != "" {
			if _, err := db.Exec(sqlText); err != nil {
				return err
			}
		}
	}
	return nil
}

// Insert 执行 INSERT，返回自增主键（无则 -1）。
func Insert(query string, args ...interface{}) (int64, error) {
	if db == nil {
		return -1, fmt.Errorf("数据库未初始化")
	}
	res, err := db.Exec(query, args...)
	if err != nil {
		return -1, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return -1, err
	}
	return id, nil
}

// Update 执行 UPDATE / DELETE，返回影响行数。
func Update(query string, args ...interface{}) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}
	res, err := db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UpdateBatch 批量执行同一 UPDATE/INSERT（单事务），返回提交行数。
func UpdateBatch(query string, paramsList [][]interface{}) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}
	if len(paramsList) == 0 {
		return 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	stmt, err := tx.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	total := 0
	for _, params := range paramsList {
		res, e := stmt.Exec(params...)
		if e != nil {
			err = e
			return 0, e
		}
		n, e := res.RowsAffected()
		if e != nil {
			err = e
			return 0, e
		}
		if n > 0 {
			total += int(n)
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// Query 查询多行，每行转为保持列顺序的 *Row。
func Query(query string, args ...interface{}) ([]*Row, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := make([]*Row, 0)
	for rows.Next() {
		raw := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := NewRow()
		for i, c := range cols {
			r.Set(c, normalizeValue(raw[i]))
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueryOne 查询单行，无结果返回 nil。
func QueryOne(query string, args ...interface{}) (*Row, error) {
	rows, err := Query(query, args...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// Scalar 查询单个标量值（第一行第一列），无结果返回 nil。
func Scalar(query string, args ...interface{}) (interface{}, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	row := db.QueryRow(query, args...)
	var v interface{}
	if err := row.Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return normalizeValue(v), nil
}

// ---------- app_config 便捷读写（与 Java Database 语义一致） ----------

func GetConfig(key string) (string, error) {
	v, err := Scalar("SELECT value FROM app_config WHERE key=?", key)
	if err != nil || v == nil {
		return "", err
	}
	return toStr(v), nil
}

func SetConfig(key, value string) error {
	_, err := Update("INSERT INTO app_config(key, value) VALUES(?, ?) "+
		"ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}

// ---------- 备份：VACUUM INTO 生成一致性快照（filePath 须不存在，用正斜杠） ----------

func BackupTo(filePath string) error {
	_, err := db.Exec("VACUUM INTO '" + strings.ReplaceAll(filePath, "'", "''") + "'")
	return err
}

// Now 当前本地时间字符串，用于日志与状态时间（yyyy-MM-dd HH:mm:ss）。
func Now() string {
	return time.Now().Format(timeLayout)
}

// ---------- 内部工具 ----------

// normalizeValue 将驱动返回值归一为 JSON 友好类型：[]byte→string，其余保持。
// SQLite 布尔列以 INTEGER 0/1 存储 → int64 → JSON 数字（与 Java rs.getObject 行为一致）。
func normalizeValue(v interface{}) interface{} {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case time.Time:
		return x.Format(timeLayout)
	default:
		return v
	}
}

func toStr(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case nil:
		return ""
	default:
		// int64/float64 等（少见：app_config.value 为 TEXT）
		return fmt.Sprintf("%v", x)
	}
}
