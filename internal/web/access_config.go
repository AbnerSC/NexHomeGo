package web

import (
	"crypto/tls"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// 访问与安全配置（HTTP 端口 / HTTPS / 安全入口），持久化在 app_config（key 前缀 web.），
// 优先级高于 nexhome.properties 引导配置；由系统设置页修改，保存后进程内重启生效，绑定失败自动回滚。
// HTTPS 证书复用「SSL 证书管理」已签发任务证书（PEM）：可指定任务，或在全部有效证书中自动挑选有效期最长的一张。

const (
	KeyPort          = "web.port"
	KeyHTTPSEnabled  = "web.https.enabled"
	KeyHTTPSPort     = "web.https.port"
	KeyHTTPSRedirect = "web.https.redirect"
	KeyHTTPSCertTask = "web.https.cert_task_id"
	KeyEntry         = "web.entry"
	KeyLastError     = "web.last_error"
)

// Snapshot 一份完整的生效配置快照，进程内重启与回滚均以此为单位。
type Snapshot struct {
	HTTPPort      int
	HTTPSEnabled  bool
	HTTPSPort     int
	HTTPSRedirect bool
	CertTaskID    int64
	Entry         string
}

// CertInfo 解析出的 HTTPS 证书上下文。
type CertInfo struct {
	TaskID    int64
	Name      string
	CertFile  string
	KeyFile   string
	NotAfter  time.Time
	TLSConfig *tls.Config
}

// LoadAccessConfig 读取生效配置（数据库优先，缺失项回退引导默认）。
func LoadAccessConfig() (*Snapshot, error) {
	port, err := core.GetConfig(KeyPort)
	if err != nil {
		return nil, err
	}
	httpPort := parseIntOr(port, core.Port())
	enabled, _ := core.GetConfig(KeyHTTPSEnabled)
	httpsPortStr, _ := core.GetConfig(KeyHTTPSPort)
	redirect, _ := core.GetConfig(KeyHTTPSRedirect)
	certTaskStr, _ := core.GetConfig(KeyHTTPSCertTask)
	entry, _ := core.GetConfig(KeyEntry)
	return &Snapshot{
		HTTPPort:      httpPort,
		HTTPSEnabled:  enabled == "1",
		HTTPSPort:     parseIntOr(httpsPortStr, 8443),
		HTTPSRedirect: redirect == "1",
		CertTaskID:    parseInt64Or(certTaskStr),
		Entry:         trimEntry(entry),
	}, nil
}

// Persist 将快照写回 app_config（回滚时恢复旧配置）。
func (s *Snapshot) Persist() error {
	set := func(k, v string) error { return core.SetConfig(k, v) }
	if err := set(KeyPort, strconv.Itoa(s.HTTPPort)); err != nil {
		return err
	}
	if err := set(KeyHTTPSEnabled, boolStr(s.HTTPSEnabled)); err != nil {
		return err
	}
	if err := set(KeyHTTPSPort, strconv.Itoa(s.HTTPSPort)); err != nil {
		return err
	}
	if err := set(KeyHTTPSRedirect, boolStr(s.HTTPSRedirect)); err != nil {
		return err
	}
	cert := ""
	if s.CertTaskID > 0 {
		cert = strconv.FormatInt(s.CertTaskID, 10)
	}
	if err := set(KeyHTTPSCertTask, cert); err != nil {
		return err
	}
	return set(KeyEntry, s.Entry)
}

// Apply 校验并保存访问配置（系统设置页提交）；HTTPS 启用时同步校验证书可解析，避免重启后降级。
func ApplyAccessConfig(body map[string]interface{}) (*Snapshot, error) {
	old, err := LoadAccessConfig()
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{
		HTTPPort:      core.BodyNum(body, "port", old.HTTPPort),
		HTTPSEnabled:  core.BodyBool(body, "httpsEnabled", old.HTTPSEnabled),
		HTTPSPort:     core.BodyNum(body, "httpsPort", old.HTTPSPort),
		HTTPSRedirect: core.BodyBool(body, "httpsRedirect", old.HTTPSRedirect),
		CertTaskID:    parseInt64Or(core.BodyStr(body, "certTaskId")),
		Entry:         trimEntry(core.BodyStr(body, "entryPath")),
	}
	if snap.HTTPPort < 1 || snap.HTTPPort > 65535 {
		return nil, core.NewBadRequest("HTTP 端口必须在 1-65535 之间")
	}
	if snap.HTTPSPort < 1 || snap.HTTPSPort > 65535 {
		return nil, core.NewBadRequest("HTTPS 端口必须在 1-65535 之间")
	}
	if snap.HTTPSEnabled && snap.HTTPSPort == snap.HTTPPort {
		return nil, core.NewBadRequest("HTTPS 端口不能与 HTTP 端口相同")
	}
	if snap.Entry != "" && !validEntry(snap.Entry) {
		return nil, core.NewBadRequest("安全入口须为 4-64 位字母/数字/下划线/中划线，且不含 /")
	}
	if snap.HTTPSEnabled {
		if _, err := ResolveCertFile(snap.CertTaskID); err != nil {
			return nil, err
		}
	}
	if err := snap.Persist(); err != nil {
		return nil, err
	}
	_ = core.SetConfig(KeyLastError, "")
	core.LogInfo(core.LogSys, "访问配置已更新: "+describe(snap))
	return snap, nil
}

// ResolveCertFile 解析 HTTPS 使用的证书：certTaskId>0 用指定任务，否则在未过期已签发证书中挑选有效期最长的一张。
func ResolveCertFile(certTaskID int64) (*CertInfo, error) {
	if certTaskID > 0 {
		task, err := core.QueryOne("SELECT * FROM cert_task WHERE id=?", certTaskID)
		if err != nil {
			return nil, err
		}
		if task == nil {
			return nil, core.NewBadRequest("HTTPS 证书任务不存在: #%d", certTaskID)
		}
		return certInfoOf(task)
	}
	tasks, err := core.Query("SELECT * FROM cert_task WHERE status='ISSUED' AND not_after IS NOT NULL")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var best *core.Row
	var bestTime time.Time
	for _, t := range tasks {
		na, err := parseInstant(str(t.Get("not_after")))
		if err != nil || na.Before(now) {
			continue
		}
		if best == nil || na.After(bestTime) {
			best, bestTime = t, na
		}
	}
	if best == nil {
		return nil, core.NewBadRequest("未找到已签发且未过期的证书，请先在「SSL 证书管理」中申请，或指定证书任务")
	}
	return certInfoOf(best)
}

func certInfoOf(task *core.Row) (*CertInfo, error) {
	id := toInt64(task.Get("id"))
	if str(task.Get("status")) != "ISSUED" {
		return nil, core.NewBadRequest("证书任务 #%d 尚未签发成功", id)
	}
	dir := filepath.Join(core.DataDir(), "certs", "task-"+strconv.FormatInt(id, 10))
	keyFile := filepath.Join(dir, "domain.key.pem")
	certFile := filepath.Join(dir, "fullchain.pem")
	if !fileExists(certFile) {
		certFile = filepath.Join(dir, "cert.pem")
	}
	if !fileExists(certFile) || !fileExists(keyFile) {
		return nil, core.NewBadRequest("证书任务 #%d 的证书文件缺失，请重新申请", id)
	}
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, core.NewBadRequest("证书解析失败: %v", err)
	}
	notAfter, _ := parseInstant(str(task.Get("not_after")))
	return &CertInfo{
		TaskID:    id,
		Name:      str(task.Get("name")),
		CertFile:  certFile,
		KeyFile:   keyFile,
		NotAfter:  notAfter,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cer}, MinVersion: tls.VersionTLS12},
	}, nil
}

// ApiView 设置页视图：当前配置 + HTTPS 实际生效状态 + 最近一次重启回滚提示。
func AccessConfigApiView() (*core.Row, error) {
	s, err := LoadAccessConfig()
	if err != nil {
		return nil, err
	}
	lastError, _ := core.GetConfig(KeyLastError)
	m := core.NewRow()
	m.Set("port", s.HTTPPort)
	m.Set("boundPort", HTTPPort())
	m.Set("httpsEnabled", bool01(s.HTTPSEnabled))
	m.Set("httpsPort", s.HTTPSPort)
	m.Set("httpsRedirect", bool01(s.HTTPSRedirect))
	m.Set("certTaskId", s.CertTaskID)
	m.Set("entryPath", s.Entry)
	m.Set("lastError", lastError)
	active := ActiveCertTaskID()
	m.Set("httpsActive", bool01(HTTPSActive()))
	m.Set("activeCertTaskId", active)
	if active > 0 {
		if t, err := core.QueryOne("SELECT name, not_after FROM cert_task WHERE id=?", active); err == nil && t != nil {
			m.Set("activeCertName", str(t.Get("name")))
			m.Set("activeCertNotAfter", str(t.Get("not_after")))
		}
	}
	return m, nil
}

// ---------- 内部工具 ----------

func describe(s *Snapshot) string {
	sb := "HTTP:" + strconv.Itoa(s.HTTPPort)
	if s.HTTPSEnabled {
		sb += " HTTPS:" + strconv.Itoa(s.HTTPSPort)
		if s.HTTPSRedirect {
			sb += "(强制跳转)"
		}
	}
	if s.Entry != "" {
		sb += " 安全入口:/" + s.Entry
	}
	return sb
}

func trimEntry(v string) string {
	return strings.Trim(strings.TrimSpace(v), "/")
}

func validEntry(e string) bool {
	if len(e) < 4 || len(e) > 64 {
		return false
	}
	for _, c := range e {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func bool01(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parseIntOr(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func parseInt64Or(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return 0
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toInt64(v interface{}) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	default:
		return 0
	}
}

func parseInstant(s string) (time.Time, error) {
	// CertService 以 RFC3339（Instant）写 not_after。
	return time.Parse(time.RFC3339, s)
}
