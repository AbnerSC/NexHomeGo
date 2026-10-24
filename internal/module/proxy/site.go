package proxy

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"NexHomeGo/internal/core"
)

// 代理站点（proxy_site 表一行的解析结果，转发期只读使用）。
// 路由匹配语义对齐 nginx server_name / location 前缀：
// domains 支持 *.example.com 通配（同时匹配 example.com 本身与任意子域）；
// paths 为逗号分隔的路径前缀，空 = 该域名全部路径。
//
// 站点分两种发布方式（对齐 nginx 的 proxy_pass 与 root 两种用法）：
// REVERSE 回源到后端地址，STATIC 直接对外发布本地目录（静态站点，免后端）。
type Site struct {
	ID          int64
	Name        string
	Mode        string // ModeReverse / ModeStatic
	Domains     []string
	Paths       []string
	Scheme      string
	BackendHost string
	BackendPort int
	BasePath    string
	RootDir     string // Mode=STATIC 时生效：站点目录（绝对路径、正斜杠形态）
	ForceHttps  bool
	CertMode    string
	CertTaskID  int64
	Adv         *Advanced
	Enabled     bool
}

const (
	// ModeReverse 反向代理到后端（默认，存量站点语义不变）。
	ModeReverse = "REVERSE"
	// ModeStatic 静态站点发布：直接对外提供本地目录中的文件，不经过任何后端。
	ModeStatic = "STATIC"
)

// parseMode 站点类型归一：空/无法识别一律回退 REVERSE（存量行为优先，避免升级后站点整站失联）。
func parseMode(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), ModeStatic) {
		return ModeStatic
	}
	return ModeReverse
}

// loadAll 从数据库加载全部站点（单行解析失败仅告警跳过，不阻塞其他站点）。
func loadAll() []*Site {
	var list []*Site
	rows, err := core.Query("SELECT * FROM proxy_site ORDER BY id")
	if err != nil {
		core.LogError(core.LogProxy, "加载代理站点失败: "+err.Error())
		return list
	}
	for _, row := range rows {
		s, err := siteOf(row)
		if err != nil {
			core.LogError(core.LogProxy, fmt.Sprintf("代理站点 #%v 配置解析失败，本次加载已跳过: %s", row.Get("id"), err.Error()))
			continue
		}
		list = append(list, s)
	}
	return list
}

// siteOf 数据库行 -> 站点模型（含 target/advanced 校验解析），非法返回 error。
func siteOf(row *core.Row) (*Site, error) {
	adv := ""
	if v := row.Get("advanced"); v != nil {
		adv = strVal(v)
	}
	a, err := parseAdvanced(adv)
	if err != nil {
		return nil, err
	}
	s := &Site{
		ID:         int64Val(row.Get("id")),
		Name:       rowStr(row, "name"),
		Mode:       parseMode(rowStr(row, "mode")),
		Domains:    splitList(rowStr(row, "domains")),
		Paths:      splitList(rowStr(row, "paths")),
		ForceHttps: intVal(row.Get("force_https")) == 1,
		CertTaskID: int64Val(row.Get("cert_task_id")),
		Adv:        a,
		Enabled:    intVal(row.Get("enabled")) == 1,
	}
	if s.CertMode = rowStr(row, "cert_mode"); s.CertMode == "" {
		s.CertMode = "AUTO"
	}
	if s.Mode == ModeStatic {
		// 加载期只校验路径形态：目录可能挂载在临时不可达的设备上，此时仍保留站点，
		// 由请求期返回可读的错误页，而不是整站从路由表消失（表现为 404 未配置站点）。
		return withStaticRoot(s, rowStr(row, "target"), false)
	}
	return withTarget(s, rowStr(row, "target"))
}

var targetDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// withTarget 解析后端地址（创建/更新站点与加载时校验）。
func withTarget(s *Site, target string) (*Site, error) {
	target = strings.TrimSpace(target)
	// 禁 query/fragment 的判定需区分“解析失败”与“携带参数”：先拒绝空白字符再解析
	if strings.ContainsAny(target, " \t\r\n") {
		return nil, fmt.Errorf("后端地址格式不正确: %s", target)
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("后端地址格式不正确: %s", target)
	}
	sc := strings.ToLower(u.Scheme)
	if sc != "http" && sc != "https" {
		return nil, fmt.Errorf("后端地址必须以 http:// 或 https:// 开头: %s", target)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("后端地址缺少主机名: %s", target)
	}
	port := 0
	if ps := u.Port(); ps != "" {
		p, cerr := strconv.Atoi(ps)
		if cerr != nil {
			return nil, fmt.Errorf("后端地址格式不正确: %s", target)
		}
		port = p
	}
	if port == 0 {
		port = 80
		if sc == "https" {
			port = 443
		}
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("后端端口非法: %d", port)
	}
	base := u.Path
	for strings.HasSuffix(base, "/") {
		base = base[:len(base)-1]
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("后端地址不能携带查询参数或片段: %s", target)
	}
	r := *s
	r.Scheme, r.BackendHost, r.BackendPort, r.BasePath = sc, host, port, base
	return &r, nil
}

// validateTarget 后端地址合法性校验（创建/更新接口用）。
func validateTarget(target string) error {
	_, err := withTarget(&Site{CertMode: "AUTO", Adv: defaults()}, target)
	return err
}

// withStaticRoot 解析静态站点目录（创建/更新站点与加载时校验）。
// 存储统一为「绝对路径 + 正斜杠」，请求期再用 filepath.FromSlash 还原平台分隔符。
// checkExists 仅在保存时置真：把「目录打错/未挂载」在保存这一刻暴露出来，
// 加载期则宽容处理，避免目录临时不可达导致站点整站从路由表消失。
func withStaticRoot(s *Site, target string, checkExists bool) (*Site, error) {
	root, err := staticRootDir(target, checkExists)
	if err != nil {
		return nil, err
	}
	r := *s
	r.RootDir = root
	return &r, nil
}

// staticRootDir 站点目录规范化与校验。
func staticRootDir(target string, checkExists bool) (string, error) {
	v := strings.TrimSpace(target)
	if v == "" {
		return "", fmt.Errorf("静态站点目录不能为空")
	}
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("静态站点目录不能含换行/控制字符: %s", v)
	}
	p := filepath.Clean(filepath.FromSlash(v))
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("静态站点目录必须是绝对路径（如 /var/www/site 或 D:/www/site）: %s", v)
	}
	if checkExists {
		st, err := os.Stat(p)
		if err != nil {
			return "", fmt.Errorf("静态站点目录不存在或不可读: %s", v)
		}
		if !st.IsDir() {
			return "", fmt.Errorf("静态站点目录不是文件夹: %s", v)
		}
	}
	return filepath.ToSlash(p), nil
}

// validateDomains 域名合法性校验（创建/更新接口用）。
func validateDomains(csv string) error {
	list := splitList(csv)
	if len(list) == 0 {
		return fmt.Errorf("匹配域名不能为空")
	}
	for _, d := range list {
		body := d
		if strings.HasPrefix(d, "*.") {
			body = d[2:]
		}
		if !targetDomainRe.MatchString(body) {
			return fmt.Errorf("域名格式不正确: %s", d)
		}
	}
	return nil
}

// parsePaths 路径前缀列表校验，空串返回空列表（= 整站）。
func parsePaths(csv string) ([]string, error) {
	var list []string
	for _, p := range splitList(csv) {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("路径前缀必须以 / 开头: %s", p)
		}
		list = append(list, p)
	}
	return list, nil
}

// matchDomain 域名匹配：精确或 *.父域（含父域本身），host 不带端口、已小写。
func (s *Site) matchDomain(host string) bool {
	for _, d := range s.Domains {
		if strings.HasPrefix(d, "*.") {
			parent := d[2:]
			if host == parent || strings.HasSuffix(host, "."+parent) {
				return true
			}
		} else if host == d {
			return true
		}
	}
	return false
}

// matchPath 路径前缀匹配（无 paths 时匹配全部路径）。
func (s *Site) matchPath(path string) bool {
	if len(s.Paths) == 0 {
		return true
	}
	for _, p := range s.Paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// pathPrefixLen 最长路径前缀（路由排序用，无 paths 视为整站匹配）。
func (s *Site) pathPrefixLen() int {
	max := 0
	for _, p := range s.Paths {
		if len(p) > max {
			max = len(p)
		}
	}
	if len(s.Paths) == 0 {
		return 0
	}
	return max
}

func (s *Site) hasDomain(host string) bool {
	for _, d := range s.Domains {
		if d == host {
			return true
		}
	}
	return false
}

// splitList 逗号/分号/空白分隔，逐项小写去空。
func splitList(csv string) []string {
	var list []string
	for _, part := range regexp.MustCompile(`[,;\s]+`).Split(csv, -1) {
		v := strings.ToLower(strings.TrimSpace(part))
		if v != "" {
			list = append(list, v)
		}
	}
	return list
}

// ---------- 行取值辅助（对齐 Java Map<String,Object> 读取） ----------

func rowStr(row *core.Row, key string) string { return strVal(row.Get(key)) }

func strVal(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func intVal(v interface{}) int { return int(int64Val(v)) }

func int64Val(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	default:
		return 0
	}
}
