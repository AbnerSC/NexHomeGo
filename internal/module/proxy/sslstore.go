package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// SSL 证书自动适应仓库：扫描「SSL 证书管理」中磁盘上已存在可用证书的任务，
// 构建域名（含通配）-> 证书映射，供 HTTPS 监听经 SNI 自动选证。
// 证书文件布局与面板 HTTPS 一致：data/certs/task-{id}/ 下 domain.key.pem（PKCS8 私钥）
// + fullchain.pem（缺失回退 cert.pem）；任务行带 cert_dir 时按该目录读取，
// 任务目录丢失时回退到 save_dir 里按域名命名的三件套。
// 站点 cert_mode=TASK 时优先使用指定任务的证书；
// AUTO 按 SNI 域名精确 > 通配匹配。均未命中时不终止握手，兜底选用剩余有效期最长的证书。
//
// 装载范围不限 status='ISSUED'：续期失败会把任务置为 ERROR，但上次签发的证书仍在有效期内，
// 若一并排除会导致证书库变空、所有站点 HTTPS 握手被终止（表现为浏览器 ERR_CONNECTION_CLOSED）。

type certEntry struct {
	taskID   int64
	name     string
	keyFile  string // 私钥路径
	certFile string // 证书链路径（fullchain 优先）
	domains  []string
	notAfter time.Time
}

var (
	sslMu      sync.Mutex
	sslOrders  []*certEntry               // reload 顺序（LinkedHashMap 语义）
	sslByTask  map[int64]*certEntry       // 证书任务 ID -> 条目
	sslDomain  map[string]int64           // 域名（精确或 *.父域）-> 证书任务 ID
	sslKeyPair map[int64]*tls.Certificate // 懒构建的任务 -> 证书+私钥
	sslMiss    map[string]bool            // 已告警过的「无匹配证书」域名（避免逐握手刷日志）
)

// sslReload 全量重载：重新扫描证书任务并解析域名映射（缺失/解析失败的任务跳过并告警）。
func sslReload() {
	sslMu.Lock()
	defer sslMu.Unlock()
	orders := make([]*certEntry, 0)
	byTask := map[int64]*certEntry{}
	domainMap := map[string]int64{}
	// ISSUED 优先占位（同域名竞态时已签发的任务生效），其余状态按 id 升序兜底
	tasks, err := core.Query("SELECT * FROM cert_task ORDER BY CASE WHEN status='ISSUED' THEN 0 ELSE 1 END, id")
	if err != nil {
		core.LogError(core.LogProxy, "SslStore 加载证书任务失败: "+err.Error())
		return
	}
	now := time.Now()
	for _, t := range tasks {
		id := int64Val(t.Get("id"))
		e, err := loadCertEntry(t)
		if err != nil {
			core.LogWarn(core.LogProxy, fmt.Sprintf("证书任务 #%d 不可用于代理 HTTPS（已跳过）: %s", id, err.Error()))
			continue
		}
		if e.notAfter.Before(now) {
			continue // 已过期不挂载
		}
		if _, dup := byTask[e.taskID]; dup {
			continue
		}
		orders = append(orders, e)
		byTask[e.taskID] = e
		for _, d := range e.domains {
			if _, ok := domainMap[d]; !ok {
				domainMap[d] = e.taskID
			}
		}
	}
	sslOrders = orders
	sslByTask = byTask
	sslDomain = domainMap
	sslKeyPair = map[int64]*tls.Certificate{} // 证书变化 -> 懒构建缓存失效
	sslMiss = map[string]bool{}
	core.LogInfo(core.LogProxy, fmt.Sprintf("代理证书库已重载：%d 张有效证书，覆盖 %d 个域名", len(orders), len(domainMap)))
}

func sslHasCert() bool {
	sslMu.Lock()
	defer sslMu.Unlock()
	return len(sslOrders) > 0
}

// sslAPIView 证书任务详情列表（供 /api/proxy/certs 展示）。
func sslAPIView() []*core.Row {
	sslMu.Lock()
	defer sslMu.Unlock()
	list := make([]*core.Row, 0, len(sslOrders))
	for _, e := range sslOrders {
		list = append(list, core.NewRow().
			Set("taskId", e.taskID).
			Set("name", e.name).
			Set("domains", strings.Join(e.domains, ", ")).
			Set("notAfter", instantString(e.notAfter)))
	}
	return list
}

func sslCount() int {
	sslMu.Lock()
	defer sslMu.Unlock()
	return len(sslOrders)
}

// forSNI 握手选证：先按当前站点列表解析（cert_mode=TASK 指定优先），再按域名映射自动匹配
// （精确 > 逐级父域通配）；均未命中时兜底选用剩余有效期最长的证书。
// 返回 nil 仅当证书库为空（握手终止）。frontH2 由命中站点的 frontProtocol 决定。
func forSNI(hostname string, sites []*Site) (*tls.Certificate, bool) {
	h2 := true
	if hostname != "" {
		h2 = siteFrontH2(strings.ToLower(hostname), sites)
	}
	sslMu.Lock()
	defer sslMu.Unlock()
	if hostname == "" {
		return sslLongestLocked(), h2
	}
	host := strings.ToLower(hostname)
	// 1. 站点指定证书任务优先
	for _, s := range sites {
		if !s.Enabled || !s.matchDomain(host) {
			continue
		}
		if s.CertMode == "TASK" && s.CertTaskID > 0 {
			if _, ok := sslByTask[s.CertTaskID]; ok {
				return certForTask(s.CertTaskID), h2
			}
		}
	}
	// 2. 域名自动匹配（精确 > 逐级父域通配）
	if id := lookupDomain(host); id != 0 {
		return certForTask(id), h2
	}
	// 3. 未匹配到域名证书：兜底剩余有效期最长的证书，避免直接中断握手
	if c := sslLongestLocked(); c != nil {
		if !sslMiss[host] {
			sslMiss[host] = true
			core.LogWarn(core.LogProxy, "SNI 域名 "+host+" 无匹配证书，已兜底使用其他证书（浏览器会提示证书名称不匹配）")
		}
		return c, h2
	}
	return nil, h2
}

// siteFrontH2 前端是否通告 h2：命中该域名的启用站点只要有一个关了 h2 就关（无站点则保持默认 h2）。
func siteFrontH2(host string, sites []*Site) bool {
	for _, s := range sites {
		if s.Enabled && s.matchDomain(host) && !s.Adv.FrontH2() {
			return false
		}
	}
	return true
}

// lookupDomain 域名查表：精确 -> *.一级父域 -> *.二级父域 ...（nginx 通配最长匹配语义）。
func lookupDomain(host string) int64 {
	if id := sslDomain[host]; id != 0 {
		return id
	}
	for {
		dot := strings.IndexByte(host, '.')
		if dot <= 0 {
			return 0
		}
		parent := host[dot+1:]
		if id := sslDomain["*."+parent]; id != 0 {
			return id
		}
		next := strings.IndexByte(parent, '.')
		if next <= 0 {
			return 0
		}
		host = parent
	}
}

// certForTask 任务 -> tls.Certificate（懒构建：SNI 首握手时加载，reload 后失效重建）。
func certForTask(taskID int64) *tls.Certificate {
	if c, ok := sslKeyPair[taskID]; ok {
		return c
	}
	e := sslByTask[taskID]
	if e == nil {
		return nil // 任务不在证书库（未装载或证书不可用）
	}
	c, err := buildKeyPair(e.keyFile, e.certFile)
	if err != nil {
		core.LogError(core.LogProxy, fmt.Sprintf("构建证书任务 #%d 的 TLS 上下文失败: %s", taskID, err.Error()))
		return nil
	}
	sslKeyPair[taskID] = c
	return c
}

// sslLongestLocked 兜底选证：剩余有效期最长的一张（调用方持 sslMu）。
func sslLongestLocked() *tls.Certificate {
	var best *certEntry
	for _, e := range sslOrders {
		if best == nil || e.notAfter.After(best.notAfter) {
			best = e
		}
	}
	if best == nil {
		return nil
	}
	return certForTask(best.taskID)
}

func certTaskDir(taskID int64) string {
	return filepath.Join(core.DataDir(), "certs", "task-"+fmt.Sprint(taskID))
}

// certFiles 定位任务的私钥与证书文件（证书 fullchain 优先，缺失回退 cert.pem）。
// 查找顺序：
//  1. 任务行 cert_dir（老库迁移后行内记录的绝对路径）；
//  2. 默认布局 data/certs/task-{id}/；
//  3. 任务保存目录 save_dir 中按域名命名的 {域名}.key + {域名}.fullchain.pem|{域名}.pem
//     —— 任务目录丢失、只剩同步副本时的兜底，避免证书文件明确存在却无法识别。
func certFiles(task *core.Row) (keyFile, certFile string, err error) {
	dirs := make([]string, 0, 2)
	if d := strings.TrimSpace(strVal(task.Get("cert_dir"))); d != "" {
		dirs = append(dirs, d)
	}
	dirs = append(dirs, certTaskDir(int64Val(task.Get("id"))))
	for _, dir := range dirs {
		if k, c, ok := layoutFiles(dir); ok {
			return k, c, nil
		}
	}
	if sd := strings.TrimSpace(strVal(task.Get("save_dir"))); sd != "" {
		if k, c, ok := savedFiles(sd, splitDomains(strVal(task.Get("domains")))); ok {
			return k, c, nil
		}
	}
	return "", "", fmt.Errorf("证书文件缺失: %s", dirs[len(dirs)-1])
}

// layoutFiles 标准布局探测：domain.key.pem + fullchain.pem（缺失回退 cert.pem）。
func layoutFiles(dir string) (string, string, bool) {
	k := filepath.Join(dir, "domain.key.pem")
	if _, err := readFileIfExists(k); err != nil {
		return "", "", false
	}
	c := filepath.Join(dir, "fullchain.pem")
	if _, err := readFileIfExists(c); err != nil {
		c = filepath.Join(dir, "cert.pem")
		if _, err := readFileIfExists(c); err != nil {
			return "", "", false
		}
	}
	return k, c, true
}

// savedFiles 在保存目录中按任务域名查找 {域名}.key 与 {域名}.fullchain.pem / {域名}.pem。
func savedFiles(dir string, domains []string) (string, string, bool) {
	for _, d := range domains {
		base := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")
		if base == "" {
			continue
		}
		k := filepath.Join(dir, base+".key")
		if _, err := readFileIfExists(k); err != nil {
			continue
		}
		c := filepath.Join(dir, base+".fullchain.pem")
		if _, err := readFileIfExists(c); err != nil {
			c = filepath.Join(dir, base+".pem")
		}
		if _, err := readFileIfExists(c); err == nil {
			return k, c, true
		}
	}
	return "", "", false
}

// splitDomains 解析任务域名串（逗号/分号/空白分隔，与 SSL 证书模块一致）。
func splitDomains(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func buildKeyPair(keyFile, certFile string) (*tls.Certificate, error) {
	keyPEM, err := readFileIfExists(keyFile)
	if err != nil {
		return nil, fmt.Errorf("私钥文件缺失: %s", keyFile)
	}
	certPEM, err := readFileIfExists(certFile)
	if err != nil {
		return nil, fmt.Errorf("证书文件缺失: %s", certFile)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &kp, nil
}

// loadCertEntry 加载并解析单个任务的证书（叶子证书 SAN DNS 名单 + 到期时间）。
func loadCertEntry(task *core.Row) (*certEntry, error) {
	keyFile, certFile, err := certFiles(task)
	if err != nil {
		return nil, err
	}
	certPEM, err := readFileIfExists(certFile)
	if err != nil {
		return nil, fmt.Errorf("证书文件缺失: %s", certFile)
	}
	var leaf *x509.Certificate
	var first *x509.Certificate
	for rest := certPEM; ; {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		rest = r
		if b.Type != "CERTIFICATE" {
			continue
		}
		cs, err := x509.ParseCertificates(b.Bytes)
		if err != nil {
			continue
		}
		for _, c := range cs {
			if first == nil {
				first = c
			}
			if !c.IsCA {
				leaf = c
				break
			}
		}
		if leaf != nil {
			break
		}
	}
	if leaf == nil {
		leaf = first
	}
	if leaf == nil {
		return nil, fmt.Errorf("证书文件中没有 X.509 证书")
	}
	domains := make([]string, 0, len(leaf.DNSNames))
	for _, d := range leaf.DNSNames {
		domains = append(domains, strings.ToLower(d))
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("证书不含 SAN 域名")
	}
	return &certEntry{
		taskID:   int64Val(task.Get("id")),
		name:     strVal(task.Get("name")),
		keyFile:  keyFile,
		certFile: certFile,
		domains:  domains,
		notAfter: leaf.NotAfter,
	}, nil
}

// instantString Java Instant.toString 形态：UTC，秒/纳秒为 0 时省略秒字段。
func instantString(t time.Time) string {
	u := t.UTC()
	if u.Second() == 0 && u.Nanosecond() == 0 {
		return u.Format("2006-01-02T15:04Z")
	}
	return u.Format(time.RFC3339)
}
