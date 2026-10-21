package cert

// SSL 证书申请与自动续期服务（复刻 Java CertService，ACME 协议为 Go 侧手写的 RFC8555 实现）。
// 服务商：Let's Encrypt（无需额外凭证）与 ZeroSSL（需要在其控制台生成 EAB 凭证：EAB KID 与
// EAB HMAC Key，在"设置"页配置，存于 app_config 表）。
// 域名验证方式：
//   - HTTP01：全自动。CA 访问 http://域名/.well-known/acme-challenge/token，由本程序内置
//     Web 服务器应答，要求 80 端口可被公网访问（或路由器 80 端口转发到本服务端口）。
//   - DNS01：引用服务商凭证配置时全自动写入 TXT（支持云解析与 ESA 托管的域名）；
//     未引用时为半自动——程序生成需要添加的 DNS TXT 记录，用户在域名服务商处添加后点击"完成验证"。
// 证书文件保存在 data/certs/task-{id}/：私钥、证书、完整证书链（PEM）。

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/module/ddns"
	"NexHomeGo/internal/module/provider"
	"NexHomeGo/internal/web"
)

// renewAheadDays 续期提前天数：到期前 21 天自动续期。
const renewAheadDays = 21

// defaultSaveDir 默认证书保存目录（与 Docker 部署的数据目录一致）：任务未填写 save_dir 时使用。
const defaultSaveDir = "/app/data/ssl"

// proxyCertRenewed 反向代理中心证书热加载钩子（proxy 模块落地后由 main 注入，等价 Java ProxyService.onCertRenewed）。
var proxyCertRenewed func()

// SetProxyCertRenewedHook 注入代理模块的证书热加载回调。
func SetProxyCertRenewedHook(fn func()) { proxyCertRenewed = fn }

// challengeMu + challenges http-01 校验：token -> keyAuthorization（由内置 Web 服务器对外应答）。
var (
	challengeMu sync.RWMutex
	challenges  = map[string]string{}
	domainRe    = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)
	unsafeRe    = regexp.MustCompile(`[^a-zA-Z0-9.\-]`)
	// 证书同步 webhook 共享 HTTP 客户端（连接超时 10s，请求超时 20s，与 Java WEBHOOK_HTTP 一致）
	webhookHTTP = &http.Client{
		Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext},
		Timeout:   20 * time.Second,
	}
)

// RegisterRoutes 注册 REST 接口（路径/方法与 Java CertService.registerRoutes 一致）。
func RegisterRoutes() {
	web.Route("GET", "/api/cert/tasks", func(c *web.Ctx) error {
		rows, err := core.Query("SELECT * FROM cert_task ORDER BY id")
		if err != nil {
			return err
		}
		c.Ok(core.Rows(rows))
		return nil
	})
	web.Route("POST", "/api/cert/tasks", create)
	web.Route("PUT", "/api/cert/tasks/{id}", update)
	web.Route("DELETE", "/api/cert/tasks/{id}", remove)
	// 发起申请/续期
	web.Route("POST", "/api/cert/tasks/{id}/issue", func(c *web.Ctx) error {
		id := c.ParamLong("id")
		if _, err := mustGet(id); err != nil {
			return err
		}
		core.LogInfo(core.LogCert, fmt.Sprintf("手动发起证书申请 #%d", id))
		core.Run(func() { issue(id, "手动申请") })
		c.Ok("申请已发起，请刷新列表查看进度")
		return nil
	})
	// DNS01 手动模式：用户添加 TXT 记录后点击"完成验证"
	web.Route("POST", "/api/cert/tasks/{id}/validate", func(c *web.Ctx) error {
		id := c.ParamLong("id")
		if _, err := mustGet(id); err != nil {
			return err
		}
		core.Run(func() { validateDns(id) })
		c.Ok("已提交验证，等待 CA 校验 DNS 记录")
		return nil
	})
	// 证书详情（有效期/域名/指纹等）
	web.Route("GET", "/api/cert/tasks/{id}/detail", func(c *web.Ctx) error {
		d, err := certDetail(c.ParamLong("id"))
		if err != nil {
			return err
		}
		c.Ok(d)
		return nil
	})
	// 证书文件下载：?file=key|cert|fullchain
	web.Route("GET", "/api/cert/tasks/{id}/download", download)
	// 服务商凭证设置（ZeroSSL EAB / 联系邮箱）；default_save_dir 供前端新增任务时预填默认保存目录
	web.Route("GET", "/api/cert/settings", func(c *web.Ctx) error {
		r := core.NewRow().
			Set("email", cfg("acme.email", "")).
			Set("zerossl_eab_kid", cfg("zerossl.eab_kid", "")).
			Set("zerossl_eab_hmac", cfg("zerossl.eab_hmac", "")).
			Set("default_save_dir", defaultSaveDir)
		c.Ok(r)
		return nil
	})
	web.Route("PUT", "/api/cert/settings", func(c *web.Ctx) error {
		b := c.Body()
		if err := core.SetConfig("acme.email", core.BodyStr(b, "email")); err != nil {
			return err
		}
		if err := core.SetConfig("zerossl.eab_kid", core.BodyStr(b, "zerossl_eab_kid")); err != nil {
			return err
		}
		if err := core.SetConfig("zerossl.eab_hmac", core.BodyStr(b, "zerossl_eab_hmac")); err != nil {
			return err
		}
		core.LogInfo(core.LogCert, "更新证书服务设置（邮箱/ZeroSSL EAB）")
		c.Ok("已保存")
		return nil
	})
	// http-01 校验应答（免登录，由 serveHTTP 在安全入口/跳转拦截前分发）
	web.Route("GET", "/.well-known/acme-challenge/{token}", func(c *web.Ctx) error {
		challengeMu.RLock()
		auth, ok := challenges[c.Param("token")]
		challengeMu.RUnlock()
		if !ok {
			c.Text(404, "challenge not found", "text/plain")
			return nil
		}
		c.Text(200, auth, "text/plain")
		return nil
	})
}

// Init 启动初始化：旧库升级列 + 重置中断签发状态 + 启动自动续期检查。
func Init() {
	ensureColumn("provider_config_id", "INTEGER") // 旧库升级：DNS01 自动验证引用凭证配置
	ensureColumn("save_dir", "TEXT")              // 旧库升级：可选的证书保存目录
	ensureColumn("webhook_url", "TEXT")           // 旧库升级：可选的证书同步 webhook
	// 重启恢复：ISSUING 是纯内存的在途状态，进程重启后不会有线程继续。
	// 若残留说明上次签发被中断（容器重启/异常退出/panic 绕过捕获），置为 ERROR 提示重新申请，
	// 避免前端永久停留在"正在签发证书..."的假象。
	stale, err := core.Update("UPDATE cert_task SET status='ERROR', message=? WHERE status='ISSUING'",
		"上次签发未完成（程序可能已重启或异常退出），请重新点击「申请」")
	if err == nil && stale > 0 {
		core.LogWarn(core.LogCert, "已重置 "+fmt.Sprintf("%d", stale)+" 个中断的证书签发任务（ISSUING → ERROR）")
	}
	// 每小时检查一次证书有效期
	core.Every(60, 3600, autoRenewCheck)
	core.LogInfo(core.LogCert, fmt.Sprintf("证书自动续期检查已启动（每小时，到期前 %d 天续期）", renewAheadDays))
}

// ensureColumn 旧库升级：补充缺失列（新库建表脚本已包含）。
func ensureColumn(name, typ string) {
	rows, err := core.Query("PRAGMA table_info(cert_task)")
	if err != nil {
		return
	}
	for _, col := range rows {
		if s, ok := col.Get("name").(string); ok && s == name {
			return
		}
	}
	_, _ = core.Update("ALTER TABLE cert_task ADD COLUMN " + name + " " + typ)
}

// ---------- 增删改 ----------

func create(c *web.Ctx) error {
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	id, err := core.Insert(`INSERT INTO cert_task(name, provider, domains, challenge_type, provider_config_id, auto_renew, save_dir, webhook_url)
		VALUES(?,?,?,?,?,?,?,?)`,
		core.BodyStr(b, "name"), core.BodyStr(b, "provider"),
		normalizeDomains(core.BodyStr(b, "domains")),
		core.BodyStr(b, "challenge_type"),
		providerConfigArg(b),
		boolToInt(core.BodyBool(b, "auto_renew", true)),
		resolveSaveDir(b),
		strings.TrimSpace(core.BodyStr(b, "webhook_url")))
	if err != nil {
		return err
	}
	core.LogInfo(core.LogCert, "新增证书任务: "+core.BodyStr(b, "name"))
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(task)
	return nil
}

func update(c *web.Ctx) error {
	id := c.ParamLong("id")
	if _, err := mustGet(id); err != nil {
		return err
	}
	b := c.Body()
	if err := validate(b); err != nil {
		return err
	}
	_, err := core.Update(`UPDATE cert_task SET name=?, provider=?, domains=?, challenge_type=?, provider_config_id=?, auto_renew=?, save_dir=?, webhook_url=? WHERE id=?`,
		core.BodyStr(b, "name"), core.BodyStr(b, "provider"),
		normalizeDomains(core.BodyStr(b, "domains")),
		core.BodyStr(b, "challenge_type"),
		providerConfigArg(b),
		boolToInt(core.BodyBool(b, "auto_renew", true)),
		resolveSaveDir(b),
		strings.TrimSpace(core.BodyStr(b, "webhook_url")), id)
	if err != nil {
		return err
	}
	core.LogInfo(core.LogCert, "更新证书任务 #"+fmt.Sprintf("%d", id)+": "+core.BodyStr(b, "name"))
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	c.Ok(task)
	return nil
}

func remove(c *web.Ctx) error {
	id := c.ParamLong("id")
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	if _, err := core.Update("DELETE FROM cert_task WHERE id=?", id); err != nil {
		return err
	}
	// 同时清理磁盘上的证书文件
	dir := taskDir(id)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
		_ = os.Remove(dir)
	}
	core.LogInfo(core.LogCert, "删除证书任务 #"+fmt.Sprintf("%d", id)+": "+taskStr(task, "name"))
	c.Ok("已删除")
	return nil
}

func validate(b map[string]interface{}) error {
	if strings.TrimSpace(core.BodyStr(b, "name")) == "" {
		return core.NewBadRequest("任务名称不能为空")
	}
	providerName := core.BodyStr(b, "provider")
	if _, ok := providerDirs[providerName]; !ok {
		return core.NewBadRequest("服务商必须为 LETSENCRYPT 或 ZEROSSL")
	}
	ct := core.BodyStr(b, "challenge_type")
	if ct != "HTTP01" && ct != "DNS01" {
		return core.NewBadRequest("验证方式必须为 HTTP01 或 DNS01")
	}
	domains := domainList(core.BodyStr(b, "domains"))
	if len(domains) == 0 {
		return core.NewBadRequest("域名不能为空")
	}
	for _, d := range domains {
		if !domainRe.MatchString(d) {
			return core.NewBadRequest("域名格式不正确: %s", d)
		}
	}
	webhook := strings.TrimSpace(core.BodyStr(b, "webhook_url"))
	if webhook != "" && !strings.HasPrefix(webhook, "http://") && !strings.HasPrefix(webhook, "https://") {
		return core.NewBadRequest("Webhook 地址必须以 http:// 或 https:// 开头")
	}
	return nil
}

// ---------- ACME 申请主流程 ----------

// issue 发起证书申请/续期。HTTP01 全自动完成；DNS01 引用凭证时全自动，否则等待用户添加 TXT 后 validateDns。
func issue(taskID int64, trigger string) {
	defer func() {
		if rec := recover(); rec != nil {
			// 捕获 panic（含运行时严重错误）：签发链路任何未预期错误都要落库为 ERROR，
			// 否则任务会永久卡在 ISSUING
			fail(taskID, trigger+"失败: "+fmt.Sprint(rec))
		}
	}()
	if err := doIssue(taskID, trigger); err != nil {
		fail(taskID, trigger+"失败: "+err.Error())
	}
}

func doIssue(taskID int64, trigger string) error {
	task, err := mustGet(taskID)
	if err != nil {
		return err
	}
	name := taskStr(task, "name")
	providerName := taskStr(task, "provider")
	challengeType := taskStr(task, "challenge_type")
	domains := domainList(taskStr(task, "domains"))
	setStatus(taskID, "ISSUING", trigger+"：正在创建订单...", nil)
	core.LogInfo(core.LogCert, "任务["+name+"] 发起证书申请("+providerName+"/"+challengeType+"): "+joinDomains(domains))

	client, err := acmeAccount(providerName)
	if err != nil {
		return err
	}
	order, err := client.newOrder(domains)
	if err != nil {
		return err
	}
	if err := core.SetConfig("cert."+fmt.Sprintf("%d", taskID)+".order", order.URL); err != nil {
		return err
	}

	if challengeType == "HTTP01" {
		// 以实际监听端口为准（启动期端口自愈后可能与配置值不同），否则转发提示会误导
		httpPort := web.HTTPPort()
		if httpPort != 80 {
			core.LogWarn(core.LogCert, "任务["+name+"] 当前服务端口非 80，http-01 验证需保证 CA 能访问 80 端口"+
				"（可配置路由器端口转发 80 -> "+fmt.Sprintf("%d", httpPort)+"）")
		}
		challengeMu.Lock()
		challenges = map[string]string{}
		challengeMu.Unlock()
		for _, authURL := range order.Authorizations {
			a, err := client.fetchAuth(authURL)
			if err != nil {
				return err
			}
			if a.Status == "valid" {
				continue
			}
			ch, err := a.findChallenge("http-01")
			if err != nil {
				return err
			}
			// 先注册应答内容，再通知 CA 来校验
			auth := keyAuthorization(ch.Token, client.jwkJSON)
			challengeMu.Lock()
			challenges[ch.Token] = auth
			challengeMu.Unlock()
			if err := client.triggerChallenge(ch.URL); err != nil {
				return err
			}
			core.LogInfo(core.LogCert, "任务["+name+"] http-01 已应答: "+
				a.Domain+"/.well-known/acme-challenge/"+ch.Token)
		}
		if err := waitAuthorizations(client, order, 120*time.Second); err != nil {
			return err
		}
		return finalizeAndDownload(taskID, task, client, order, domains)
	}

	// DNS01：引用服务商凭证配置时全自动（写入 TXT -> 触发校验 -> 签发后清理），
	// 未引用时收集提示等待用户添加 TXT 后点「完成验证」
	cred, err := dnsCredentials(task)
	if err != nil {
		return err
	}
	if cred != nil {
		added := []txtRecord{}
		defer func() { cleanupTxt(cred, added) }() // 验证完成/失败后均清理自动写入的 TXT
		for _, authURL := range order.Authorizations {
			a, err := client.fetchAuth(authURL)
			if err != nil {
				return err
			}
			if a.Status == "valid" {
				continue
			}
			ch, err := a.findChallenge("dns-01")
			if err != nil {
				return err
			}
			domain := a.Domain
			digest := dns01Digest(keyAuthorization(ch.Token, client.jwkJSON))
			txt, err := autoApplyTxt(cred, domain, digest)
			if err != nil {
				return err
			}
			added = append(added, txt)
			if err := client.triggerChallenge(ch.URL); err != nil {
				return err
			}
			core.LogInfo(core.LogCert, "任务["+name+"] dns-01 已自动写入"+txt.channelName()+
				" TXT: _acme-challenge."+domain)
		}
		if err := waitAuthorizations(client, order, 180*time.Second); err != nil {
			return err
		}
		return finalizeAndDownload(taskID, task, client, order, domains)
	}

	var hint strings.Builder
	for _, authURL := range order.Authorizations {
		a, err := client.fetchAuth(authURL)
		if err != nil {
			return err
		}
		if a.Status == "valid" {
			continue
		}
		ch, err := a.findChallenge("dns-01")
		if err != nil {
			return err
		}
		digest := dns01Digest(keyAuthorization(ch.Token, client.jwkJSON))
		hint.WriteString("记录类型: TXT\n主机记录: _acme-challenge." + a.Domain +
			"\n记录值: " + digest + "\n\n")
	}
	_, err = core.Update("UPDATE cert_task SET status='PENDING_VALIDATION', dns_hint=?, message=? WHERE id=?",
		hint.String(),
		"请前往域名服务商添加以上 TXT 记录（等待生效后）点击\"完成验证\"", taskID)
	if err != nil {
		return err
	}
	core.LogInfo(core.LogCert, "任务["+name+"] 等待用户添加 DNS TXT 记录")
	return nil
}

// validateDns DNS01 第二步：用户添加 TXT 记录后触发验证并完成签发。
func validateDns(taskID int64) {
	defer func() {
		if rec := recover(); rec != nil {
			fail(taskID, "DNS验证失败: "+fmt.Sprint(rec))
		}
	}()
	if err := doValidateDns(taskID); err != nil {
		fail(taskID, "DNS验证失败: "+err.Error())
	}
}

func doValidateDns(taskID int64) error {
	task, err := mustGet(taskID)
	if err != nil {
		return err
	}
	setStatus(taskID, "ISSUING", "正在请求 CA 校验 DNS 记录...", nil)
	providerName := taskStr(task, "provider")
	client, err := acmeBind(providerName)
	if err != nil {
		return err
	}
	orderURL, err := core.GetConfig("cert." + fmt.Sprintf("%d", taskID) + ".order")
	if err != nil {
		return err
	}
	if orderURL == "" {
		return errors.New("订单不存在，请先发起申请")
	}
	order, err := client.fetchOrder(orderURL)
	if err != nil {
		return err
	}
	for _, authURL := range order.Authorizations {
		a, err := client.fetchAuth(authURL)
		if err != nil {
			return err
		}
		if a.Status == "valid" {
			continue
		}
		for i := range a.Challenges {
			if a.Challenges[i].Type != "dns-01" {
				continue
			}
			// 通知 CA 开始校验 TXT 记录
			if err := client.triggerChallenge(a.Challenges[i].URL); err != nil {
				return fmt.Errorf("触发验证失败: %w", err)
			}
		}
	}
	if err := waitAuthorizations(client, order, 180*time.Second); err != nil {
		return err
	}
	return finalizeAndDownload(taskID, task, client, order, domainList(taskStr(task, "domains")))
}

// waitAuthorizations 等待全部授权完成（等价 acme4j waitForCompletion）。
func waitAuthorizations(c *acmeClient, order *acmeOrder, timeout time.Duration) error {
	for _, authURL := range order.Authorizations {
		a, err := c.fetchAuth(authURL)
		if err != nil {
			return err
		}
		if a.Status == "valid" {
			continue
		}
		a, err = c.waitAuth(authURL, timeout)
		if err != nil {
			return err
		}
		if a.Status != "valid" {
			return fmt.Errorf("域名 %s 验证未通过(%s)，请检查验证配置后重试", a.Domain, strings.ToUpper(a.Status))
		}
	}
	return nil
}

// finalizeAndDownload 生成私钥与 CSR，提交签发并保存证书文件。
func finalizeAndDownload(taskID int64, task *core.Row, client *acmeClient, order *acmeOrder, domains []string) error {
	setStatus(taskID, "ISSUING", "验证通过，正在签发证书...", nil)
	dir := taskDir(taskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// 域名私钥：RSA 2048（兼容性最好）
	domainKey, err := generateRSA2048()
	if err != nil {
		return err
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(domainKey)
	if err != nil {
		return err
	}
	keyPem := pemEncode("PRIVATE KEY", keyDer)
	if err := os.WriteFile(filepath.Join(dir, "domain.key.pem"), []byte(keyPem), 0o600); err != nil {
		return err
	}

	// 构造 CSR 并提交订单
	csrDER, err := buildCSR(domainKey, domains)
	if err != nil {
		return err
	}
	o, err := client.finalize(order.URL, order.Finalize, csrDER)
	if err != nil {
		return err
	}
	o, err = client.waitOrder(o.URL, 60*time.Second)
	if err != nil {
		return err
	}
	if o.Status != "valid" {
		return errors.New("签发失败，订单状态: " + strings.ToUpper(o.Status))
	}

	// 保存证书与完整证书链
	chainPEM, err := client.getCertChain(o.Certificate)
	if err != nil {
		return err
	}
	leafDer, fullchainPem, err := splitChain(chainPEM)
	if err != nil {
		return err
	}
	certPem := pemEncode("CERTIFICATE", leafDer)
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(certPem), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte(fullchainPem), 0o644); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(leafDer)
	if err != nil {
		return err
	}
	notAfter := leaf.NotAfter.UTC().Format(time.RFC3339)
	if _, err := core.Update(`UPDATE cert_task SET status='ISSUED', message=?, dns_hint=NULL, not_after=?, cert_dir=? WHERE id=?`,
		"证书签发成功", notAfter, dir, taskID); err != nil {
		return err
	}
	core.LogInfo(core.LogCert, "任务["+taskStr(task, "name")+"] 证书签发成功，域名: "+joinDomains(domains)+
		"，有效期至 "+leaf.NotAfter.Format("2006-01-02 15:04:05"))

	// 可选：按任务配置同步到自定义保存目录、推送到 webhook（任一失败不影响已签发证书，仅记日志）
	saveToCustomDir(taskStr(task, "save_dir"), domains, keyDer, leafDer, fullchainPem)
	pushWebhook(taskStr(task, "webhook_url"), task, domains, keyPem, certPem, fullchainPem,
		leaf.NotBefore.UTC(), leaf.NotAfter.UTC())
	// HTTPS 正在使用该证书时自动重启 Web 服务，加载续期后的新证书
	web.OnCertRenewed(taskID)
	// 反向代理中心：热加载证书库，使 SNI 立即用上续期后的新证书
	if proxyCertRenewed != nil {
		proxyCertRenewed()
	}
	return nil
}

// splitChain 拆分证书链 PEM：返回叶子 DER 与按序重编码的完整链文本（等价 acme4j getCertificate/getCertificateChain）。
func splitChain(chainPEM string) (leafDer []byte, fullchain string, err error) {
	rest := []byte(chainPEM)
	var sb strings.Builder
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		sb.WriteString(pemEncode("CERTIFICATE", blk.Bytes))
		if leafDer == nil {
			leafDer = blk.Bytes
		}
	}
	if leafDer == nil {
		return nil, "", errors.New("CA 返回的证书链为空或格式不正确")
	}
	return leafDer, sb.String(), nil
}

// autoRenewCheck 定时自动续期：到期前 renewAheadDays 天自动重新申请。
func autoRenewCheck() {
	defer func() {
		if rec := recover(); rec != nil {
			core.LogError(core.LogCert, "自动续期检查异常: "+fmt.Sprint(rec))
		}
	}()
	rows, err := core.Query("SELECT * FROM cert_task WHERE auto_renew=1 AND status='ISSUED' AND not_after IS NOT NULL")
	if err != nil {
		core.LogError(core.LogCert, "自动续期检查异常: "+err.Error())
		return
	}
	for _, task := range rows {
		notAfter, err := time.Parse(time.RFC3339, taskStr(task, "not_after"))
		if err != nil {
			core.LogError(core.LogCert, "自动续期检查异常: "+err.Error())
			return // 与 Java 一致：解析失败中断本轮检查
		}
		if notAfter.Before(time.Now().Add(time.Duration(renewAheadDays) * 24 * time.Hour)) {
			core.LogInfo(core.LogCert, "任务["+taskStr(task, "name")+"] 即将到期("+taskStr(task, "not_after")+")，自动续期")
			issue(taskID(task), "自动续期")
		}
	}
}

// ---------- 证书详情与下载 ----------

// certDetail 读取已签发证书的详细信息。
// 说明：subject/issuer 文本为展示用途，Java X500Principal.getName() 采用 RFC2253 逆序输出，
// Go x509 按证书 RDN 原序输出，属性顺序可能不同，内容一致。
func certDetail(taskID int64) (*core.Row, error) {
	task, err := mustGet(taskID)
	if err != nil {
		return nil, err
	}
	result := core.NewRow().Set("task", task)
	certFile := filepath.Join(taskDir(taskID), "cert.pem")
	data, err := os.ReadFile(certFile)
	if err != nil {
		result.Set("hasCert", false)
		return result, nil
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		result.Set("hasCert", false)
		return result, nil
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	sans := make([]string, 0, len(cert.DNSNames))
	sans = append(sans, cert.DNSNames...) // SAN type-2（DNS），等价 Java getSubjectAlternativeNames 过滤
	sum := sha256.Sum256(blk.Bytes)
	result.Set("hasCert", true).
		Set("subject", cert.Subject.String()).
		Set("issuer", cert.Issuer.String()).
		Set("domains", sans).
		Set("notBefore", cert.NotBefore.UTC().Format(time.RFC3339)).
		Set("notAfter", cert.NotAfter.UTC().Format(time.RFC3339)).
		Set("serial", cert.SerialNumber.Text(16)).
		Set("sha256", hex.EncodeToString(sum[:]))
	return result, nil
}

func download(c *web.Ctx) error {
	id := c.ParamLong("id")
	task, err := mustGet(id)
	if err != nil {
		return err
	}
	file := c.Query("file")
	var p string
	switch file {
	case "key":
		p = filepath.Join(taskDir(id), "domain.key.pem")
	case "cert":
		p = filepath.Join(taskDir(id), "cert.pem")
	case "fullchain":
		p = filepath.Join(taskDir(id), "fullchain.pem")
	default:
		return core.NewBadRequest("不支持的文件类型: %s", file)
	}
	if _, err := os.Stat(p); err != nil {
		return core.NewBadRequest("文件尚未生成，请先成功申请证书")
	}
	if err := c.File(p, taskStr(task, "name")+"-"+file+".pem"); err != nil {
		return err
	}
	core.LogInfo(core.LogCert, "下载证书文件: 任务#"+fmt.Sprintf("%d", id)+" "+file)
	return nil
}

// ---------- DNS01 自动验证（引用服务商凭证配置） ----------

// dnsCred DNS01 自动验证凭证上下文：阿里云 AK/SK + 凭证配置中可选的 ESA 站点（域名托管在 ESA 时降级使用）。
type dnsCred struct {
	ak        string
	sk        string
	esaSiteId string
}

// txtRecord 自动写入的 TXT 记录：channel 标识写入通道（DNS=云解析 / ESA=边缘安全加速），验证后按原通道删除。
type txtRecord struct {
	channel  string
	recordId string // 空串等价 Java null：复用的已有记录，无需清理
}

func (t txtRecord) channelName() string {
	if t.channel == "ESA" {
		return "阿里云ESA"
	}
	return "阿里云云解析"
}

// dnsCredentials 任务引用的服务商凭证（DNS01 自动模式）；未引用配置返回 nil。
func dnsCredentials(task *core.Row) (*dnsCred, error) {
	pid, ok := task.Get("provider_config_id").(int64)
	if !ok {
		return nil, nil
	}
	ak, sk, err := provider.Credentials(pid)
	if err != nil {
		return nil, err
	}
	site, err := provider.ESASiteID(pid)
	if err != nil {
		return nil, err
	}
	return &dnsCred{ak: ak, sk: sk, esaSiteId: site}, nil
}

// autoApplyTxt 向阿里云写入 dns-01 TXT 记录并返回写入结果，供验证结束后按原通道清理。
// 授权域可能是主域或其子域（泛域名授权的 identifier 为主域），而云解析接口的 DomainName 参数
// 必须是账户内的主域：优先整域探测，失败逐级剥离左段重试（最多三层）。
// 已存在相同值的 TXT 直接复用（如上次失败残留），避免重复添加。
// 云解析全部探测失败且凭证配置填写了 ESA 站点时，说明域名解析托管在 ESA，降级改走 ESA 记录接口。
func autoApplyTxt(cred *dnsCred, domain, value string) (txtRecord, error) {
	parts := strings.Split(domain, ".")
	maxStrip := 2
	if len(parts)-2 < maxStrip {
		maxStrip = len(parts) - 2
	}
	var lastErr error
	for strip := 0; strip <= maxStrip; strip++ {
		zone := strings.Join(parts[strip:], ".")
		rr := "_acme-challenge"
		if strip > 0 {
			rr = "_acme-challenge." + strings.Join(parts[:strip], ".")
		}
		records, err := ddns.DnsDescribeRecords(cred.ak, cred.sk, zone, "_acme-challenge")
		if err != nil {
			var ae *ddns.APIError
			if errors.As(err, &ae) {
				lastErr = err // 域名不在当前账户/不存在：剥离左段继续探测主域
				continue
			}
			return txtRecord{}, err // 网络等其他异常直接上抛（与 Java 一致）
		}
		for _, r := range records {
			if strings.EqualFold(fieldStr(r, "RR"), rr) &&
				strings.EqualFold(fieldStr(r, "Type"), "TXT") &&
				value == fieldStr(r, "Value") {
				return txtRecord{channel: "DNS"}, nil // 已有相同值记录，无需重复添加
			}
		}
		id, err := ddns.DnsAddRecord(cred.ak, cred.sk, zone, rr, "TXT", value, 600)
		if err != nil {
			var ae *ddns.APIError
			if errors.As(err, &ae) {
				lastErr = err
				continue
			}
			return txtRecord{}, err
		}
		return txtRecord{channel: "DNS", recordId: id}, nil
	}
	if strings.TrimSpace(cred.esaSiteId) != "" {
		return esaApplyTxt(cred, domain, value)
	}
	msg := ""
	if lastErr != nil {
		msg = lastErr.Error()
	}
	return txtRecord{}, fmt.Errorf("自动写入 TXT 失败（无法定位 %s 的主域；若域名解析托管在阿里云 ESA，"+
		"请在所引用的凭证配置中填写 ESA 站点 SiteId）: %s", domain, msg)
}

// esaApplyTxt ESA 托管域名：向站点写入 _acme-challenge TXT（ESA 记录名为完整记录名）。
func esaApplyTxt(cred *dnsCred, domain, value string) (txtRecord, error) {
	fullName := "_acme-challenge." + domain
	records, err := ddns.EsaListRecords(cred.ak, cred.sk, cred.esaSiteId, fullName)
	if err != nil {
		return txtRecord{}, fmt.Errorf("ESA 写入 TXT 失败（请检查凭证配置的 ESA 站点 SiteId 是否为 %s 所在站点）: %w", domain, err)
	}
	for _, r := range records {
		data := fieldObj(r, "Data")
		if strings.EqualFold(fieldStr(r, "Type"), "TXT") && data != nil && value == fieldStr(data, "Value") {
			return txtRecord{channel: "ESA"}, nil // 已有相同值记录，无需重复添加
		}
	}
	id, err := ddns.EsaCreateRecord(cred.ak, cred.sk, cred.esaSiteId, fullName, "TXT", value, 600)
	if err != nil {
		return txtRecord{}, fmt.Errorf("ESA 写入 TXT 失败（请检查凭证配置的 ESA 站点 SiteId 是否为 %s 所在站点）: %w", domain, err)
	}
	return txtRecord{channel: "ESA", recordId: id}, nil
}

// cleanupTxt 验证结束后清理自动写入的 TXT 记录（CA 已缓存验证结果，删除不影响签发；失败仅记日志）。
func cleanupTxt(cred *dnsCred, added []txtRecord) {
	if cred == nil {
		return
	}
	for _, t := range added {
		if t.recordId == "" {
			continue // 复用的已有记录，无需清理
		}
		var err error
		if t.channel == "ESA" {
			err = ddns.EsaDeleteRecord(cred.ak, cred.sk, t.recordId)
		} else {
			err = ddns.DnsDeleteRecord(cred.ak, cred.sk, t.recordId)
		}
		if err != nil {
			core.LogWarn(core.LogCert, "清理 dns-01 TXT 记录失败("+t.channel+" RecordId="+t.recordId+"): "+err.Error())
		}
	}
}

// ---------- ACME 账号管理 ----------

// acmeAccount 获取或创建 ACME 账号（按服务商独立，密钥持久化在 data/certs/acme/ 下），返回绑定账号的客户端。
func acmeAccount(providerName string) (*acmeClient, error) {
	dir := filepath.Join(core.DataDir(), "certs", "acme", strings.ToLower(providerName))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	keyFile := filepath.Join(dir, "account.pem")
	locKey := "cert.account." + providerName

	// EAB 凭证完整性检查前置（避免配置缺失时先发起 CA 网络请求）
	eab, err := eabFor(providerName)
	if err != nil {
		return nil, err
	}
	loc, err := core.GetConfig(locKey)
	if err != nil {
		return nil, err
	}
	var keyPair *rsa.PrivateKey
	if _, err := os.Stat(keyFile); err == nil {
		// 已有账号密钥
		kp, err := loadAccountKey(keyFile)
		if err != nil {
			return nil, err
		}
		keyPair = kp
		if loc == "" {
			// 密钥在但账号位置丢失：尝试按已有密钥找回
			client, err := newAcmeClient(providerName, keyPair, "")
			if err != nil {
				return nil, err
			}
			loc, err = client.newAccount("", true, eab)
			if err != nil {
				return nil, err
			}
			if err := core.SetConfig(locKey, loc); err != nil {
				return nil, err
			}
		}
	} else {
		// 首次注册新账号
		kp, err := generateRSA2048()
		if err != nil {
			return nil, err
		}
		client, err := newAcmeClient(providerName, kp, "")
		if err != nil {
			return nil, err
		}
		loc, err = client.newAccount(cfg("acme.email", ""), false, eab)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyFile, []byte(pemEncode("PRIVATE KEY", mustPKCS8(kp))), 0o600); err != nil {
			return nil, err
		}
		keyPair = kp
		if err := core.SetConfig(locKey, loc); err != nil {
			return nil, err
		}
		core.LogInfo(core.LogCert, "已注册 "+providerName+" ACME 账号")
	}
	return newAcmeClient(providerName, keyPair, loc)
}

// acmeBind 按任务保存的账号信息重建客户端（等价 Java bindLogin，不发起注册）。
func acmeBind(providerName string) (*acmeClient, error) {
	dir := filepath.Join(core.DataDir(), "certs", "acme", strings.ToLower(providerName))
	keyFile := filepath.Join(dir, "account.pem")
	if _, err := os.Stat(keyFile); err != nil {
		return nil, errors.New("ACME 账号不存在，请先发起一次申请")
	}
	keyPair, err := loadAccountKey(keyFile)
	if err != nil {
		return nil, err
	}
	loc, err := core.GetConfig("cert.account." + providerName)
	if err != nil {
		return nil, err
	}
	if loc == "" {
		return nil, errors.New("ACME 账号位置丢失，请重新申请")
	}
	return newAcmeClient(providerName, keyPair, loc)
}

// eabFor ZeroSSL 需要外部账号绑定（EAB），凭证在"设置"中配置；其他服务商返回 nil。
func eabFor(providerName string) (*eabParams, error) {
	if providerName != "ZEROSSL" {
		return nil, nil
	}
	kid := cfg("zerossl.eab_kid", "")
	hmacKey := cfg("zerossl.eab_hmac", "")
	if strings.TrimSpace(kid) == "" || strings.TrimSpace(hmacKey) == "" {
		return nil, core.NewBadRequest("ZeroSSL 需要 EAB 凭证：请先在 设置 -> 证书设置 中填写 EAB KID 与 EAB HMAC Key" +
			"（ZeroSSL 控制台 Developer 页面生成）")
	}
	return &eabParams{KID: kid, HMACBase64: hmacKey}, nil
}

func loadAccountKey(file string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	der, err := parsePem(string(data), "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("%w（%s）", err, file)
	}
	return parseAccountKey(der)
}

func mustPKCS8(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return der
}

// ---------- 工具 ----------

func mustGet(id int64) (*core.Row, error) {
	task, err := core.QueryOne("SELECT * FROM cert_task WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, core.NewBadRequest("证书任务不存在: #%d", id)
	}
	return task, nil
}

func setStatus(taskID int64, status, message string, notAfter *string) {
	var err error
	if notAfter == nil {
		_, err = core.Update("UPDATE cert_task SET status=?, message=? WHERE id=?", status, message, taskID)
	} else {
		_, err = core.Update("UPDATE cert_task SET status=?, message=?, not_after=? WHERE id=?",
			status, message, *notAfter, taskID)
	}
	if err != nil {
		core.LogError(core.LogCert, "更新证书任务状态失败: "+err.Error())
	}
}

func fail(taskID int64, message string) {
	setStatus(taskID, "ERROR", message, nil)
	core.LogError(core.LogCert, "任务 #"+fmt.Sprintf("%d", taskID)+": "+message)
}

func taskDir(id int64) string {
	return filepath.Join(core.DataDir(), "certs", "task-"+fmt.Sprintf("%d", id))
}

func taskStr(r *core.Row, key string) string {
	v := r.Get(key)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func taskID(r *core.Row) int64 {
	if v, ok := r.Get("id").(int64); ok {
		return v
	}
	return 0
}

// domainList 域名串解析：支持逗号/分号/空白分隔。
func domainList(domains string) []string {
	fields := strings.FieldsFunc(domains, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v'
	})
	list := make([]string, 0, len(fields))
	for _, d := range fields {
		if d != "" {
			list = append(list, strings.ToLower(strings.TrimSpace(d)))
		}
	}
	return list
}

func normalizeDomains(domains string) string {
	return strings.Join(domainList(domains), ",")
}

// joinDomains 复刻 Java List.toString() 的日志格式：[a.com, b.com]。
func joinDomains(domains []string) string {
	return "[" + strings.Join(domains, ", ") + "]"
}

// primaryDomain 主域名（作为保存文件名）：取第一个域名，泛域名去除 *. 前缀，非安全字符替换为下划线。
func primaryDomain(domains []string) string {
	d := "cert"
	if len(domains) > 0 {
		d = domains[0]
	}
	d = strings.TrimPrefix(d, "*.")
	return unsafeRe.ReplaceAllString(d, "_")
}

// resolveSaveDir 解析任务保存目录：留空时回退到默认目录。
func resolveSaveDir(b map[string]interface{}) string {
	dir := strings.TrimSpace(core.BodyStr(b, "save_dir"))
	if dir == "" {
		return defaultSaveDir
	}
	return dir
}

// providerConfigArg 凭证配置引用参数：未选配置写 NULL。
func providerConfigArg(b map[string]interface{}) interface{} {
	id, ok := provider.ParseID(b, "provider_config_id")
	if !ok {
		return nil
	}
	return id
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func cfg(key, def string) string {
	v, err := core.GetConfig(key)
	if err != nil || v == "" {
		return def
	}
	return v
}

// fieldStr/fieldObj 阿里云响应 map 的宽松访问（等价 JsonUtils 语义）。
func fieldStr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func fieldObj(m map[string]interface{}, key string) map[string]interface{} {
	v, ok := m[key]
	if !ok {
		return nil
	}
	o, _ := v.(map[string]interface{})
	return o
}

// ---------- 保存目录与 webhook ----------

// saveToCustomDir 将证书以主域名作为文件名写入保存目录（save_dir）。
// 生成 {domain}.key / {domain}.pem / {domain}.fullchain.pem 三个文件；目录不存在时自动新建。
// 失败不阻断签发主流程（文件已存于默认任务目录），仅记日志。
func saveToCustomDir(saveDir string, domains []string, keyDer, leafDer []byte, fullchainPem string) {
	if strings.TrimSpace(saveDir) == "" {
		saveDir = defaultSaveDir
	}
	base := primaryDomain(domains)
	dir := strings.TrimSpace(saveDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		core.LogWarn(core.LogCert, "保存证书到自定义目录失败("+saveDir+"): "+err.Error())
		return
	}
	err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(pemEncode("PRIVATE KEY", keyDer)), 0o600)
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, base+".pem"), []byte(pemEncode("CERTIFICATE", leafDer)), 0o644)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, base+".fullchain.pem"), []byte(fullchainPem), 0o644)
	}
	if err != nil {
		core.LogWarn(core.LogCert, "保存证书到自定义目录失败("+saveDir+"): "+err.Error())
		return
	}
	core.LogInfo(core.LogCert, "证书已保存到自定义目录: "+dir+"/"+base+".*")
}

// pushWebhook 可选：签发成功后将证书完整内容（证书/私钥/证书链 PEM）POST 推送到 webhook，用于同步到其他系统。
// 失败不阻断签发主流程，仅记日志。
func pushWebhook(url string, task *core.Row, domains []string, keyPem, certPem, fullchainPem string, notBefore, notAfter time.Time) {
	if strings.TrimSpace(url) == "" {
		return
	}
	payload := core.NewRow().
		Set("event", "certificate.issued").
		Set("taskId", taskStr(task, "id")).
		Set("name", taskStr(task, "name")).
		Set("domains", domains).
		Set("notBefore", notBefore.Format(time.RFC3339)).
		Set("notAfter", notAfter.Format(time.RFC3339)).
		Set("keyPem", keyPem).
		Set("certPem", certPem).
		Set("fullchainPem", fullchainPem)
	jsonText, err := core.MarshalJSON(payload)
	if err != nil {
		core.LogWarn(core.LogCert, "推送 webhook 失败("+url+"): "+err.Error())
		return
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSpace(url), strings.NewReader(string(jsonText)))
	if err != nil {
		core.LogWarn(core.LogCert, "推送 webhook 失败("+url+"): "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := webhookHTTP.Do(req)
	if err != nil {
		core.LogWarn(core.LogCert, "推送 webhook 失败("+url+"): "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := readAllLimit(resp.Body, 1<<20)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		core.LogInfo(core.LogCert, "证书已推送 webhook: "+url+" (HTTP "+fmt.Sprintf("%d", resp.StatusCode)+")")
	} else {
		core.LogWarn(core.LogCert, "推送 webhook 返回非 2xx: HTTP "+fmt.Sprintf("%d", resp.StatusCode)+" "+truncate(string(body)))
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func readAllLimit(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}
