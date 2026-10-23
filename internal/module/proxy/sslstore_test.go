package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// setupTestDB 独立临时数据目录（与 cert 模块测试同思路）：切换工作目录 + 重解析数据路径 + 重建库。
func setupTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := core.InitPaths(); err != nil {
		t.Fatalf("InitPaths: %v", err)
	}
	core.CloseDB() // 允许重复初始化（多用例共享进程）
	if err := core.InitDB(filepath.Join(dir, "nexhome.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

// writeSelfSigned 生成自签证书与 PKCS8 私钥（文件名自定，便于覆盖标准布局与 save_dir 副本两种布局）。
func writeSelfSigned(t *testing.T, dir, keyName, certName string, domains []string, notAfter time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: domains[0]},
		DNSNames:              domains,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyName), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, certName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func insertTask(t *testing.T, name, domains, status, saveDir string) int64 {
	t.Helper()
	id, err := core.Insert(`INSERT INTO cert_task(name, provider, domains, challenge_type, status, save_dir)
		VALUES(?,?,?,?,?,?)`, name, "LETSENCRYPT", domains, "DNS01", status, saveDir)
	if err != nil {
		t.Fatalf("insert cert_task: %v", err)
	}
	return id
}

// insertTaskEmptySaveDir 插入 save_dir 为空的任务（模拟老库升级 ADD COLUMN 后的 NULL/空值行）。
func insertTaskEmptySaveDir(t *testing.T, domains, status string) int64 {
	t.Helper()
	id, err := core.Insert(`INSERT INTO cert_task(name, provider, domains, challenge_type, status, save_dir)
		VALUES(?,?,?,?,?,?)`, "老库任务", "LETSENCRYPT", domains, "DNS01", status, "")
	if err != nil {
		t.Fatalf("insert cert_task: %v", err)
	}
	return id
}

// TestSslReloadServesErrorTaskCert 续期失败（status=ERROR）但证书仍在有效期内的任务必须继续供证：
// 否则证书库会变空，所有站点 HTTPS 握手被终止（线上表现为浏览器 ERR_CONNECTION_CLOSED）。
func TestSslReloadServesErrorTaskCert(t *testing.T) {
	setupTestDB(t)
	id := insertTask(t, "续期失败", "*.example.com,example.com", "ERROR", "/nonexistent")
	dir := filepath.Join(core.DataDir(), "certs", "task-"+itoa(id))
	writeSelfSigned(t, dir, "domain.key.pem", "fullchain.pem",
		[]string{"*.example.com", "example.com"}, time.Now().Add(30*24*time.Hour))

	sslReload()
	if got := sslCount(); got != 1 {
		t.Fatalf("证书库应装载 1 张（ERROR 但证书有效），got %d", got)
	}
	if c, _ := forSNI("git.example.com", nil); c == nil {
		t.Fatal("通配域名应由 *.example.com 命中")
	}
	if c, _ := forSNI("example.com", nil); c == nil {
		t.Fatal("精确域名应命中")
	}
	// 无匹配域名：兜底供证而不是中断握手
	if c, _ := forSNI("other.test", nil); c == nil {
		t.Fatal("无匹配域名应兜底返回证书，避免握手被终止")
	}
}

// TestSslReloadFallsBackToSaveDir 任务目录丢失、仅剩 save_dir 副本时仍应识别（老数据/迁移场景）。
func TestSslReloadFallsBackToSaveDir(t *testing.T) {
	setupTestDB(t)
	saveDir := t.TempDir()
	writeSelfSigned(t, saveDir, "example.com.key", "example.com.fullchain.pem",
		[]string{"example.com"}, time.Now().Add(30*24*time.Hour))
	insertTask(t, "仅副本", "example.com", "ERROR", saveDir)

	sslReload()
	if c, _ := forSNI("example.com", nil); c == nil {
		t.Fatal("save_dir 中的 {域名}.key/.fullchain.pem 应被识别")
	}
}

// TestSslReloadHonorsCertDir 行内 cert_dir 指向非默认目录时按该目录读取（老库迁移场景）。
func TestSslReloadHonorsCertDir(t *testing.T) {
	setupTestDB(t)
	id := insertTask(t, "旧目录", "old.example.com", "ISSUED", "/nonexistent")
	oldDir := t.TempDir()
	writeSelfSigned(t, oldDir, "domain.key.pem", "cert.pem",
		[]string{"old.example.com"}, time.Now().Add(30*24*time.Hour))
	if _, err := core.Update("UPDATE cert_task SET cert_dir=? WHERE id=?", oldDir, id); err != nil {
		t.Fatal(err)
	}

	sslReload()
	if c, _ := forSNI("old.example.com", nil); c == nil {
		t.Fatal("cert_dir 指定的目录应被识别")
	}
}

// TestSslReloadSkipsExpired 过期证书不挂载（避免向浏览器提供失效证书）。
func TestSslReloadSkipsExpired(t *testing.T) {
	setupTestDB(t)
	id := insertTask(t, "已过期", "expired.example.com", "ERROR", "/nonexistent")
	dir := filepath.Join(core.DataDir(), "certs", "task-"+itoa(id))
	writeSelfSigned(t, dir, "domain.key.pem", "fullchain.pem",
		[]string{"expired.example.com"}, time.Now().Add(-time.Hour))

	sslReload()
	if got := sslCount(); got != 0 {
		t.Fatalf("过期证书不应挂载, got %d", got)
	}
}

// TestSslReloadDefaultsToDataSsl 老库 save_dir 为空/为 NULL、任务目录已丢失时，回退到默认保存目录 data/ssl。
func TestSslReloadDefaultsToDataSsl(t *testing.T) {
	setupTestDB(t)
	insertTaskEmptySaveDir(t, "*.pi.example.com", "ERROR")
	saveDir := filepath.Join(core.DataDir(), "ssl") // 与 cert 模块默认保存目录一致
	writeSelfSigned(t, saveDir, "pi.example.com.key", "pi.example.com.fullchain.pem",
		[]string{"*.pi.example.com", "pi.example.com"}, time.Now().Add(30*24*time.Hour))

	sslReload()
	if c, _ := forSNI("git.pi.example.com", nil); c == nil {
		t.Fatal("save_dir 为 NULL 时应回退到默认 data/ssl")
	}
}

// TestSslReloadScansBySAN 保存目录内文件名与当前域名列表不一致时，按证书 SAN 仍应识别。
func TestSslReloadScansBySAN(t *testing.T) {
	setupTestDB(t)
	saveDir := t.TempDir()
	writeSelfSigned(t, saveDir, "renamed.key", "renamed.fullchain.pem",
		[]string{"m.other.com"}, time.Now().Add(30*24*time.Hour))
	insertTask(t, "重命名副本", "m.other.com", "ERROR", saveDir)

	sslReload()
	if c, _ := forSNI("m.other.com", nil); c == nil {
		t.Fatal("应按证书 SAN 识别同目录下的证书文件")
	}
}

// TestSanCovers 通配语义：*.a.com 覆盖 x.a.com，不覆盖 a.com。
func TestSanCovers(t *testing.T) {
	if !sanCovers([]string{"*.a.com"}, []string{"x.a.com"}) {
		t.Error("通配证书应覆盖子域")
	}
	if sanCovers([]string{"*.a.com"}, []string{"a.com"}) {
		t.Error("通配证书不应覆盖主域")
	}
	if !sanCovers([]string{"b.example.com"}, []string{"B.Example.com"}) {
		t.Error("域名比较应忽略大小写")
	}
}

// itoa 小工具：避免为测试引入额外依赖。
func itoa(id int64) string {
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[i:])
}
