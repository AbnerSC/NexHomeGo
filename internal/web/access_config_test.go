package web

// 面板 HTTPS 与 HTTP 并存保底回归：
// ① 升级时关闭历史上的「HTTP 强制跳转」；② HTTPS 未真正生效时不跳转；
// ③ 证书任务目录丢失时用保存目录副本解析证书。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"NexHomeGo/internal/core"
)

// setupWebTestDB 独立临时数据目录，供需要 app_config / cert_task 的用例使用。
func setupWebTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := core.InitPaths(); err != nil {
		t.Fatalf("InitPaths: %v", err)
	}
	core.CloseDB()
	if err := core.InitDB(filepath.Join(dir, "nexhome.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(core.CloseDB)
}

// writeSelfSignedForWeb 按保存目录命名写自签名证书副本：{base}.key + {base}.fullchain.pem。
func writeSelfSignedForWeb(t *testing.T, dir, base string, notAfter time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: base},
		DNSNames:              []string{base, "*." + base},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书: %v", err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("序列化私钥: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, base+".key"), keyPEM, 0o600); err != nil {
		t.Fatalf("写私钥: %v", err)
	}
	for _, name := range []string{base + ".pem", base + ".fullchain.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), certPEM, 0o644); err != nil {
			t.Fatalf("写证书: %v", err)
		}
	}
}

// TestMigrateHTTPRedirect 历史强制跳转只被关闭一次，用户重新开启后保留。
func TestMigrateHTTPRedirect(t *testing.T) {
	setupWebTestDB(t)
	if err := core.SetConfig(KeyHTTPSRedirect, "1"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	MigrateHTTPRedirect()
	if got, _ := core.GetConfig(KeyHTTPSRedirect); got != "0" {
		t.Fatalf("升级后应关闭强制跳转, got %q", got)
	}

	// 用户显式重新开启后，再次启动不应被重置
	if err := core.SetConfig(KeyHTTPSRedirect, "1"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	MigrateHTTPRedirect()
	if got, _ := core.GetConfig(KeyHTTPSRedirect); got != "1" {
		t.Errorf("迁移只做一次，用户重新开启应保留, got %q", got)
	}
}

// TestServeHTTPNoRedirectWhenHTTPSInactive HTTPS 未挂载（降级）时不得 302 到不可用端口。
func TestServeHTTPNoRedirectWhenHTTPSInactive(t *testing.T) {
	oldCfg, oldCert := currentCfg, activeCertID
	t.Cleanup(func() { currentCfg, activeCertID = oldCfg, oldCert })

	currentCfg = &Snapshot{HTTPPort: 8090, HTTPSEnabled: true, HTTPSPort: 8443, HTTPSRedirect: true}
	activeCertID = -1 // 证书解析失败/端口占用的降级态

	rec := httptest.NewRecorder()
	serveHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code == http.StatusFound {
		t.Fatalf("HTTPS 未生效时不应跳转, got %d -> %q", rec.Code, rec.Header().Get("Location"))
	}

	// HTTPS 正常挂载时仍按用户配置跳转
	activeCertID = 7
	rec = httptest.NewRecorder()
	serveHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("HTTPS 生效时应跳转, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc == "" || loc[:5] != "https" {
		t.Errorf("跳转目标错误: %q", loc)
	}
}

// TestResolveCertFileFallsBackToSaveDir 任务目录缺失时，用保存目录副本解析证书。
func TestResolveCertFileFallsBackToSaveDir(t *testing.T) {
	setupWebTestDB(t)
	saveDir := filepath.Join(core.DataDir(), "ssl")
	writeSelfSignedForWeb(t, saveDir, "pi.example.com", time.Now().Add(30*24*time.Hour))
	id, err := core.Insert(`INSERT INTO cert_task(name, provider, domains, challenge_type, status, save_dir, not_after)
		VALUES(?,?,?,?,?,?,?)`, "老库任务", "LETSENCRYPT", "*.pi.example.com", "DNS01", "ERROR", "", "")
	if err != nil {
		t.Fatalf("insert cert_task: %v", err)
	}

	info, err := ResolveCertFile(id)
	if err != nil {
		t.Fatalf("应回退到 data/ssl 副本: %v", err)
	}
	if info.TaskID != id {
		t.Errorf("TaskID got %d want %d", info.TaskID, id)
	}
}
