package cert

// 续期保底回归：续期失败不得让仍在有效期内的旧证书失效。
// 覆盖三点：① fail 不把任务降级为 ERROR；② 新私钥/证书先写 .new，失败不覆盖旧三件套；
// ③ 重启残留的 ISSUING 在旧证书可用时恢复为 ISSUED。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"NexHomeGo/internal/core"
)

// genCertPEM 生成自签名证书（SAN example.com）的私钥与证书 PEM。
func genCertPEM(t *testing.T, notAfter time.Time) (keyPEM, certPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
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
	return pemEncode("PRIVATE KEY", keyDer), pemEncode("CERTIFICATE", der)
}

// writeCertPair 按正式布局写证书三件套到 dir。
func writeCertPair(t *testing.T, dir string, notAfter time.Time) {
	t.Helper()
	keyPEM, certPEM := genCertPEM(t, notAfter)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "domain.key.pem"), []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("写私钥: %v", err)
	}
	for _, name := range []string{"cert.pem", "fullchain.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(certPEM), 0o644); err != nil {
			t.Fatalf("写证书: %v", err)
		}
	}
}

// TestFailKeepsUsableOldCert 续期失败但旧证书仍有效：状态回到 ISSUED，证书记录不变，只提示。
func TestFailKeepsUsableOldCert(t *testing.T) {
	setupTestDB(t)
	id := insertCertTask(t, "DNS01", "", "")
	na := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	writeCertPair(t, taskDir(id), time.Now().Add(30*24*time.Hour))
	if _, err := core.Update("UPDATE cert_task SET status='ISSUING', not_after=? WHERE id=?", na, id); err != nil {
		t.Fatalf("准备任务: %v", err)
	}

	fail(id, "CA 错误: 模拟续期失败")

	task := getTask(t, id)
	if got := taskStr(task, "status"); got != "ISSUED" {
		t.Fatalf("续期失败不应把任务置为 ERROR, got %q", got)
	}
	if got := taskStr(task, "not_after"); got != na {
		t.Errorf("not_after 不应被改动: got %q want %q", got, na)
	}
	if msg := taskStr(task, "message"); !strings.Contains(msg, "续期失败") {
		t.Errorf("提示字段应记录失败原因, got %q", msg)
	}
	if _, ok := renewFailAt(id); !ok {
		t.Error("应记录失败时间用于退避")
	}
}

// TestFailMarksErrorWithoutCert 首次申请失败（无可用旧证书）：仍需 ERROR 便于排查。
func TestFailMarksErrorWithoutCert(t *testing.T) {
	setupTestDB(t)
	id := insertCertTask(t, "DNS01", "", "")
	if _, err := core.Update("UPDATE cert_task SET status='ISSUING' WHERE id=?", id); err != nil {
		t.Fatalf("准备任务: %v", err)
	}

	fail(id, "CA 错误: 首次申请失败")

	if got := taskStr(getTask(t, id), "status"); got != "ERROR" {
		t.Fatalf("无旧证书时失败应置为 ERROR, got %q", got)
	}
}

// TestCommitCertFilesKeepsOldOnMismatch 私钥与证书不匹配时拒绝提交，旧三件套原样保留。
func TestCommitCertFilesKeepsOldOnMismatch(t *testing.T) {
	dir := t.TempDir()
	writeCertPair(t, dir, time.Now().Add(30*24*time.Hour))
	oldKey, err := os.ReadFile(filepath.Join(dir, "domain.key.pem"))
	if err != nil {
		t.Fatalf("读旧私钥: %v", err)
	}
	oldChain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		t.Fatalf("读旧证书: %v", err)
	}

	// 新私钥 + 与之不匹配的旧证书链
	newKeyPEM, _ := genCertPEM(t, time.Now().Add(90*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "domain.key.pem.new"), []byte(newKeyPEM), 0o600); err != nil {
		t.Fatalf("写临时私钥: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem.new"), oldChain, 0o644); err != nil {
		t.Fatalf("写临时证书: %v", err)
	}

	if err := commitCertFiles(dir); err == nil {
		t.Fatal("私钥与证书不匹配时应拒绝提交")
	}
	for name, want := range map[string][]byte{"domain.key.pem": oldKey, "fullchain.pem": oldChain} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != string(want) {
			t.Errorf("%s 应保持原样（续期失败不能破坏可用证书）", name)
		}
	}
}

// TestCommitCertFilesReplaces 校验通过时三件套同时替换。
func TestCommitCertFilesReplaces(t *testing.T) {
	dir := t.TempDir()
	writeCertPair(t, dir, time.Now().Add(10*24*time.Hour))
	oldKey, _ := os.ReadFile(filepath.Join(dir, "domain.key.pem"))

	newKeyPEM, newCertPEM := genCertPEM(t, time.Now().Add(90*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "domain.key.pem.new"), []byte(newKeyPEM), 0o600); err != nil {
		t.Fatalf("写临时私钥: %v", err)
	}
	for _, name := range []string{"cert.pem.new", "fullchain.pem.new"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(newCertPEM), 0o644); err != nil {
			t.Fatalf("写临时证书: %v", err)
		}
	}
	if err := commitCertFiles(dir); err != nil {
		t.Fatalf("commitCertFiles: %v", err)
	}
	newKey, err := os.ReadFile(filepath.Join(dir, "domain.key.pem"))
	if err != nil || string(newKey) == string(oldKey) {
		t.Error("私钥应被替换")
	}
	if _, err := os.Stat(filepath.Join(dir, "domain.key.pem.new")); !os.IsNotExist(err) {
		t.Error("临时文件应已改名")
	}
	if err := checkCertPair(dir); err != nil {
		t.Errorf("替换后的三件套应可加载: %v", err)
	}
}

// checkCertPair 校验三件套可用（避免测试直接依赖 tls 细节）。
func checkCertPair(dir string) error {
	keyPEM, err := os.ReadFile(filepath.Join(dir, "domain.key.pem"))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return err
	}
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	return err
}

// TestResetStaleIssuingKeepsOldCert 重启残留 ISSUING：有可用旧证书恢复 ISSUED，否则 ERROR。
func TestResetStaleIssuingKeepsOldCert(t *testing.T) {
	setupTestDB(t)
	withCert := insertCertTask(t, "DNS01", "", "")
	na := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339)
	writeCertPair(t, taskDir(withCert), time.Now().Add(20*24*time.Hour))
	if _, err := core.Update("UPDATE cert_task SET status='ISSUING', not_after=? WHERE id=?", na, withCert); err != nil {
		t.Fatalf("准备任务: %v", err)
	}
	without := insertCertTask(t, "DNS01", "", "")
	if _, err := core.Update("UPDATE cert_task SET status='ISSUING' WHERE id=?", without); err != nil {
		t.Fatalf("准备任务: %v", err)
	}

	resetStaleIssuing()

	if got := taskStr(getTask(t, withCert), "status"); got != "ISSUED" {
		t.Errorf("有可用旧证书应恢复为 ISSUED, got %q", got)
	}
	if got := taskStr(getTask(t, without), "status"); got != "ERROR" {
		t.Errorf("无可用证书应置为 ERROR, got %q", got)
	}
}
