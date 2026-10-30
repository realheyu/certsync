package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genCert 生成自签证书 + 私钥 PEM(带中间证书凑 fullchain)。
func genCert(t *testing.T, cn string) (certPEM, keyPEM []byte, tlsCert tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafT := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{cn},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, tc
}

func startTLS(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestInstallSuccessAndProbe(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, tlsCert := genCert(t, "example.com")
	addr := startTLS(t, tlsCert)

	tgt := Target{Domain: "example.com",
		CertFile: filepath.Join(dir, "fullchain.pem"),
		KeyFile:  filepath.Join(dir, "privkey.pem")}
	opts := Options{
		CheckCmd:  []string{"true"},
		ReloadCmd: []string{"true"},
		BackupDir: filepath.Join(dir, "backup"),
		ProbeAddr: addr,
	}
	if _, err := Install(tgt, certPEM, keyPEM, opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// 文件内容与权限
	certData, _ := os.ReadFile(tgt.CertFile)
	keyData, _ := os.ReadFile(tgt.KeyFile)
	if string(certData) != string(certPEM) || string(keyData) != string(keyPEM) {
		t.Fatal("安装产物与输入不一致")
	}
	kinfo, _ := os.Stat(tgt.KeyFile)
	if kinfo.Mode().Perm() != 0o600 {
		t.Errorf("私钥权限 = %v", kinfo.Mode().Perm())
	}
}

func TestRollbackOnCheckFailure(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, _ := genCert(t, "example.com")

	tgt := Target{Domain: "example.com",
		CertFile: filepath.Join(dir, "fullchain.pem"),
		KeyFile:  filepath.Join(dir, "privkey.pem")}

	// 先装一份旧证书(探测地址故意不可达——首装时探测失败不影响文件落位,错误忽略)
	oldPEM, oldKey, _ := genCert(t, "example.com")
	_, _ = Install(tgt, oldPEM, oldKey, Options{
		CheckCmd: []string{"true"}, ReloadCmd: []string{"true"},
		BackupDir: filepath.Join(dir, "backup"), ProbeAddr: "127.0.0.1:1",
	})

	// 再装新证书但 check_cmd 失败 → 应回滚为旧证书
	if _, err := Install(tgt, certPEM, keyPEM, Options{
		CheckCmd:  []string{"false"},
		BackupDir: filepath.Join(dir, "backup"),
		ProbeAddr: "127.0.0.1:1",
	}); err == nil {
		t.Fatal("check_cmd 失败未被报出")
	}
	got, _ := os.ReadFile(tgt.CertFile)
	if string(got) != string(oldPEM) {
		t.Fatal("回滚失败:证书未恢复为旧版本")
	}
}

func TestFirstInstallCheckFailRemovesNew(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, _ := genCert(t, "example.com")
	tgt := Target{Domain: "example.com",
		CertFile: filepath.Join(dir, "fullchain.pem"),
		KeyFile:  filepath.Join(dir, "privkey.pem")}
	if _, err := Install(tgt, certPEM, keyPEM, Options{
		CheckCmd: []string{"false"},
		BackupDir: filepath.Join(dir, "backup"),
	}); err == nil {
		t.Fatal("应当失败")
	}
	if fileExists(tgt.CertFile) || fileExists(tgt.KeyFile) {
		t.Fatal("首次安装失败后应删除新增文件")
	}
}

func TestProbeMismatchNotRolledBack(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, _ := genCert(t, "example.com")
	// 起一个服务"别的"证书的 TLS 端口
	_, _, other := genCert(t, "other.example.com")
	addr := startTLS(t, other)

	tgt := Target{Domain: "example.com",
		CertFile: filepath.Join(dir, "fullchain.pem"),
		KeyFile:  filepath.Join(dir, "privkey.pem")}
	_, err := Install(tgt, certPEM, keyPEM, Options{
		CheckCmd:  []string{"true"},
		ReloadCmd: []string{"true"},
		BackupDir: filepath.Join(dir, "backup"),
		ProbeAddr: addr,
	})
	if err == nil {
		t.Fatal("探测不一致应报错")
	}
	if !errors.Is(err, ErrProbeMismatch) {
		t.Fatalf("应为 ErrProbeMismatch, got %v", err)
	}
	// 关键:文件不回滚(内容校验已过)
	got, _ := os.ReadFile(tgt.CertFile)
	if string(got) != string(certPEM) {
		t.Fatal("探测不一致时不应回滚文件")
	}
}

func TestPruneBackups(t *testing.T) {
	dir := t.TempDir()
	domain := filepath.Join(dir, "example.com")
	for i := 0; i < KeepBackups+3; i++ {
		os.MkdirAll(filepath.Join(domain, time.Date(2026, 1, i+1, 0, 0, 0, 0, time.UTC).Format("20060102T150405Z")), 0o700)
	}
	pruneBackups(domain, KeepBackups)
	entries, _ := os.ReadDir(domain)
	if len(entries) != KeepBackups {
		t.Errorf("保留 %d 份,实际 %d", KeepBackups, len(entries))
	}
}
