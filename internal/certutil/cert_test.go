package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// testChain 生成 root → intermediate → leaf 三级链,返回 fullchain PEM(leaf+intermediate)
// 与 leaf 私钥 PEM,以及各证书对象。
type testChain struct {
	fullchainPEM []byte
	leafKeyPEM   []byte
	leaf         *x509.Certificate
	intermediate *x509.Certificate
	root         *x509.Certificate
	otherKeyPEM  []byte // 与 leaf 不配对的另一把私钥
}

func mintCert(t *testing.T, tmpl, parent *x509.Certificate, pub, parentPriv any) (*x509.Certificate, []byte) {
	t.Helper()
	priv, ok := parentPriv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("测试仅支持 ECDSA 父密钥")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestChain(t *testing.T, sans []string, notBefore, notAfter time.Time) *testChain {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serial := func() *big.Int { return big.NewInt(time.Now().UnixNano()) }

	rootT := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root, _ := mintCert(t, rootT, rootT, &rootKey.PublicKey, rootKey)

	intT := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "test-intermediate"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	inter, interPEM := mintCert(t, intT, root, &intKey.PublicKey, rootKey)

	sansDNS := []string{}
	var ips []net.IP
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			sansDNS = append(sansDNS, s)
		}
	}
	leafT := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: notBefore, NotAfter: notAfter,
		DNSNames: sansDNS, IPAddresses: ips,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, leafPEM := mintCert(t, leafT, inter, &leafKey.PublicKey, intKey)

	leafKeyDER, _ := x509.MarshalECPrivateKey(leafKey)
	otherDER, _ := x509.MarshalECPrivateKey(otherKey)

	return &testChain{
		fullchainPEM: append(append([]byte{}, leafPEM...), interPEM...),
		leafKeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
		otherKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherDER}),
		leaf:         leaf, intermediate: inter, root: root,
	}
}

func keyPEM(t *testing.T, c *testChain) []byte { return c.leafKeyPEM }

func TestFingerprintStable(t *testing.T) {
	now := time.Now()
	tc := newTestChain(t, []string{"example.com"}, now, now.Add(90*24*time.Hour))
	if Fingerprint(tc.leaf) != Fingerprint(tc.leaf) {
		t.Fatal("同一证书指纹不稳定")
	}
	if Fingerprint(tc.leaf) == Fingerprint(tc.intermediate) {
		t.Fatal("不同证书指纹相同")
	}
}

func TestValidateFullchain(t *testing.T) {
	now := time.Now()
	tc := newTestChain(t, []string{"example.com"}, now, now.Add(90*24*time.Hour))
	certs, err := ParseCertificates(tc.fullchainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFullchain(certs); err != nil {
		t.Fatalf("合法 fullchain 被拒: %v", err)
	}
	// 仅叶子:应拒绝(Bundle 未开启的典型症状)
	leafOnly := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.leaf.Raw})
	certs1, _ := ParseCertificates(leafOnly)
	if err := ValidateFullchain(certs1); err == nil {
		t.Fatal("仅叶子的链未被拒绝")
	}
}

func TestMatchSANWildcard(t *testing.T) {
	now := time.Now()
	tc := newTestChain(t, []string{"example.com", "*.example.com"}, now, now.Add(90*24*time.Hour))
	leaf := tc.leaf

	cases := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"a.example.com", true},
		{"a.b.example.com", false}, // 通配只匹配一层
		{"example.org", false},
		{"EXAMPLE.com", true}, // 大小写不敏感
		{"badexample.com", false},
	}
	for _, c := range cases {
		if got := MatchSAN(leaf, c.domain); got != c.want {
			t.Errorf("MatchSAN(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestKeyPairMatches(t *testing.T) {
	now := time.Now()
	tc := newTestChain(t, []string{"example.com"}, now, now.Add(90*24*time.Hour))
	good, err := ParsePrivateKey(keyPEM(t, tc))
	if err != nil {
		t.Fatal(err)
	}
	if !KeyPairMatches(tc.leaf, good) {
		t.Fatal("正确私钥配对失败")
	}
	bad, err := ParsePrivateKey(tc.otherKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if KeyPairMatches(tc.leaf, bad) {
		t.Fatal("错误私钥被判为配对")
	}
}

func TestTimeWindowAndRenewal(t *testing.T) {
	now := time.Now()
	tc := newTestChain(t, []string{"example.com"}, now, now.Add(90*24*time.Hour))
	if err := TimeWindow(tc.leaf, now); err != nil {
		t.Fatalf("有效期内被拒: %v", err)
	}
	if err := TimeWindow(tc.leaf, now.Add(91*24*time.Hour)); err == nil {
		t.Fatal("过期证书未被检出")
	}
	if err := TimeWindow(tc.leaf, now.Add(-48*time.Hour)); err == nil {
		t.Fatal("未生效证书未被检出")
	}
	if RenewalDue(tc.leaf, 30, now) {
		t.Fatal("剩 90 天不应触发 30 天窗口")
	}
	if !RenewalDue(tc.leaf, 30, now.Add(70*24*time.Hour)) {
		t.Fatal("剩 20 天应触发 30 天窗口")
	}
	if d := RemainingDays(tc.leaf, now); d != 90 && d != 89 {
		t.Errorf("RemainingDays = %d, want 89~90", d)
	}
}

func TestValidateChain(t *testing.T) {
	now := time.Now()
	tc := newTestChain(t, []string{"example.com", "*.example.com"}, now, now.Add(90*24*time.Hour))

	if _, err := ValidateChain(tc.fullchainPEM, tc.leafKeyPEM, "web.example.com", now); err != nil {
		t.Fatalf("合法输入被拒: %v", err)
	}
	if _, err := ValidateChain(tc.fullchainPEM, tc.otherKeyPEM, "example.com", now); err == nil {
		t.Fatal("不配对私钥未被拒")
	}
	if _, err := ValidateChain(tc.fullchainPEM, tc.leafKeyPEM, "other.org", now); err == nil {
		t.Fatal("SAN 不覆盖未被拒")
	}
	leafOnly := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.leaf.Raw})
	if _, err := ValidateChain(leafOnly, tc.leafKeyPEM, "example.com", now); err == nil {
		t.Fatal("链不完整未被拒")
	}
}
