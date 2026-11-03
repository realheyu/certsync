// Offline fixtures shared by certificate and distribution tests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type Chain struct {
	Cert, Key, Leaf []byte
	Roots           *x509.CertPool
	Root            *x509.Certificate
}

func newTestChain(t testing.TB, expired bool, names ...string) Chain {
	if len(names) == 0 {
		names = []string{"example.com", "*.example.com"}
	}
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	mint := func(c, p *x509.Certificate, k, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
		der, e := x509.CreateCertificate(rand.Reader, c, p, &k.PublicKey, signer)
		if e != nil {
			t.Fatal(e)
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	now := time.Now()
	caKey, intKey, leafKey := key(), key(), key()
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour)}
	root, _ := mint(rootT, rootT, caKey, caKey)
	intT := *rootT
	intT.SerialNumber = big.NewInt(2)
	intT.Subject.CommonName = "test intermediate"
	inter, interPEM := mint(&intT, root, intKey, caKey)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: names, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if expired {
		leafT.NotAfter = now.Add(-time.Hour)
	}
	_, leaf := mint(leafT, inter, leafKey, intKey)
	der, e := x509.MarshalECPrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return Chain{Cert: append(append([]byte{}, leaf...), interPEM...), Leaf: leaf, Key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), Roots: pool, Root: root}
}
