// validates a complete server certificate and private key.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// certificateExpiry reads metadata only; Validate still decides whether a
// certificate may be published or installed, including when it has expired.
func certificateExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.IsCA {
		return time.Time{}, errors.New("叶子证书解析失败")
	}
	return cert.NotAfter, nil
}

// Validate uses system roots when roots is nil. Custom roots are for tests only.
func Validate(certPEM, keyPEM []byte, domains []string, now time.Time, roots *x509.CertPool) error {
	if len(domains) == 0 {
		return errors.New("缺少目标域名")
	}
	var certs []*x509.Certificate
	rest := certPEM
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("证书链包含无效 PEM 数据")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("证书 PEM 解析失败")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("证书解析失败")
		}
		certs = append(certs, cert)
		rest = tail
	}
	if len(certs) < 2 || certs[0].IsCA {
		return errors.New("fullchain 必须是叶子证书及中间证书")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.New("证书私钥解析或配对失败")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		if !cert.IsCA {
			return errors.New("证书链包含非 CA 中间证书")
		}
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("证书链或有效期校验失败: %w", err)
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			// A matching concrete hostname does not prove wildcard coverage.
			// Require the wildcard SAN itself, without requiring its apex SAN.
			found := false
			for _, san := range certs[0].DNSNames {
				if strings.EqualFold(san, domain) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("证书 SAN 未包含目标通配域名 %s", domain)
			}
		} else if err := certs[0].VerifyHostname(domain); err != nil {
			return fmt.Errorf("证书未覆盖目标域名 %s", domain)
		}
	}
	return nil
}
