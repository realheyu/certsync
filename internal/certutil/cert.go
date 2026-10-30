// Package certutil 证书解析与校验:指纹、SAN 通配匹配、密钥配对、
// fullchain 结构、有效期与续期窗口(7.1 节校验链的实现)。
package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Fingerprint 返回证书 DER 的 SHA-256 十六进制指纹(全网唯一比对依据,4 节)。
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ParseCertificates 解析 PEM 证书链(一个或多个 CERTIFICATE 块)。
func ParseCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("非预期的 PEM 块类型 %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("未找到任何 CERTIFICATE 块")
	}
	return certs, nil
}

// ValidateFullchain 校验 7.1 节第 2 条:首块为叶子证书,且至少含一张中间证书。
// (兜住 Bundle 未开启/链不完整的错误签发。)
func ValidateFullchain(certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return fmt.Errorf("fullchain 仅含 %d 张证书,应为叶子+至少一张中间证书", len(certs))
	}
	if certs[0].IsCA {
		return errors.New("fullchain 首块是 CA 证书,应为叶子证书")
	}
	return nil
}

// Leaf 返回链中叶子证书(约定为首块,ValidateFullchain 已保证)。
func Leaf(certs []*x509.Certificate) *x509.Certificate { return certs[0] }

// ParsePrivateKey 解析 PEM 私钥(SEC1 EC / PKCS1 RSA / PKCS8)。
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("私钥 PEM 解码失败")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("无法识别的私钥格式(支持 EC/RSA/PKCS8)")
}

// KeyPairMatches 校验证书与私钥配对:双方公钥逐位相等(7.1 节第 5 条)。
func KeyPairMatches(cert *x509.Certificate, key crypto.PrivateKey) bool {
	type public interface{ Equal(crypto.PublicKey) bool }
	var keyPub public
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyPub = &k.PublicKey
	case *rsa.PrivateKey:
		keyPub = &k.PublicKey
	case ed25519.PrivateKey:
		keyPub = k.Public().(ed25519.PublicKey)
	default:
		return false
	}
	certPub, ok := cert.PublicKey.(public)
	if !ok {
		return false
	}
	return certPub.Equal(keyPub)
}

// MatchSAN 校验证书 SAN 覆盖目标域名:精确匹配或通配匹配一层子域(7.1 节第 4 条)。
// "*.example.com" 匹配 "a.example.com",不匹配 "a.b.example.com" 与 "example.com"。
func MatchSAN(cert *x509.Certificate, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, san := range cert.DNSNames {
		san = strings.ToLower(san)
		if san == domain {
			return true
		}
		if strings.HasPrefix(san, "*.") {
			parent := san[2:]
			if i := strings.Index(domain, "."); i > 0 && domain[i+1:] == parent {
				return true
			}
		}
	}
	if ip := net.ParseIP(domain); ip != nil {
		for _, cip := range cert.IPAddresses {
			if cip.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// TimeWindow 校验当前时间在 not_before ~ not_after 内(7.1 节第 3 条)。
func TimeWindow(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效(NotBefore %s)", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期(NotAfter %s)", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// RenewalDue 判断是否进入续期窗口:剩余有效期 < beforeDays(3 节 renew)。
func RenewalDue(cert *x509.Certificate, beforeDays int, now time.Time) bool {
	return now.AddDate(0, 0, beforeDays).After(cert.NotAfter)
}

// RemainingDays 剩余整天数(向下取整,status/告警用)。
func RemainingDays(cert *x509.Certificate, now time.Time) int {
	d := cert.NotAfter.Sub(now)
	if d < 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}

// NewKey 生成默认密钥(ECDSA P-256,与 lego 默认 EC256 一致)。
func NewKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ValidateChain 执行 7.1 节校验链第 2~5 条(解密在 cryptoutil,指纹比对在调用方)。
func ValidateChain(fullchainPEM, keyPEM []byte, domain string, now time.Time) (*x509.Certificate, error) {
	certs, err := ParseCertificates(fullchainPEM)
	if err != nil {
		return nil, err
	}
	if err := ValidateFullchain(certs); err != nil {
		return nil, err
	}
	leaf := Leaf(certs)
	if err := TimeWindow(leaf, now); err != nil {
		return nil, err
	}
	if !MatchSAN(leaf, domain) {
		return nil, fmt.Errorf("证书 SAN %v 不覆盖目标域名 %q", leaf.DNSNames, domain)
	}
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !KeyPairMatches(leaf, key) {
		return nil, errors.New("证书与私钥不配对")
	}
	return leaf, nil
}
