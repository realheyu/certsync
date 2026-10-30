// Package acme 封装 lego v5:账户管理、alidns DNS-01、Obtain(Bundle: true 取 fullchain)。
// 注意:ObtainRequest 必须 Bundle: true,否则 res.Certificate 只含叶子证书,链不完整(10 节)。
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/alidns"
	"github.com/go-acme/lego/v5/registration"

	"github.com/hy/certsync/internal/config"
)

// LEDirectoryStaging LE 测试环境(--staging 默认覆盖,3 节)。
func LEDirectoryStaging() string {
	u, err := lego.GetDirectoryURL(lego.CodeLetsEncryptStaging)
	if err != nil {
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return u
}

type user struct {
	email string
	reg   *acme.ExtendedAccount
	key   crypto.Signer
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *acme.ExtendedAccount  { return u.reg }
func (u *user) GetPrivateKey() crypto.Signer            { return u.key }

// Obtain 申领证书并落盘 state;stateDir 由调用方决定(--staging 传独立子目录,3 节)。
func Obtain(ctx context.Context, cfg config.ACME, stateDir string) (*certificate.Resource, error) {
	if cfg.Email == "" {
		return nil, fmt.Errorf("acme.email 未配置")
	}
	if len(cfg.Domains) == 0 {
		return nil, fmt.Errorf("acme.domains 未配置")
	}
	u, err := loadOrCreateUser(stateDir, cfg.Email)
	if err != nil {
		return nil, err
	}

	dirURL := cfg.CAServer
	if dirURL == "" {
		if dirURL, err = lego.GetDirectoryURL(lego.CodeLetsEncrypt); err != nil {
			return nil, fmt.Errorf("解析 LE 正式环境地址: %w", err)
		}
	}
	lc := lego.NewConfig(u)
	lc.CADirURL = dirURL

	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("创建 ACME 客户端: %w", err)
	}

	// DNS-01:alidns provider 读 ALICLOUD_ACCESS_KEY / ALICLOUD_SECRET_KEY 环境变量(8 节)
	provider, err := alidns.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("初始化 alidns provider(检查 ALICLOUD_* 环境变量): %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("挂载 DNS-01: %w", err)
	}

	if err := ensureRegistration(ctx, client, u, cfg, stateDir); err != nil {
		return nil, err
	}

	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: cfg.Domains,
		Bundle:  true, // 10 节:必须,取叶子+中间的 fullchain
		KeyType: certcrypto.EC256,
	})
	if err != nil {
		return nil, fmt.Errorf("ACME 申领: %w", err)
	}

	if err := SaveResource(stateDir, cfg.Domains[0], res); err != nil {
		return nil, err
	}
	return res, nil
}

// ensureRegistration:已有账户先解析(幂等),否则注册;ZeroSSL 等 EAB CA 走
// RegisterWithExternalAccountBinding(8 节 acme.eab)。
func ensureRegistration(ctx context.Context, client *lego.Client, u *user, cfg config.ACME, stateDir string) error {
	if u.reg != nil {
		return nil
	}
	if reg, err := client.Registration.ResolveAccountByKey(ctx); err == nil {
		u.reg = reg
	} else if cfg.EAB.KID != "" {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  cfg.EAB.KID,
			HmacEncoded:          cfg.EAB.HMAC,
		})
		if err != nil {
			return fmt.Errorf("EAB 注册: %w", err)
		}
		u.reg = reg
	} else {
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("账户注册: %w", err)
		}
		u.reg = reg
	}
	return saveUser(stateDir, u)
}

// StateCertDir state 下证书目录:<stateDir>/certs/<primary_domain>(6.5 节)。
func StateCertDir(stateDir, primaryDomain string) string {
	return filepath.Join(stateDir, "certs", primaryDomain)
}

// SaveResource 落盘 fullchain.pem / privkey.pem / resource.json(命名三方一致,6.5 节)。
func SaveResource(stateDir, primaryDomain string, res *certificate.Resource) error {
	dir := StateCertDir(stateDir, primaryDomain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), res.Certificate, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), res.PrivateKey, 0o600); err != nil {
		return err
	}
	// Resource 的敏感字段带 json:"-",此处为安全元数据存档(吊销时用 CertURL)
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "resource.json"), raw, 0o644)
}

// LoadLocal 从 state 读最近一次申领产物(renew/push 用)。
func LoadLocal(stateDir, primaryDomain string) (certPEM, keyPEM []byte, err error) {
	dir := StateCertDir(stateDir, primaryDomain)
	certPEM, err = os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func accountDir(stateDir, email string) string {
	return filepath.Join(stateDir, "accounts", email)
}

// loadOrCreateUser 账户私钥存在则复用;丢失 = 重新生成(重新注册,6.5 节)。
func loadOrCreateUser(stateDir, email string) (*user, error) {
	dir := accountDir(stateDir, email)
	keyPath := filepath.Join(dir, "account.key")

	u := &user{email: email}
	if raw, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("账户私钥 %s PEM 解析失败", keyPath)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析账户私钥: %w", err)
		}
		u.key = key
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		u.key = key
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
			Type: "EC PRIVATE KEY", Bytes: der,
		}), 0o600); err != nil {
			return nil, err
		}
	}

	// 恢复注册信息(存在时)
	if raw, err := os.ReadFile(filepath.Join(dir, "account.json")); err == nil {
		var reg acme.ExtendedAccount
		if json.Unmarshal(raw, &reg) == nil && reg.Location != "" {
			u.reg = &reg
		}
	}
	return u, nil
}

func saveUser(stateDir string, u *user) error {
	raw, err := json.MarshalIndent(u.reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(accountDir(stateDir, u.email), "account.json"), raw, 0o600)
}
