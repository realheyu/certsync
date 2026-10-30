package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/hy/certsync/internal/acme"
	"github.com/hy/certsync/internal/alert"
	"github.com/hy/certsync/internal/certutil"
	"github.com/hy/certsync/internal/config"
	"github.com/hy/certsync/internal/cryptoutil"
	"github.com/hy/certsync/internal/store"
)

func acmeStagingDirURL() string { return acme.LEDirectoryStaging() }

func newIssueCmd() *cobra.Command {
	var staging bool
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "强制向 CA 申请新证书并落盘、加密上传(首次部署/测试)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runIssue(cfg, staging)
		},
	}
	cmd.Flags().BoolVar(&staging, "staging", false, "使用 LE 测试环境与隔离的 state/OSS 前缀(3 节)")
	return cmd
}

// runIssue:申领 → 落盘 state → 加密上传;issue_ok / issue_fail 告警(12.1 节)。
func runIssue(cfg *config.Config, staging bool) error {
	log := logger()
	primary := cfg.PrimaryDomain()
	if primary == "" {
		return errors.New("acme.domains 未配置")
	}

	err := func() error {
		acmeCfg := cfg.ACME
		acmeCfg.CAServer = caServerFor(cfg, staging)
		// Obtain 内部已把产物落盘 state,pushLocal 从 state 读取后上传
		if _, err := acme.Obtain(context.Background(), acmeCfg, cfg.AliDNS, stateDirFor(cfg, staging)); err != nil {
			return err
		}
		return pushLocal(cfg, staging, "") // 上传刚落盘的产物
	}()

	alerter := alert.NewSender(cfg.Alert, log)
	if err != nil {
		log.Error("issue 失败", "err", err)
		alerter.Send(alert.NewEvent("issue_fail", "error", alert.Hostname(), primary, err.Error()))
		return err
	}
	log.Info("issue 成功", "domain", primary)
	alerter.Send(alert.NewEvent("issue_ok", "info", alert.Hostname(), primary, "证书签发并上传成功"))
	return nil
}

func newRenewCmd() *cobra.Command {
	var staging bool
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "到续期窗口(默认剩余<30天)才触发 issue,否则退出;并自愈 OSS 缺失(13 节)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runRenew(cfg, staging)
		},
	}
	cmd.Flags().BoolVar(&staging, "staging", false, "staging 链路")
	return cmd
}

func runRenew(cfg *config.Config, staging bool) error {
	log := logger()
	primary := cfg.PrimaryDomain()
	stateDir := stateDirFor(cfg, staging)

	certPEM, _, err := acme.LoadLocal(stateDir, primary)
	if err != nil {
		// 无本地证书(首次/损坏)→ 直接签发
		log.Info("本地无证书,触发 issue")
		return runIssue(cfg, staging)
	}
	certs, err := certutil.ParseCertificates(certPEM)
	if err != nil {
		log.Error("本地证书解析失败,触发重新签发", "err", err)
		return runIssue(cfg, staging)
	}
	leaf := certutil.Leaf(certs)

	if !certutil.RenewalDue(leaf, cfg.ACME.RenewBeforeDays, now()) {
		log.Debug("renew_skipped:未到续期窗口",
			"remaining_days", certutil.RemainingDays(leaf, now()),
			"renew_before_days", cfg.ACME.RenewBeforeDays)
		// 13 节自愈:证书未变但 OSS 对象缺失/不一致时补推
		return selfHealOSS(cfg, staging)
	}
	log.Info("进入续期窗口,触发 issue", "remaining_days", certutil.RemainingDays(leaf, now()))
	return runIssue(cfg, staging)
}

// selfHealOSS 未到窗口时校验 OSS meta 与本地指纹一致,不一致/缺失则 push 修复。
func selfHealOSS(cfg *config.Config, staging bool) error {
	log := logger()
	primary := cfg.PrimaryDomain()
	st, err := store.New(cfg.OSS, prefixFor(cfg, staging), log)
	if err != nil {
		return err
	}
	certPEM, _, err := acme.LoadLocal(stateDirFor(cfg, staging), primary)
	if err != nil {
		return err
	}
	certs, _ := certutil.ParseCertificates(certPEM)
	localFP := certutil.Fingerprint(certutil.Leaf(certs))

	meta, err := st.GetMeta(primary)
	if err == nil && meta.Fingerprint == localFP {
		return nil // 一致,无事可做
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Warn("检查 OSS meta 失败,本轮跳过自愈", "err", err)
		return nil
	}
	log.Info("OSS 与本地不一致,执行 push 自愈")
	return pushLocal(cfg, staging, "")
}

func newPushCmd() *cobra.Command {
	var staging, keyFileOverride bool
	var keyFile string
	cmd := &cobra.Command{
		Use:   "push",
		Short: "不联系 CA,把本地 state 证书重新加密上传(误删恢复/换密钥重加密,6.4 节)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			override := ""
			if keyFileOverride {
				override = keyFile
			}
			return pushLocal(cfg, staging, override)
		},
	}
	cmd.Flags().BoolVar(&staging, "staging", false, "staging 链路")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "覆盖主密钥文件路径(密钥轮换用)")
	cmd.Flags().BoolVar(&keyFileOverride, "with-key-file", false, "启用 --key-file 覆盖")
	return cmd
}

// pushLocal 读 state 产物 → 用主密钥加密 → 按 5.3 节顺序上传。
// keyFileOverride 非空时用它替代配置里的主密钥文件(6.4 节轮换流程)。
func pushLocal(cfg *config.Config, staging bool, keyFileOverride string) error {
	log := logger()
	primary := cfg.PrimaryDomain()

	certPEM, keyPEM, err := acme.LoadLocal(stateDirFor(cfg, staging), primary)
	if err != nil {
		return fmt.Errorf("读取本地 state 证书(先执行 issue): %w", err)
	}
	certs, err := certutil.ParseCertificates(certPEM)
	if err != nil {
		return err
	}
	if err := certutil.ValidateFullchain(certs); err != nil {
		return fmt.Errorf("本地证书不完整,拒绝上传: %w", err)
	}

	masterKey := keyFileOverride
	if masterKey == "" {
		masterKey = cfg.Crypto.KeyFile
	}
	key, err := cryptoutil.LoadKey(masterKey)
	if err != nil {
		return err
	}
	certEnc, err := cryptoutil.Encrypt(key, certPEM)
	if err != nil {
		return err
	}
	keyEnc, err := cryptoutil.Encrypt(key, keyPEM)
	if err != nil {
		return err
	}

	st, err := store.New(cfg.OSS, prefixFor(cfg, staging), log)
	if err != nil {
		return err
	}
	leaf := certutil.Leaf(certs)
	meta := store.Meta{
		Domain:      primary,
		Fingerprint: certutil.Fingerprint(leaf),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		SANs:        leaf.DNSNames,
		Issuer:      leaf.Issuer.CommonName,
		UpdatedAt:   time.Now().Unix(),
	}
	if err := st.PushCert(primary, certEnc, keyEnc, meta); err != nil {
		return err
	}
	log.Info("push 完成", "domain", primary, "fingerprint", meta.Fingerprint[:16]+"…")
	return nil
}
