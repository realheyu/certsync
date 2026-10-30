package cli

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hy/certsync/internal/alert"
	"github.com/hy/certsync/internal/certutil"
	"github.com/hy/certsync/internal/config"
	"github.com/hy/certsync/internal/cryptoutil"
	"github.com/hy/certsync/internal/deploy"
	"github.com/hy/certsync/internal/store"
)

func newPullCmd() *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "pull [--domain x]",
		Short: "拉取、校验、原子安装、reload、探测确认(业务机 timer,§3)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runPull(cfg, domain)
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "只处理指定 target(灰度单台观察,§14)")
	return cmd
}

func runPull(cfg *config.Config, onlyDomain string) error {
	log := logger()
	if len(cfg.Pull.Targets) == 0 {
		return errors.New("pull.targets 未配置")
	}

	lock, err := lockInstance(cfg.State.LockFile)
	if err != nil {
		return err
	}
	defer lock.Close()

	alerter := alert.NewSender(cfg.Alert, log)
	st, err := store.New(cfg.OSS, "", log)
	if err != nil {
		return err
	}
	key, err := cryptoutil.LoadKey(cfg.Crypto.KeyFile)
	if err != nil {
		return err
	}

	failed := false
	for _, tgt := range cfg.Pull.Targets {
		if onlyDomain != "" && tgt.Domain != onlyDomain {
			continue
		}
		if err := pullTarget(cfg, st, alerter, key, tgt); err != nil {
			log.Error("target 处理失败", "domain", tgt.Domain, "err", err)
			failed = true
		}
	}
	if failed {
		return errors.New("存在失败的 target(详见日志与告警)")
	}
	return nil
}

// pullTarget 单个 target 的完整流程:meta → 指纹比对 → 下载解密 → §7.1 校验链
// → 原子安装(§7.2)→ 到期检查(§12.1 expiry_warning 兜底生命线)。
func pullTarget(cfg *config.Config, st *store.Store, alerter *alert.Sender, key []byte, tgt config.PullTarget) error {
	log := logger()

	meta, err := st.GetMeta(tgt.Domain)
	if err != nil {
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain,
			"读取 OSS meta.json 失败: "+err.Error()))
		return err
	}

	// 本地已装证书指纹(读不到视为空 → 必须安装)
	localFP := ""
	if raw, rerr := os.ReadFile(tgt.CertFile); rerr == nil {
		if certs, perr := certutil.ParseCertificates(raw); perr == nil {
			localFP = certutil.Fingerprint(certutil.Leaf(certs))
			// 到期兜底检查独立于安装链路(§12.1:签发端瘫痪时仍持续告警)
			checkExpiry(cfg, alerter, certutil.Leaf(certs), tgt.Domain)
		}
	}

	if localFP == meta.Fingerprint {
		log.Debug("指纹一致,跳过", "domain", tgt.Domain, "fingerprint", meta.Fingerprint[:16]+"…")
		return nil
	}

	certEnc, keyEnc, err := st.GetEncryptedPair(tgt.Domain)
	if err != nil {
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain,
			"下载密文失败: "+err.Error()))
		return err
	}
	certPEM, err := cryptoutil.Decrypt(key, certEnc)
	if err != nil {
		// 密钥不对/密文损坏:保留旧证书,告警(§13 过渡期行为)
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain,
			"解密失败(主密钥不一致或密文损坏,已保留本地旧证书): "+err.Error()))
		return err
	}
	keyPEM, err := cryptoutil.Decrypt(key, keyEnc)
	if err != nil {
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain,
			"解密私钥失败: "+err.Error()))
		return err
	}

	// §7.1 校验链(2~5 条在 ValidateChain 内)
	leaf, err := certutil.ValidateChain(certPEM, keyPEM, tgt.Domain, now())
	if err != nil {
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain,
			"校验链失败(已保留本地旧证书): "+err.Error()))
		return err
	}
	// §7.1 第 6 条:指纹必须与 meta 一致(防半更新)
	if got := certutil.Fingerprint(leaf); got != meta.Fingerprint {
		err := fmt.Errorf("证书指纹与 meta.json 不一致(半更新状态): got %s want %s", got, meta.Fingerprint)
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain, err.Error()))
		return err
	}

	opts := deploy.Options{
		CheckCmd:  cfg.Pull.CheckCmd,
		ReloadCmd: cfg.Pull.ReloadCmd,
		BackupDir: cfg.Pull.BackupDir,
		SkipProbe: !cfg.Pull.ProbeEnabled(), // post_reload_probe=false 时跳过探测
	}

	_, err = deploy.Install(deploy.Target{
		Domain: tgt.Domain, CertFile: tgt.CertFile, KeyFile: tgt.KeyFile,
	}, certPEM, keyPEM, opts)
	if err != nil {
		detail := err.Error()
		if errors.Is(err, deploy.ErrProbeMismatch) {
			// §7.2 例外:文件已过全部校验,不回滚,只告警
			detail += "(文件已保留,请检查 nginx 配置引用路径/reload 是否生效)"
		}
		alerter.Send(alert.NewEvent("install_fail", "error", alert.Hostname(), tgt.Domain, detail))
		return err
	}

	alerter.Send(alert.NewEvent("install_ok", "info", alert.Hostname(), tgt.Domain,
		"安装并 reload 成功,指纹 "+meta.Fingerprint[:16]+"…"))
	checkExpiry(cfg, alerter, leaf, tgt.Domain)
	return nil
}

// checkExpiry 剩余天数低于 expire_alert_days 每轮都告警(§12.1 兜底生命线:
// 即使签发端整体瘫痪,业务机仍持续喊"快过期")。
func checkExpiry(cfg *config.Config, alerter *alert.Sender, leaf *x509.Certificate, domain string) {
	if d := certutil.RemainingDays(leaf, now()); d < cfg.Pull.ExpireAlertDays {
		alerter.Send(alert.NewEvent("expiry_warning", "error", alert.Hostname(), domain,
			fmt.Sprintf("证书剩余 %d 天,低于阈值 %d 天", d, cfg.Pull.ExpireAlertDays)))
	}
}
