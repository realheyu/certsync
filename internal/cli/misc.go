package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hy/certsync/internal/acme"
	"github.com/hy/certsync/internal/alert"
	"github.com/hy/certsync/internal/certutil"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "打印各 target 本地证书的域名、到期时间、剩余天数(§3 巡检)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-32s %-20s %10s  %s\n", "DOMAIN", "NOT_AFTER(UTC)", "REMAINING", "SOURCE")

			printRow := func(domain, path string) {
				raw, err := os.ReadFile(path)
				if err != nil {
					fmt.Fprintf(out, "%-32s %-20s %10s  %s\n", domain, "-", "-", path+"(未安装)")
					return
				}
				certs, err := certutil.ParseCertificates(raw)
				if err != nil {
					fmt.Fprintf(out, "%-32s %-20s %10s  %s\n", domain, "-", "-", path+"(解析失败)")
					return
				}
				leaf := certutil.Leaf(certs)
				fmt.Fprintf(out, "%-32s %-20s %8dd  %s\n",
					domain,
					leaf.NotAfter.UTC().Format("2006-01-02"),
					certutil.RemainingDays(leaf, now()),
					path)
			}

			if len(cfg.Pull.Targets) > 0 {
				for _, t := range cfg.Pull.Targets {
					printRow(t.Domain, t.CertFile)
				}
			}
			if primary := cfg.PrimaryDomain(); primary != "" {
				printRow(primary+"/state", acme.StateCertDir(cfg.State.Dir, primary)+"/fullchain.pem")
			}
			if len(cfg.Pull.Targets) == 0 && cfg.PrimaryDomain() == "" {
				fmt.Fprintln(out, "(未配置 pull.targets 与 acme.domains)")
			}
			return nil
		},
	}
}

func newOnFailureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "on-failure <unit>",
		Short: "systemd OnFailure 兜底钩子:极短路径,只发 unit_failed 告警(§11.2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			alert.NewSender(cfg.Alert, logger()).Send(alert.NewEvent(
				"unit_failed", "error", alert.Hostname(), "",
				"systemd 单元失败: "+args[0]+"(进程内告警未执行,由 OnFailure 钩子发出;详见 journalctl -u "+args[0]))
			return nil
		},
	}
}
