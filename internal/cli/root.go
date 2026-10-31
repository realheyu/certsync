// Package cli cobra 命令接线:root/keygen/issue/renew/push/pull/status/version/on-failure(3 节)。
package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/hy/certsync/internal/config"
)

var (
	configFile string
	Version    = "dev"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "certsync",
		Short:   "集中签发 + OSS 加密中转 + 多机拉取部署的证书管理",
		Version: Version,
	}
	root.PersistentFlags().StringVar(&configFile, "config", config.DefaultConfigFile, "配置文件路径")
	root.AddCommand(
		newKeygenCmd(),
		newIssueCmd(),
		newRenewCmd(),
		newPushCmd(),
		newPullCmd(),
		newStatusCmd(),
		newVersionCmd(),
		newOnFailureCmd(),
	)
	return root
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func loadConfig() (*config.Config, error) {
	return config.Load(configFile)
}

// stateDirFor --staging 使用独立 state 子目录(3 节隔离规则)。
func stateDirFor(cfg *config.Config, staging bool) string {
	if staging {
		return filepath.Join(cfg.State.Dir, "staging")
	}
	return cfg.State.Dir
}

// prefixFor --staging 强制替换 OSS 前缀(3 节隔离规则:staging 证书绝不进正式链路)。
func prefixFor(cfg *config.Config, staging bool) string {
	if staging {
		return cfg.StagingPrefix()
	}
	return cfg.OSS.Prefix
}

// caServerFor --staging 覆盖 CA 为测试环境;显式配置的 ca_server 优先(便于自测其他 CA)。
func caServerFor(cfg *config.Config, staging bool) string {
	if staging && cfg.ACME.CAServer == "" {
		return acmeStagingDirURL()
	}
	return cfg.ACME.CAServer
}

// lockInstance flock 抢锁;抢不到直接退出(7.3 节,cron 重叠/手工并发安全)。
func lockInstance(lockFile string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockFile), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("已有 certsync 实例在运行(%s): %w", lockFile, err)
	}
	return f, nil
}

func now() time.Time { return time.Now() }
