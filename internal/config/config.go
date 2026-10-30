// Package config 加载 /etc/certsync/config.toml 并按 §8 约定做空值环境变量回退。
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Paths 是默认文件位置,可被测试覆盖。
var (
	DefaultConfigFile = "/etc/certsync/config.toml"
)

type Config struct {
	ACME   ACME   `toml:"acme"`
	AliDNS AliDNS `toml:"alidns"`
	OSS    OSS    `toml:"oss"`
	Crypto Crypto `toml:"crypto"`
	State  State  `toml:"state"`
	Pull   Pull   `toml:"pull"`
	Alert  Alert  `toml:"alert"`
}

type ACME struct {
	CAServer        string `toml:"ca_server"`
	Email           string `toml:"email"`
	Domains         []string `toml:"domains"`
	RenewBeforeDays int    `toml:"renew_before_days"`
	EAB             EAB    `toml:"eab"`
}

type EAB struct {
	KID  string `toml:"kid"`
	HMAC string `toml:"hmac"`
}

type AliDNS struct {
	AccessKey string `toml:"access_key"` // env: ALICLOUD_ACCESS_KEY
	SecretKey string `toml:"secret_key"` // env: ALICLOUD_SECRET_KEY
}

type OSS struct {
	Endpoint  string `toml:"endpoint"`
	Region    string `toml:"region"`
	Bucket    string `toml:"bucket"`
	Prefix    string `toml:"prefix"`
	AccessKey string `toml:"access_key"` // env: OSS_ACCESS_KEY_ID
	SecretKey string `toml:"secret_key"` // env: OSS_ACCESS_KEY_SECRET
}

type Crypto struct {
	KeyFile string `toml:"key_file"` // 主密钥文件;env: CERTSYNC_KEY(base64)优先
}

type State struct {
	Dir      string `toml:"dir"`
	LockFile string `toml:"lock_file"`
}

type PullTarget struct {
	Domain   string `toml:"domain"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type Pull struct {
	Targets         []PullTarget `toml:"targets"`
	CheckCmd        []string     `toml:"check_cmd"`
	ReloadCmd       []string     `toml:"reload_cmd"`
	BackupDir       string       `toml:"backup_dir"`
	ExpireAlertDays int          `toml:"expire_alert_days"`
	// PostReloadProbe 用指针区分"未配置"(默认开)与"显式 false"(§7.2)。
	PostReloadProbe *bool `toml:"post_reload_probe"`
}

// ProbeEnabled 返回 reload 后探测是否启用,未配置时默认 true。
func (p Pull) ProbeEnabled() bool { return p.PostReloadProbe == nil || *p.PostReloadProbe }

type AlertWebhook struct {
	URL     string            `toml:"url"`
	Headers map[string]string `toml:"headers"`
}

type AlertDingTalk struct {
	Webhook   string   `toml:"webhook"`
	Secret    string   `toml:"secret"` // env: DINGTALK_SECRET
	AtMobiles []string `toml:"at_mobiles"`
}

type AlertMail struct {
	Host     string   `toml:"host"`
	Port     int      `toml:"port"`
	Username string   `toml:"username"` // env: ALERT_MAIL_USER
	Password string   `toml:"password"` // env: ALERT_MAIL_PASS
	From     string   `toml:"from"`
	To       []string `toml:"to"`
}

type Alert struct {
	Webhook  AlertWebhook  `toml:"webhook"`
	DingTalk AlertDingTalk `toml:"dingtalk"`
	Mail     AlertMail     `toml:"mail"`
}

// Load 读取 toml → 应用默认值 → 敏感字段空值回退环境变量。
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigFile
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var c Config
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("解析 toml %s: %w", path, err)
	}
	c.applyDefaults()
	c.envFallback()
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.ACME.RenewBeforeDays <= 0 {
		c.ACME.RenewBeforeDays = 30
	}
	if c.State.Dir == "" {
		c.State.Dir = "/var/lib/certsync"
	}
	if c.State.LockFile == "" {
		c.State.LockFile = "/run/certsync.lock"
	}
	if c.Pull.BackupDir == "" {
		c.Pull.BackupDir = filepath.Join(c.State.Dir, "backup")
	}
	if c.Pull.ExpireAlertDays <= 0 {
		c.Pull.ExpireAlertDays = 15
	}
}

// envFallback:toml 留空 → 取环境变量(§8 表内标注的项)。
func (c *Config) envFallback() {
	setIfEmpty(&c.AliDNS.AccessKey, "ALICLOUD_ACCESS_KEY")
	setIfEmpty(&c.AliDNS.SecretKey, "ALICLOUD_SECRET_KEY")
	setIfEmpty(&c.OSS.AccessKey, "OSS_ACCESS_KEY_ID")
	setIfEmpty(&c.OSS.SecretKey, "OSS_ACCESS_KEY_SECRET")
	setIfEmpty(&c.Alert.DingTalk.Secret, "DINGTALK_SECRET")
	setIfEmpty(&c.Alert.Mail.Username, "ALERT_MAIL_USER")
	setIfEmpty(&c.Alert.Mail.Password, "ALERT_MAIL_PASS")
}

func setIfEmpty(dst *string, env string) {
	if *dst == "" {
		*dst = os.Getenv(env)
	}
}

// PrimaryDomain 返回证书组主域名(存储主键,§5.1)。
func (c *Config) PrimaryDomain() string {
	if len(c.ACME.Domains) == 0 {
		return ""
	}
	return c.ACME.Domains[0]
}

// StagingPrefix 返回 --staging 模式强制使用的 OSS 前缀(§3)。
func (c *Config) StagingPrefix() string {
	return c.OSS.Prefix + "-staging"
}
