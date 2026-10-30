package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleTOML = `
[acme]
ca_server = ""
email = "ops@example.com"
domains = ["example.com", "*.example.com"]
renew_before_days = 30

[alidns]
access_key = ""
secret_key = ""

[oss]
endpoint = "oss-cn-hangzhou.aliyuncs.com"
region = "cn-hangzhou"
bucket = "my-cert-bucket"
prefix = "certsync"
access_key = ""
secret_key = ""

[crypto]
key_file = "/etc/certsync/certsync.key"

[state]
dir = "/var/lib/certsync"
lock_file = "/run/certsync.lock"

[pull]
check_cmd  = ["nginx", "-t"]
reload_cmd = ["systemctl", "reload", "nginx"]
backup_dir = "/var/lib/certsync/backup"
expire_alert_days = 15

[[pull.targets]]
domain = "example.com"
cert_file = "/etc/nginx/certs/example.com/fullchain.pem"
key_file  = "/etc/nginx/certs/example.com/privkey.pem"

[alert.webhook]
url = "https://hooks.example.com/x"

[alert.webhook.headers]
Authorization = "Bearer tok"

[alert.dingtalk]
webhook = "https://oapi.dingtalk.com/robot/send?access_token=abc"

[alert.mail]
host = "smtp.example.com"
port = 465
`

func TestLoadBasic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(sampleTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.PrimaryDomain() != "example.com" {
		t.Errorf("PrimaryDomain = %q", c.PrimaryDomain())
	}
	if len(c.Pull.Targets) != 1 || c.Pull.Targets[0].Domain != "example.com" {
		t.Errorf("pull.targets 解析错误: %+v", c.Pull.Targets)
	}
	if c.Alert.Webhook.Headers["Authorization"] != "Bearer tok" {
		t.Errorf("webhook headers 解析错误: %+v", c.Alert.Webhook.Headers)
	}
	if !c.Pull.ProbeEnabled() {
		t.Error("post_reload_probe 未配置时应默认开启")
	}
	if c.StagingPrefix() != "certsync-staging" {
		t.Errorf("StagingPrefix = %q", c.StagingPrefix())
	}
}

func TestEnvFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(sampleTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALICLOUD_ACCESS_KEY", "ak-test")
	t.Setenv("OSS_ACCESS_KEY_ID", "oss-id")
	t.Setenv("OSS_ACCESS_KEY_SECRET", "oss-secret")
	t.Setenv("DINGTALK_SECRET", "sec-test")
	t.Setenv("ALERT_MAIL_USER", "mail-user")
	t.Setenv("ALERT_MAIL_PASS", "mail-pass")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.AliDNS.AccessKey != "ak-test" {
		t.Errorf("AliDNS.AccessKey = %q, want ak-test", c.AliDNS.AccessKey)
	}
	if c.OSS.AccessKey != "oss-id" || c.OSS.SecretKey != "oss-secret" {
		t.Errorf("OSS 凭证回退失败: %+v", c.OSS)
	}
	if c.Alert.DingTalk.Secret != "sec-test" {
		t.Errorf("DingTalk.Secret = %q", c.Alert.DingTalk.Secret)
	}
	if c.Alert.Mail.Username != "mail-user" || c.Alert.Mail.Password != "mail-pass" {
		t.Errorf("邮件凭证回退失败: %+v", c.Alert.Mail)
	}
}

func TestProbeExplicitFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	tomlFalse := sampleTOML + "\npost_reload_probe = false\n"
	// 追加到 [pull] 段需要重写;直接写一个仅含 pull 段的配置
	tomlFalse = `[pull]
post_reload_probe = false
`
	if err := os.WriteFile(path, []byte(tomlFalse), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Pull.ProbeEnabled() {
		t.Error("显式 false 时 ProbeEnabled 应为 false")
	}
}

func TestDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[acme]\nemail=\"a@b.c\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ACME.RenewBeforeDays != 30 {
		t.Errorf("renew_before_days 默认值 = %d", c.ACME.RenewBeforeDays)
	}
	if c.State.Dir != "/var/lib/certsync" || c.State.LockFile != "/run/certsync.lock" {
		t.Errorf("state 默认值错误: %+v", c.State)
	}
	if c.Pull.ExpireAlertDays != 15 {
		t.Errorf("expire_alert_days 默认值 = %d", c.Pull.ExpireAlertDays)
	}
}
