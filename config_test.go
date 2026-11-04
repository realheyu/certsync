package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCommonConfig = `
key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
oss_region = "cn-hangzhou"
oss_bucket = "bucket"
oss_prefix = "certsync/production/"
oss_access_key_id = "fake"
oss_access_key_secret = "secret"
`

const testPushConfig = `[push]
source_dir = "/certs"
` + testCommonConfig

const testPullConfig = `[pull]
output_dir = "/nginx/certs"
groups = ["*.example.com", "other.com"]
` + testCommonConfig

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestDingTalkConfig(t *testing.T) {
	const webhook = "https://oapi.dingtalk.com/robot/send?access_token=private-token"
	const secret = "SEC-private-secret"
	for command, settings := range map[string]string{"push": testPushConfig, "pull": testPullConfig} {
		file := writeTestConfig(t, settings+fmt.Sprintf("dingtalk_webhook = %q\ndingtalk_secret = %q\n", webhook, secret))
		cfg, err := Load(command, file)
		if err != nil || cfg.DingTalkWebhook != webhook || cfg.DingTalkSecret != secret {
			t.Fatalf("valid notification configuration rejected: %v", err)
		}
	}
	for _, bad := range []string{"", "http://oapi.dingtalk.com/robot/send", "https://user:private-token@example.com/send", "https://example.com/send#private-token", "://private-token"} {
		file := writeTestConfig(t, testPullConfig+fmt.Sprintf("dingtalk_webhook = %q\ndingtalk_secret = %q\n", bad, secret))
		_, err := Load("pull", file)
		if err == nil {
			t.Fatal("invalid notification configuration accepted")
		}
		if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), secret) {
			t.Fatal("notification credentials exposed")
		}
	}
	file := writeTestConfig(t, testPullConfig+fmt.Sprintf("dingtalk_webhook = %q\n", webhook))
	if _, err := Load("pull", file); err != nil {
		t.Fatalf("keyword/IP based robot rejected: %v", err)
	}
}

func TestInvalidConfig(t *testing.T) {
	tests := []struct {
		name, command, contents string
	}{
		{"key", "push", strings.Replace(testPushConfig, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "bad-secret-value", 1)},
		{"missing credential", "push", strings.Replace(testPushConfig, `oss_access_key_secret = "secret"`, "", 1)},
		{"endpoint", "push", testPushConfig + "oss_endpoint = \"http://localhost\"\n"},
		{"group type", "pull", strings.Replace(testPullConfig, `["*.example.com", "other.com"]`, `"example.com"`, 1)},
		{"group list", "pull", strings.Replace(testPullConfig, `["*.example.com", "other.com"]`, `[]`, 1)},
		{"output path", "pull", strings.Replace(testPullConfig, "/nginx/certs", "relative", 1)},
		{"source path", "push", strings.Replace(testPushConfig, "/certs", "relative", 1)},
		{"empty prefix", "pull", strings.Replace(testPullConfig, "certsync/production/", "", 1)},
		{"absolute prefix", "push", strings.Replace(testPushConfig, "certsync/production/", "/certsync", 1)},
		{"relative path segment", "pull", strings.Replace(testPullConfig, "certsync/production/", "certsync/../other", 1)},
		{"URL prefix", "push", strings.Replace(testPushConfig, "certsync/production/", "oss://bucket/x", 1)},
		{"backslash prefix", "push", strings.Replace(testPushConfig, "certsync/production/", `certsync\\other`, 1)},
		{"unknown field", "pull", testPullConfig + "oss_object_key = \"certsync/example.com/bundle.enc\"\n"},
		{"missing role", "pull", testPushConfig},
		{"invalid TOML", "push", testPushConfig + "dingtalk_webhook = bad-secret-value\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.command, writeTestConfig(t, tt.contents))
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if strings.Contains(err.Error(), "bad-secret-value") {
				t.Fatal("secret exposed")
			}
		})
	}
}

func TestRoleSpecificConfig(t *testing.T) {
	pull := strings.Replace(testPullConfig, `oss_access_key_id = "fake"`, `oss_access_key_id = "download"`, 1)
	file := writeTestConfig(t, testPushConfig+pull)
	pushConfig, err := Load("push", file)
	if err != nil {
		t.Fatal(err)
	}
	pullConfig, err := Load("pull", file)
	if err != nil {
		t.Fatal(err)
	}
	if pushConfig.Directory != "/certs" || pushConfig.AccessKey != "fake" || pushConfig.Prefix != "certsync/production" || len(pushConfig.Groups) != 0 {
		t.Fatal("unexpected push configuration")
	}
	if pullConfig.Directory != "/nginx/certs" || pullConfig.AccessKey != "download" || pullConfig.Prefix != "certsync/production" || strings.Join(pullConfig.Groups, ",") != "*.example.com,other.com" {
		t.Fatal("unexpected pull configuration")
	}

	file = writeTestConfig(t, testPushConfig+"[pull]\ngroups = false\n")
	if _, err := Load("push", file); err != nil {
		t.Fatalf("push should ignore invalid pull settings: %v", err)
	}
	if _, err := Load("pull", file); err == nil {
		t.Fatal("invalid selected role accepted")
	}
}

func TestGroupsValidation(t *testing.T) {
	for _, s := range []string{
		"", "foo..com", "-foo.com", "a.com/xx", "../example.com", "example.com,", "foo_.com",
		"example.com,example.com", "Example.com", "example.com,OTHER.com",
		"*", "*.", "*.com", "*example.com", "foo*.example.com", "api.*.example.com",
		"**.example.com", "*.*.example.com", "*.Example.com", "*.../example.com",
		"*.example.com/xx", `*\.example.com`, "*.example.com, *.example.com ",
		"*." + strings.Repeat("a", 64) + ".com",
		"*." + strings.Repeat(strings.Repeat("a", 62)+".", 3) + strings.Repeat("a", 63),
	} {
		if _, err := parseGroups(strings.Split(s, ",")); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, tt := range []struct{ raw, want string }{
		{"example.com, other.com ", "example.com,other.com"},
		{"*.fsbtiot.com", "*.fsbtiot.com"},
		{" *.example.com , example.com,other.com ", "*.example.com,example.com,other.com"},
		{"*.sub.example.com", "*.sub.example.com"},
		{"*.xn--bcher-kva.example", "*.xn--bcher-kva.example"},
	} {
		groups, err := parseGroups(strings.Split(tt.raw, ","))
		if err != nil || strings.Join(groups, ",") != tt.want {
			t.Fatalf("valid list %q rejected or changed: %v, %v", tt.raw, groups, err)
		}
	}
}
