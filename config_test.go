package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func setTestEnvironment(t *testing.T) {
	t.Helper()
	vars := map[string]string{
		"CERTSYNC_KEY":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"CERTSYNC_GROUPS": "example.com,other.com", "OSS_REGION": "cn-hangzhou",
		"OSS_BUCKET": "bucket", "OSS_PREFIX": "certsync", "OSS_OBJECT_KEY": "", "CERTSYNC_DOMAINS": "",
		"OSS_ACCESS_KEY_ID": "fake", "OSS_ACCESS_KEY_SECRET": "secret",
		"CERTSYNC_SOURCE_DIR": t.TempDir(), "CERTSYNC_OUTPUT_DIR": t.TempDir(), "OSS_ENDPOINT": "",
		"DINGTALK_WEBHOOK": "", "DINGTALK_SECRET": "",
	}
	for name, value := range vars {
		t.Setenv(name, value)
	}
}

func TestDingTalkEnvironment(t *testing.T) {
	setTestEnvironment(t)
	t.Setenv("DINGTALK_WEBHOOK", "https://oapi.dingtalk.com/robot/send?access_token=private-token")
	t.Setenv("DINGTALK_SECRET", "SEC-private-secret")
	for _, command := range []string{"push", "pull"} {
		cfg, err := Load(command)
		if err != nil || cfg.DingTalkWebhook == "" || cfg.DingTalkSecret == "" {
			t.Fatalf("valid notification configuration rejected: %v", err)
		}
	}
	for _, webhook := range []string{"", "http://oapi.dingtalk.com/robot/send", "https://user:private-token@example.com/send", "https://example.com/send#private-token", "://private-token"} {
		t.Setenv("DINGTALK_WEBHOOK", webhook)
		_, err := Load("pull")
		if err == nil {
			t.Fatal("invalid notification configuration accepted")
		}
		if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "SEC-private-secret") {
			t.Fatal("notification credentials exposed")
		}
	}
	t.Setenv("DINGTALK_WEBHOOK", "https://oapi.dingtalk.com/robot/send?access_token=private-token")
	t.Setenv("DINGTALK_SECRET", "")
	if _, err := Load("pull"); err != nil {
		t.Fatalf("keyword/IP based robot rejected: %v", err)
	}
}
func TestEnvironment(t *testing.T) {
	setTestEnvironment(t)
	for _, cmd := range []string{"push", "pull"} {
		if _, err := Load(cmd); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct{ name, value, cmd string }{
		{"CERTSYNC_KEY", "bad-secret-value", "push"}, {"OSS_ACCESS_KEY_SECRET", "", "push"},
		{"OSS_ENDPOINT", "http://localhost", "push"}, {"CERTSYNC_GROUPS", "example.com,,other.com", "pull"},
		{"CERTSYNC_GROUPS", "", "pull"}, {"CERTSYNC_OUTPUT_DIR", "relative", "pull"},
		{"CERTSYNC_SOURCE_DIR", "relative", "push"}, {"OSS_PREFIX", "", "pull"},
		{"OSS_PREFIX", "/certsync", "push"}, {"OSS_PREFIX", "certsync/../other", "pull"},
		{"OSS_PREFIX", "oss://bucket/x", "push"}, {"OSS_OBJECT_KEY", "certsync/example.com/bundle.enc", "pull"},
		{"CERTSYNC_DOMAINS", "example.com,*.example.com", "pull"},
	}
	for _, tt := range tests {
		t.Run(tt.name+tt.value, func(t *testing.T) {
			t.Setenv(tt.name, tt.value)
			_, err := Load(tt.cmd)
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if strings.Contains(err.Error(), "bad-secret-value") {
				t.Fatal("secret exposed")
			}
		})
	}
}
func TestRoleSpecificEnvironment(t *testing.T) {
	t.Run("push discovers groups", func(t *testing.T) {
		setTestEnvironment(t)
		t.Setenv("CERTSYNC_GROUPS", "")
		t.Setenv("CERTSYNC_OUTPUT_DIR", "")
		t.Setenv("OSS_PREFIX", "certsync/production/")
		cfg, err := Load("push")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Prefix != "certsync/production" || len(cfg.Groups) != 0 {
			t.Fatal("unexpected push configuration")
		}
	})
	t.Run("pull uses selected groups", func(t *testing.T) {
		setTestEnvironment(t)
		t.Setenv("CERTSYNC_SOURCE_DIR", "")
		t.Setenv("CERTSYNC_GROUPS", "*.example.com,other.com")
		t.Setenv("OSS_PREFIX", "certsync/production/")
		cfg, err := Load("pull")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Prefix != "certsync/production" || strings.Join(cfg.Groups, ",") != "*.example.com,other.com" {
			t.Fatal("unexpected pull configuration")
		}
	})
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
		if _, err := ParseGroups(s); err == nil {
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
		groups, err := ParseGroups(tt.raw)
		if err != nil || strings.Join(groups, ",") != tt.want {
			t.Fatalf("valid list %q rejected or changed: %v, %v", tt.raw, groups, err)
		}
	}
}
