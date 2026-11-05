package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func recordingRobot(t *testing.T, messages *[]string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Error("invalid robot request")
		}
		var payload struct {
			MsgType string `json:"msgtype"`
			Text    struct {
				Content string `json:"content"`
			} `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.MsgType != "text" {
			t.Error("invalid notification payload")
		}
		*messages = append(*messages, payload.Text.Content)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestDingTalkSignature(t *testing.T) {
	endpoint, err := signedDingTalkURL("https://oapi.dingtalk.com/robot/send?access_token=test-token", "SEC-test-secret", time.UnixMilli(1700000000123))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// Independent HMAC-SHA256 test vector, then standard Base64 and URL encoding.
	if u.Query().Get("sign") != "3af6SnEp8FmxEKMZeIjGMiivmb/0jfjQ5S6M9fg6/Vc=" || u.Query().Get("timestamp") != "1700000000123" || u.Query().Get("access_token") != "test-token" {
		t.Fatal("invalid signature, timestamp, or access token")
	}
	unsigned := "https://oapi.dingtalk.com/robot/send?access_token=test-token"
	if actual, err := signedDingTalkURL(unsigned, "", time.Now()); err != nil || actual != unsigned {
		t.Fatal("unsigned webhook changed")
	}
}

func TestExpiryThresholdAndMessageBatching(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	n := newNotifications(&Config{}, &out)
	n.now, n.host = now, "issuer-frankfurt"
	n.expiring("healthy.com", now.Add(expiryWarningWindow+time.Second))
	n.expiring("boundary.com", now.Add(expiryWarningWindow))
	n.expiring("*.example.com", now.Add(expiryWarningWindow-time.Second))
	n.expiring("expired.com", now.Add(-time.Hour))
	if len(n.events) != 2 {
		t.Fatalf("less-than-15-day threshold incorrect: %d events", len(n.events))
	}
	message := strings.Join(n.messages(), "\n")
	for _, want := range []string{"certsync", "issuer-frankfurt", "*.example.com", "expired.com", "已过期", "+08:00"} {
		if !strings.Contains(message, want) {
			t.Fatalf("notification missing %q", want)
		}
	}
	if strings.Contains(message, "boundary.com") || strings.Contains(message, "healthy.com") {
		t.Fatal("healthy certificates alerted")
	}
	for i := 0; i < 100; i++ {
		n.replaced(strings.Repeat("a", 60)+".example.com", now.Add(24*time.Hour))
	}
	messages := n.messages()
	if len(messages) < 2 {
		t.Fatal("large notification batch not split")
	}
	total := 0
	for _, message := range messages {
		if len(message) > 12000 || !strings.Contains(message, "certsync") {
			t.Fatal("invalid notification chunk")
		}
		total += strings.Count(message, "证书组：")
	}
	if total != 102 {
		t.Fatal("events lost while splitting messages")
	}
}

func TestPushExpiryAlertsOnEveryRunAndFailures(t *testing.T) {
	for _, scenario := range []string{"success", "upload failure", "expired", "missing key"} {
		t.Run(scenario, func(t *testing.T) {
			var messages []string
			server := recordingRobot(t, &messages)
			fixture := newTestChain(t, scenario == "expired")
			cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: t.TempDir(), DingTalkWebhook: server.URL}
			writeGroup(t, cfg.Directory, "example.com", fixture)
			if scenario == "missing key" {
				if err := os.Remove(filepath.Join(cfg.Directory, "example.com", KeyName)); err != nil {
					t.Fatal(err)
				}
			}
			st := &memoryStore{fail: scenario == "upload failure"}
			for attempt := 0; attempt < 2; attempt++ {
				err := run(context.Background(), &bytes.Buffer{}, "push", cfg, st, fixture.Roots)
				if (err != nil) != (scenario != "success") {
					t.Fatalf("unexpected push result: %v", err)
				}
			}
			if len(messages) != 2 {
				t.Fatalf("expiry alert must repeat on each push, got %d", len(messages))
			}
			if !strings.Contains(messages[0], "example.com") || !strings.Contains(messages[0], "到期时间") {
				t.Fatal("expiry notification missing certificate details")
			}
			if scenario == "expired" && (st.puts != 0 || !strings.Contains(messages[0], "已过期")) {
				t.Fatal("expired certificate was uploaded or not alerted")
			}
		})
	}
}

func TestPullReportsFailuresAndSuccessfulReplacements(t *testing.T) {
	var messages []string
	server := recordingRobot(t, &messages)
	fixture := newTestChain(t, false)
	key := make([]byte, 32)
	data, err := Encrypt(key, Bundle{FullchainPEM: string(fixture.Cert), PrivateKeyPEM: string(fixture.Key)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Key: key, Prefix: "certsync", Groups: []string{"example.com"}, Directory: t.TempDir(), DingTalkWebhook: server.URL}
	st := &memoryStore{objects: map[string][]byte{"certsync/example.com/bundle.enc": data}}
	pull := func() error { return run(context.Background(), &bytes.Buffer{}, "pull", cfg, st, fixture.Roots) }
	if err := pull(); err != nil || len(messages) != 1 {
		t.Fatalf("first install not notified: %v", err)
	}
	if !strings.Contains(messages[0], "成功替换") || !strings.Contains(messages[0], "尚未确认服务 reload") {
		t.Fatal("replacement notification misstates service status")
	}
	if err := pull(); err != nil || len(messages) != 1 {
		t.Fatal("unchanged files caused a notification")
	}
	if err := os.Remove(filepath.Join(cfg.Directory, "example.com", KeyName)); err != nil {
		t.Fatal(err)
	}
	if err := pull(); err != nil || len(messages) != 2 {
		t.Fatal("repairing a missing key was not notified")
	}
	st.objects["certsync/example.com/bundle.enc"] = []byte("corrupt bundle")
	if err := pull(); err == nil || len(messages) != 3 || !strings.Contains(messages[2], "失败阶段：解密证书包") {
		t.Fatal("failed download/decryption did not send a failure notification")
	}
	st.objects["certsync/example.com/bundle.enc"] = data
	cfg.Directory = t.TempDir()
	blocked := filepath.Join(cfg.Directory, "example.com", KeyName)
	if err := os.MkdirAll(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pull(); err == nil || len(messages) != 4 || !strings.Contains(messages[3], "失败阶段：安装证书文件") {
		t.Fatal("failed installation did not send a failure notification")
	}
	cfg.Directory = t.TempDir()
	cfg.Groups = []string{"missing.com", "example.com"}
	if err := pull(); err == nil || len(messages) != 5 {
		t.Fatal("partial batch did not send a combined notification")
	}
	if !strings.Contains(messages[4], "证书组：missing.com\n事件：执行失败") || !strings.Contains(messages[4], "证书组：example.com\n事件：证书和私钥已成功替换") || !strings.Contains(messages[4], "成功 1 组，失败 1 组") {
		t.Fatal("partial batch omitted failure or successful replacement details")
	}
}

func TestRobotFailureDoesNotFailDistributionOrExposeSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"private-token SEC-private-secret"}`))
	}))
	defer server.Close()
	fixture := newTestChain(t, false)
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: t.TempDir(), DingTalkWebhook: server.URL + "?access_token=private-token", DingTalkSecret: "SEC-private-secret"}
	writeGroup(t, cfg.Directory, "example.com", fixture)
	st := &memoryStore{}
	var out bytes.Buffer
	if err := run(context.Background(), &out, "push", cfg, st, fixture.Roots); err != nil || st.puts != 1 {
		t.Fatalf("notification failure prevented upload: %v", err)
	}
	cfg.Directory, cfg.Groups = t.TempDir(), []string{"example.com"}
	if err := run(context.Background(), &out, "pull", cfg, st, fixture.Roots); err != nil {
		t.Fatalf("notification failure prevented installation/reload: %v", err)
	}
	if !strings.Contains(out.String(), "errcode=310000") || strings.Contains(out.String(), "通知已发送") {
		t.Fatal("HTTP 200 with an error code treated as success")
	}
	for _, secret := range []string{"private-token", "SEC-private-secret", "PRIVATE KEY"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("notification log exposed secrets")
		}
	}
}

func TestDingTalkResponseValidation(t *testing.T) {
	for _, body := range []string{`{}`, `{"errcode":null}`, `{"errcode":"0"}`, `not-json`, strings.Repeat("x", 65537)} {
		t.Run(body[:min(len(body), 24)], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			if err := sendDingTalk(context.Background(), server.Client(), server.URL, "", "certsync test"); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer server.Close()
	if err := sendDingTalk(context.Background(), server.Client(), server.URL, "", "certsync test"); err != nil || requests != 2 {
		t.Fatalf("transient HTTP failure not retried: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sendDingTalk(ctx, server.Client(), server.URL+"?access_token=private-token", "SEC-private-secret", "certsync test"); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("cancelled request succeeded or exposed credentials")
	}
}
