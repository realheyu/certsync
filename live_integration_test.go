package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
)

// Explicitly opt in: this test writes isolated objects to the configured real
// bucket and sends labelled messages to the configured real DingTalk robot.
// Objects are retained unless CERTSYNC_LIVE_CLEANUP=1 explicitly requests deletion.
// Normal go test runs never contact either service through this test.
func TestLiveConfiguredDistribution(t *testing.T) {
	filename := os.Getenv("CERTSYNC_LIVE_CONFIG")
	if filename == "" || os.Getenv("CERTSYNC_LIVE_SEND_NOTIFICATIONS") != "1" {
		t.Skip("set CERTSYNC_LIVE_CONFIG and CERTSYNC_LIVE_SEND_NOTIFICATIONS=1 to run live tests")
	}
	push, err := Load("push", filename)
	if err != nil {
		t.Fatal("live push configuration is invalid")
	}
	pull, err := Load("pull", filename)
	if err != nil {
		t.Fatal("live pull configuration is invalid")
	}
	if !bytes.Equal(push.Key, pull.Key) || push.Bucket != pull.Bucket || push.Prefix != pull.Prefix {
		t.Fatal("live push/pull must use the same key, bucket and prefix")
	}
	if push.DingTalkWebhook == "" || pull.DingTalkWebhook == "" {
		t.Fatal("both roles need a live robot for notification verification")
	}
	originalSource, originalOutput := push.Directory, pull.Directory
	originalSnapshot := snapshotLiveInputs(t, filename, originalSource, originalOutput)
	work := t.TempDir()
	runID := time.Now().UTC().Format("20060102T150405") + "-" + filepath.Base(work)
	prefix := path.Join(push.Prefix, "certsync-live-test", runID)
	push.Prefix, pull.Prefix = prefix, prefix
	push.Directory, pull.Directory = filepath.Join(work, "source"), filepath.Join(work, "output")
	if err := os.MkdirAll(filepath.Join(work, "locks"), 0700); err != nil {
		t.Fatal(err)
	}
	pushStore, pullStore := newStore(push), newStore(pull)
	written := map[string]bool{}
	tracked := &liveTrackingStore{objectStore: pushStore, written: written}
	var mu sync.Mutex
	var activeCase, activeOperation string
	var delivered []liveMessage
	var deliveryFailures int
	realPushURL, realPushSecret := push.DingTalkWebhook, push.DingTalkSecret
	realPullURL, realPullSecret := pull.DingTalkWebhook, pull.DingTalkSecret
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text struct {
				Content string `json:"content"`
			} `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid test payload", http.StatusBadRequest)
			return
		}
		mu.Lock()
		label, operation := activeCase, activeOperation
		mu.Unlock()
		endpoint, secret := realPullURL, realPullSecret
		if operation == "push" {
			endpoint, secret = realPushURL, realPushSecret
		}
		message := fmt.Sprintf("[certsync 实测 %s / %s]\n%s", runID, label, body.Text.Content)
		err := sendDingTalk(r.Context(), &http.Client{Timeout: 10 * time.Second}, endpoint, secret, message)
		mu.Lock()
		if err == nil {
			delivered = append(delivered, liveMessage{Case: label, Text: message})
		} else {
			deliveryFailures++
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			_, _ = w.Write([]byte(`{"errcode":1,"errmsg":"live delivery failed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	t.Cleanup(relay.Close)
	push.DingTalkWebhook, pull.DingTalkWebhook = relay.URL, relay.URL
	report := liveReport{RunID: runID, Bucket: push.Bucket, Prefix: prefix, CleanupRequested: os.Getenv("CERTSYNC_LIVE_CLEANUP") == "1"}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for key := range written {
			if !strings.HasPrefix(key, prefix+"/") {
				t.Error("refused cleanup outside the isolated test prefix")
				continue
			}
			if !report.CleanupRequested {
				report.RemainingObjects = append(report.RemainingObjects, key)
				continue
			}
			_, err := pushStore.client.DeleteObject(ctx, &oss.DeleteObjectRequest{Bucket: oss.Ptr(push.Bucket), Key: oss.Ptr(key)})
			if err != nil {
				report.RemainingObjects = append(report.RemainingObjects, key)
			} else {
				report.DeletedObjects++
			}
		}
		sort.Strings(report.RemainingObjects)
		mu.Lock()
		report.Messages = append(report.Messages, delivered...)
		report.NotificationDeliveryFailures = deliveryFailures
		mu.Unlock()
		report.OriginalInputsUnchanged = equalLiveSnapshots(originalSnapshot, snapshotLiveInputs(t, filename, originalSource, originalOutput))
		if !report.OriginalInputsUnchanged {
			t.Error("original configuration or certificate files changed")
		}
		if reportPath := os.Getenv("CERTSYNC_LIVE_REPORT"); reportPath != "" {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil || os.WriteFile(reportPath, data, 0600) != nil {
				t.Error("could not write live test report")
			}
		}
		t.Logf("live summary: cases=%d messages=%d delivery_failures=%d deleted_objects=%d remaining_objects=%d inputs_unchanged=%v", len(report.Cases), len(report.Messages), report.NotificationDeliveryFailures, report.DeletedObjects, len(report.RemainingObjects), report.OriginalInputsUnchanged)
	})

	runCase := func(t *testing.T, name, operation string, cfg *Config, store objectStore, roots *x509.CertPool, opts taskOptions, wantFailure bool, wantMessages, wantCommands int, fragments ...string) {
		t.Helper()
		mu.Lock()
		activeCase, activeOperation = name, operation
		before := len(delivered)
		mu.Unlock()
		baseExecute := opts.execute
		var commands []string
		opts.execute = func(ctx context.Context, command string, args ...string) (string, error) {
			commands = append(commands, command+" "+strings.Join(args, " "))
			if baseExecute != nil {
				return baseExecute(ctx, command, args...)
			}
			return "certsync live test: simulated service success", nil
		}
		if opts.lockPath == "" {
			opts.lockPath = filepath.Join(work, "locks", operation+".lock")
		}
		var out bytes.Buffer
		err := runTask(context.Background(), &out, operation, cfg, store, roots, opts)
		mu.Lock()
		messages := append([]liveMessage{}, delivered[before:]...)
		mu.Unlock()
		item := liveCase{Name: name, ExpectedFailure: wantFailure, Failed: err != nil, Messages: len(messages), Commands: commands, Log: out.String()}
		report.Cases = append(report.Cases, item)
		t.Logf("%s: expected_failure=%v failure=%v messages=%d service_commands=%d", name, wantFailure, err != nil, len(messages), len(commands))
		if (err != nil) != wantFailure || len(messages) != wantMessages || len(commands) != wantCommands {
			t.Fatalf("unexpected live result: %s", out.String())
		}
		text := ""
		for _, message := range messages {
			text += message.Text
		}
		for _, fragment := range fragments {
			if !strings.Contains(text, fragment) {
				t.Errorf("live notification missing %q", fragment)
			}
		}
		if wantMessages > 0 {
			// Space live robot requests instead of stress-testing its rate limit.
			time.Sleep(4 * time.Second)
		}
	}

	sourceGroup := pull.Groups[0]
	cert, err := os.ReadFile(filepath.Join(originalSource, sourceGroup, CertName))
	if err != nil {
		t.Fatal("could not read supplied certificate")
	}
	key, err := os.ReadFile(filepath.Join(originalSource, sourceGroup, KeyName))
	if err != nil {
		t.Fatal("could not read supplied private key")
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("supplied certificate PEM is invalid")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("supplied leaf certificate is invalid")
	}
	baseDomain := ""
	for _, domain := range leaf.DNSNames {
		if strings.HasPrefix(domain, "*.") {
			baseDomain = strings.TrimPrefix(domain, "*.")
			break
		}
	}
	if baseDomain == "" {
		t.Fatal("live multi-group fixture needs a certificate covering a wildcard and its base domain")
	}
	groups := []string{baseDomain, "*." + baseDomain, "api." + baseDomain, "www." + baseDomain, "certsync-test." + baseDomain}
	for _, group := range groups {
		if err := Validate(cert, key, []string{group}, time.Now(), nil); err != nil {
			t.Fatalf("supplied certificate does not validate for %s", group)
		}
		writeGroup(t, push.Directory, group, Chain{Cert: cert, Key: key})
	}
	pull.Groups = groups
	if !t.Run("public_push_five_groups", func(t *testing.T) {
		runCase(t, "public_push_five_groups", "push", push, tracked, nil, taskOptions{}, false, 0, 0)
	}) {
		return
	}
	if !t.Run("public_pull_five_groups", func(t *testing.T) {
		runCase(t, "public_pull_five_groups", "pull", pull, pullStore, nil, taskOptions{reloadNginx: true}, false, 1, 2, "成功 5 组，失败 0 组", "成功替换 5 组", "reload 成功")
		assertLiveFiles(t, push.Directory, pull.Directory, groups)
	}) {
		return
	}
	before := snapshotLiveTree(t, pull.Directory)
	t.Run("unchanged_no_notification", func(t *testing.T) {
		runCase(t, "unchanged_no_notification", "pull", pull, pullStore, nil, taskOptions{reloadNginx: true}, false, 0, 2)
		if !equalLiveSnapshots(before, snapshotLiveTree(t, pull.Directory)) {
			t.Error("unchanged files were rewritten")
		}
	})
	t.Run("missing_private_key_repaired", func(t *testing.T) {
		if err := os.Remove(filepath.Join(pull.Directory, groups[0], KeyName)); err != nil {
			t.Fatal(err)
		}
		runCase(t, "missing_private_key_repaired", "pull", pull, pullStore, nil, taskOptions{reloadNginx: true}, false, 1, 2, "成功替换 1 组", "reload 成功")
		assertLiveFiles(t, push.Directory, pull.Directory, groups)
	})
	publicPayload, err := pullStore.Get(context.Background(), path.Join(prefix, groups[0], "bundle.enc"))
	if err != nil {
		t.Fatal("could not read isolated test object")
	}
	publicMemory := &memoryStore{objects: map[string][]byte{path.Join(prefix, groups[0], "bundle.enc"): publicPayload}}
	one := *pull
	one.Groups = []string{groups[0]}
	t.Run("partial_missing_remote_object", func(t *testing.T) {
		cfg := *pull
		missing := "missing-certsync-test." + baseDomain
		cfg.Groups = append([]string{missing}, groups...)
		writeGroup(t, pull.Directory, missing, Chain{Cert: []byte("old test certificate"), Key: []byte("old test private key")})
		before := snapshotLiveTree(t, filepath.Join(pull.Directory, missing))
		runCase(t, "partial_missing_remote_object", "pull", &cfg, pullStore, nil, taskOptions{reloadNginx: true}, true, 1, 0, "成功 5 组，失败 1 组", "失败阶段：OSS 下载", "已跳过 Nginx")
		if !equalLiveSnapshots(before, snapshotLiveTree(t, filepath.Join(pull.Directory, missing))) {
			t.Error("failed group files changed")
		}
	})
	t.Run("all_remote_objects_missing", func(t *testing.T) {
		cfg := *pull
		cfg.Groups = []string{"missing-a." + baseDomain, "missing-b." + baseDomain}
		runCase(t, "all_remote_objects_missing", "pull", &cfg, pullStore, nil, taskOptions{reloadNginx: true}, true, 1, 0, "成功 0 组，失败 2 组", "任务结果：失败")
	})
	t.Run("wrong_decryption_key", func(t *testing.T) {
		cfg := one
		cfg.Key = append([]byte{}, one.Key...)
		cfg.Key[0] ^= 1
		runCase(t, "wrong_decryption_key", "pull", &cfg, pullStore, nil, taskOptions{reloadNginx: true}, true, 1, 0, "失败阶段：解密证书包")
	})
	t.Run("tampered_remote_bundle", func(t *testing.T) {
		object := path.Join(prefix, groups[0], "bundle.enc")
		corrupt := append([]byte{}, publicPayload...)
		corrupt[len(corrupt)-1] ^= 1
		if err := tracked.Put(context.Background(), object, corrupt); err != nil {
			t.Fatal("could not prepare isolated corrupt object")
		}
		defer func() {
			if err := tracked.Put(context.Background(), object, publicPayload); err != nil {
				t.Error("could not restore isolated test object")
			}
		}()
		before := snapshotLiveTree(t, filepath.Join(pull.Directory, groups[0]))
		runCase(t, "tampered_remote_bundle", "pull", &one, pullStore, nil, taskOptions{reloadNginx: true}, true, 1, 0, "失败阶段：解密证书包")
		if !equalLiveSnapshots(before, snapshotLiveTree(t, filepath.Join(pull.Directory, groups[0]))) {
			t.Error("corrupt object changed local files")
		}
	})
	t.Run("local_install_failure", func(t *testing.T) {
		cfg := one
		cfg.Directory = filepath.Join(work, "blocked-output")
		if err := os.MkdirAll(filepath.Join(cfg.Directory, groups[0], KeyName), 0700); err != nil {
			t.Fatal(err)
		}
		runCase(t, "local_install_failure", "pull", &cfg, publicMemory, nil, taskOptions{reloadNginx: true}, true, 1, 0, "失败阶段：安装证书文件", "可能已部分替换")
	})
	for _, stage := range []string{"nginx", "systemctl"} {
		t.Run(stage+"_failure_on_unchanged_files", func(t *testing.T) {
			calls := 1
			if stage == "systemctl" {
				calls = 2
			}
			runCase(t, stage+"_failure_on_unchanged_files", "pull", &one, publicMemory, nil, taskOptions{reloadNginx: true, execute: func(_ context.Context, command string, _ ...string) (string, error) {
				if command == stage {
					return "certsync live test: simulated service failure", errors.New("simulated service command failure")
				}
				return "simulated check success", nil
			}}, true, 1, calls, "任务结果：失败", "成功替换 0 组", "simulated service failure")
		})
	}
	t.Run("timeout_still_sends_notification", func(t *testing.T) {
		runCase(t, "timeout_still_sends_notification", "pull", &one, publicMemory, nil, taskOptions{reloadNginx: true, timeout: 100 * time.Millisecond, execute: func(ctx context.Context, _ string, _ ...string) (string, error) {
			<-ctx.Done()
			return "simulated timeout", ctx.Err()
		}}, true, 1, 1, "任务执行超时", "失败阶段：Nginx 配置检查")
	})
	t.Run("lock_conflict_sends_notification", func(t *testing.T) {
		lock := filepath.Join(work, "locks", "pull.lock")
		release, err := acquireTaskLock(lock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = release() }()
		runCase(t, "lock_conflict_sends_notification", "pull", &one, publicMemory, nil, taskOptions{reloadNginx: true, lockPath: lock}, true, 1, 0, "占锁", "失败阶段：获取任务锁")
	})
	t.Run("push_partial_missing_key", func(t *testing.T) {
		group := "broken-certsync-test." + baseDomain
		writeGroup(t, push.Directory, group, Chain{Cert: cert, Key: key})
		if err := os.Remove(filepath.Join(push.Directory, group, KeyName)); err != nil {
			t.Fatal(err)
		}
		runCase(t, "push_partial_missing_key", "push", push, tracked, nil, taskOptions{}, true, 1, 0, "成功 5 组，失败 1 组", "失败阶段：读取私钥")
	})
	t.Run("three_distinct_chains_and_expired_certificate", func(t *testing.T) {
		cfgPush, cfgPull := *push, *pull
		cfgPush.Prefix, cfgPull.Prefix = path.Join(prefix, "test-ca"), path.Join(prefix, "test-ca")
		cfgPush.Directory, cfgPull.Directory = filepath.Join(work, "ca-source"), filepath.Join(work, "ca-output")
		roots := x509.NewCertPool()
		cfgPull.Groups = []string{"alpha.certsync.test", "beta.certsync.test", "*.certsync.test"}
		for _, group := range cfgPull.Groups {
			fixture := newTestChain(t, false, group)
			roots.AddCert(fixture.Root)
			writeGroup(t, cfgPush.Directory, group, fixture)
		}
		expired := newTestChain(t, true, "expired.certsync.test")
		roots.AddCert(expired.Root)
		writeGroup(t, cfgPush.Directory, "expired.certsync.test", expired)
		runCase(t, "test_ca_push_with_expired_failure", "push", &cfgPush, tracked, roots, taskOptions{}, true, 1, 0, "成功 3 组，失败 1 组", "证书已过期", "失败阶段：上传证书校验", "有效期少于 15 天")
		runCase(t, "test_ca_pull_three_distinct_certificates", "pull", &cfgPull, pullStore, roots, taskOptions{reloadNginx: true}, false, 1, 2, "成功 3 组，失败 0 组", "成功替换 3 组", "reload 成功")
		assertLiveFiles(t, cfgPush.Directory, cfgPull.Directory, cfgPull.Groups)
	})
}

type liveMessage struct{ Case, Text string }
type liveCase struct {
	Name                    string
	ExpectedFailure, Failed bool
	Messages                int
	Commands                []string
	Log                     string
}
type liveReport struct {
	CleanupRequested                             bool
	RunID, Bucket, Prefix                        string
	Cases                                        []liveCase
	Messages                                     []liveMessage
	NotificationDeliveryFailures, DeletedObjects int
	RemainingObjects                             []string
	OriginalInputsUnchanged                      bool
}
type liveTrackingStore struct {
	objectStore
	written map[string]bool
}

func (s *liveTrackingStore) Put(ctx context.Context, key string, data []byte) error {
	s.written[key] = true
	return s.objectStore.Put(ctx, key, data)
}

func snapshotLiveInputs(t *testing.T, config, source, output string) map[string]string {
	t.Helper()
	all := snapshotLiveTree(t, source)
	for name, sum := range snapshotLiveTree(t, output) {
		all[name] = sum
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal("could not snapshot live configuration")
	}
	all[config] = fmt.Sprintf("%x", sha256.Sum256(data))
	return all
}
func snapshotLiveTree(t *testing.T, directory string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(directory, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == ".DS_Store" {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		result[name] = fmt.Sprintf("%x:%d:%04o", sha256.Sum256(data), info.ModTime().UnixNano(), info.Mode().Perm())
		return nil
	})
	if err != nil {
		t.Fatal("could not snapshot live certificate files")
	}
	return result
}
func equalLiveSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, sum := range a {
		if b[name] != sum {
			return false
		}
	}
	return true
}
func assertLiveFiles(t *testing.T, source, output string, groups []string) {
	t.Helper()
	for _, group := range groups {
		for _, name := range []string{CertName, KeyName} {
			expected, err := os.ReadFile(filepath.Join(source, group, name))
			if err != nil {
				t.Fatal("could not read source fixture")
			}
			filename := filepath.Join(output, group, name)
			actual, err := os.ReadFile(filename)
			if err != nil || !bytes.Equal(expected, actual) {
				t.Fatalf("downloaded file differs: group=%s file=%s", group, name)
			}
			info, err := os.Stat(filename)
			mode := os.FileMode(0644)
			if name == KeyName {
				mode = 0600
			}
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("incorrect downloaded permissions: group=%s file=%s", group, name)
			}
		}
		matches, err := filepath.Glob(filepath.Join(output, strings.ReplaceAll(group, "*", "[*]"), ".certsync-*"))
		if err != nil || len(matches) > 0 {
			t.Fatalf("temporary files were not cleaned: group=%s", group)
		}
	}
}
