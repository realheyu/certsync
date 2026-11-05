package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pullFixture(t *testing.T) (*Config, *memoryStore, *x509.CertPool) {
	t.Helper()
	fixture := newTestChain(t, false)
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Groups: []string{"example.com"}, Directory: t.TempDir()}
	data, err := Encrypt(cfg.Key, Bundle{FullchainPEM: string(fixture.Cert), PrivateKeyPEM: string(fixture.Key)})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, &memoryStore{objects: map[string][]byte{"certsync/example.com/bundle.enc": data}}, fixture.Roots
}

func TestNginxStagesAndFinalNotifications(t *testing.T) {
	for _, scenario := range []struct {
		name, failAt, service string
		unchanged             bool
		wantCalls, wantMsgs   int
	}{
		{"success", "", "reload 成功", false, 2, 1},
		{"unchanged success", "", "reload 成功", true, 2, 0},
		{"check failure", "nginx", "未执行 reload", false, 1, 1},
		{"reload failure", "systemctl", "reload 失败", false, 2, 1},
		{"unchanged check failure", "nginx", "未执行 reload", true, 1, 1},
		{"unchanged reload failure", "systemctl", "reload 失败", true, 2, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg, store, roots := pullFixture(t)
			if scenario.unchanged {
				if err := run(context.Background(), &bytes.Buffer{}, "pull", cfg, store, roots); err != nil {
					t.Fatal(err)
				}
			}
			var messages []string
			cfg.DingTalkWebhook = recordingRobot(t, &messages).URL
			var calls []string
			opts := taskOptions{reloadNginx: true, execute: func(ctx context.Context, name string, args ...string) (string, error) {
				if len(messages) != 0 {
					t.Fatal("notification sent before Nginx result was known")
				}
				calls = append(calls, name+" "+strings.Join(args, " "))
				if name == scenario.failAt {
					return "service diagnostic", errors.New("command failed")
				}
				return "ok", nil
			}}
			var out bytes.Buffer
			err := runTask(context.Background(), &out, "pull", cfg, store, roots, opts)
			if (err != nil) != (scenario.failAt != "") || len(calls) != scenario.wantCalls || len(messages) != scenario.wantMsgs {
				t.Fatalf("unexpected result: err=%v calls=%v messages=%v", err, calls, messages)
			}
			if calls[0] != "nginx -t" || (len(calls) == 2 && calls[1] != "systemctl reload nginx") {
				t.Fatalf("incorrect commands: %v", calls)
			}
			if len(messages) > 0 && !strings.Contains(messages[0], scenario.service) {
				t.Fatalf("service state missing: %s", messages[0])
			}
			if scenario.failAt != "" && (!strings.Contains(messages[0], "任务结果：失败") || !strings.Contains(messages[0], "service diagnostic")) {
				t.Fatalf("failure diagnostics missing: %s", messages[0])
			}
		})
	}
}

func TestFailedBatchSkipsNginxAndReportsEveryGroup(t *testing.T) {
	for _, allFailed := range []bool{false, true} {
		cfg, store, roots := pullFixture(t)
		cfg.Groups = []string{"missing.com", "example.com"}
		store.fail = allFailed
		var messages []string
		cfg.DingTalkWebhook = recordingRobot(t, &messages).URL
		err := runTask(context.Background(), &bytes.Buffer{}, "pull", cfg, store, roots, taskOptions{
			reloadNginx: true, execute: func(context.Context, string, ...string) (string, error) {
				t.Fatal("failed batch executed a service command")
				return "", nil
			},
		})
		if err == nil || len(messages) != 1 || !strings.Contains(messages[0], "证书组：missing.com\n事件：执行失败") || !strings.Contains(messages[0], "已跳过 Nginx") {
			t.Fatalf("failure was not reported: %v %v", err, messages)
		}
		if allFailed && !strings.Contains(messages[0], "成功 0 组，失败 2 组") {
			t.Fatal("all-failed batch summary incorrect")
		}
		if !allFailed && !strings.Contains(messages[0], "成功 1 组，失败 1 组") {
			t.Fatal("partially failed batch summary incorrect")
		}
	}
}

func TestTaskLockConflictAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "task.lock")
	release, err := acquireTaskLock(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release() })
	cfg, store, roots := pullFixture(t)
	var messages []string
	cfg.DingTalkWebhook = recordingRobot(t, &messages).URL
	err = runTask(context.Background(), &bytes.Buffer{}, "pull", cfg, store, roots, taskOptions{lockPath: path})
	if !errors.Is(err, errTaskLocked) || len(store.gets) != 0 || len(messages) != 1 || !strings.Contains(messages[0], "占锁") {
		t.Fatalf("lock contention was not reported: %v %v", err, messages)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	// A failed batch must release the lock so the next run can repair it.
	store.fail = true
	if err := runTask(context.Background(), &bytes.Buffer{}, "pull", cfg, store, roots, taskOptions{lockPath: path}); err == nil {
		t.Fatal("expected failed download")
	}
	store.fail = false
	if err := runTask(context.Background(), &bytes.Buffer{}, "pull", cfg, store, roots, taskOptions{lockPath: path}); err != nil {
		t.Fatalf("lock leaked after failed task: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("shared lock file should not be removed")
	}
}

type waitingStore struct{}

func (waitingStore) Get(ctx context.Context, _ string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (waitingStore) Put(ctx context.Context, _ string, _ []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestTimeoutAndCancellationStillDeliverAlerts(t *testing.T) {
	for _, phase := range []string{"download", "nginx", "reload", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			cfg, store, roots := pullFixture(t)
			var messages []string
			cfg.DingTalkWebhook = recordingRobot(t, &messages).URL
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "cancelled" {
				cancel()
			}
			opts := taskOptions{reloadNginx: true, timeout: 50 * time.Millisecond,
				execute: func(ctx context.Context, name string, _ ...string) (string, error) {
					if (phase == "nginx" && name == "nginx") || (phase == "reload" && name == "systemctl") {
						<-ctx.Done()
						return "timed out diagnostic", ctx.Err()
					}
					return "ok", nil
				}}
			var st objectStore = store
			if phase == "download" {
				st = waitingStore{}
			}
			err := runTask(ctx, &bytes.Buffer{}, "pull", cfg, st, roots, opts)
			if err == nil || len(messages) != 1 {
				t.Fatalf("timeout/cancellation alert not delivered: %v %v", err, messages)
			}
			want := "任务执行超时"
			if phase == "cancelled" {
				want = "任务已取消"
			}
			if !strings.Contains(messages[0], want) {
				t.Fatalf("wrong timeout notification: %s", messages[0])
			}
		})
	}
}

func TestServiceErrorsAreRedactedEverywhere(t *testing.T) {
	cfg, store, roots := pullFixture(t)
	var messages []string
	cfg.DingTalkWebhook = recordingRobot(t, &messages).URL + "?access_token=private-token"
	cfg.AccessKey, cfg.SecretKey, cfg.DingTalkSecret = "access-id", "oss-secret", "robot-secret"
	privatePEM := string(newTestChain(t, false).Key)
	privateBody := strings.Split(privatePEM, "\n")[1]
	secretOutput := strings.Join([]string{cfg.AccessKey, cfg.SecretKey, cfg.DingTalkSecret, "private-token", base64.StdEncoding.EncodeToString(cfg.Key), "https://oss.example.com/file?Signature=unknown-signature", privatePEM}, " ")
	var out bytes.Buffer
	err := runTask(context.Background(), &out, "pull", cfg, store, roots, taskOptions{reloadNginx: true,
		execute: func(context.Context, string, ...string) (string, error) {
			return secretOutput, errors.New(secretOutput)
		},
	})
	if err == nil || len(messages) != 1 {
		t.Fatal("expected service failure notification")
	}
	all := out.String() + err.Error() + messages[0]
	for _, secret := range []string{cfg.AccessKey, cfg.SecretKey, cfg.DingTalkSecret, "private-token", base64.StdEncoding.EncodeToString(cfg.Key), "unknown-signature", "PRIVATE KEY", privateBody} {
		if strings.Contains(all, secret) {
			t.Fatalf("sensitive error data was exposed: %q", secret)
		}
	}
}

func TestPushFailuresIncludeStageAndBatchResult(t *testing.T) {
	for _, scenario := range []string{"missing directory", "empty directory", "missing key", "bad certificate", "invalid group", "upload failure"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newTestChain(t, false)
			cfg := &Config{Key: make([]byte, 32), Directory: t.TempDir(), Prefix: "certsync"}
			store := &memoryStore{}
			writeGroup(t, cfg.Directory, "example.com", fixture)
			switch scenario {
			case "missing directory":
				cfg.Directory = filepath.Join(t.TempDir(), "missing")
			case "empty directory":
				cfg.Directory = t.TempDir()
			case "missing key":
				if err := os.Remove(filepath.Join(cfg.Directory, "example.com", KeyName)); err != nil {
					t.Fatal(err)
				}
			case "bad certificate":
				if err := os.WriteFile(filepath.Join(cfg.Directory, "example.com", CertName), []byte("invalid PEM"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid group":
				if err := os.Rename(filepath.Join(cfg.Directory, "example.com"), filepath.Join(cfg.Directory, "Invalid.COM")); err != nil {
					t.Fatal(err)
				}
			case "upload failure":
				store.fail = true
			}
			var messages []string
			cfg.DingTalkWebhook = recordingRobot(t, &messages).URL
			err := run(context.Background(), &bytes.Buffer{}, "push", cfg, store, fixture.Roots)
			if err == nil || len(messages) != 1 || !strings.Contains(messages[0], "任务结果：失败") || !strings.Contains(messages[0], "事件：执行失败") || !strings.Contains(messages[0], "失败阶段：") {
				t.Fatalf("push failure was not reported: %v %v", err, messages)
			}
		})
	}
}

func TestLockFileErrorsAreNotified(t *testing.T) {
	cfg, store, roots := pullFixture(t)
	path := filepath.Join(t.TempDir(), "lock-link")
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
		t.Fatal(err)
	}
	var messages []string
	cfg.DingTalkWebhook = recordingRobot(t, &messages).URL
	err := runTask(context.Background(), &bytes.Buffer{}, "pull", cfg, store, roots, taskOptions{lockPath: path})
	if err == nil || len(store.gets) != 0 || len(messages) != 1 || !strings.Contains(messages[0], "失败阶段：获取任务锁") {
		t.Fatalf("unsafe lock file was not rejected and reported: %v %v", err, messages)
	}
}

func TestExecuteProcessCapturesErrorsAndCancelsProcessGroup(t *testing.T) {
	output, err := executeProcess(exec.CommandContext(context.Background(), "/bin/sh", "-c", "echo diagnostic >&2; exit 7"))
	if err == nil || !strings.Contains(output, "diagnostic") {
		t.Fatalf("command failure/output missing: %v %q", err, output)
	}
	if _, err := executeProcess(exec.CommandContext(context.Background(), filepath.Join(t.TempDir(), "missing-command"))); err == nil {
		t.Fatal("missing command reported success")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := executeProcess(exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & wait")); err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("process group was not cancelled promptly: %v", err)
	}
	output, err = executeProcess(exec.CommandContext(context.Background(), "/bin/sh", "-c", "yes output | head -c 65536"))
	if err != nil || len(output) > 8192 {
		t.Fatalf("command output was not bounded: %v %d", err, len(output))
	}
}

func TestServiceCommandsAreFixedAndMissingNginxFails(t *testing.T) {
	for _, command := range [][]string{{"/bin/sh", "-c", "true"}, {"nginx", "-s", "reload"}, {"systemctl", "restart", "nginx"}, {"systemctl", "reload", "other-service"}} {
		if _, err := executeCommand(context.Background(), command[0], command[1:]...); err == nil || !strings.Contains(err.Error(), "不支持") {
			t.Fatalf("unexpected service command accepted: %v", command)
		}
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := executeCommand(context.Background(), "nginx", "-t"); err == nil {
		t.Fatal("missing nginx command reported success")
	}
}
