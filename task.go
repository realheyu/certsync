package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const taskTimeout = 30 * time.Minute
const notificationTimeout = 15 * time.Second

type taskOptions struct {
	reloadNginx bool
	lockPath    string // Empty only for isolated core tests.
	timeout     time.Duration
	execute     func(context.Context, string, ...string) (string, error)
}

func defaultLockPath(command string) string {
	if command == "push" {
		return "/run/certsync-issuer.lock"
	}
	return "/run/certsync-pull.lock"
}

// Configuration has already been validated. roots is injected only by tests.
func runTask(parent context.Context, out io.Writer, command string, c *Config, st objectStore, roots *x509.CertPool, opts taskOptions) (result error) {
	if opts.timeout <= 0 {
		opts.timeout = taskTimeout
	}
	if opts.execute == nil {
		opts.execute = executeCommand
	}
	ctx, cancel := context.WithTimeout(parent, opts.timeout)
	defer cancel()
	n := newNotifications(c, out)
	n.operation = command
	n.at("", "启动任务")
	if command == "pull" {
		n.service = "未请求 Nginx 检查和重载（尚未确认服务 reload）"
		if opts.reloadNginx {
			n.service = "尚未执行 Nginx 检查和重载"
		}
	}
	var release func() error
	defer func() {
		if err := ctx.Err(); err != nil {
			if !errors.Is(result, err) {
				result = errors.Join(result, err)
			}
			reason := "任务已取消"
			if errors.Is(err, context.DeadlineExceeded) {
				reason = fmt.Sprintf("任务执行超时（总时限 %s）", opts.timeout)
			}
			n.failure(n.group, n.stage, fmt.Errorf("%s: %w", reason, result))
		} else if result != nil && n.failureCount == 0 {
			n.failure(n.group, n.stage, result)
		}
		if release != nil {
			if err := release(); err != nil {
				n.failure("", "释放任务锁", err)
				result = errors.Join(result, err)
			}
		}
		n.result = "成功"
		if result != nil {
			n.result = "失败"
			result = &redactedError{message: n.clean(result.Error()), cause: result}
		}
		// Cancellation of the task must not cancel delivery of its failure alert.
		notifyCtx, stop := context.WithTimeout(context.WithoutCancel(parent), notificationTimeout)
		defer stop()
		n.flush(notifyCtx)
	}()
	if opts.lockPath != "" {
		n.at("", "获取任务锁")
		var err error
		release, err = acquireTaskLock(opts.lockPath)
		if err != nil {
			if errors.Is(err, errTaskLocked) {
				n.service = "因占锁跳过本轮任务"
			}
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if command == "push" {
		return pushAll(ctx, out, c, st, roots, n)
	}
	if err := pullAll(ctx, out, c, st, roots, n); err != nil {
		if opts.reloadNginx {
			n.service = "已跳过 Nginx 检查和 reload：证书同步失败"
		}
		return err
	}
	if !opts.reloadNginx {
		return nil
	}
	n.service = "检查未通过，未执行 reload"
	if err := runServiceCommand(ctx, out, n, opts.execute, "Nginx 配置检查", "nginx", "-t"); err != nil {
		return err
	}
	n.service = "检查通过，reload 失败或未确认生效"
	if err := runServiceCommand(ctx, out, n, opts.execute, "Nginx 重载", "systemctl", "reload", "nginx"); err != nil {
		return err
	}
	n.service = "Nginx 检查通过，reload 成功"
	fmt.Fprintln(out, n.service)
	return nil
}

func runServiceCommand(ctx context.Context, out io.Writer, n *notifications, execute func(context.Context, string, ...string) (string, error), stage, name string, args ...string) error {
	n.at("", stage)
	if err := ctx.Err(); err != nil {
		return err
	}
	output, err := execute(ctx, name, args...)
	output = n.clean(strings.TrimSpace(output))
	if output != "" {
		fmt.Fprintf(out, "%s: %s\n", stage, output)
	}
	if ctx.Err() != nil {
		if !errors.Is(err, ctx.Err()) {
			err = errors.Join(err, ctx.Err())
		}
	}
	if err != nil {
		if output != "" {
			return fmt.Errorf("%s: %w；输出：%s", stage, err, output)
		}
		return fmt.Errorf("%s: %w", stage, err)
	}
	return nil
}

type redactedError struct {
	message string
	cause   error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

// Consume all output without allowing a noisy child process to fill memory.
type commandOutput struct{ data []byte }

func (b *commandOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 8192 - len(b.data); remaining > 0 {
		b.data = append(b.data, p[:min(len(p), remaining)]...)
	}
	return n, nil
}

func executeCommand(ctx context.Context, name string, args ...string) (string, error) {
	if name == "nginx" && len(args) == 1 && args[0] == "-t" {
		return executeProcess(exec.CommandContext(ctx, "nginx", "-t"))
	}
	if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "nginx" {
		return executeProcess(exec.CommandContext(ctx, "systemctl", "reload", "nginx"))
	}
	return "", errors.New("不支持的服务命令")
}

func executeProcess(cmd *exec.Cmd) (string, error) {
	configureCommand(cmd)
	cmd.WaitDelay = time.Second
	output := &commandOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	return strings.ToValidUTF8(string(output.data), "�"), err
}
