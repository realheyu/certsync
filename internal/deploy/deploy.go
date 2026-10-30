// Package deploy 原子安装、备份、check/reload、回滚与 reload 后探测(§7.2)。
package deploy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hy/certsync/internal/certutil"
)

const KeepBackups = 10 // 每域名保留最近 10 份

// ErrProbeMismatch:reload 后探测指纹不一致——文件已过全部内容校验,
// 不一致几乎必是 nginx 配置引用了别的路径,回滚无意义,只告警(§7.2 例外路径)。
var ErrProbeMismatch = errors.New("reload 后实际服务证书指纹与预期不一致(不回滚,请检查 nginx 配置路径)")

type Target struct {
	Domain   string
	CertFile string
	KeyFile  string
}

type Options struct {
	CheckCmd  []string
	ReloadCmd []string
	BackupDir string
	// ProbeAddr 探测地址,默认 127.0.0.1:443;测试可覆盖。
	ProbeAddr string
	// SkipProbe 跳过 reload 后探测(pull.post_reload_probe = false 时)。
	SkipProbe bool
}

// Install 执行 §7.2 流程:临时文件 → 备份 → rename → check → reload → 探测。
// 任一步失败(探测除外)从备份恢复原文件或删除新增文件后返回错误。
func Install(t Target, certPEM, keyPEM []byte, opts Options) (string, error) {
	certTmp, err := writeTemp(t.CertFile, certPEM, 0o644)
	if err != nil {
		return "", err
	}
	keyTmp, err := writeTemp(t.KeyFile, keyPEM, 0o600)
	if err != nil {
		os.Remove(certTmp)
		return "", err
	}

	backupDir, err := backupExisting(t, opts.BackupDir)
	if err != nil {
		os.Remove(certTmp)
		os.Remove(keyTmp)
		return "", err
	}

	if err := os.Rename(certTmp, t.CertFile); err != nil {
		cleanupFailedInstall(t, backupDir, certTmp, keyTmp)
		return "", fmt.Errorf("落位证书: %w", err)
	}
	if err := os.Rename(keyTmp, t.KeyFile); err != nil {
		cleanupFailedInstall(t, backupDir, certTmp, keyTmp)
		return "", fmt.Errorf("落位私钥: %w", err)
	}

	if len(opts.CheckCmd) > 0 {
		if out, err := runCmd(opts.CheckCmd); err != nil {
			rollback(t, backupDir)
			return backupDir, fmt.Errorf("check_cmd 失败(%s): %v: %s", strings.Join(opts.CheckCmd, " "), err, strings.TrimSpace(out))
		}
	}
	if len(opts.ReloadCmd) > 0 {
		if out, err := runCmd(opts.ReloadCmd); err != nil {
			rollback(t, backupDir)
			return backupDir, fmt.Errorf("reload_cmd 失败(%s): %v: %s", strings.Join(opts.ReloadCmd, " "), err, strings.TrimSpace(out))
		}
	}

	if opts.SkipProbe {
		pruneBackups(filepath.Join(opts.BackupDir, t.Domain), KeepBackups)
		return backupDir, nil
	}
	addr := opts.ProbeAddr
	if addr == "" {
		addr = "127.0.0.1:443"
	}
	want, err := expectedFingerprint(certPEM)
	if err != nil {
		return backupDir, err
	}
	if err := ProbeServed(addr, t.Domain, want); err != nil {
		return backupDir, err // 探测不一致:不回滚,由调用方告警
	}
	pruneBackups(filepath.Join(opts.BackupDir, t.Domain), KeepBackups)
	return backupDir, nil
}

// ProbeServed 以 SNI 握手探测实际服务证书,比对叶子指纹。
func ProbeServed(addr, domain, wantFingerprint string) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // 只比对指纹,不验证链
	})
	if err != nil {
		return fmt.Errorf("探测 %s 失败: %w", addr, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("探测 %s:对端未返回证书", addr)
	}
	got := certutil.Fingerprint(certs[0])
	if got != wantFingerprint {
		return fmt.Errorf("%w: got %s want %s", ErrProbeMismatch, got, wantFingerprint)
	}
	return nil
}

func expectedFingerprint(certPEM []byte) (string, error) {
	certs, err := certutil.ParseCertificates(certPEM)
	if err != nil {
		return "", err
	}
	return certutil.Fingerprint(certutil.Leaf(certs)), nil
}

// writeTemp 写临时文件:与目标同目录保证 rename 原子性(§7.2)。
func writeTemp(dst string, data []byte, mode os.FileMode) (string, error) {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".certsync-*")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), tmp.Close()
}

// backupExisting 把旧证书/私钥备份到 <backupDir>/<domain>/<时间戳>/,无旧文件返回空串。
func backupExisting(t Target, backupDir string) (string, error) {
	if !fileExists(t.CertFile) && !fileExists(t.KeyFile) {
		return "", nil
	}
	dir := filepath.Join(backupDir, t.Domain, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, f := range []string{t.CertFile, t.KeyFile} {
		if fileExists(f) {
			if err := os.Rename(f, filepath.Join(dir, filepath.Base(f))); err != nil {
				return "", fmt.Errorf("备份 %s: %w", f, err)
			}
		}
	}
	return dir, nil
}

// rollback 从备份恢复;无备份(首次安装)则删除新增文件。
func rollback(t Target, backupDir string) {
	restore := func(dst string) {
		base := filepath.Base(dst)
		src := filepath.Join(backupDir, base)
		if backupDir != "" && fileExists(src) {
			if err := os.Rename(src, dst); err == nil {
				return
			}
		}
		os.Remove(dst) // 无备份:删除新增
	}
	restore(t.CertFile)
	restore(t.KeyFile)
}

func cleanupFailedInstall(t Target, backupDir, certTmp, keyTmp string) {
	os.Remove(certTmp)
	os.Remove(keyTmp)
	if backupDir != "" {
		rollback(t, backupDir)
	}
}

// pruneBackups 只保留最近 n 份时间戳目录。
func pruneBackups(domainDir string, n int) {
	entries, err := os.ReadDir(domainDir)
	if err != nil {
		return
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs) // 时间戳字典序即时间序
	for len(dirs) > n {
		os.RemoveAll(filepath.Join(domainDir, dirs[0]))
		dirs = dirs[1:]
	}
}

func runCmd(cmd []string) (string, error) {
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	return string(out), err
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
