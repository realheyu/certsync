// exposes only push, pull and version.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

type objectStore interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{Use: "certsync", Short: "加密上传和下载证书包", Version: Version, SilenceUsage: true, SilenceErrors: true}
	root.CompletionOptions.DisableDefaultCmd = true
	var configPath string
	root.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "TOML 配置文件路径")
	for _, name := range []string{"push", "pull"} {
		description := "遍历总目录，逐组校验并加密上传 OSS"
		if name == "pull" {
			description = "按组列表批量下载，解密校验后安装到各自子目录"
		}
		root.AddCommand(&cobra.Command{Use: name, Short: description, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := Load(cmd.Name(), configPath)
			if err != nil {
				return err
			}
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.Name(), cfg, newStore(cfg), nil)
		}})
	}
	root.AddCommand(&cobra.Command{Use: "version", Args: cobra.NoArgs, Run: func(cmd *cobra.Command, args []string) { fmt.Fprintln(cmd.OutOrStdout(), Version) }})
	return root
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "certsync:", err)
		os.Exit(1)
	}
}

func readBounded(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("输入必须是普通文件: %s", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("输入必须是普通文件: %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBundleSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBundleSize {
		return nil, fmt.Errorf("输入文件超过 1 MiB")
	}
	return data, nil
}

// roots is only injected by tests; the executable always uses system roots.
func run(ctx context.Context, out io.Writer, command string, c *Config, st objectStore, roots *x509.CertPool) error {
	notices := newNotifications(c, out)
	defer notices.flush(ctx)
	if command == "push" {
		return pushAll(ctx, out, c, st, roots, notices)
	}
	return pullAll(ctx, out, c, st, roots, notices)
}

func pushAll(ctx context.Context, out io.Writer, c *Config, st objectStore, roots *x509.CertPool, notices *notifications) error {
	root, err := os.OpenRoot(c.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	succeeded, failed := 0, 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			failed++
			fmt.Fprintf(out, "push 失败，组 %q: 不支持软链接\n", entry.Name())
			continue
		}
		if !entry.IsDir() {
			continue
		}
		if err := pushGroup(ctx, root, entry.Name(), c, st, roots, notices); err != nil {
			failed++
			fmt.Fprintf(out, "push 失败，组 %q: %v\n", entry.Name(), err)
			continue
		}
		succeeded++
		fmt.Fprintf(out, "push 成功，组 %s → %s\n", entry.Name(), path.Join(c.Prefix, entry.Name(), "bundle.enc"))
	}
	fmt.Fprintf(out, "push 汇总：成功 %d 组，失败 %d 组\n", succeeded, failed)
	if failed > 0 {
		return fmt.Errorf("存在 %d 组上传失败，详见日志", failed)
	}
	if succeeded == 0 {
		return fmt.Errorf("总目录中没有证书组，请将文件放入 <总目录>/<域名>/ 子目录")
	}
	return nil
}

func pushGroup(ctx context.Context, root *os.Root, group string, c *Config, st objectStore, roots *x509.CertPool, notices *notifications) error {
	if !validGroupName(group) {
		return fmt.Errorf("子目录名必须是小写普通域名或以 *. 开头的通配域名")
	}
	cert, err := readBounded(root, filepath.Join(group, CertName))
	if err != nil {
		return err
	}
	// Check expiry before key/chain validation and OSS upload, so expired
	// certificates and failed uploads still produce the expiry warning.
	if expires, err := certificateExpiry(cert); err == nil {
		notices.expiring(group, expires)
	}
	key, err := readBounded(root, filepath.Join(group, KeyName))
	if err != nil {
		return err
	}
	if err := Validate(cert, key, []string{group}, time.Now(), roots); err != nil {
		return err
	}
	data, err := Encrypt(c.Key, Bundle{FullchainPEM: string(cert), PrivateKeyPEM: string(key)})
	if err != nil {
		return err
	}
	return st.Put(ctx, path.Join(c.Prefix, group, "bundle.enc"), data)
}

func pullAll(ctx context.Context, out io.Writer, c *Config, st objectStore, roots *x509.CertPool, notices *notifications) error {
	if len(c.Groups) == 0 {
		return fmt.Errorf("缺少下载组列表 groups")
	}
	// Reject malformed groups before any downloads or filesystem changes.
	for _, group := range c.Groups {
		if !validGroupName(group) {
			return fmt.Errorf("无效的下载组名 %q", group)
		}
	}
	info, err := os.Lstat(c.Directory)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !info.IsDir() {
		return fmt.Errorf("输出总目录必须是普通目录")
	}
	succeeded, failed := 0, 0
	for _, group := range c.Groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		changed, err := pullGroup(ctx, group, c, st, roots, notices)
		if err != nil {
			failed++
			fmt.Fprintf(out, "pull 失败，组 %s: %v\n", group, err)
			continue
		}
		succeeded++
		if changed {
			fmt.Fprintf(out, "pull 成功，组 %s: 证书和私钥已替换\n", group)
		} else {
			fmt.Fprintf(out, "pull 成功，组 %s: 文件内容未变化\n", group)
		}
	}
	fmt.Fprintf(out, "pull 汇总：成功 %d 组，失败 %d 组\n", succeeded, failed)
	if failed > 0 {
		return fmt.Errorf("存在 %d 组下载或安装失败，详见日志", failed)
	}
	return nil
}

func pullGroup(ctx context.Context, group string, c *Config, st objectStore, roots *x509.CertPool, notices *notifications) (bool, error) {
	data, err := st.Get(ctx, path.Join(c.Prefix, group, "bundle.enc"))
	if err != nil {
		return false, err
	}
	bundle, err := Decrypt(c.Key, data)
	if err != nil {
		return false, err
	}
	cert, key := []byte(bundle.FullchainPEM), []byte(bundle.PrivateKeyPEM)
	if err := Validate(cert, key, []string{group}, time.Now(), roots); err != nil {
		return false, err
	}
	expires, err := certificateExpiry(cert)
	if err != nil {
		return false, err
	}
	changed, err := Install(filepath.Join(c.Directory, group), cert, key)
	if err == nil && changed {
		notices.replaced(group, expires)
	}
	return changed, err
}
