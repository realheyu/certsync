// installs validated files. It does not reload services or roll back.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const CertName = "fullchain.pem"
const KeyName = "privkey.pem"

func checkRegular(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("目标必须是普通文件: %s", path)
	}
	return nil
}

func Install(dir string, cert, key []byte) (bool, error) {
	return install(dir, cert, key, os.Rename)
}

func install(dir string, cert, key []byte, rename func(string, string) error) (bool, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errors.New("输出路径必须是普通目录")
	}
	certPath, keyPath := filepath.Join(dir, CertName), filepath.Join(dir, KeyName)
	for _, path := range []string{certPath, keyPath} {
		if err := checkRegular(path); err != nil {
			return false, err
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	oldCert, certErr := root.ReadFile(CertName)
	oldKey, keyErr := root.ReadFile(KeyName)
	if certErr != nil && !os.IsNotExist(certErr) {
		return false, certErr
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return false, keyErr
	}
	if certErr == nil && keyErr == nil && bytes.Equal(oldCert, cert) && bytes.Equal(oldKey, key) {
		return false, root.Chmod(KeyName, 0o600)
	}
	certTmp, err := writeTemp(dir, cert, 0o644)
	if err != nil {
		return false, err
	}
	defer os.Remove(certTmp)
	keyTmp, err := writeTemp(dir, key, 0o600)
	if err != nil {
		return false, err
	}
	defer os.Remove(keyTmp)
	if err := rename(certTmp, certPath); err != nil {
		return false, fmt.Errorf("替换证书: %w", err)
	}
	if err := rename(keyTmp, keyPath); err != nil {
		return false, fmt.Errorf("替换私钥失败，请重新 pull: %w", err)
	}
	return true, nil
}

func writeTemp(dir string, data []byte, mode os.FileMode) (name string, err error) {
	f, err := os.CreateTemp(dir, ".certsync-*")
	if err != nil {
		return "", err
	}
	name = f.Name()
	defer func() {
		if err != nil {
			_ = f.Close() // Preserve the original write/sync/close error.
			if removeErr := os.Remove(name); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("清理临时文件失败: %w", removeErr))
			}
		}
	}()
	// CreateTemp starts at 0600; widen only the certificate file's permissions.
	if err = f.Chmod(mode); err != nil {
		return name, err
	}
	if _, err = f.Write(data); err != nil {
		return name, err
	}
	if err = f.Sync(); err != nil {
		return name, err
	}
	err = f.Close()
	return name, err
}
