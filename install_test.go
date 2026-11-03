package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInterruptedPairReplacementCanRetry(t *testing.T) {
	dir := t.TempDir()
	if _, err := Install(dir, []byte("old cert"), []byte("old key")); err != nil {
		t.Fatal(err)
	}
	renamed := 0
	_, err := install(dir, []byte("new cert"), []byte("new key"), func(src, dst string) error {
		renamed++
		if renamed == 2 {
			return errors.New("simulated rename failure")
		}
		return os.Rename(src, dst)
	})
	if err == nil {
		t.Fatal("second rename failure swallowed")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".certsync-*"))
	if len(leftovers) != 0 {
		t.Fatal("temporary private key left behind")
	}
	if _, err := Install(dir, []byte("new cert"), []byte("new key")); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, KeyName))
	if err != nil || string(key) != "new key" {
		t.Fatalf("retry did not repair key: %v", err)
	}
}

func TestInstallRepairAndPermissions(t *testing.T) {
	dir := t.TempDir()
	cert, key := []byte("cert"), []byte("key")
	changed, err := Install(dir, cert, key)
	if err != nil || !changed {
		t.Fatalf("install: %v", err)
	}
	before, _ := os.Stat(filepath.Join(dir, CertName))
	os.Chmod(filepath.Join(dir, KeyName), 0644)
	changed, err = Install(dir, cert, key)
	if err != nil || changed {
		t.Fatalf("unchanged: %v", err)
	}
	info, _ := os.Stat(filepath.Join(dir, KeyName))
	if info.Mode().Perm() != 0600 {
		t.Fatal("key permissions")
	}
	after, _ := os.Stat(filepath.Join(dir, CertName))
	if !os.SameFile(before, after) {
		t.Fatal("unchanged cert rewritten")
	}
	os.Remove(filepath.Join(dir, KeyName))
	changed, err = Install(dir, cert, key)
	if err != nil || !changed {
		t.Fatalf("repair: %v", err)
	}
	os.Remove(filepath.Join(dir, KeyName))
	target := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(target, []byte("old"), 0600)
	os.Symlink(target, filepath.Join(dir, KeyName))
	if _, err := Install(dir, []byte("new"), key); err == nil {
		t.Fatal("symlink accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "old" {
		t.Fatal("symlink target changed")
	}
	data, _ = os.ReadFile(filepath.Join(dir, CertName))
	if string(data) != "cert" {
		t.Fatal("cert changed before preflight failure")
	}
}
