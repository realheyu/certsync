package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPullMultipleGroups(t *testing.T) {
	first, second := newTestChain(t, false), newTestChain(t, false, "other.com")
	roots := first.Roots.Clone()
	roots.AddCert(second.Root)
	source := t.TempDir()
	writeGroup(t, source, "example.com", first)
	writeGroup(t, source, "other.com", second)
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync/prod", Directory: source}
	st := &memoryStore{}
	var out bytes.Buffer
	if err := run(context.Background(), &out, "push", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	cfg.Directory = filepath.Join(t.TempDir(), "certs")
	cfg.Groups = []string{"other.com", "example.com"}
	if err := run(context.Background(), &out, "pull", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if strings.Join(st.gets, ",") != "certsync/prod/other.com/bundle.enc,certsync/prod/example.com/bundle.enc" {
		t.Fatalf("wrong objects fetched: %v", st.gets)
	}
	for group, c := range map[string]Chain{"example.com": first, "other.com": second} {
		cert, err := os.ReadFile(filepath.Join(cfg.Directory, group, CertName))
		if err != nil || !bytes.Equal(cert, c.Cert) {
			t.Fatalf("wrong cert in %s: %v", group, err)
		}
		key, err := os.ReadFile(filepath.Join(cfg.Directory, group, KeyName))
		if err != nil || !bytes.Equal(key, c.Key) {
			t.Fatalf("wrong key in %s: %v", group, err)
		}
		info, err := os.Stat(filepath.Join(cfg.Directory, group, KeyName))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("wrong key permissions")
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, CertName)); !os.IsNotExist(err) {
		t.Fatal("file installed into base directory")
	}
	before, _ := os.Stat(filepath.Join(cfg.Directory, "example.com", CertName))
	if err := run(context.Background(), &out, "pull", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(cfg.Directory, "example.com", CertName))
	if !os.SameFile(before, after) {
		t.Fatal("unchanged certificate rewritten")
	}
	os.Remove(filepath.Join(cfg.Directory, "example.com", KeyName))
	// Select only one group; leave another installed group and unrelated local files alone.
	cfg.Groups = []string{"example.com"}
	st.gets = nil
	os.WriteFile(filepath.Join(cfg.Directory, "keep.txt"), []byte("keep"), 0600)
	if err := run(context.Background(), &out, "pull", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if len(st.gets) != 1 {
		t.Fatal("unselected group fetched")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "example.com", KeyName)); err != nil {
		t.Fatal("missing private key not repaired")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "other.com", KeyName)); err != nil {
		t.Fatal("unselected group removed")
	}
	if data, _ := os.ReadFile(filepath.Join(cfg.Directory, "keep.txt")); string(data) != "keep" {
		t.Fatal("unrelated file removed")
	}
}

func TestPullContinuesAndPreservesFailedGroup(t *testing.T) {
	first, second := newTestChain(t, false), newTestChain(t, false, "other.com")
	roots := first.Roots.Clone()
	roots.AddCert(second.Root)
	key := make([]byte, 32)
	firstData, err := Encrypt(key, Bundle{FullchainPEM: string(first.Cert), PrivateKeyPEM: string(first.Key)})
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := Encrypt(key, Bundle{FullchainPEM: string(second.Cert), PrivateKeyPEM: string(second.Key)})
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"network", "missing", "corrupt", "wrong key", "wrong domain", "install"} {
		t.Run(failure, func(t *testing.T) {
			cfg := &Config{Key: key, Prefix: "certsync", Groups: []string{"example.com", "other.com"}, Directory: t.TempDir()}
			st := &memoryStore{objects: map[string][]byte{"certsync/example.com/bundle.enc": append([]byte{}, firstData...), "certsync/other.com/bundle.enc": secondData}}
			writeGroup(t, cfg.Directory, "example.com", Chain{Cert: []byte("old cert"), Key: []byte("old key")})
			failedDir := filepath.Join(cfg.Directory, "example.com")
			switch failure {
			case "network":
				st.getFailures = map[string]bool{"certsync/example.com/bundle.enc": true}
			case "missing":
				delete(st.objects, "certsync/example.com/bundle.enc")
			case "corrupt":
				st.objects["certsync/example.com/bundle.enc"][len(firstData)-1] ^= 1
			case "wrong key":
				wrong := make([]byte, 32)
				wrong[0] = 1
				st.objects["certsync/example.com/bundle.enc"], err = Encrypt(wrong, Bundle{FullchainPEM: string(first.Cert), PrivateKeyPEM: string(first.Key)})
				if err != nil {
					t.Fatal(err)
				}
			case "wrong domain":
				st.objects["certsync/example.com/bundle.enc"] = secondData
			case "install":
				outside := t.TempDir()
				os.WriteFile(filepath.Join(outside, CertName), []byte("old cert"), 0600)
				os.WriteFile(filepath.Join(outside, KeyName), []byte("old key"), 0600)
				os.RemoveAll(failedDir)
				if err := os.Symlink(outside, failedDir); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if err := run(context.Background(), &out, "pull", cfg, st, roots); err == nil {
				t.Fatal("partial failure returned success")
			}
			if !strings.Contains(out.String(), "成功 1 组，失败 1 组") {
				t.Fatalf("bad summary: %s", out.String())
			}
			for file, want := range map[string]string{CertName: "old cert", KeyName: "old key"} {
				data, err := os.ReadFile(filepath.Join(failedDir, file))
				if err != nil || string(data) != want {
					t.Fatalf("failed group changed %s: %v", file, err)
				}
			}
			data, err := os.ReadFile(filepath.Join(cfg.Directory, "other.com", CertName))
			if err != nil || !bytes.Equal(data, second.Cert) {
				t.Fatalf("valid group after failure not installed: %v", err)
			}
		})
	}
}

func TestPullPreflightAndCancellation(t *testing.T) {
	for _, groups := range [][]string{nil, {"../escape.com"}, {"api.*.example.com"}, {"*.example.com/escape"}} {
		st := &memoryStore{}
		cfg := &Config{Groups: groups, Directory: t.TempDir()}
		if err := run(context.Background(), &bytes.Buffer{}, "pull", cfg, st, nil); err == nil || len(st.gets) != 0 {
			t.Fatal("invalid groups caused download")
		}
	}
	st := &memoryStore{}
	cfg := &Config{Groups: []string{"example.com"}, Directory: filepath.Join(t.TempDir(), "linked")}
	if err := os.Symlink(t.TempDir(), cfg.Directory); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), &bytes.Buffer{}, "pull", cfg, st, nil); err == nil || len(st.gets) != 0 {
		t.Fatal("linked output root accepted")
	}
	cfg.Directory = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, &bytes.Buffer{}, "pull", cfg, st, nil); err == nil || len(st.gets) != 0 {
		t.Fatal("cancelled pull performed downloads")
	}
}
