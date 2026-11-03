package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memoryStore struct {
	objects     map[string][]byte
	fail        bool
	failKeys    map[string]bool
	puts        int
	gets        []string
	getFailures map[string]bool
}

func (s *memoryStore) Put(_ context.Context, key string, b []byte) error {
	if s.fail || s.failKeys[key] {
		return errors.New("upload unavailable")
	}
	if s.objects == nil {
		s.objects = make(map[string][]byte)
	}
	s.objects[key] = append([]byte{}, b...)
	s.puts++
	return nil
}
func (s *memoryStore) Get(_ context.Context, key string) ([]byte, error) {
	s.gets = append(s.gets, key)
	if s.fail || s.getFailures[key] {
		return nil, errors.New("download unavailable")
	}
	data, ok := s.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}
func writeGroup(t *testing.T, dir, group string, c Chain) {
	t.Helper()
	dir = filepath.Join(dir, group)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CertName), c.Cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyName), c.Key, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPushPullOffline(t *testing.T) {
	fixture := newTestChain(t, false)
	dir := t.TempDir()
	writeGroup(t, dir, "example.com", fixture)
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: dir}
	st := &memoryStore{}
	var out bytes.Buffer
	if err := run(context.Background(), &out, "push", cfg, st, fixture.Roots); err != nil {
		t.Fatal(err)
	}
	objectKey := "certsync/example.com/bundle.enc"
	if bytes.Contains(st.objects[objectKey], fixture.Key) {
		t.Fatal("plaintext uploaded")
	}
	cfg.Directory = t.TempDir()
	cfg.Groups = []string{"example.com"}
	pull := func() error { return run(context.Background(), &out, "pull", cfg, st, fixture.Roots) }
	if err := pull(); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(cfg.Directory, "example.com", KeyName))
	if err := pull(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(cfg.Directory, "example.com", CertName))
	cfg.Key[0] = 1
	if err := pull(); err == nil {
		t.Fatal("wrong key accepted")
	}
	cfg.Key[0] = 0
	st.objects[objectKey][len(st.objects[objectKey])-1] ^= 1
	if err := pull(); err == nil {
		t.Fatal("corruption accepted")
	}
	st.fail = true
	if err := pull(); err == nil {
		t.Fatal("network failure swallowed")
	}
	after, _ := os.ReadFile(filepath.Join(cfg.Directory, "example.com", CertName))
	if !bytes.Equal(before, after) {
		t.Fatal("old cert lost")
	}
	cfg.Directory = dir
	if err := run(context.Background(), &out, "push", cfg, st, fixture.Roots); err == nil {
		t.Fatal("upload failure swallowed")
	}
}
func TestPushMultipleGroups(t *testing.T) {
	first, second := newTestChain(t, false), newTestChain(t, false, "other.com", "*.other.com")
	roots := first.Roots.Clone()
	roots.AddCert(second.Root)
	dir := t.TempDir()
	writeGroup(t, dir, "example.com", first)
	writeGroup(t, dir, "other.com", second)
	os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignored root file"), 0600)
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync/production", Directory: dir}
	st := &memoryStore{}
	var out bytes.Buffer
	if err := run(context.Background(), &out, "push", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if st.puts != 2 || len(st.objects) != 2 {
		t.Fatalf("expected two objects, got %d", st.puts)
	}
	for group, chain := range map[string]Chain{"example.com": first, "other.com": second} {
		data := st.objects["certsync/production/"+group+"/bundle.enc"]
		b, err := Decrypt(cfg.Key, data)
		if err != nil || b.FullchainPEM != string(chain.Cert) || b.PrivateKeyPEM != string(chain.Key) {
			t.Fatalf("wrong bundle for %s: %v", group, err)
		}
	}
	// New batches replace existing objects, never publish a combined all-domain bundle.
	if err := run(context.Background(), &out, "push", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if st.puts != 4 || len(st.objects) != 2 {
		t.Fatal("batch re-upload failed")
	}
}

func TestPushPullWildcardAndPlainGroups(t *testing.T) {
	first := newTestChain(t, false, "*.fsbtiot.com", "fsbtiot.com")
	wildcardOnly := newTestChain(t, false, "*.other.com")
	roots := first.Roots.Clone()
	roots.AddCert(wildcardOnly.Root)
	groups := map[string]Chain{"*.fsbtiot.com": first, "fsbtiot.com": first, "*.other.com": wildcardOnly}
	source := t.TempDir()
	for group, chain := range groups {
		writeGroup(t, source, group, chain)
	}
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: source}
	st := &memoryStore{}
	if err := run(context.Background(), &bytes.Buffer{}, "push", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if len(st.objects) != len(groups) {
		t.Fatalf("expected %d independent objects, got %d", len(groups), len(st.objects))
	}
	for group, chain := range groups {
		data := st.objects["certsync/"+group+"/bundle.enc"]
		bundle, err := Decrypt(cfg.Key, data)
		if err != nil || bundle.FullchainPEM != string(chain.Cert) || bundle.PrivateKeyPEM != string(chain.Key) {
			t.Fatalf("wrong bundle for literal group %q: %v", group, err)
		}
	}
	var err error
	cfg.Groups, err = ParseGroups(" *.fsbtiot.com, fsbtiot.com, *.other.com ")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Directory = t.TempDir()
	if err := run(context.Background(), &bytes.Buffer{}, "pull", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if strings.Join(st.gets, ",") != "certsync/*.fsbtiot.com/bundle.enc,certsync/fsbtiot.com/bundle.enc,certsync/*.other.com/bundle.enc" {
		t.Fatalf("group names were expanded or changed: %v", st.gets)
	}
	for group, chain := range groups {
		for file, want := range map[string][]byte{CertName: chain.Cert, KeyName: chain.Key} {
			data, err := os.ReadFile(filepath.Join(cfg.Directory, group, file))
			if err != nil || !bytes.Equal(data, want) {
				t.Fatalf("wrong %s in literal directory %q: %v", file, group, err)
			}
		}
	}
	// Selecting the wildcard group must not fetch or overwrite the plain group.
	plainCert := filepath.Join(cfg.Directory, "fsbtiot.com", CertName)
	before, err := os.Stat(plainCert)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Groups = []string{"*.fsbtiot.com"}
	st.gets = nil
	keyPath := filepath.Join(cfg.Directory, "*.fsbtiot.com", KeyName)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), &bytes.Buffer{}, "pull", cfg, st, roots); err != nil {
		t.Fatal(err)
	}
	if len(st.gets) != 1 || st.gets[0] != "certsync/*.fsbtiot.com/bundle.enc" {
		t.Fatalf("wildcard group acted as a pattern: %v", st.gets)
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wildcard group private key not repaired with mode 0600")
	}
	after, err := os.Stat(plainCert)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("unselected plain group changed")
	}
}

func TestPushContinuesAfterGroupFailures(t *testing.T) {
	first, second := newTestChain(t, false), newTestChain(t, false, "other.com")
	roots := first.Roots.Clone()
	roots.AddCert(second.Root)
	dir := t.TempDir()
	writeGroup(t, dir, "a-missing.com", first)
	os.Remove(filepath.Join(dir, "a-missing.com", KeyName))
	writeGroup(t, dir, "bad.com", first) // Certificate does not cover the directory name.
	writeGroup(t, dir, "example.com", first)
	writeGroup(t, dir, "other.com", second)
	writeGroup(t, dir, "Invalid.COM", first)
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "linked.com")); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: dir}
	st := &memoryStore{failKeys: map[string]bool{"certsync/example.com/bundle.enc": true}}
	var out bytes.Buffer
	if err := run(context.Background(), &out, "push", cfg, st, roots); err == nil {
		t.Fatal("partial batch must return nonzero")
	}
	if len(st.objects) != 1 || st.objects["certsync/other.com/bundle.enc"] == nil {
		t.Fatal("valid group after failure was not uploaded")
	}
	if !strings.Contains(out.String(), "成功 1 组，失败 5 组") {
		t.Fatalf("bad summary: %s", out.String())
	}
}
func TestPushRejectsEmptyAndNonRecursiveLayout(t *testing.T) {
	fixture := newTestChain(t, false)
	for _, layout := range []string{"empty", "old single group", "nested"} {
		t.Run(layout, func(t *testing.T) {
			dir := t.TempDir()
			if layout == "old single group" {
				writeGroup(t, dir, ".", fixture)
			}
			if layout == "nested" {
				writeGroup(t, dir, "example.com/nested.com", fixture)
			}
			st := &memoryStore{}
			cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: dir}
			if err := run(context.Background(), &bytes.Buffer{}, "push", cfg, st, fixture.Roots); err == nil {
				t.Fatal("empty/invalid layout accepted")
			}
			if st.puts != 0 {
				t.Fatal("unexpected publication")
			}
		})
	}
}
func TestPushRejectsLinkedSourceFile(t *testing.T) {
	fixture := newTestChain(t, false)
	dir := t.TempDir()
	writeGroup(t, dir, "example.com", fixture)
	keyPath := filepath.Join(dir, "example.com", KeyName)
	os.Remove(keyPath)
	external := filepath.Join(t.TempDir(), KeyName)
	os.WriteFile(external, fixture.Key, 0600)
	os.Symlink(external, keyPath)
	st := &memoryStore{}
	cfg := &Config{Key: make([]byte, 32), Prefix: "certsync", Directory: dir}
	if err := run(context.Background(), &bytes.Buffer{}, "push", cfg, st, fixture.Roots); err == nil || st.puts != 0 {
		t.Fatal("linked source was published")
	}
}
func TestCommands(t *testing.T) {
	for _, name := range []string{"issue", "renew", "keygen", "status", "on-failure"} {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{name})
		if err := cmd.Execute(); err == nil {
			t.Fatalf("legacy command %s accepted", name)
		}
	}
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}
