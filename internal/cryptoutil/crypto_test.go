package cryptoutil

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----")
	enc, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, plain) {
		t.Fatal("密文与明文相同")
	}
	got, err := Decrypt(key, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("往返不一致: %q", got)
	}
}

func TestNonceNotReused(t *testing.T) {
	key, _ := GenerateKey()
	a, _ := Encrypt(key, []byte("same plaintext"))
	b, _ := Encrypt(key, []byte("same plaintext"))
	if bytes.Equal(a, b) {
		t.Fatal("两次加密输出相同:nonce 被重用")
	}
}

func TestTamperDetected(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := Encrypt(key, []byte("secret cert"))
	for _, i := range []int{0, 13, len(enc) - 1} {
		bad := append([]byte(nil), enc...)
		bad[i] ^= 0xFF
		if _, err := Decrypt(key, bad); err == nil {
			t.Fatalf("篡改位置 %d 未被检出", i)
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	enc, _ := Encrypt(k1, []byte("data"))
	if _, err := Decrypt(k2, enc); err == nil {
		t.Fatal("错误密钥解密成功")
	}
}

func TestKeyFileRoundtrip(t *testing.T) {
	key, _ := GenerateKey()
	path := filepath.Join(t.TempDir(), "certsync.key")
	if err := WriteKeyFile(path, key); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("密钥文件权限 = %v,应为 0600", info.Mode().Perm())
	}
	got, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("密钥文件往返不一致")
	}
}

func TestLoadKeyEnvPriority(t *testing.T) {
	fileKey, _ := GenerateKey()
	path := filepath.Join(t.TempDir(), "k")
	_ = WriteKeyFile(path, fileKey)

	envKey, _ := GenerateKey()
	t.Setenv("CERTSYNC_KEY", base64.StdEncoding.EncodeToString(envKey))
	got, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, envKey) {
		t.Fatal("CERTSYNC_KEY 应优先于文件")
	}
}
