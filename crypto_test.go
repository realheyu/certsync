package main

import (
	"bytes"
	"testing"
)

func TestBundleAuthentication(t *testing.T) {
	key := make([]byte, 32)
	b := Bundle{FullchainPEM: "cert", PrivateKeyPEM: "key"}
	data, err := Encrypt(key, b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decrypt(key, data)
	if err != nil || *decoded != b {
		t.Fatalf("roundtrip: %v", err)
	}
	second, _ := Encrypt(key, b)
	if bytes.Equal(data, second) {
		t.Fatal("nonce reused")
	}
	wrong := append([]byte{}, key...)
	wrong[0] = 1
	if _, err := Decrypt(wrong, data); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, i := range []int{0, 9, len(data) - 1} {
		bad := append([]byte{}, data...)
		bad[i] ^= 1
		if _, err := Decrypt(key, bad); err == nil {
			t.Fatalf("tampering accepted at %d", i)
		}
	}
	for _, n := range []int{0, 9, 21, len(data) - 1} {
		if _, err := Decrypt(key, data[:n]); err == nil {
			t.Fatal("truncated accepted")
		}
	}
	if _, err := Decrypt(key, make([]byte, MaxBundleSize+1)); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := Encrypt(key, Bundle{FullchainPEM: string(make([]byte, MaxBundleSize)), PrivateKeyPEM: "key"}); err == nil {
		t.Fatal("oversize encrypted")
	}
}
