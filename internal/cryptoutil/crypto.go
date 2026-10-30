// Package cryptoutil 实现 §6.1:AES-256-GCM、随机 nonce 前置、主密钥生成与加载。
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

const KeySize = 32 // AES-256

// GenerateKey 生成 32 字节随机主密钥。
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("读取随机源: %w", err)
	}
	return key, nil
}

// Encrypt AES-256-GCM 加密,输出 = nonce(12B) || ciphertext||tag。
// 同一密钥每次加密使用全新随机 nonce(§6.1)。
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("密钥长度 %d,应为 %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt 解密 Encrypt 的输出;密文被篡改或密钥不符时返回错误(GCM 认证标签)。
func Decrypt(key, data []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("密钥长度 %d,应为 %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("密文过短")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// LoadKey 加载主密钥:环境变量 CERTSYNC_KEY(base64)优先,否则读文件(base64,§8)。
func LoadKey(keyFile string) ([]byte, error) {
	if env := os.Getenv("CERTSYNC_KEY"); env != "" {
		key, err := base64.StdEncoding.DecodeString(env)
		if err != nil {
			return nil, fmt.Errorf("解析 CERTSYNC_KEY: %w", err)
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("CERTSYNC_KEY 长度 %d,应为 %d", len(key), KeySize)
		}
		return key, nil
	}
	if keyFile == "" {
		return nil, errors.New("未配置 key_file,也未设置 CERTSYNC_KEY")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("读取密钥文件 %s: %w", keyFile, err)
	}
	key, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("解析密钥文件 %s(base64): %w", keyFile, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("密钥文件 %s 长度 %d,应为 %d", keyFile, len(key), KeySize)
	}
	return key, nil
}

// WriteKeyFile 把密钥以 base64 写入 0600 文件(keygen 命令用)。
func WriteKeyFile(path string, key []byte) error {
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600)
}
