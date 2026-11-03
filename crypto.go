// implements the authenticated CERTSYNC1 bundle format.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
)

const KeySize = 32
const MaxBundleSize = 1 << 20
const header = "CERTSYNC1"

type Bundle struct {
	FullchainPEM  string `json:"fullchain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("加密密钥必须为 32 字节")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Encrypt(key []byte, bundle Bundle) ([]byte, error) {
	if bundle.FullchainPEM == "" || bundle.PrivateKeyPEM == "" {
		return nil, errors.New("证书包缺少证书或私钥")
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(raw)+len(header)+gcm.NonceSize()+gcm.Overhead() > MaxBundleSize {
		return nil, errors.New("证书包超过 1 MiB")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(header), nonce...)
	return gcm.Seal(out, nonce, raw, []byte(header)), nil
}

func Decrypt(key, data []byte) (*Bundle, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBundleSize || len(data) < len(header)+gcm.NonceSize()+gcm.Overhead() || !bytes.HasPrefix(data, []byte(header)) {
		return nil, errors.New("证书包格式或大小错误")
	}
	nonce := data[len(header) : len(header)+gcm.NonceSize()]
	raw, err := gcm.Open(nil, nonce, data[len(header)+gcm.NonceSize():], []byte(header))
	if err != nil {
		return nil, errors.New("证书包认证解密失败：密钥不匹配或密文损坏")
	}
	var b Bundle
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&b); err != nil {
		return nil, errors.New("解析证书包失败")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("证书包包含多余数据")
	}
	if b.FullchainPEM == "" || b.PrivateKeyPEM == "" {
		return nil, errors.New("证书包缺少证书或私钥")
	}
	return &b, nil
}
