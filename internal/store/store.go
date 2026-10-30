// Package store OSS 读写:meta.json、密文对象、5.3 节上传顺序约定、7.4 节重试。
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"

	"github.com/hy/certsync/internal/config"
)

// ErrNotFound 对象不存在(pull 侧据此告警,13 节)。
var ErrNotFound = errors.New("OSS 对象不存在")

// Meta 5.2 节:明文元数据,指纹是全网唯一比对依据。
type Meta struct {
	Domain      string    `json:"domain"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SANs        []string  `json:"sans"`
	Issuer      string    `json:"issuer"`
	UpdatedAt   int64     `json:"updated_at"`
}

type Store struct {
	client *oss.Client
	bucket string
	prefix string
	log    *slog.Logger
}

// New 创建 OSS 客户端;prefix 传空则用 cfg.Prefix(--staging 时传 cfg.StagingPrefix,3 节)。
func New(cfg config.OSS, prefix string, log *slog.Logger) (*Store, error) {
	if cfg.Region == "" || cfg.Bucket == "" || cfg.AccessKey == "" {
		return nil, fmt.Errorf("oss 配置不完整(region/bucket/凭证),请检查 config.toml 与 certsync.env")
	}
	if prefix == "" {
		prefix = cfg.Prefix
	}
	ocfg := oss.LoadDefaultConfig().
		WithRegion(cfg.Region).
		WithEndpoint(cfg.Endpoint).
		WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey))
	return &Store{client: oss.NewClient(ocfg), bucket: cfg.Bucket, prefix: prefix, log: log}, nil
}

func (s *Store) certKey(domain string) string {
	return s.prefix + "/certs/" + domain + "/fullchain.pem.enc"
}

func (s *Store) keyKey(domain string) string {
	return s.prefix + "/certs/" + domain + "/privkey.pem.enc"
}

func (s *Store) metaKey(domain string) string {
	return s.prefix + "/certs/" + domain + "/meta.json"
}

// PushCert 按 5.3 节顺序上传:fullchain.enc → privkey.enc → meta.json(提交点)。
func (s *Store) PushCert(domain string, certEnc, keyEnc []byte, meta Meta) error {
	ctx := context.Background()
	if err := s.put(ctx, s.certKey(domain), certEnc); err != nil {
		return fmt.Errorf("上传 fullchain.pem.enc: %w", err)
	}
	if err := s.put(ctx, s.keyKey(domain), keyEnc); err != nil {
		return fmt.Errorf("上传 privkey.pem.enc: %w", err)
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := s.put(ctx, s.metaKey(domain), metaJSON); err != nil {
		return fmt.Errorf("上传 meta.json: %w", err)
	}
	return nil
}

// GetMeta 拉取 meta.json。
func (s *Store) GetMeta(domain string) (*Meta, error) {
	raw, err := s.get(s.metaKey(domain))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("解析 meta.json: %w", err)
	}
	return &m, nil
}

// GetEncryptedPair 拉取两个密文对象。
func (s *Store) GetEncryptedPair(domain string) (certEnc, keyEnc []byte, err error) {
	if certEnc, err = s.get(s.certKey(domain)); err != nil {
		return nil, nil, fmt.Errorf("下载 fullchain.pem.enc: %w", err)
	}
	if keyEnc, err = s.get(s.keyKey(domain)); err != nil {
		return nil, nil, fmt.Errorf("下载 privkey.pem.enc: %w", err)
	}
	return certEnc, keyEnc, nil
}

// put 带指数退避重试(1s/2s/4s,3 次,7.4 节)。
func (s *Store) put(ctx context.Context, key string, data []byte) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<(attempt-1)) * time.Second)
		}
		_, err := s.client.PutObject(ctx, &oss.PutObjectRequest{
			Bucket: oss.Ptr(s.bucket),
			Key:    oss.Ptr(key),
			Body:   bytes.NewReader(data),
		})
		if err == nil {
			return nil
		}
		lastErr = err
		s.log.Warn("OSS PutObject 重试", "key", key, "attempt", attempt+1, "err", err)
	}
	return lastErr
}

// get 带重试的下载,单请求 30s 超时(7.4 节)。
func (s *Store) get(key string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<(attempt-1)) * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, err := s.client.GetObject(ctx, &oss.GetObjectRequest{
			Bucket: oss.Ptr(s.bucket),
			Key:    oss.Ptr(key),
		})
		if err != nil {
			cancel()
			if isNotFound(err) {
				return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
			}
			lastErr = err
			s.log.Warn("OSS GetObject 重试", "key", key, "attempt", attempt+1, "err", err)
			continue
		}
		data, rerr := io.ReadAll(res.Body)
		res.Body.Close()
		cancel()
		if rerr == nil {
			return data, nil
		}
		lastErr = rerr
	}
	return nil, lastErr
}

// isNotFound 识别 404(SDK 以 ServiceError 暴露状态码)。
func isNotFound(err error) bool {
	var se *oss.ServiceError
	if errors.As(err, &se) {
		return se.StatusCode == 404
	}
	return false
}
