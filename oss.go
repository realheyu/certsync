// transfers one bounded encrypted object through OSS.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

type Store struct {
	client *oss.Client
	bucket string
}

func newStore(c *Config) *Store {
	cfg := oss.LoadDefaultConfig().WithRegion(c.Region).
		WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey)).
		WithRetryMaxAttempts(1).WithConnectTimeout(10 * time.Second).WithReadWriteTimeout(30 * time.Second)
	if c.Endpoint != "" {
		cfg.WithEndpoint(c.Endpoint)
	}
	return &Store{client: oss.NewClient(cfg), bucket: c.Bucket}
}

func (s *Store) Put(ctx context.Context, key string, data []byte) error {
	if len(data) > MaxBundleSize {
		return errors.New("证书包超过 1 MiB")
	}
	return retry(ctx, func(ctx context.Context) error {
		_, err := s.client.PutObject(ctx, &oss.PutObjectRequest{Bucket: oss.Ptr(s.bucket), Key: oss.Ptr(key), Body: bytes.NewReader(data)})
		return err
	})
}

func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	err := retry(ctx, func(ctx context.Context) error {
		res, err := s.client.GetObject(ctx, &oss.GetObjectRequest{Bucket: oss.Ptr(s.bucket), Key: oss.Ptr(key)})
		if err != nil {
			return err
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, MaxBundleSize+1))
		if err != nil {
			return err
		}
		if len(raw) > MaxBundleSize {
			return errOversize
		}
		data = raw
		return nil
	})
	return data, err
}

var errOversize = errors.New("证书包超过 1 MiB")

func retry(parent context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(1<<(attempt-1)) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		callCtx, callCancel := context.WithTimeout(ctx, 30*time.Second)
		last = fn(callCtx)
		callCancel()
		if last == nil {
			return nil
		}
		if errors.Is(last, errOversize) {
			return last
		}
		var se *oss.ServiceError
		if errors.As(last, &se) && se.StatusCode >= 400 && se.StatusCode < 500 && se.StatusCode != 408 && se.StatusCode != 429 {
			return fmt.Errorf("OSS 请求失败 (HTTP %d, code %s)", se.StatusCode, se.Code)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	// SDK errors may include signed request details; do not print raw errors.
	return errors.New("OSS 请求失败，已达到重试上限")
}
