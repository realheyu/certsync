package main

import (
	"bytes"
	"context"
	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"

	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSingleObjectAndErrors(t *testing.T) {
	for _, group := range []string{"example.com", "*.example.com"} {
		t.Run(group, func(t *testing.T) {
			testSingleObjectAndErrors(t, "certsync/"+group+"/bundle.enc")
		})
	}
}

func testSingleObjectAndErrors(t *testing.T, objectKey string) {
	t.Helper()
	var saved []byte
	status := 0
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/bucket/"+objectKey {
			t.Errorf("wrong object path %s", r.URL.Path)
		}
		if status != 0 {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(status)
			io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>")
			return
		}
		if r.Method == "PUT" {
			saved, _ = io.ReadAll(r.Body)
			return
		}
		if r.Method != "GET" {
			t.Errorf("unexpected method %s", r.Method)
		}
		w.Write(saved)
	}))
	defer server.Close()
	cfg := oss.LoadDefaultConfig().WithRegion("cn-hangzhou").WithEndpoint(server.URL).WithUsePathStyle(true).WithRetryMaxAttempts(1).WithCredentialsProvider(credentials.NewStaticCredentialsProvider("fake", "fake"))
	st := &Store{client: oss.NewClient(cfg), bucket: "bucket"}
	if err := st.Put(context.Background(), objectKey, []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	data, err := st.Get(context.Background(), objectKey)
	if err != nil || !bytes.Equal(data, saved) {
		t.Fatalf("get: %v", err)
	}
	if requests != 2 {
		t.Fatalf("expected PUT + GET only, got %d", requests)
	}
	status = 403
	before := requests
	if _, err := st.Get(context.Background(), objectKey); err == nil {
		t.Fatal("403 accepted")
	}
	if requests != before+1 {
		t.Fatal("403 retried")
	}
	status = 0
	saved = make([]byte, MaxBundleSize+1)
	if _, err := st.Get(context.Background(), objectKey); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestRetryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := retry(ctx, func(ctx context.Context) error { return ctx.Err() })
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation not honored")
	}
}
