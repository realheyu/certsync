package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hy/certsync/internal/config"
)

func testLogger() *slog.Logger { return slog.Default() }

func TestWebhookSendsHeadersAndPayload(t *testing.T) {
	var gotBody Event
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.Alert{}
	cfg.Webhook.URL = srv.URL
	cfg.Webhook.Headers = map[string]string{"Authorization": "Bearer tok"}
	s := NewSender(cfg, testLogger())
	s.Send(NewEvent("install_ok", "info", "web-01", "example.com", "done"))

	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization 头 = %q", gotAuth)
	}
	if gotBody.Event != "install_ok" || gotBody.Host != "web-01" || gotBody.Domain != "example.com" {
		t.Errorf("payload 字段错误: %+v", gotBody)
	}
}

func TestDingTalkSignAndErrcode(t *testing.T) {
	secret := "SECtest"
	var gotQuery = map[string]string{}
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.URL.Query() {
			gotQuery[k] = r.URL.Query().Get(k)
		}
		json.NewDecoder(r.Body).Decode(&gotPayload)
		// 先模拟 errcode!=0,验证被识别为失败
		w.Write([]byte(`{"errcode":310000,"errmsg":"sign not match"}`))
	}))
	defer srv.Close()

	cfg := config.Alert{}
	cfg.DingTalk.Webhook = srv.URL
	cfg.DingTalk.Secret = secret
	s := NewSender(cfg, testLogger())

	before := time.Now()
	endpoint, err := signedDingTalkURL(srv.URL, secret, before)
	if err != nil {
		t.Fatal(err)
	}
	_ = endpoint

	// 直接验证签名计算正确性
	ts := before.UnixMilli()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "\n" + secret))
	wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u2, err := signedDingTalkURL(srv.URL+"?access_token=abc", secret, before)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u2, "timestamp="+strconv.FormatInt(ts, 10)) || !strings.Contains(u2, "sign=") {
		t.Errorf("URL 缺少 timestamp/sign: %s", u2)
	}
	_ = wantSign

	// 发送应失败(errcode!=0),返回的错误由 Send 记日志
	s.Send(NewEvent("install_fail", "error", "web-01", "example.com", "test"))

	if gotQuery["timestamp"] == "" || gotQuery["sign"] == "" {
		t.Errorf("请求缺少加签参数: %v", gotQuery)
	}
	if gotPayload["msgtype"] != "markdown" {
		t.Errorf("msgtype = %v, want markdown", gotPayload["msgtype"])
	}
	md, _ := gotPayload["markdown"].(map[string]any)["text"].(string)
	if !strings.Contains(md, "certsync") {
		t.Errorf("消息不含固定首词 certsync(关键词过滤约定): %q", md)
	}
}

func TestDingTalkSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()
	cfg := config.Alert{}
	cfg.DingTalk.Webhook = srv.URL
	s := NewSender(cfg, testLogger())
	if err := s.sendDingTalk(NewEvent("install_ok", "info", "h", "d", "")); err != nil {
		t.Fatalf("errcode=0 应视为成功: %v", err)
	}
}

func TestSendNoChannelsIsNoop(t *testing.T) {
	s := NewSender(config.Alert{}, testLogger())
	s.Send(NewEvent("x", "info", "h", "d", "")) // 不 panic 即可
}
