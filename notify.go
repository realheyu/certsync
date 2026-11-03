// DingTalk notifications are optional; send failures do not fail deployment.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const expiryWarningWindow = 15 * 24 * time.Hour

type certificateNotice struct {
	group, event string
	expires      time.Time
}

type notifications struct {
	config *Config
	out    io.Writer
	now    time.Time
	host   string
	events []certificateNotice
}

func newNotifications(config *Config, out io.Writer) *notifications {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return &notifications{config: config, out: out, now: time.Now(), host: host}
}

func (n *notifications) expiring(group string, expires time.Time) {
	if expires.Sub(n.now) >= expiryWarningWindow {
		return
	}
	event := "证书剩余有效期少于 15 天"
	if !expires.After(n.now) {
		event = "证书已过期"
	}
	n.events = append(n.events, certificateNotice{group: group, event: event, expires: expires})
	fmt.Fprintf(n.out, "有效期告警，组 %s: %s，到期 %s\n", group, event, noticeTime(expires))
}

func (n *notifications) replaced(group string, expires time.Time) {
	n.events = append(n.events, certificateNotice{group: group, event: "证书和私钥已成功替换（尚未确认服务 reload）", expires: expires})
}

func noticeTime(value time.Time) string {
	return value.In(time.FixedZone("UTC+8", 8*60*60)).Format("2006-01-02 15:04:05 -07:00")
}

func (n *notifications) messages() []string {
	header := fmt.Sprintf("certsync 证书通知\n机器：%s\n检查时间：%s\n", n.host, noticeTime(n.now))
	var messages []string
	content := header
	for _, event := range n.events {
		remaining := event.expires.Sub(n.now)
		status := "剩余"
		if remaining <= 0 {
			status = "已过期"
			remaining = -remaining
		}
		days := int(remaining / (24 * time.Hour))
		hours := int(remaining % (24 * time.Hour) / time.Hour)
		row := fmt.Sprintf("\n证书组：%s\n事件：%s\n到期时间：%s\n%s：%d 天 %d 小时\n", event.group, event.event, noticeTime(event.expires), status, days, hours)
		// Keep text messages small and split only between complete events.
		if len(content)+len(row) > 12000 && content != header {
			messages = append(messages, content)
			content = header
		}
		content += row
	}
	if content != header {
		messages = append(messages, content)
	}
	return messages
}

func (n *notifications) flush(ctx context.Context) {
	if n.config.DingTalkWebhook == "" || len(n.events) == 0 {
		return
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, message := range n.messages() {
		if err := sendDingTalk(ctx, client, n.config.DingTalkWebhook, n.config.DingTalkSecret, message); err != nil {
			fmt.Fprintf(n.out, "钉钉通知失败（不影响证书上传、替换或后续 reload）: %v\n", err)
		} else {
			fmt.Fprintln(n.out, "钉钉通知已发送")
		}
	}
}

func signedDingTalkURL(webhook, secret string, now time.Time) (string, error) {
	u, err := url.Parse(webhook)
	if err != nil {
		return "", errors.New("机器人地址无效")
	}
	if secret != "" {
		timestamp := fmt.Sprint(now.UnixMilli())
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(timestamp + "\n" + secret))
		query := u.Query()
		query.Set("timestamp", timestamp)
		query.Set("sign", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		u.RawQuery = query.Encode()
	}
	return u.String(), nil
}

func sendDingTalk(ctx context.Context, client *http.Client, webhook, secret, message string) error {
	body, err := json.Marshal(struct {
		MsgType string            `json:"msgtype"`
		Text    map[string]string `json:"text"`
	}{MsgType: "text", Text: map[string]string{"content": message}})
	if err != nil {
		return errors.New("通知消息编码失败")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errors.New("通知请求已取消或超时")
			case <-timer.C:
			}
		}
		endpoint, err := signedDingTalkURL(webhook, secret, time.Now())
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("无法创建通知请求")
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		response, err := client.Do(req)
		if err != nil {
			// Raw HTTP errors may include the access token or signed URL.
			lastErr = errors.New("机器人网络请求失败")
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
		_ = response.Body.Close()
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			lastErr = fmt.Errorf("机器人 HTTP %d", response.StatusCode)
			continue
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("机器人 HTTP %d", response.StatusCode)
		}
		if readErr != nil {
			lastErr = errors.New("读取机器人响应失败")
			continue
		}
		if len(raw) > 65536 {
			return errors.New("机器人响应超限")
		}
		var result struct {
			ErrCode *int `json:"errcode"`
		}
		if err := json.Unmarshal(raw, &result); err != nil || result.ErrCode == nil {
			return errors.New("机器人响应格式无效")
		}
		if *result.ErrCode != 0 {
			// Do not echo errmsg: upstream responses can reflect credentials.
			return fmt.Errorf("机器人拒绝消息，errcode=%d，请检查加签、关键词、IP 白名单或限流", *result.ErrCode)
		}
		return nil
	}
	if ctx.Err() != nil {
		return errors.New("通知请求已取消或超时")
	}
	return lastErr
}
