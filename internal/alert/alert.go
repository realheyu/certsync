// Package alert 多通道告警:通用 webhook、钉钉群机器人(加签)、SMTP 邮件(12.2 节)。
package alert

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hy/certsync/internal/config"
)

// Event 一条告警事件(字段与 12.2 节 payload 一致,Level 用于邮件主题)。
type Event struct {
	Event  string `json:"event"`
	Level  string `json:"level,omitempty"`
	Host   string `json:"host"`
	Domain string `json:"domain,omitempty"`
	Detail string `json:"detail,omitempty"`
	Time   string `json:"time"`
}

func NewEvent(event, level, host, domain, detail string) Event {
	return Event{Event: event, Level: level, Host: host, Domain: domain, Detail: detail,
		Time: time.Now().Format(time.RFC3339)}
}

// Sender 把事件扇出到所有已配置通道;全空 = 不告警。
type Sender struct {
	cfg    config.Alert
	client *http.Client
	log    *slog.Logger
}

func NewSender(cfg config.Alert, log *slog.Logger) *Sender {
	return &Sender{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}, log: log}
}

// Send 并行语义简化为顺序发送;单通道失败只记日志,不阻塞其他通道(7.4 节)。
func (s *Sender) Send(ev Event) {
	if s.cfg.Webhook.URL != "" {
		if err := s.sendWebhook(ev); err != nil {
			s.log.Error("webhook 告警失败", "err", err)
		}
	}
	if s.cfg.DingTalk.Webhook != "" {
		if err := s.sendDingTalk(ev); err != nil {
			s.log.Error("钉钉告警失败", "err", err)
		}
	}
	if s.cfg.Mail.Host != "" && len(s.cfg.Mail.To) > 0 {
		if err := s.sendMail(ev); err != nil {
			s.log.Error("邮件告警失败", "err", err)
		}
	}
}

func (s *Sender) sendWebhook(ev Event) error {
	body, _ := json.Marshal(ev)
	req, err := http.NewRequest(http.MethodPost, s.cfg.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.cfg.Webhook.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// dingTalkResp 钉钉返回体:HTTP 200 ≠ 成功,必须查 errcode(12.2 节)。
type dingTalkResp struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func (s *Sender) sendDingTalk(ev Event) error {
	endpoint, err := signedDingTalkURL(s.cfg.DingTalk.Webhook, s.cfg.DingTalk.Secret, time.Now())
	if err != nil {
		return err
	}
	md := fmt.Sprintf("**certsync %s** %s\n\n- 主机: %s\n- 域名: %s\n- 详情: %s\n- 时间: %s",
		ev.Level, ev.Event, ev.Host, ev.Domain, ev.Detail, ev.Time)
	at := ""
	if len(s.cfg.DingTalk.AtMobiles) > 0 {
		at = " @" + strings.Join(s.cfg.DingTalk.AtMobiles, " @")
	}
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": "certsync " + ev.Event, "text": md + at},
		"at":       map[string]any{"atMobiles": s.cfg.DingTalk.AtMobiles, "isAtAll": false},
	}
	body, _ := json.Marshal(payload)
	resp, err := s.client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var dr dingTalkResp
	if err := json.Unmarshal(raw, &dr); err != nil {
		return fmt.Errorf("解析钉钉响应 %q: %w", string(raw), err)
	}
	if dr.ErrCode != 0 {
		return fmt.Errorf("钉钉 errcode=%d errmsg=%s(常见原因:加签密钥错/关键词不匹配/限流)", dr.ErrCode, dr.ErrMsg)
	}
	return nil
}

// signedDingTalkURL 按加签规范附加 timestamp 与 sign(12.2 节:HMAC-SHA256,密钥与
// 被签串均为 "<timestamp>\n<secret>",base64 后 urlencode)。
func signedDingTalkURL(webhook, secret string, now time.Time) (string, error) {
	if webhook == "" {
		return "", fmt.Errorf("钉钉 webhook 未配置")
	}
	u, err := url.Parse(webhook)
	if err != nil {
		return "", fmt.Errorf("解析 webhook: %w", err)
	}
	q := u.Query()
	if secret != "" {
		ts := now.UnixMilli()
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strconv.FormatInt(ts, 10) + "\n" + secret))
		sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		q.Set("timestamp", strconv.FormatInt(ts, 10))
		q.Set("sign", sig)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// sendMail 邮件通道:主题 [certsync] <级别> <event> <host> <域名>,正文为事件 JSON。
// 465=隐式 TLS(自行 tls.Dial),587=STARTTLS,25=仅限内网中继(12.2 节)。
func (s *Sender) sendMail(ev Event) error {
	m := s.cfg.Mail
	addr := m.Host + ":" + strconv.Itoa(m.Port)
	subject := fmt.Sprintf("[certsync] %s %s %s %s", ev.Level, ev.Event, ev.Host, ev.Domain)
	body, _ := json.MarshalIndent(ev, "", "  ")

	from := m.From
	if from == "" {
		from = m.Username
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return fmt.Errorf("发件地址 %q 无效: %w", from, err)
	}

	var auth smtp.Auth
	if m.Username != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}
	msg := buildMail(from, m.To, subject, string(body))

	var client *smtp.Client
	var err error
	if m.Port == 465 {
		conn, derr := tls.Dial("tcp", addr, &tls.Config{ServerName: m.Host})
		if derr != nil {
			return fmt.Errorf("连接 %s: %w", addr, derr)
		}
		client, err = smtp.NewClient(conn, m.Host)
	} else {
		client, err = smtp.Dial(addr)
	}
	if err != nil {
		return fmt.Errorf("连接 %s: %w", addr, err)
	}
	defer client.Close()

	if m.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err = client.StartTLS(&tls.Config{ServerName: m.Host}); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		}
	}
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP 认证(确认用的是授权码而非登录密码): %w", err)
		}
	}
	if err = client.Mail(from); err != nil {
		return err
	}
	for _, to := range m.To {
		if err = client.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildMail(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ","))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(body)
	return b.Bytes()
}

// Hostname 本机主机名(事件里的 host 字段)。
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
