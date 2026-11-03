// reads the complete runtime configuration from the environment.
package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Key                                                    []byte
	Groups                                                 []string
	Region, Endpoint, Bucket, Prefix, AccessKey, SecretKey string
	Directory                                              string
	DingTalkWebhook, DingTalkSecret                        string
}

func Load(command string) (*Config, error) {
	c := &Config{}
	required := map[string]*string{
		"OSS_REGION": &c.Region, "OSS_BUCKET": &c.Bucket, "OSS_PREFIX": &c.Prefix,
		"OSS_ACCESS_KEY_ID": &c.AccessKey, "OSS_ACCESS_KEY_SECRET": &c.SecretKey,
	}
	dirVar := "CERTSYNC_SOURCE_DIR"
	if command == "pull" {
		dirVar = "CERTSYNC_OUTPUT_DIR"
		if os.Getenv("OSS_OBJECT_KEY") != "" || os.Getenv("CERTSYNC_DOMAINS") != "" {
			return nil, fmt.Errorf("pull 已改为批量模式，请移除 OSS_OBJECT_KEY、CERTSYNC_DOMAINS，改用 OSS_PREFIX、CERTSYNC_GROUPS，并将 CERTSYNC_OUTPUT_DIR 设为总目录")
		}
	} else if command != "push" {
		return nil, fmt.Errorf("未知操作")
	}
	required[dirVar] = &c.Directory
	for name, dst := range required {
		*dst = os.Getenv(name)
		if strings.TrimSpace(*dst) == "" {
			return nil, fmt.Errorf("缺少环境变量 %s", name)
		}
	}
	if !filepath.IsAbs(c.Directory) {
		return nil, fmt.Errorf("%s 必须是绝对路径", dirVar)
	}
	c.Prefix = strings.TrimRight(c.Prefix, "/")
	if c.Prefix == "" || strings.HasPrefix(c.Prefix, "/") || strings.Contains(c.Prefix, "://") || strings.ContainsAny(c.Prefix, "\\\r\n") {
		return nil, fmt.Errorf("OSS_PREFIX 必须是非空的相对对象前缀，例如 certsync")
	}
	for _, part := range strings.Split(c.Prefix, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("OSS_PREFIX 不允许空路径段或相对路径段")
		}
	}
	var err error
	c.Key, err = base64.StdEncoding.Strict().DecodeString(os.Getenv("CERTSYNC_KEY"))
	if err != nil || len(c.Key) != 32 {
		return nil, fmt.Errorf("CERTSYNC_KEY 必须是 32 字节随机密钥的标准 Base64 编码")
	}
	if command == "pull" {
		c.Groups, err = ParseGroups(os.Getenv("CERTSYNC_GROUPS"))
		if err != nil {
			return nil, err
		}
	}
	c.Endpoint = os.Getenv("OSS_ENDPOINT")
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, fmt.Errorf("OSS_ENDPOINT 必须是 HTTPS 服务地址")
		}
	}
	c.DingTalkWebhook = strings.TrimSpace(os.Getenv("DINGTALK_WEBHOOK"))
	c.DingTalkSecret = strings.TrimSpace(os.Getenv("DINGTALK_SECRET"))
	if c.DingTalkWebhook == "" && c.DingTalkSecret != "" {
		return nil, fmt.Errorf("配置 DINGTALK_SECRET 时必须同时配置 DINGTALK_WEBHOOK")
	}
	if c.DingTalkWebhook != "" {
		u, err := url.Parse(c.DingTalkWebhook)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("DINGTALK_WEBHOOK 必须是 HTTPS 机器人地址")
		}
	}
	return c, nil
}

func ParseGroups(raw string) ([]string, error) {
	groups := strings.Split(raw, ",")
	seen := make(map[string]bool)
	for i, group := range groups {
		group = strings.TrimSpace(group)
		if !validGroupName(group) {
			return nil, fmt.Errorf("CERTSYNC_GROUPS 必须为小写普通域名或以 *. 开头的通配域名组名列表，英文逗号分隔，不允许空项或路径")
		}
		if seen[group] {
			return nil, fmt.Errorf("CERTSYNC_GROUPS 含重复组名 %s", group)
		}
		seen[group] = true
		groups[i] = group
	}
	return groups, nil
}

func validGroupName(group string) bool {
	if len(group) == 0 || len(group) > 253 {
		return false
	}
	// A wildcard is allowed only as the complete leftmost label. Keep the
	// original group name for object keys and paths; it is never a glob.
	group = strings.TrimPrefix(group, "*.")
	if !strings.Contains(group, ".") {
		return false
	}
	for _, label := range strings.Split(group, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
