// Loads the configuration table for the selected command.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

const defaultConfigPath = "/etc/certsync/config.toml"

type Config struct {
	Key                                                    []byte
	Groups                                                 []string
	Region, Endpoint, Bucket, Prefix, AccessKey, SecretKey string
	Directory                                              string
	DingTalkWebhook, DingTalkSecret                        string
}

type configSection struct {
	Key             string   `toml:"key"`
	SourceDir       string   `toml:"source_dir"`
	OutputDir       string   `toml:"output_dir"`
	Groups          []string `toml:"groups"`
	Region          string   `toml:"oss_region"`
	Endpoint        string   `toml:"oss_endpoint"`
	Bucket          string   `toml:"oss_bucket"`
	Prefix          string   `toml:"oss_prefix"`
	AccessKey       string   `toml:"oss_access_key_id"`
	SecretKey       string   `toml:"oss_access_key_secret"`
	DingTalkWebhook string   `toml:"dingtalk_webhook"`
	DingTalkSecret  string   `toml:"dingtalk_secret"`
}

func Load(command, filename string) (*Config, error) {
	if command != "push" && command != "pull" {
		return nil, fmt.Errorf("未知操作 %q", command)
	}

	// Defer decoding so only the selected table needs valid settings.
	var sections struct {
		Push toml.Primitive `toml:"push"`
		Pull toml.Primitive `toml:"pull"`
	}
	meta, err := toml.DecodeFile(filename, &sections)
	if err != nil {
		var parseErr toml.ParseError
		if errors.As(err, &parseErr) {
			return nil, fmt.Errorf("配置文件 %q 第 %d 行 TOML 格式错误", filename, parseErr.Position.Line)
		}
		return nil, fmt.Errorf("读取配置文件: %w", err)
	}
	if !meta.IsDefined(command) {
		return nil, fmt.Errorf("配置文件 %q 缺少 [%s] 区块", filename, command)
	}

	section := sections.Push
	if command == "pull" {
		section = sections.Pull
	}
	var settings configSection
	if err := meta.PrimitiveDecode(section, &settings); err != nil {
		var parseErr toml.ParseError
		if errors.As(err, &parseErr) {
			return nil, fmt.Errorf("配置文件 %q 第 %d 行 [%s] 字段类型错误", filename, parseErr.Position.Line, command)
		}
		return nil, fmt.Errorf("配置文件 %q 的 [%s] 区块格式错误", filename, command)
	}

	for _, key := range meta.Undecoded() {
		if key[0] == command || (key[0] != "push" && key[0] != "pull") {
			return nil, fmt.Errorf("配置文件 %q 含未知字段 %s", filename, key)
		}
	}
	c, err := settings.validate(command)
	if err != nil {
		return nil, fmt.Errorf("配置文件 %q 的 [%s]: %w", filename, command, err)
	}
	return c, nil
}

func (s configSection) validate(command string) (*Config, error) {
	c := &Config{
		Region: s.Region, Endpoint: s.Endpoint, Bucket: s.Bucket,
		Prefix: s.Prefix, AccessKey: s.AccessKey, SecretKey: s.SecretKey,
		Directory:       s.SourceDir,
		DingTalkWebhook: strings.TrimSpace(s.DingTalkWebhook),
		DingTalkSecret:  strings.TrimSpace(s.DingTalkSecret),
	}
	dirField := "source_dir"
	if command == "pull" {
		dirField, c.Directory = "output_dir", s.OutputDir
	}
	for _, field := range []struct{ name, value string }{
		{"oss_region", c.Region}, {"oss_bucket", c.Bucket}, {"oss_prefix", c.Prefix},
		{"oss_access_key_id", c.AccessKey}, {"oss_access_key_secret", c.SecretKey}, {dirField, c.Directory},
	} {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("缺少 %s", field.name)
		}
	}
	if !filepath.IsAbs(c.Directory) {
		return nil, fmt.Errorf("%s 必须是绝对路径", dirField)
	}
	c.Prefix = strings.TrimRight(c.Prefix, "/")
	if c.Prefix == "" || strings.HasPrefix(c.Prefix, "/") || strings.Contains(c.Prefix, "://") || strings.ContainsAny(c.Prefix, "\\\r\n") {
		return nil, fmt.Errorf("oss_prefix 必须是非空的相对对象前缀，例如 certsync")
	}
	for _, part := range strings.Split(c.Prefix, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("oss_prefix 不允许空路径段或相对路径段")
		}
	}
	var err error
	c.Key, err = base64.StdEncoding.Strict().DecodeString(s.Key)
	if err != nil || len(c.Key) != 32 {
		return nil, fmt.Errorf("key 必须是 32 字节随机密钥的标准 Base64 编码")
	}
	if command == "pull" {
		c.Groups, err = parseGroups(s.Groups)
		if err != nil {
			return nil, err
		}
	}
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, fmt.Errorf("oss_endpoint 必须是 HTTPS 服务地址")
		}
	}
	if c.DingTalkWebhook == "" && c.DingTalkSecret != "" {
		return nil, fmt.Errorf("配置 dingtalk_secret 时必须同时配置 dingtalk_webhook")
	}
	if c.DingTalkWebhook != "" {
		u, err := url.Parse(c.DingTalkWebhook)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("dingtalk_webhook 必须是 HTTPS 机器人地址")
		}
	}
	return c, nil
}

func parseGroups(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("groups 至少需要一个证书组")
	}
	groups := make([]string, len(raw))
	seen := make(map[string]bool, len(raw))
	for i, group := range raw {
		group = strings.TrimSpace(group)
		if !validGroupName(group) {
			return nil, fmt.Errorf("groups 第 %d 项必须为小写普通域名或以 *. 开头的通配域名", i+1)
		}
		if seen[group] {
			return nil, fmt.Errorf("groups 含重复组名 %s", group)
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
