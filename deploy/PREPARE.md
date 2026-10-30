# certsync 上线准备清单(办一件勾一件)

> 设计依据:DESIGN.md §5.4 / §6.2 / §6.5 / §11;权限/路径明细以设计文档为准。

## 一、阿里云控制台

- [ ] 创建 OSS bucket(区域就近,如 cn-hangzhou),私有读写(bucket 不开版本控制/访问日志)
- [ ] 记录 endpoint(`oss-cn-hangzhou.aliyuncs.com`)/ region(`cn-hangzhou`)/ bucket 名
- [ ] RAM 上传账号(签发机用):自定义策略仅 `oss:PutObject` 于 `<bucket>/certsync/certs/*`(策略 JSON 见 §6.2),禁控制台登录,生成 AK/SK
- [ ] RAM 拉取账号(业务机公用):仅 `oss:GetObject` 同前缀,禁控制台登录,生成 AK/SK
- [ ] RAM DNS 账号(签发机用):授权 `AddDomainRecord` / `DescribeDomainRecords` / `UpdateDomainRecord` / `DeleteDomainRecord`,生成 AK/SK
- [ ] 确认域名托管在阿里云 DNS(现状已满足则直接勾)

## 二、告警通道(至少办一个)

- [ ] 钉钉:建告警群 → 群设置 → 添加"自定义机器人" → 安全设置选**加签** → 记录 webhook URL(access_token)与 secret(SEC 开头)
- [ ] SMTP(可选):发件邮箱开启 SMTP 服务,生成**授权码**(非登录密码);记录 host / 端口(国内 465)/ username / 授权码 / 收件人列表

## 三、机器

- [ ] 签发机 ×1:现代 Linux(systemd),无业务,单独使用(§6.3 最高危机器)
- [ ] 签发机出网白名单:`api.letsencrypt.org:443` + `acme-staging-v02.api.letsencrypt.org:443`、`alidns.aliyuncs.com:443`、`<bucket>.oss-*.aliyuncs.com:443`、`oapi.dingtalk.com:443`、SMTP 465/587
- [ ] 签发机 NTP 运行中(`timedatectl status` 确认 NTP synchronized)
- [ ] 业务机 ×1~2(Phase 1 用非核心机):nginx 已装、`systemctl reload nginx` 可用
- [ ] 业务机出网:`<bucket>.oss-*.aliyuncs.com:443`(+ 告警地址)
- [ ] 业务机 NTP 运行中
- [ ] nginx 配置先行:写入 `ssl_certificate` / `ssl_certificate_key` 路径(与 config.toml 的 pull.targets 一致),`nginx -t` 通过

## 四、每台机器的运行时文件(代码交付后)

- [ ] `/etc/certsync/config.toml`(0644):从 `deploy/config.example.toml` 裁剪——签发机填 acme(email、domains)+ oss 段;业务机填 oss + pull 段
- [ ] `/etc/certsync/certsync.env`(0600):签发机 = DNS AK/SK + OSS 上传 AK/SK + 告警凭证;业务机 = OSS 拉取 AK/SK + 告警凭证(**同变量名、不同账号,勿拷贝混用**)
- [ ] `/etc/certsync/certsync.key`(0600):`certsync keygen` 产物,带外分发到**每台**
- [ ] systemd 单元:签发机 enable `certsync-renew.timer` + `certsync-backup.timer`;业务机 enable `certsync-pull.timer`(均配 `certsync-fail@` 兜底)

## 五、不需要准备(免查)

- LE 正式/staging 账户:lego 首跑自动注册(只需定一个接 CA 通知的邮箱)
- ZeroSSL EAB:切 CA 那天才办
- pebble / challtestsrv:CI 自带
- acme.sh:保持运行不动,Phase 2 才停(§15)

## 完成标志

以上全勾 + Phase 0 三层验收(CI / staging / 演练)通过 → 进入 §15 Phase 1 共存观察期。
