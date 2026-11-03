# certsync 设计：acme.sh 签发 + Go 分发

| 项目 | 内容 |
|---|---|
| 版本 | v1.2 批量分发版，替代 v0.5 全流程 Go 方案 |
| 日期 | 2026-11-03 |
| 状态 | 简版已实现；本地测试、静态检查和双架构构建已通过，待实际环境验收 |
| 范围 | Linux；一个签发机，多组证书，多个业务机 |

## 1. 方案与职责

acme.sh 负责申请和续期；certsync 是 Go 编写的单二进制工具，只负责证书包加密上传、下载校验和文件替换。所有运行配置从环境变量读取。

```text
签发机                         私有 OSS                    业务机
acme.sh DNS-01 申请/续期
  → 各组导出到域名子目录
  → certsync push
      逐组校验、合并、加密 ─→ 每组 bundle.enc ─────────────→ certsync pull
                                                        下载、解密、校验
                                                        替换两个文件
                                                        ↓
                                                  外层 nginx -t && reload
```

| 组件 | 功能 |
|---|---|
| acme.sh | CA 交互、DNS-01、账户管理、签发续期、导出证书 |
| certsync push | 遍历总目录，逐组校验、合并为 JSON、加密并上传独立 OSS 对象 |
| certsync pull | 按组列表下载、完整解密、校验，分别安装到输出总目录下的组子目录 |
| cron / 外层命令 | 定时执行、互斥、任务总超时、nginx 检查及 reload |
| 钉钉群自定义机器人 | 可选：下载替换成功通知、签发端少于 15 天有效期告警 |
| 现有运维体系 | 日志收集、其他故障告警、服务端证书到期监控、备份和人工恢复 |

Go 工具不调用 acme.sh，不读取或使用 DNS 凭证，不管理账户、续期窗口或服务状态。编译后只需拷贝一个二进制；目标机器仍需系统 CA 根证书，签发机还需要 acme.sh 的运行依赖。不再安装 age、ossutil 或 Python 库。

## 2. 功能取舍

保留每组证书和私钥整体加密、按组独立上传下载、基本证书校验、完整内容比较、临时文件替换、日志、非零失败退出码和请求超时。

| 删除内容 | 简化后的处理 |
|---|---|
| 内嵌 lego、issue/renew、ACME state | 交给 acme.sh |
| keygen、密钥文件、覆盖优先级、轮换与密钥版本 | 用户设置固定环境变量字符串 |
| meta.json、组内多个对象提交顺序、指纹版本协议 | 每组一个加密包，一次上传 |
| 远程状态检查、自动自愈状态 | 每日重新上传本地有效产物 |
| nginx 命令配置、服务探测 | 外层命令检查和 reload |
| 自动备份、回滚、历史清理 | 现有备份体系和人工恢复 |
| 通用多渠道告警、邮件、on-failure | 仅保留两类钉钉通知，其余依赖日志、退出码和现有监控 |
| 多目标配置文件、灰度参数、status、自更新 | 上传从目录发现分组，下载用环境变量列举组名 |

签发机一份环境配置处理整个总目录；业务机一份配置选择多个组，一次拉取分别安装到各自子目录，整批成功后统一 reload。各组独立发布，不保证整批同时更新，不自动删除远程已存在对象。只实现当前分发用途，不增加 Web UI、KMS、自动切 CA 或二进制分发平台。

## 3. 命令接口

```text
certsync push       遍历总目录，逐组读取证书和私钥，加密并上传
certsync pull       按组列表批量下载、解密、校验并安装到各自子目录
certsync version    输出构建版本
```

不设配置文件参数或密钥覆盖参数。成功退出 0；配置、网络、解密、校验和文件操作失败均退出非零。pull 内容未变也退出 0，外层命令可继续检查和 reload。

不把叶子证书指纹当作完整部署状态：即使证书相同，私钥缺失或不同，也必须重新安装正确文件。

## 4. 环境变量

工具只读环境，不读 TOML、独立密钥文件或登录 shell 初始化文件。

| 变量 | 使用方 | 说明 |
|---|---|---|
| CERTSYNC_KEY | push / pull，必填 | 32 字节随机密钥的标准 Base64 编码，通常为 44 个字符 |
| CERTSYNC_GROUPS | 仅 pull，必填 | 要下载的组名列表，例如 `*.example.com,other.com`；每项与上传子目录名完全一致，支持小写普通域名和以 `*.` 开头的通配域名；按字面值选择组，不是 SAN 列表或组名匹配模式，不允许空项、重复项或路径，逗号周围可有空格 |
| OSS_ACCESS_KEY_ID | push / pull，必填 | 各角色自己的 OSS AccessKey ID |
| OSS_ACCESS_KEY_SECRET | push / pull，必填 | OSS AccessKey Secret |
| OSS_REGION | push / pull，必填 | Bucket 地域，例如 cn-hangzhou |
| OSS_ENDPOINT | push / pull，可选 | 未设时由 SDK 根据地域解析；显式设置时只允许 HTTPS |
| OSS_BUCKET | push / pull，必填 | Bucket 名称 |
| OSS_PREFIX | push / pull，必填 | 两端相同的对象前缀，例如 certsync；生成 <前缀>/<组目录名>/bundle.enc，禁止绝对路径、URL、空路径段及 . / .. 路径段，末尾 / 自动去除 |
| CERTSYNC_SOURCE_DIR | push，必填 | 证书总目录，每个直接域名子目录包含 fullchain.pem 和 privkey.pem |
| CERTSYNC_OUTPUT_DIR | pull，必填 | 输出总目录；各组安装到 <总目录>/<组名>/fullchain.pem 和 privkey.pem |
| DINGTALK_WEBHOOK | push / pull，可选 | 群自定义机器人完整 HTTPS 地址；留空不发送群消息 |
| DINGTALK_SECRET | push / pull，可选 | 加签密钥 `SEC...`；设置时须同时设置 DINGTALK_WEBHOOK，关键词/IP 验证可留空 |
| ACME_HOME | 仅签发机 | acme.sh 安装和状态目录，例如 /opt/acme.sh |
| ACME_EMAIL | 仅首次注册 | 接收 CA 账户通知的邮箱 |
| ACME_SERVER | 仅签发机 | 显式选择 CA，例如 letsencrypt；由 acme.sh 保存到签发配置 |
| ACME_DOMAINS | 手动首签时指定 | 本次申请的一组域名，例如 example.com,*.example.com；Go 不读取 |
| Ali_Key / Ali_Secret | 仅签发机上的 acme.sh | 阿里云 DNS 凭证，与 OSS 账号分开 |

缺失或格式不合法时立即报错，不猜测凭证、不回退到其他密钥来源。机器时间应保持同步。

### 4.1 签发机

文件 /etc/certsync/issuer.env，root 拥有，权限 0600，父目录权限 0700：

```sh
CERTSYNC_KEY='填写生成的完整Base64密钥'
CERTSYNC_SOURCE_DIR='/var/lib/certsync/certs'
ACME_HOME='/opt/acme.sh'
ACME_EMAIL='ops@example.com'
ACME_SERVER='letsencrypt'
OSS_ACCESS_KEY_ID='填写上传账号AK'
OSS_ACCESS_KEY_SECRET='填写上传账号SK'
OSS_REGION='cn-hangzhou'
OSS_ENDPOINT='https://oss-cn-hangzhou.aliyuncs.com'
OSS_BUCKET='my-cert-bucket'
OSS_PREFIX='certsync'
Ali_Key='填写DNS账号AK'
Ali_Secret='填写DNS账号SK'
DINGTALK_WEBHOOK=''
DINGTALK_SECRET=''
```

### 4.2 业务机

文件 /etc/certsync/pull.env，权限同上。业务机没有 DNS 凭证：

```sh
CERTSYNC_KEY='与签发机相同的完整Base64密钥'
CERTSYNC_GROUPS='*.example.com,other.com'
CERTSYNC_OUTPUT_DIR='/etc/nginx/certs'
OSS_ACCESS_KEY_ID='填写下载账号AK'
OSS_ACCESS_KEY_SECRET='填写下载账号SK'
OSS_REGION='cn-hangzhou'
OSS_ENDPOINT='https://oss-cn-hangzhou.aliyuncs.com'
OSS_BUCKET='my-cert-bucket'
OSS_PREFIX='certsync'
DINGTALK_WEBHOOK=''
DINGTALK_SECRET=''
```

env 是受信任的 root 管理的 shell 赋值文件，真实值不提交 Git。用 `set -a; . 文件; set +a` 加载，使普通赋值也被导出；只 source 不足以让子进程读取未导出的变量。容器也可直接注入相同环境变量。

### 4.3 组名规则

组名是小写 ASCII/Punycode 普通域名，或在同样的域名前加一个完整的 `*.` 标签，例如 `example.com`、`*.example.com`、`*.sub.example.com`。去掉可选的 `*.` 后仍须包含至少两个非空标签；每个普通标签不超过 63 字符，只含小写字母、数字和非首尾连字符，整个组名（含 `*.`）不超过 253 字符。拒绝路径、空项、重复项、裸 `*`、`api.*.example.com`、`foo*.example.com` 和 `**.example.com`。

组名在目录、OSS 对象键和下载配置中保持原样；`*` 是字面字符，不进行 Shell glob 或组名匹配。`example.com` 与 `*.example.com` 是两个独立组，可以同时存在，下载其中一组不会选择另一组。包含星号的 Shell 参数和路径须加引号。组名不枚举证书所有 SAN，也不隐含根域名覆盖，证书校验规则见第 8 节。

不打印环境、不启用包含敏感值的 shell 调试输出、不将密钥放命令行参数。acme.sh 可能把 DNS 凭证保存到自己的账户配置，这是它的内部行为；其目录也须作为敏感数据保护，certsync 不管理它。

## 5. 加密与 OSS 对象

### 5.1 固定密钥

用户生成一次随机值，并在两端配置同一个 CERTSYNC_KEY：

```sh
openssl rand -base64 32
```

解码后必须恰为 32 字节。普通自选密码不作为输入，不实现密码派生、密钥文件、自动轮换或过渡期兼容。用户修改密钥后，自行同步所有机器并重新 push。

### 5.2 包格式

明文是一个小 JSON 对象，不使用 tar/zip：

```json
{
  "fullchain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

密文格式：

```text
格式头 CERTSYNC1（9 字节） | 随机 nonce（12 字节） | AES-256-GCM 密文和认证标签
```

使用 Go 标准库 crypto/rand、crypto/aes、crypto/cipher。格式头作为 GCM 附加认证数据，每次加密使用新 nonce；格式头是固定解析标记，不是证书或密钥版本。证书包上限 1 MiB，下载超限即拒绝，不能无限读取远程对象。

客户端完整下载并认证解密后，才解析和使用明文。错误密钥、截断和篡改均失败。本方案不实现签发者身份签名、有效期内旧包防重放或吊销检查；OSS 写权限仍属于发布权限。

### 5.3 每组独立发布

```text
oss://my-cert-bucket/certsync/*.example.com/bundle.enc
oss://my-cert-bucket/certsync/other.com/bundle.enc
```

push 对每组分别校验和加密后，对 <OSS_PREFIX>/<目录名>/bundle.enc 执行一次 PutObject，不先删除旧对象。不上传明文、账户信息、meta.json 或其他旁文件，不维护多个对象的提交状态。

客户端上传报错时不推断服务端是否已提交，直接报告失败。重传当前有效证书包即可，无需重新申请证书。

沿用 OSS Go SDK，凭证显式取自环境变量。上传账号仅授权上传前缀下各组对象的 oss:PutObject，下载账号仅授权所需组对象的 oss:GetObject；不使用列表、HEAD、自愈和删除接口。使用私有 Bucket、不同角色账号和 HTTPS。真实 SDK 所需权限须在验收时验证。

通配组对象键保留字面值 `*`，例如 `certsync/*.example.com/bundle.enc`。OSS RAM 授权策略里的 `*` 仍表示匹配符，不能把含星号的对象键直接拼入策略后视为精确对象授权，须单独核对授权范围。

## 6. 批量 push 流程

上传目录布局：

```text
/var/lib/certsync/certs/
├── *.example.com/
│   ├── fullchain.pem
│   └── privkey.pem
└── other.com/
    ├── fullchain.pem
    └── privkey.pem
```

1. 检查公共配置、总目录和 OSS_PREFIX，解析密钥；上传组名由目录获取，不读取 CERTSYNC_GROUPS。
2. 只枚举总目录直接子项，按名字排序。普通文件忽略，软链接按失败处理，不递归查找。
3. 每个子目录名必须符合第 4.3 节的普通或通配域名规则，作为组标识与该组期望域名；保持字面值，不转换或展开星号。
4. 读取 fullchain 后先检查叶子证书 NotAfter，剩余有效期严格少于 15 × 24 小时则记录临期事件；已过期也记录。再完整读取私钥并校验证书覆盖目录域名、可信链、有效期和私钥配对，不接受软链接文件。元数据检查不能代替证书校验，过期证书仍拒绝上传。
5. 把两个 PEM 内容编码为一个 JSON，整体加密后上传到 <OSS_PREFIX>/<目录名>/bundle.enc；不改变包格式。
6. 一组失败记录原因后继续其余组。每组记录结果，最后汇总成功／失败数量；有失败则整体非零退出。总目录为空、没有组目录或仍采用旧的平铺布局时也报错。上下文取消则停止剩余处理。

每次 push 都上传全部有效组，不先查询远程指纹。失败组的本地文件不删除；本地删除组不触发 OSS 删除。可以直接重跑整个批次，不必重新申请证书或维护上传完成标记。各组分别提交，不建立整批事务。

acme.sh 导出失败可能留下不配对文件，由校验阻止该组发布，其他有效组仍能上传。总目录独立于 acme.sh 内部工作目录和业务 nginx 正在使用的路径。

## 7. 批量 pull 流程和替换边界

例如 `CERTSYNC_GROUPS='*.example.com,other.com'`、`OSS_PREFIX='certsync'`、`CERTSYNC_OUTPUT_DIR='/etc/nginx/certs'`：

```text
certsync/*.example.com/bundle.enc → /etc/nginx/certs/*.example.com/{fullchain.pem,privkey.pem}
certsync/other.com/bundle.enc     → /etc/nginx/certs/other.com/{fullchain.pem,privkey.pem}
```

1. 检查公共配置、组列表和输出总目录。组名支持普通和以 `*.` 开头的通配域名，英文逗号分隔，可有周围空格；按字面值选择组，禁止空项、重复项、非法星号和路径；旧单组变量 OSS_OBJECT_KEY / CERTSYNC_DOMAINS 存在时直接给出迁移错误。
2. 按配置顺序，下载 <OSS_PREFIX>/<组名>/bundle.enc，限制单包大小；不列举远程对象，不下载未选择组。
3. 完整认证解密并解析 JSON，校验链、有效期、私钥配对及证书覆盖组名。
4. 比较 <输出总目录>/<组名>/ 中两个文件的完整内容；均相同时不重写，缺失私钥时安装完整配对文件。
5. 在该组目录中准备两个临时文件，证书 0644、私钥 0600；Write、Sync、Close 成功后分别 rename 替换。内容相同仍检查私钥权限。
6. 一组失败记录具体原因，继续其余组；最后汇总成功／失败数，有任一失败返回非零。整批成功包括文件未变时才返回 0，由外层统一检查和 reload。

输出总目录和组子目录必须是普通目录，不支持软链接；目标文件也不支持软链接。未选择的本地目录和文件不会删除。

每组下载、解密、校验和准备临时文件阶段失败，保留该组旧文件。整批不是事务，成功组不会因其他组失败而回滚。单组的两次 rename 也不是一个事务：替换中途退出可能留下混合版本，此时外层不 reload；重跑 pull 会比较并修复各组文件。

不要让其他任务同时重写输出树或在替换中途重启服务。不实现自动回滚、掉电事务或整批原子切换。

## 8. 共用校验

push / pull 使用同一套 Go 校验逻辑：

- 证书 PEM 和私钥可解析，首张为叶子证书，fullchain 提供所需中间证书。
- 使用 tls.X509KeyPair 检查公私钥配对，支持实际使用的 EC / RSA 格式。
- 使用 x509.Verify、系统可信根和 fullchain 的中间证书，验证服务器用途、证书链及有效期；不能只数 PEM 块数。
- 上传校验证书覆盖组目录名，下载校验证书覆盖对应组名。普通域名使用 VerifyHostname；以 `*.` 开头的通配组要求证书 DNS SAN 中存在相同的通配域名（不区分 SAN 大小写），不通过构造某个子域名来推测覆盖范围。
- `*.example.com` 组接受同时包含根域名的证书，也接受只包含对应通配符 SAN 的证书；仅包含 `example.com`、`api.example.com` 或 `*.sub.example.com` 的证书不满足该组。普通 `example.com` 组仍要求覆盖根域名，仅有 `*.example.com` SAN 不满足要求。
- 拒绝空包、缺字段、超限包、未知格式及无效域名配置。

正式分发不设跳过可信链验证的环境开关。测试根只在自动测试中注入；真实 staging 证书用于验证 acme.sh 签发，不上传正式对象、不安装到正式服务。

### 8.1 钉钉通知

通知通过可选的 DINGTALK_WEBHOOK、DINGTALK_SECRET 配置，签发机和业务机可以配置不同机器人。不配置 Webhook 时保持原分发行为，签发端的有效期警告仍写入本地日志。消息包含固定关键词 `certsync`、机器名、组名、事件、叶子证书到期时间和剩余时长；时间显示 UTC+8，不包含私钥或任何访问凭证。

- pull 仅在 Install 返回 changed=true 且无错误时收集替换成功事件，包括首次安装和缺失文件修复；内容未变、仅修正私钥权限以及任何下载/校验/安装失败均不发送成功通知。部分批次失败时成功组仍通知，消息明确说明尚未确认外层服务 reload。
- push 使用每轮开始时间检查 NotAfter，剩余时长严格少于 15 × 24 小时才告警，恰好 15 天不告警。每次 push 都重新检查，不根据证书变化去重。检查在私钥验证及 OSS 上传前进行，确保缺私钥、过期或上传失败时临期事件仍能发送；过期事件不能使证书绕过验证。
- 任务结束时合并本轮事件并分条发送，每条文本最多 12000 字节。支持机器人关键词/IP 验证和加签：以 Secret 为 HMAC-SHA256 密钥，对毫秒 timestamp + 换行 + Secret 签名，标准 Base64 后由 URL 查询参数编码发送。重试会重新生成 timestamp 和签名。
- HTTP 200 且 JSON errcode 明确为 0 才算成功。网络错误和 HTTP 429/5xx 最多尝试三次，退避 1 秒、2 秒；每次 HTTP 请求时限 10 秒，单条消息总时限 15 秒，响应最多 64 KiB。不跟随重定向，不打印原始网络错误、响应 errmsg 或机器人 URL，防止泄露 Token/Secret。
- 通知失败记明确日志，不改变分发返回状态，不回滚文件、不阻断外层 reload。暂不维护持久通知队列；失败的替换成功通知不会在后续“内容未变”的 pull 中补发，临期告警会在下轮 push 再次尝试。网络超时后的重试可能产生重复消息。

机器人若启用关键词验证，须将 `certsync` 设为允许的关键词；若启用加签，填写 Secret；若限制 IP，允许对应机器的出口 IP。该通知只覆盖用户要求的两个事件，不能代替服务侧证书到期检查和其他故障告警。

## 9. acme.sh 接入

按官方方式安装到 /opt/acme.sh，使用已验证的版本。关闭安装器生成的默认 cron，统一由第 10 节调度。Go 不实现续期阈值、CA 选择或账户管理。

### 9.1 首签与导出

以下命令以 root 执行，先替换真实域名和邮箱，初始化时暂不启用定时任务：

```bash
set -euo pipefail
umask 077
set -a
. /etc/certsync/issuer.env
set +a

# 每组执行一次，另一个组使用不同 ACME_DOMAINS；不是 push 的全局过滤条件。
export ACME_DOMAINS='*.example.com,example.com'
IFS=',' read -r -a domains <<< "$ACME_DOMAINS"
export_dir="$CERTSYNC_SOURCE_DIR/${domains[0]}"
install -d -m 700 "$export_dir"
domain_args=()
for domain in "${domains[@]}"; do
  domain_args+=(-d "$domain")
done
"$ACME_HOME/acme.sh" --register-account --home "$ACME_HOME" \
  --server "$ACME_SERVER" -m "$ACME_EMAIL"
"$ACME_HOME/acme.sh" --issue --home "$ACME_HOME" \
  --server "$ACME_SERVER" --dns dns_ali --keylength ec-256 \
  "${domain_args[@]}"
"$ACME_HOME/acme.sh" --install-cert --home "$ACME_HOME" \
  -d "${domains[0]}" --ecc \
  --fullchain-file "$export_dir/fullchain.pem" \
  --key-file "$export_dir/privkey.pem"
/usr/local/bin/certsync push
```

acme.sh 使用 Ali_Key、Ali_Secret 调用阿里云 DNS。通过 --install-cert 导出到固定路径，不打包 acme.sh 内部工作文件；续期会重新安装到记录的导出路径。初始命令从本次手动指定的 ACME_DOMAINS 读取域名；使用英文逗号且不加空格，第一项为小写普通或通配主域名。上例同时把第一项作为 certsync 组名，因此导出到字面目录 `*.example.com/`。使用原有 `ACME_DOMAINS='example.com,*.example.com'` 仍可导出为普通组 `example.com/`。为其他组重复申请和导出步骤；随后一次 push 处理全部子目录。后续修改域名或 CA 由用户重新执行申请与导出步骤，单纯改 env 不会修改 acme.sh 已保存的证书配置。

不设置上传 hook 或 reloadcmd：上传由每日任务独立执行，上传失败后不必等下次续期。

已有证书不必为组名重签。acme.sh 保存的主域名与 certsync 导出组名可以不同：主域名为 `example.com`、SAN 同时包含 `*.example.com` 的已有证书，可以继续用 `--install-cert -d example.com --ecc`，把两个输出路径改为 `"$CERTSYNC_SOURCE_DIR/*.example.com/fullchain.pem"` 和 `"$CERTSYNC_SOURCE_DIR/*.example.com/privkey.pem"`。先创建该字面目录，再导出、push，并同步业务机的组列表和服务路径。签发机自身使用该证书时，须同步服务路径并在导出命令中保留所需 reloadcmd。原有普通域名组无需改名；改名不会自动迁移或删除旧目录、旧 OSS 对象。

### 9.2 每日包装脚本

仅保留一个薄 Bash 包装 /usr/local/sbin/certsync-issuer-job，加载环境、串联工具并保留失败状态。业务逻辑仍在 Go：

```bash
#!/bin/bash
set -euo pipefail
umask 077
set -a
. /etc/certsync/issuer.env
set +a

acme_rc=0
"$ACME_HOME/acme.sh" --cron --home "$ACME_HOME" || acme_rc=$?
push_rc=0
/usr/local/bin/certsync push || push_rc=$?

printf 'acme_exit=%s push_exit=%s\n' "$acme_rc" "$push_rc"
if (( acme_rc != 0 || push_rc != 0 )); then
  exit 1
fi
```

即使 CA 当天不可用，也尝试上传已有有效产物，但整个任务仍报告续期失败。文件过期或不完整时，push 自己拒绝发布。

## 10. 调度、锁和超时

锁统一由外层 Linux flock 提供，Go 不维护第二套锁。签发机锁覆盖申请、导出和上传；业务机锁覆盖下载、替换和 reload。手动操作也使用相同锁。签发机一把锁覆盖同一 ACME_HOME 的统一续期和整个批量上传；业务机一把锁覆盖选定组的整批下载、安装和统一 reload；同一个输出树不得被其他任务并发改写。

/etc/cron.d/certsync 按机器角色选用以下行。GNU timeout、flock、nginx、systemctl 的可用路径按发行版确认：

```cron
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 签发机：每日检查续期，并上传已有有效证书；总时限 30 分钟
23 3 * * * root flock -n /run/certsync-issuer.lock timeout 1800 /usr/local/sbin/certsync-issuer-job >>/var/log/certsync.log 2>&1

# 业务机：每 6 小时；加载环境后批量拉取，整批成功再统一 reload；总时限 30 分钟
41 */6 * * * root flock -n /run/certsync-pull.lock timeout 1800 /bin/bash -ec 'set -a; . /etc/certsync/pull.env; set +a; /usr/local/bin/certsync pull; nginx -t; systemctl reload nginx' >>/var/log/certsync.log 2>&1
```

业务机每次整批 pull 成功都检查和 reload，包括内容未变时。这使上一轮 reload 失败能够下轮重试，无需维护服务部署状态或特殊退出码。不要因内容相同直接跳过整个外层任务。不需要自动 reload 的环境可去掉服务命令。

Go 中 OSS 单次请求超时 30 秒，最多 3 次尝试，退避 1 秒、2 秒；每组上传或下载的网络阶段上限 120 秒；整批总耗时随组数增长，由外层 30 分钟任务时限约束。SDK 内部重试必须计入上限，不能与外层无限叠加。配置、认证、解密和证书校验错误不重试。

外层总超时覆盖 ACME、文件操作、钉钉通知和服务命令。超时不能保证完成两文件替换，恢复边界见第 7 节。锁竞争、超时和分发错误均保留非零状态。钉钉仅发送第 8.1 节的事件，其他故障告警和外部到期监控由现有体系接入。

## 11. 失败行为

| 场景 | 处理 |
|---|---|
| CA / DNS 失败 | 尝试上传旧的有效产物，整次任务报告失败，下轮再试 |
| 某组申请成功、上传失败 | 保存导出产物，继续其他组；整批非零退出，手动 push 或次日重传，不重新申请 |
| OSS 对象缺失 | pull 失败，保留本地；手动 push 或每日任务恢复 |
| 某组下载、解密、校验失败 | 保留该组旧文件，继续其余组；整批非零退出，不执行统一 reload |
| 本地缺私钥 | 重新安装完整配对文件，不按叶子指纹跳过 |
| 两次 rename 之间失败 | 不 reload；下轮重试或人工恢复，无自动回滚 |
| nginx 检查 / reload 失败 | 外层失败，不回滚文件；修复配置后重跑完整任务 |
| 签发机丢失 | 从现有备份恢复 acme.sh 目录和环境配置；无备份则重新初始化申请 |
| 钉钉消息发送失败 | 记录脱敏错误，不影响证书分发退出状态和外层 reload，无持久通知队列 |

## 12. 改造与验收

### 12.1 实现范围

- 保留 Go 入口、push、pull 和 version。
- 已删除内置 ACME、签发命令、原多渠道告警和 TOML 依赖，清理 lego 等依赖；仅增加第 8.1 节的两类钉钉通知。
- config 按角色读取环境；oss.go 按显式对象键传输；cli.go 上传遍历总目录，下载按组列表逐个安装；crypto.go 的 JSON 包和加密格式保持不变。
- cert.go 共用证书校验；install.go 负责内容比较、权限检查、临时写入和替换。
- 重写 env 示例、cron 模板、部署准备清单和相关测试。
- Go 文件直接放在仓库根目录，统一为 main 包；按职责分文件，不保留 internal 层。测试辅助证书生成器放在 testcert_test.go，仅参与测试编译。

代码和 deploy/ 模板已按此范围改造。实际 CA 签发、真实 OSS 最小权限及 nginx 生效验证须按部署清单人工验收。

### 12.2 必须验证

- 加密往返、错误密钥、篡改、截断、格式错误、超限包。
- 过期证书、错误域名、不配对私钥、缺失中间证书、重复叶子伪链。
- 缺失私钥能够修复；两个文件相同时不重写；私钥权限始终满足要求。
- 请求按上限退出；替换前失败保留旧文件；第二次 rename 失败明确报错。
- 干净 cron 环境中变量能传给子进程，日志和命令参数不暴露密钥。
- 模拟 OSS 跑通多组 push → 批量 pull，验证每个对象是独立 JSON 加密包；真实最小权限账号验证上传下载。
- 普通域名与通配域名组混用，字面星号在 OSS 对象键和本地目录中原样保留；同一根域名的普通组和通配组彼此独立，选择通配组不展开其他组。通配组必须有精确通配符 SAN，不误接受根域名或具体子域名证书，也不强制额外包含根域名 SAN。
- 空目录、旧平铺目录、嵌套层级、非法组名、错误证书、缺私钥和软链接不能误发布；一组网络失败后后面的有效组仍上传，最终报告非零。
- 批量下载校验选择列表、组目录隔离、同内容不重写、缺私钥修复；某组网络、解密、域名或安装失败后其余有效组继续，失败组旧文件不被下载／校验错误覆盖，最后非零退出。
- 本地模拟机器人验证仅替换成功通知、未变静默、部分失败不漏报成功组；临期阈值小于/等于 15 天、过期仍告警但不上传、上传失败及重复 push 仍告警；签名、非零/缺失 errcode、无效响应、重试/取消和日志脱敏。
- acme.sh 测试环境验证 DNS-01；正式证书在非核心机验证完整分发及 reload。
- 演练上传失败后独立重传、错误密钥、OSS 缺失、reload 失败后重试；不反复强制申请正式证书。

从单组上传升级时：签发机将 OSS_OBJECT_KEY 改为 OSS_PREFIX，总目录下按域名归组；不再配置上传端 CERTSYNC_DOMAINS。下载端移除 OSS_OBJECT_KEY、CERTSYNC_DOMAINS，改用 OSS_PREFIX、CERTSYNC_GROUPS，CERTSYNC_OUTPUT_DIR 改为输出总目录。程序拒绝旧单组变量，已导出的值需 unset 或重开 shell。已有 JSON 加密包格式保持兼容。

现有 Go 测试通过不代表真实环境已验收。上线时关闭旧 certsync renew/pull 任务，确认仅有一套签发和部署调度。

## 13. 参考资料

- [acme.sh 官方说明：申请、导出与续期](https://github.com/acmesh-official/acme.sh)
- [acme.sh 阿里云 DNS：Ali_Key / Ali_Secret](https://github.com/acmesh-official/acme.sh/wiki/dnsapi#11-use-aliyun-domain-api-to-automatically-issue-cert)
- [acme.sh hook 与 reloadcmd](https://github.com/acmesh-official/acme.sh/wiki/using-pre-hook-post-hook-renew-hook-reloadcmd)
- [阿里云 OSS Go SDK V2](https://github.com/aliyun/alibabacloud-oss-go-sdk-v2)
- [Go crypto/cipher：AEAD](https://pkg.go.dev/crypto/cipher#AEAD)
- [Go crypto/x509：验证链和有效期](https://pkg.go.dev/crypto/x509#Certificate.Verify)
- [钉钉自定义机器人安全设置](https://open.dingtalk.com/document/robots/customize-robot-security-settings)
- [钉钉自定义机器人发送群消息](https://open.dingtalk.com/document/orgapp/custom-robots-send-group-messages)

外部工具以部署时固定版本的官方文档和验收结果为准。本文不绑定“最新版本”或固定证书有效天数。
