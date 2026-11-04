# certsync

certsync 是 Go 单二进制证书分发工具，负责加密上传 OSS、下载校验和替换文件，配置来自 TOML 文件。acme.sh 独立管理证书申请、续期和导出，保留它自己的配置与定时任务。

```text
acme.sh（独立运行）→ 导出 fullchain.pem / privkey.pem 到各域名子目录
                                                   ↓ 读取文件
上传端：独立定时执行 certsync push → OSS 每组一个加密证书包
                                                   ↓
业务机：certsync pull 批量下载 → 各组解密、校验、替换 → 统一检查和 reload
```

certsync 的安装和任务不会调用 acme.sh，也不接管它的 cron、账户或 DNS 凭证。两者通过导出目录衔接，上传失败直接重跑 push。

| 命令 | 功能 |
|---|---|
| `certsync push` | 遍历总目录，逐组验证并将 JSON 包整体 AES-256-GCM 加密上传 |
| `certsync pull` | 按组列表批量下载到各自子目录，解密校验后替换文件；相同内容不重写 |
| `certsync version` | 输出构建版本 |

## 安装和部署

上传端准备由 acme.sh 导出的证书。上传端和业务机都需要系统 CA 根证书、cron、`flock` 和 GNU `timeout`，并能访问私有 OSS Bucket。业务机还要确认 Nginx 的检查和重载命令。acme.sh 保留自己的续期任务和 DNS 凭证。

### 构建和安装

在仓库根目录按服务器架构选择构建目标。以下以 x86_64 为例。

```sh
make build-linux-amd64
```

把生成的 `certsync-linux-amd64` 和 `deploy/` 模板目录复制到服务器的同一个目录。在服务器上进入该目录，以 root 执行。

```sh
install -D -m 755 certsync-linux-amd64 /usr/local/bin/certsync
/usr/local/bin/certsync version

install -d -m 700 /etc/certsync
install -m 600 deploy/config.toml.example /etc/certsync/config.toml
```

ARM64 服务器使用 `make build-linux-arm64`，安装时把源文件名换成 `certsync-linux-arm64`。安装后按 [配置说明](#配置) 填写本机使用的区块。

### 首次同步

确认 acme.sh 已按下文的[目录约定](#证书目录与上传逻辑)导出证书，先在上传端执行 push。在业务机的 Nginx 站点填好[证书路径](#配置)，再执行 pull。下载、检查和重载在同一把锁内依次执行。

```bash
# 上传端
flock -n /run/certsync-issuer.lock timeout 1800 /usr/local/bin/certsync push

# 业务机
flock -n /run/certsync-pull.lock timeout 1800 /bin/bash -ec \
  '/usr/local/bin/certsync pull; nginx -t; systemctl reload nginx'
```

在非核心机上确认 OSS 对象、下载到本地的证书及私钥权限（`0600`），并从外部检查 Nginx 实际提供的证书。模拟一组下载或校验失败时，确认该组保留原证书，整批返回失败且跳过重载。修复后重跑任务，Nginx 会在整批成功后再次检查和重载。完整验收清单见 [设计文档](docs/DESIGN.md#122-必须验证)。

### 启用定时任务

手动验收后，按角色从 `deploy/` 安装对应的 cron 模板，替换旧的 certsync 分发任务。

```sh
# 上传端
install -m 644 deploy/cron.issuer.example /etc/cron.d/certsync
# 业务机改用下一行
# install -m 644 deploy/cron.pull.example /etc/cron.d/certsync
```

上传模板默认每日 03:23 执行，下载模板每 6 小时执行一次。双角色服务器可以把两条任务放入同一 cron 文件，也可以使用两个不同的文件名。任务日志写入 `/var/log/certsync.log`，可选用 [日志轮转模板](deploy/logrotate.example)。

### 从旧配置切换

1. 把旧 `issuer.env` 的值填入 `[push]`，旧 `pull.env` 的值填入 `[pull]`。`CERTSYNC_KEY`、`CERTSYNC_SOURCE_DIR` 和 `CERTSYNC_OUTPUT_DIR` 分别对应 `key`、`source_dir` 和 `output_dir`。`CERTSYNC_GROUPS` 改为字符串数组 `groups`，OSS 和钉钉字段使用模板中的小写字段名。
2. 安装新版二进制并手动验收，再替换旧 certsync cron。确认旧 env 和包装脚本已无任务引用后，可以移除它们。若以前关闭过 acme.sh 续期任务，按原来的方式恢复并验证。
3. 从旧单组部署升级时，将证书放入上传总目录下对应的域名子目录，下载端填写 `oss_prefix`、`groups` 和 `output_dir`。已有批量 `bundle.enc` 可以继续使用。若 OSS 仍是旧的三个文件格式，先将证书上传为 `bundle.enc`，在非核心机验收后再切换生产任务。

## 证书目录与上传逻辑

`push` 的来源目录是**总目录**，每个直接子目录是一组证书。目录名支持小写普通域名（`example.com`）和以 `*.` 开头的通配域名（`*.example.com`），两种命名可以混用：

```text
/var/lib/certsync/certs/
├── *.example.com/
│   ├── fullchain.pem
│   └── privkey.pem
└── other.com/
    ├── fullchain.pem
    └── privkey.pem
```

在 `[push]` 中设置 `source_dir = "/var/lib/certsync/certs"` 和 `oss_prefix = "certsync"`，执行一次 `certsync push`，分别上传：

```text
oss://my-cert-bucket/certsync/*.example.com/bundle.enc
oss://my-cert-bucket/certsync/other.com/bundle.enc
```

每组的两个 PEM 文件先合并为 JSON，再整体加密成一个 `bundle.enc`；不使用 tar，也不把所有组混成一个包。`pull` 按配置列表下载每组对象，分别完整解密、解析 JSON、校验并还原两个 PEM 文件。

只遍历一层子目录，普通文件忽略；非法目录名、目录或 PEM 文件软链接、缺失文件、证书不覆盖目录名、校验或上传错误都按该组失败处理。其余组继续，最后汇总成功／失败数量，有任一失败则非零退出。空目录或旧的“总目录直接放两个 PEM”布局会报错。所有组按目录名字典序处理，重复执行会重传每个有效组；本地删组不会删除 OSS 对象，各组不构成整体事务。

组名按字面值使用，`*` 不会展开或匹配其他组；`example.com` 和 `*.example.com` 是两个独立组，不会自动合并或相互替代。星号只允许作为最左侧完整的 `*.` 前缀，`api.*.example.com`、`foo*.example.com`、`**.example.com` 均不合法。域名使用小写 ASCII，国际化域名使用 Punycode。

普通域名组通过 `VerifyHostname` 校验证书覆盖范围；通配域名组要求证书 SAN 中明确包含对应的 `*.example.com`，仅包含根域名或某个具体子域名的证书不能用于该通配组。通配组的证书可以同时包含 `example.com`，也可以只包含 `*.example.com`；组名不代表额外包含根域名。

先由独立管理的 acme.sh 为每组配置固定导出路径。下面仅展示已有证书的导出方式：把主域名为 `example.com` 的证书导出为 `*.example.com` 组（该证书须包含 `*.example.com` SAN），路径按实际安装位置调整：

```bash
# 在 acme.sh 所属用户下执行；示例使用 root 的默认安装路径。
install -d -m 700 '/var/lib/certsync/certs/*.example.com'
/root/.acme.sh/acme.sh --install-cert \
  -d example.com --ecc \
  --fullchain-file '/var/lib/certsync/certs/*.example.com/fullchain.pem' \
  --key-file '/var/lib/certsync/certs/*.example.com/privkey.pem'
```

`--install-cert -d` 使用 acme.sh 已保存的主域名，不必与 certsync 组名相同；若当初以 `*.example.com` 为主域名申请，则填写 `-d '*.example.com'`。包含 `*` 的 Shell 参数和路径须加引号。其他组导出到自己的子目录。acme.sh 按它自己的任务续期并更新导出文件；certsync 按独立上传计划读取整个总目录，两项任务没有固定的先后依赖，续期后的文件在下一次 push 时上传。

已有普通域名组可以沿用原来的组名和 OSS 对象键。如果要把已有 `example.com` 组改名为 `*.example.com`，按上例更新 acme.sh 导出路径并 push，再同步业务机的 `groups` 和 Nginx 证书路径，无需重签。签发机自身也使用该证书时，同步其服务路径，并在导出命令中保留所需的 `--reloadcmd`。仅修改组列表不会重命名本地目录或 OSS 对象，旧对象不会自动删除。

## 批量下载与覆盖

业务机使用一份配置选择需要的组，不列举 OSS 全部对象，也不下载未选择组的私钥：

```toml
[pull]
groups = ["*.example.com", "other.com"]
oss_prefix = "certsync"
output_dir = "/etc/nginx/certs"
```

加上加密密钥、OSS Bucket、地域和下载凭证后，执行一次 `certsync pull`：

```text
OSS 对象                                      本地目录
certsync/*.example.com/bundle.enc     →       /etc/nginx/certs/*.example.com/
certsync/other.com/bundle.enc          →       /etc/nginx/certs/other.com/
```

每个组目录中写入 `fullchain.pem` 和 `privkey.pem`，有旧文件时替换，内容相同则不重写。组名与上传端的目录名完全一致，**不是 SAN 列表，也不是组名匹配模式**。例如 `groups = ["*.example.com"]` 只下载名为 `*.example.com` 的组，不会下载 `example.com` 或 `api.example.com` 组；只需要一组时，组列表填写一个名称即可。

按列表顺序处理。某组下载、解密、证书校验或安装失败会记录错误并继续其他组；下载、解密和校验失败时保留该组原文件，最终汇总并非零退出。整批不是事务，已成功的组不会回滚；两文件替换中断的边界见下文。没有列入本次配置的本地目录不会删除。

外层任务仅在整批成功后执行一次 `nginx -t` 和 reload；失败后重跑整批即可。输出总目录和组子目录不支持软链接。

## 配置

每台机器使用一份 [配置模板](deploy/config.toml.example)。上传端填写 `[push]`，业务机填写 `[pull]`，同机运行两种任务时可以同时填写。每条命令只校验自己的区块。配置文件由运行用户持有，权限设为 `0600`。ACME 账户、CA、域名和 DNS 凭证由 acme.sh 独立管理。

默认读取 `/etc/certsync/config.toml`，也可以用 `certsync pull --config /opt/myapp/certsync.toml` 指定路径。`version` 无需配置。

| 字段 | 必填范围 | 说明 |
|---|---|---|
| `key` | 两端 | 用 `openssl rand -base64 32` 生成一次，将同一个完整字符串填入两端 |
| `source_dir` | `[push]` | 证书来源总目录的绝对路径，每组从独立子目录读取 PEM 文件 |
| `output_dir` | `[pull]` | 证书输出总目录的绝对路径，例如 `/etc/nginx/certs` |
| `groups` | `[pull]` | 证书组的字符串数组，名称与上传子目录完全一致，例如 `["*.example.com", "other.com"]` |
| `oss_access_key_id` / `oss_access_key_secret` | 两端 | 当前区块使用的 OSS 凭证 |
| `oss_region` | 两端 | Bucket 所在地域，例如 `cn-hangzhou` |
| `oss_endpoint` | 可选 | OSS HTTPS 地址，省略时由 SDK 根据地域解析 |
| `oss_bucket` | 两端 | Bucket 名称，例如 `my-cert-bucket` |
| `oss_prefix` | 两端 | 对象前缀，例如 `certsync`。使用相对路径，避免空路径段和 `.` / `..` |
| `dingtalk_webhook` / `dingtalk_secret` | 可选 | 钉钉机器人 Webhook 和加签密钥 |

两端填写相同的 `key`、Bucket 和 `oss_prefix`，分别使用上传和下载凭证。上传账号仅需上传前缀下的 `oss:PutObject`，下载账号仅需所需对象的 `oss:GetObject`。对象键为 `<oss_prefix>/<组名>/bundle.enc`。OSS RAM 策略中的 `*` 是匹配符，含 `*` 的组名写入策略时须核对实际授权范围。

Nginx 站点引用对应输出组中的两个文件。以下示例使用 `*.example.com` 组：

```nginx
ssl_certificate     "/etc/nginx/certs/*.example.com/fullchain.pem";
ssl_certificate_key "/etc/nginx/certs/*.example.com/privkey.pem";
```

### 钉钉通知

在需要通知的 `[push]` 或 `[pull]` 区块填写机器人的配置。

```toml
dingtalk_webhook = "https://oapi.dingtalk.com/robot/send?access_token=填写机器人Token"
dingtalk_secret = "填写加签密钥SEC..."
```

机器人启用加签时必须填写对应 Secret；采用关键词或 IP 验证时 Secret 可留空。消息始终包含 `certsync`，如启用关键词验证，将关键词设置为 `certsync`。IP 白名单应允许对应机器的公网出口 IP。Webhook 和 Secret 同样保存在权限为 `0600` 的 TOML 文件中。

| 场景 | 通知行为 |
|---|---|
| `pull` 首次安装、内容变化或修复缺失文件，两个文件均安装成功 | 发送替换成功通知；同批多个成功组合并，失败组不报成功 |
| `pull` 内容相同、仅校正私钥权限、下载/校验/安装失败 | 不发送替换成功通知 |
| `push` 叶子证书距到期严格少于 `15 × 24` 小时 | 每次运行告警，不依赖本轮是否续期、内容是否变化或上传是否成功 |
| `push` 证书已经过期 | 发送过期告警；证书校验仍失败，不上传过期证书 |

消息包含机器名、证书组、事件、到期时间和剩余时长，时间显示为 UTC+8。下载通知在文件安装后、外层服务检查和 reload 前发送，明确标注尚未确认 reload，不能据此判断 Nginx 已加载新证书。

每轮结束发送本轮收集的事件，部分组失败时已成功组仍通知。大批事件分条发送，每条最多 12000 字节。HTTP 200 且响应 `errcode=0` 才记录发送成功；网络错误、HTTP 429/5xx 最多尝试三次，单条通知总时限 15 秒，其余错误记录失败，不输出 Webhook、Secret、私钥或原始错误响应。

通知失败只记日志，不回滚文件、不改变上传/下载退出状态，也不阻断后续 reload。当前不维护持久通知队列；失败的替换成功通知不会在下次“内容未变化”时补发，临期告警则在下次 push 再次尝试。全程未配置 Webhook 时兼容原有部署。

## 运行和恢复

上传失败后可重跑 push，已有有效的导出文件可以继续使用。下载或校验失败时，重新运行 pull 修复后再重载。若文件替换中途退出，重跑完整下载任务以恢复一对可用文件。Nginx 检查或重载失败时，修复服务配置后重跑任务。

备份 certsync 的 TOML 配置和必要的业务文件，acme.sh 的账户及工作目录按其独立运维方案备份。其他失败和服务端证书到期告警接入现有监控。格式和失败边界见 [设计文档](docs/DESIGN.md)。

## 验证

```sh
go test -race ./...
go vet ./...
```

测试使用临时目录、本地模拟 OSS 和测试 CA，不申请真实证书、不操作真实 Bucket。上线前仍需在实际环境验收 acme.sh、OSS 权限和 nginx。

## 代码结构

Go 源码直接放在根目录，使用一个 main 包，构建方式为 `go build .`：

| 文件 | 职责 |
|---|---|
| main.go / cli.go | 入口和命令编排 |
| config.go | TOML 配置加载和校验 |
| crypto.go | 证书包加解密 |
| cert.go | 证书和私钥校验 |
| oss.go | OSS 上传下载 |
| install.go | 文件比较和替换 |
| notify.go | 钉钉通知、加签与签发端有效期告警 |
| *_test.go | 自动测试及仅测试使用的证书生成器 |
| deploy/ | 配置、cron 和日志轮转模板 |
| docs/ | 设计文档 |
