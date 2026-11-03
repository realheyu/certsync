# certsync

acme.sh 集中申请和续期证书，Go 单二进制负责加密上传 OSS、下载校验和替换文件。配置全部来自环境变量。

```text
签发机：acme.sh → 导出到各域名子目录 → certsync push 批量上传
                                                        ↓
                                                OSS 每组一个加密证书包
                                                        ↓
业务机：certsync pull 批量下载 → 各组解密、校验、替换 → 统一检查和 reload
```

| 命令 | 功能 |
|---|---|
| `certsync push` | 遍历总目录，逐组验证并将 JSON 包整体 AES-256-GCM 加密上传 |
| `certsync pull` | 按组列表批量下载到各自子目录，解密校验后替换文件；相同内容不重写 |
| `certsync version` | 输出构建版本 |

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

设置 `CERTSYNC_SOURCE_DIR=/var/lib/certsync/certs`、`OSS_PREFIX=certsync`，执行一次 `certsync push`，分别上传：

```text
oss://my-cert-bucket/certsync/*.example.com/bundle.enc
oss://my-cert-bucket/certsync/other.com/bundle.enc
```

每组的两个 PEM 文件先合并为 JSON，再整体加密成一个 `bundle.enc`；不使用 tar，也不把所有组混成一个包。`pull` 按配置列表下载每组对象，分别完整解密、解析 JSON、校验并还原两个 PEM 文件。

只遍历一层子目录，普通文件忽略；非法目录名、目录或 PEM 文件软链接、缺失文件、证书不覆盖目录名、校验或上传错误都按该组失败处理。其余组继续，最后汇总成功／失败数量，有任一失败则非零退出。空目录或旧的“总目录直接放两个 PEM”布局会报错。所有组按目录名字典序处理，重复执行会重传每个有效组；本地删组不会删除 OSS 对象，各组不构成整体事务。

组名按字面值使用，`*` 不会展开或匹配其他组；`example.com` 和 `*.example.com` 是两个独立组，不会自动合并或相互替代。星号只允许作为最左侧完整的 `*.` 前缀，`api.*.example.com`、`foo*.example.com`、`**.example.com` 均不合法。域名使用小写 ASCII，国际化域名使用 Punycode。

普通域名组通过 `VerifyHostname` 校验证书覆盖范围；通配域名组要求证书 SAN 中明确包含对应的 `*.example.com`，仅包含根域名或某个具体子域名的证书不能用于该通配组。通配组的证书可以同时包含 `example.com`，也可以只包含 `*.example.com`；组名不代表额外包含根域名。

acme.sh 需要为每组分别记录导出路径。下面把 acme.sh 中主域名为 `example.com` 的已有证书导出为 `*.example.com` 组（该证书须包含 `*.example.com` SAN）：

```bash
# 在已申请该组证书、已加载签发机环境后执行：
install -d -m 700 "$CERTSYNC_SOURCE_DIR/*.example.com"
"$ACME_HOME/acme.sh" --install-cert --home "$ACME_HOME" \
  -d example.com --ecc \
  --fullchain-file "$CERTSYNC_SOURCE_DIR/*.example.com/fullchain.pem" \
  --key-file "$CERTSYNC_SOURCE_DIR/*.example.com/privkey.pem"
```

`--install-cert -d` 使用 acme.sh 已保存的主域名，不必与 certsync 组名相同；若当初以 `*.example.com` 为主域名申请，则填写 `-d '*.example.com'`。包含 `*` 的 Shell 参数和路径须加引号。其他组导出到自己的子目录。续期由一次 acme.sh cron 统一检查，随后一次 push 上传整个总目录。

已有普通域名组无需迁移，旧配置和 OSS 对象键继续兼容。如果要把已有 `example.com` 组改名为 `*.example.com`，按上例更新 acme.sh 导出路径并 push，再同步业务机的 `CERTSYNC_GROUPS` 和 Nginx 证书路径，无需重签。签发机自身也使用该证书时，同步其服务路径，并在导出命令中保留所需的 `--reloadcmd`。仅修改组列表不会重命名本地目录或 OSS 对象，旧对象不会自动删除。

## 批量下载与覆盖

业务机使用一份配置选择需要的组，不列举 OSS 全部对象，也不下载未选择组的私钥：

```sh
CERTSYNC_GROUPS='*.example.com,other.com'
OSS_PREFIX='certsync'
CERTSYNC_OUTPUT_DIR='/etc/nginx/certs'
```

加上加密密钥、OSS Bucket、地域和下载凭证后，执行一次 `certsync pull`：

```text
OSS 对象                                      本地目录
certsync/*.example.com/bundle.enc     →       /etc/nginx/certs/*.example.com/
certsync/other.com/bundle.enc          →       /etc/nginx/certs/other.com/
```

每个组目录中写入 `fullchain.pem` 和 `privkey.pem`，有旧文件时替换，内容相同则不重写。组名与上传端的目录名完全一致，**不是 SAN 列表，也不是组名匹配模式**。例如 `CERTSYNC_GROUPS='*.example.com'` 只下载名为 `*.example.com` 的组，不会下载 `example.com` 或 `api.example.com` 组；只需要一组时，组列表填写一个名称即可。

按列表顺序处理。某组下载、解密、证书校验或安装失败会记录错误并继续其他组；下载、解密和校验失败时保留该组原文件，最终汇总并非零退出。整批不是事务，已成功的组不会回滚；两文件替换中断的边界见下文。没有列入本次配置的本地目录不会删除。

外层任务仅在整批成功后执行一次 `nginx -t` 和 reload；失败后重跑整批即可。输出总目录和组子目录不支持软链接。

## 配置

程序只读取环境变量，不自动加载 `.env` 文件，也不读取 TOML 配置。`version` 不需要配置；`push` 和 `pull` 的配置如下。

### 环境变量说明

| 变量 | 必填范围 | 说明 |
|---|---|---|
| `CERTSYNC_KEY` | push / pull | 加密密钥，必须是 **32 字节随机值的标准 Base64 编码**，两端填写相同字符串 |
| `CERTSYNC_GROUPS` | 仅 pull | 要下载的证书组，例如 `*.example.com,other.com`；与上传子目录名完全一致，支持小写普通域名和以 `*.` 开头的通配域名，国际化域名使用 Punycode；按字面值选择组，不展开匹配；不允许空项、重复项或路径，逗号周围可有空格 |
| `OSS_ACCESS_KEY_ID` | push / pull | 当前机器角色的 OSS AccessKey ID |
| `OSS_ACCESS_KEY_SECRET` | push / pull | 对应的 OSS AccessKey Secret |
| `OSS_REGION` | push / pull | Bucket 所在地域，例如 `cn-hangzhou` |
| `OSS_ENDPOINT` | 可选 | OSS HTTPS 地址，例如 `https://oss-cn-hangzhou.aliyuncs.com`；未设置时由 SDK 根据地域解析 |
| `OSS_BUCKET` | push / pull | Bucket 名称，例如 `my-cert-bucket` |
| `OSS_PREFIX` | push / pull | 两端相同的对象前缀，例如 `certsync`；组对象为 `<前缀>/<组名>/bundle.enc`，不包含 Bucket 或 `oss://`，不得以 `/` 开头或包含 `.` / `..` 路径段 |
| `CERTSYNC_SOURCE_DIR` | 仅 push | 证书总目录的绝对路径，读取每个直接子目录中的两个 PEM 文件 |
| `CERTSYNC_OUTPUT_DIR` | 仅 pull | 输出总目录的绝对路径，例如 `/etc/nginx/certs`；各组安装到 `<总目录>/<组名>/` |
| `DINGTALK_WEBHOOK` | 可选 | 钉钉群自定义机器人完整 HTTPS Webhook；留空不发群消息，签发端仍记录本地临期日志 |
| `DINGTALK_SECRET` | 可选 | 机器人启用“加签”时填写 `SEC...` 密钥；设置此项必须同时设置 Webhook |

以下变量只供签发机上的 acme.sh 和包装脚本使用，Go 工具不读取：

| 变量 | 说明 |
|---|---|
| `ACME_HOME` | acme.sh 安装及状态目录，例如 `/opt/acme.sh`，每日包装脚本必填 |
| `ACME_EMAIL` | 首次注册 ACME 账户使用的邮箱 |
| `ACME_SERVER` | 首次申请使用的 CA，例如 `letsencrypt` |
| `ACME_DOMAINS` | 手动申请每组时临时指定该组域名，例如 `example.com,*.example.com`，具体命令见设计文档；Go 不读取 |
| `Ali_Key` / `Ali_Secret` | 阿里云 DNS 凭证，变量名区分大小写；只配置在签发机 |

`ACME_EMAIL`、`ACME_SERVER` 由首次注册和申请命令使用，后续 acme.sh 使用其保存的证书配置。修改 CA 或域名后，需要重新执行申请和导出步骤，仅修改 env 不会改变已有签发配置。

### 生成加密密钥

执行一次，将输出的完整字符串填写到两端的 `CERTSYNC_KEY`：

```sh
openssl rand -base64 32
```

这里是证书包的加密密钥，与证书私钥、OSS AccessKey 和 DNS 凭证分别配置。不要使用普通自选密码。

### 签发机配置示例

保存为 `/etc/certsync/issuer.env`，将占位值替换成实际值：

```sh
CERTSYNC_KEY='填写生成的完整Base64密钥'
CERTSYNC_SOURCE_DIR='/var/lib/certsync/certs'

ACME_HOME='/opt/acme.sh'
ACME_EMAIL='ops@example.com'
ACME_SERVER='letsencrypt'
Ali_Key='填写DNS账号AK'
Ali_Secret='填写DNS账号SK'

OSS_ACCESS_KEY_ID='填写OSS上传账号AK'
OSS_ACCESS_KEY_SECRET='填写OSS上传账号SK'
OSS_REGION='cn-hangzhou'
OSS_ENDPOINT='https://oss-cn-hangzhou.aliyuncs.com'
OSS_BUCKET='my-cert-bucket'
OSS_PREFIX='certsync'
# 可选：签发端剩余有效期少于 15 天时发钉钉告警。
DINGTALK_WEBHOOK=''
DINGTALK_SECRET=''
```

签发机不设置 `CERTSYNC_GROUPS`，组名从直接子目录获取。每组 `--install-cert` 导出到 `$CERTSYNC_SOURCE_DIR/<组名>/`，如 `"$CERTSYNC_SOURCE_DIR/*.example.com/"`，不使用 acme.sh 内部工作目录。

### 业务机配置示例

保存为 `/etc/certsync/pull.env`：

```sh
CERTSYNC_KEY='与签发机相同的完整Base64密钥'
CERTSYNC_GROUPS='*.example.com,other.com'
CERTSYNC_OUTPUT_DIR='/etc/nginx/certs'

OSS_ACCESS_KEY_ID='填写OSS下载账号AK'
OSS_ACCESS_KEY_SECRET='填写OSS下载账号SK'
OSS_REGION='cn-hangzhou'
OSS_ENDPOINT='https://oss-cn-hangzhou.aliyuncs.com'
OSS_BUCKET='my-cert-bucket'
OSS_PREFIX='certsync'
# 可选：证书和私钥确实替换成功后发钉钉通知。
DINGTALK_WEBHOOK=''
DINGTALK_SECRET=''
```

两端的密钥、Bucket 和 `OSS_PREFIX` 应保持一致。下载对象键由前缀和组名组成，例如 `certsync/*.example.com/bundle.enc`，保留字面值 `*`；`CERTSYNC_GROUPS` 可选择上传组的子集。每组都会检查证书覆盖该组名对应的域名，通配组要求存在对应的通配符 SAN。上传账号仅需上传前缀下的 `oss:PutObject`，下载账号仅需所需对象的 `oss:GetObject`，使用不同账号。业务机不配置 DNS 凭证。OSS RAM 策略中的 `*` 是匹配符，将含 `*` 的对象键写入策略时需核对实际授权范围，不能视为精确对象授权。

nginx 每个站点引用 `${CERTSYNC_OUTPUT_DIR}/<组名>/fullchain.pem` 和 `${CERTSYNC_OUTPUT_DIR}/<组名>/privkey.pem`。签发机一份配置上传全部组，业务机一份配置拉取选定组，一个定时任务统一 reload。

例如 `*.example.com` 组的 Nginx 配置：

```nginx
ssl_certificate     "/etc/nginx/certs/*.example.com/fullchain.pem";
ssl_certificate_key "/etc/nginx/certs/*.example.com/privkey.pem";
```

### 保存和加载配置

可以从仓库模板安装，再填写实际配置。以下安装命令按机器角色二选一：

```sh
install -d -m 700 /etc/certsync
# 签发机：
install -m 600 deploy/issuer.env.example /etc/certsync/issuer.env
# 业务机：
install -m 600 deploy/pull.env.example /etc/certsync/pull.env
```

配置文件由 root 拥有，权限 `0600`；真实密钥和凭证不提交 Git。文件使用 shell 赋值语法，值用单引号包围。手动执行 push 前加载：

```bash
set -a
. /etc/certsync/issuer.env
set +a
flock -n /run/certsync-issuer.lock timeout 1800 /usr/local/bin/certsync push
```

执行 pull 时加载 `/etc/certsync/pull.env`，示例见下方。`set -a` 确保变量导出到子进程；只 source 普通赋值文件，Go 程序可能读不到这些变量。cron 模板和签发包装脚本已包含对应加载方式；也可以由容器直接注入这些环境变量。

### 钉钉通知

在需要通知的机器上配置群自定义机器人，可使用同一群或不同群：

```sh
DINGTALK_WEBHOOK='https://oapi.dingtalk.com/robot/send?access_token=填写机器人Token'
DINGTALK_SECRET='填写加签密钥SEC...'
```

机器人启用加签时必须填写对应 Secret；采用关键词或 IP 验证时 Secret 可留空。消息始终包含 `certsync`，如启用关键词验证，将关键词设置为 `certsync`。IP 白名单应允许对应机器的公网出口 IP。Webhook 和 Secret 同样保存在权限为 `0600` 的 env 文件中。

| 场景 | 通知行为 |
|---|---|
| `pull` 首次安装、内容变化或修复缺失文件，两个文件均安装成功 | 发送替换成功通知；同批多个成功组合并，失败组不报成功 |
| `pull` 内容相同、仅校正私钥权限、下载/校验/安装失败 | 不发送替换成功通知 |
| `push` 叶子证书距到期严格少于 `15 × 24` 小时 | 每次运行告警，不依赖本轮是否续期、内容是否变化或上传是否成功 |
| `push` 证书已经过期 | 发送过期告警；证书校验仍失败，不上传过期证书 |

消息包含机器名、证书组、事件、到期时间和剩余时长，时间显示为 UTC+8。下载通知在文件安装后、外层服务检查和 reload 前发送，明确标注尚未确认 reload，不能据此判断 Nginx 已加载新证书。

每轮结束发送本轮收集的事件，部分组失败时已成功组仍通知。大批事件分条发送，每条最多 12000 字节。HTTP 200 且响应 `errcode=0` 才记录发送成功；网络错误、HTTP 429/5xx 最多尝试三次，单条通知总时限 15 秒，其余错误记录失败，不输出 Webhook、Secret、私钥或原始错误响应。

通知失败只记日志，不回滚文件、不改变上传/下载退出状态，也不阻断后续 reload。当前不维护持久通知队列；失败的替换成功通知不会在下次“内容未变化”时补发，临期告警则在下次 push 再次尝试。全程未配置 Webhook 时兼容原有部署。

## 使用

1. `make build-linux-amd64` 或 `make build-linux-arm64`，安装二进制到 /usr/local/bin/certsync。
2. 根据角色填写 [签发机环境示例](deploy/issuer.env.example) 或 [业务机环境示例](deploy/pull.env.example)，env 文件设为 0600。
3. 用 `openssl rand -base64 32` 生成 CERTSYNC_KEY，两端配置相同字符串。上传、下载使用不同 OSS 凭证。
4. acme.sh 为各组通过 --install-cert 导出到总目录的域名子目录，Go 仅使用这些导出文件。
5. 手动加载环境并 push/pull，验证后启用 [签发任务](deploy/cron.issuer.example) 或 [下载任务](deploy/cron.pull.example)。

```bash
set -a
. /etc/certsync/pull.env
set +a
# 互斥覆盖下载、检查和 reload。每次成功 pull 后都重试服务命令。
flock -n /run/certsync-pull.lock timeout 1800 /bin/bash -ec \
  '/usr/local/bin/certsync pull; nginx -t; systemctl reload nginx'
```

[设计文档](docs/DESIGN.md) 包含全部环境变量、首次申请与导出、格式和失败边界；[部署清单](deploy/PREPARE.md) 包含安装、验收及迁移步骤。

Go 不管理 ACME 账户、密钥轮换、服务探测或备份回滚；提供上述两类可选钉钉通知，其他故障告警由现有监控负责。两个文件逐个替换，不是一个事务；中途失败应重新 pull，成功后再 reload。升级到批量模式时，签发机改用 `OSS_PREFIX` 和来源总目录；业务机移除旧 `OSS_OBJECT_KEY`、`CERTSYNC_DOMAINS`，改用 `OSS_PREFIX`、`CERTSYNC_GROUPS`，输出路径改为总目录。程序检测到旧下载变量会报错提示迁移；已导出的旧变量还需 `unset OSS_OBJECT_KEY CERTSYNC_DOMAINS` 或重新打开 shell。JSON 加密包格式保持不变。TLS 链使用系统可信根验证，目标机器应安装 CA 根证书。

新格式使用一个 bundle.enc，与旧的 fullchain.pem.enc / privkey.pem.enc / meta.json 不兼容。切换前停止旧任务，先在独立对象和非核心机验收。

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
| config.go | 环境变量配置 |
| crypto.go | 证书包加解密 |
| cert.go | 证书和私钥校验 |
| oss.go | OSS 上传下载 |
| install.go | 文件比较和替换 |
| notify.go | 钉钉通知、加签与签发端有效期告警 |
| *_test.go | 自动测试及仅测试使用的证书生成器 |
| deploy/ | 环境示例、任务脚本和部署清单 |
| docs/ | 设计文档 |
