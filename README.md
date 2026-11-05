# certsync

certsync 是 Go 单二进制证书分发工具，负责加密上传 OSS、下载校验、替换文件，以及可选的 Nginx 检查和重载。配置来自 TOML 文件，程序内置互斥锁、任务超时和钉钉通知。acme.sh 独立管理证书申请、续期和导出，保留它自己的配置与定时任务。

```text
acme.sh（独立运行）→ 导出 fullchain.pem / privkey.pem 到各域名子目录
                                                   ↓ 读取文件
上传端：独立定时执行 certsync push → OSS 每组一个加密证书包
                                                   ↓
业务机：certsync pull --reload-nginx → 下载、校验、替换 → 检查和 reload → 汇总通知
```

certsync 的安装和任务不会调用 acme.sh，也不接管它的 cron、账户或 DNS 凭证。两者通过导出目录衔接，上传失败直接重跑 push。

| 命令 | 功能 |
|---|---|
| `certsync push` | 遍历总目录，逐组验证并将 JSON 包整体 AES-256-GCM 加密上传 |
| `certsync pull` | 按组列表批量下载到各自子目录，解密校验后替换文件；相同内容不重写 |
| `certsync pull --reload-nginx` | 所有组成功后，由 Go 执行 `nginx -t` 和 `systemctl reload nginx`，最后汇总通知 |
| `certsync version` | 输出构建版本 |

## 安装和部署

上传端（签发机）准备由 acme.sh 导出的证书，业务机（获取机）下载自己需要的组。两端都需要系统 CA 根证书和 cron，并能访问私有 OSS Bucket。锁和 30 分钟任务超时内置在 Go 中。业务机启用 `--reload-nginx` 时需要 PATH 中有 `nginx` 和 `systemctl`，程序执行固定的检查、重载命令；其他服务使用普通 `pull` 并自行管理服务加载。acme.sh 保留自己的续期任务和 DNS 凭证。

`deploy/` 中都是部署模板，复制到对应系统路径后才会生效：

| 模板 | 安装位置 | 使用角色 |
|---|---|---|
| `config.toml.example` | `/etc/certsync/config.toml` | 两端分别填写自己的配置 |
| `cron.issuer.example` | `/etc/cron.d/certsync` | 上传端 |
| `cron.pull.example` | `/etc/cron.d/certsync` | 业务机 |
| `logrotate.example` | `/etc/logrotate.d/certsync` | 两端，可选 |

### 构建和安装

先在目标服务器执行 `uname -m` 确认架构：`x86_64` 对应 amd64，`aarch64` / `arm64` 对应 arm64。再在仓库根目录按服务器架构选择构建目标。以下以 x86_64 为例。

```sh
make build-linux-amd64
```

把生成的 `certsync-linux-amd64` 和 `deploy/` 模板目录复制到服务器的同一个目录。以下安装命令均以 root 执行，并假定保留了 `deploy/` 目录；若模板直接放在当前目录，安装时去掉源文件路径中的 `deploy/` 前缀。上传端和业务机分别安装一次。

```sh
install -D -m 755 certsync-linux-amd64 /usr/local/bin/certsync
/usr/local/bin/certsync version

install -d -m 700 /etc/certsync
install -m 600 deploy/config.toml.example /etc/certsync/config.toml
```

ARM64 服务器使用 `make build-linux-arm64`，安装时把源文件名换成 `certsync-linux-arm64`。如果已经准备好填写过的 `config.toml`，上面的配置安装命令改用它作为源文件；模板中的空值需要填写后才能运行。

默认读取 `/etc/certsync/config.toml`。上传端只需 `[push]`，可以删除整个 `[pull]` 区块；业务机只需 `[pull]`，可以删除整个 `[push]` 区块。仅执行本机角色对应的命令，不会因为缺少另一个区块而报错。双角色机器可以同时填写两个区块。字段见 [配置说明](#配置)。

两端的 `key` 必须是同一个完整字符串，OSS 地域、Bucket 和 `oss_prefix` 对应同一套对象；上传、下载可以使用不同权限的 OSS 凭证。`source_dir`、`output_dir` 是各自机器上的总目录绝对路径，可以自行选择，组名必须与上传子目录名完全一致。

安装后检查配置文件权限：

```sh
stat -c '%U:%G %a %n' /etc/certsync/config.toml
```

预期为 `root:root 600 /etc/certsync/config.toml`。共享排错输出时只提供目录、组名和 OSS 位置等必要字段，隐藏 `key`、OSS Secret 和机器人凭证。

### 首次同步

先在上传端确认 acme.sh 已按下文的[目录约定](#证书目录与上传逻辑)导出证书。以下示例使用 `source_dir = "/var/lib/certsync/certs"`：

```sh
find /var/lib/certsync/certs -maxdepth 2 -printf '%y %p\n' | sort
```

每组目录中应有普通文件 `fullchain.pem` 和 `privkey.pem`；输出中的 `d` 是目录，`f` 是普通文件，`l` 是软链接。确认续期后的证书会自动导出到这个总目录，再手动上传：

```bash
/usr/local/bin/certsync push
```

确认汇总中失败组数为 0，并核对 OSS 中的 `<oss_prefix>/<组名>/bundle.enc`。然后在业务机先单独验证下载和文件安装。以下示例使用 `output_dir = "/etc/nginx/certs"`、`groups = ["*.example.com"]`：

```bash
/usr/local/bin/certsync pull

stat -c '%U:%G %a %n' \
  '/etc/nginx/certs/*.example.com/fullchain.pem' \
  '/etc/nginx/certs/*.example.com/privkey.pem'
```

首次安装成功会输出“证书和私钥已替换”，后续内容相同则输出“文件内容未变化”。新安装的证书权限为 `0644`，私钥为 `0600`，运行用户为 root 时归属为 `root:root`。路径中的字面星号须保留引号。

单独执行 `certsync pull` 只下载、校验和安装文件。接下来让 Nginx 站点引用对应的[证书路径](#配置)，再运行完整任务：

```bash
/usr/local/bin/certsync pull --reload-nginx
```

程序使用 `/run/certsync-issuer.lock` 和 `/run/certsync-pull.lock` 分别保护上传、下载；下载锁覆盖文件替换、Nginx 检查和 reload。任务时限为 30 分钟，告警发送另有最多 15 秒时限。只有所有组成功，才会执行 `nginx -t`；检查通过后才 reload。内容相同仍算下载成功，启用该选项时仍检查和 reload。通知包含整轮结果，详见 [通知说明](#钉钉通知)。

在非核心机上从外部检查 Nginx 实际提供的证书。模拟一组下载或校验失败时，确认该组保留原证书，其余组继续处理，最终任务返回失败并跳过重载；已成功替换的组不回滚。修复后重跑完整任务。完整验收清单见 [设计文档](docs/DESIGN.md#122-必须验证)。

### 启用定时任务

手动验收后，先检查服务器时区和已有的 certsync 定时任务：

```sh
date '+%F %T %Z %z'
crontab -l 2>/dev/null | grep -n 'certsync'
grep -R -n 'certsync' /etc/crontab /etc/cron.d 2>/dev/null
```

后两条没有输出，表示这些位置未找到相关任务。已有旧分发任务时替换它，避免重复执行，保留 acme.sh 自有的续期任务。上传端安装：

```sh
install -m 644 deploy/cron.issuer.example /etc/cron.d/certsync
```

业务机安装：

```sh
install -m 644 deploy/cron.pull.example /etc/cron.d/certsync
```

两台机器分别检查安装结果：

```sh
stat -c '%U:%G %a %n' /etc/cron.d/certsync
cat /etc/cron.d/certsync
systemctl is-active cron
```

预期文件归属和权限为 `root:root 644`，cron 服务状态为 `active`；使用 `crond` 服务名的系统改查该服务。正在运行的 cron 会自动读取文件。`/etc/cron.d/` 格式包含 `root` 用户字段；改放到 `crontab -e` 时要去掉该字段。

上传模板默认每日 **03:23** 执行，下载模板默认每日 **04:23** 执行，均以各服务器 cron 使用的时区为准。两端时区相同时，下载比上传晚一小时；若不同时区，按实际时差调整。每天一次下载失败后，下次自动重试在次日，也可以手动重跑完整任务。

两个角色模板的目标路径相同。同机承担双角色时，把两条任务合入同一 cron 文件，或分别使用不同文件名。仅调整模板时，重新上传并安装对应模板即可，程序不需要重新编译。

从外层锁和重载命令的旧版本升级时，必须同时更新二进制和两端 cron 模板。新版 cron 直接调用程序，下载使用 `pull --reload-nginx`。移除旧的 `flock`、`timeout` 和外层 Nginx 命令；旧 `flock` 包住新版程序会与内置锁冲突。手动执行也使用上面的直接调用方式，TOML 字段和 OSS 包格式不变。

定时任务通过 `>>/var/log/certsync.log 2>&1` 追加标准输出和错误输出；前面的手动命令只输出到终端。首次定时任务执行时会创建日志，之后可查看：

```sh
tail -n 50 /var/log/certsync.log
```

### 日志轮转（可选）

上传端和业务机分别安装 [日志轮转模板](deploy/logrotate.example)：

```sh
install -m 644 deploy/logrotate.example /etc/logrotate.d/certsync
logrotate -d /etc/logrotate.d/certsync
```

规则为每周轮转，保留 8 份历史日志并压缩；文件缺失或为空时跳过。模板中的 `su root root` 与 root cron 的运行身份一致，也兼容 `/var/log` 为 `root:syslog 0775` 的系统。

`-d` 只做检查，不实际轮转或更新状态文件。常见输出含义如下：

| 输出 | 含义及处理 |
|---|---|
| `logrotate in debug mode does nothing` | 正常提示，说明正在使用检查模式 |
| 多次 `Creating new state` | 加载轮转状态时的调试信息，各机器数量可以不同 |
| `log does not exist -- skipping` | 日志尚未生成，按 `missingok` 正常跳过 |
| `parent directory has insecure permissions` | 父目录允许非 root 组或其他用户写入；用 `stat -c '%U:%G %a %n' /var/log` 检查，并确认已安装包含 `su root root` 的最新模板 |

实际轮转由系统的 `logrotate.timer` 或 cron 日任务触发。使用 systemd timer 的系统可用 `systemctl list-timers --all logrotate.timer` 核对调度；使用 cron 的系统核对 `/etc/cron.daily/logrotate` 和 cron 服务。一次 `-d` 检查通过只表示规则检查没有报错。

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

每个组目录中写入 `fullchain.pem` 和 `privkey.pem`。比较两个文件的完整内容，均相同时不重写，但仍检查并校正私钥权限为 `0600`；任一文件不同或缺失时重新安装两个文件。组名与上传端的目录名完全一致，**不是 SAN 列表，也不是组名匹配模式**。例如 `groups = ["*.example.com"]` 只下载名为 `*.example.com` 的组，不会下载 `example.com` 或 `api.example.com` 组；只需要一组时，组列表填写一个名称即可。

下载的加密包和解密后的内容先保存在内存中。需要替换时，在对应组目录中创建两个 `.certsync-随机字符` 临时文件，例如 `/etc/nginx/certs/*.example.com/.certsync-123456`；证书临时文件权限为 `0644`，私钥为 `0600`。写入、同步和关闭后，分别重命名替换目标文件，正常返回时清理临时文件。

按列表顺序处理。某组下载、解密、证书校验或安装失败会记录错误并继续其他组；下载、解密和校验失败时保留该组原文件，最终汇总并非零退出。整批不是事务，已成功的组不会回滚；两文件替换中断的边界见 [设计文档](docs/DESIGN.md#7-批量-pull-流程和替换边界)。没有列入本次配置的本地目录不会删除。输出总目录和组子目录不支持软链接。

“整批成功”指所有配置的组都成功，包括内容未变的组；“整批失败”包含部分组失败。启用 `--reload-nginx` 时，Go 按下面的规则执行：

| 情况 | 检查与重载行为 |
|---|---|
| 所有组成功，有文件替换 | 执行一次 `nginx -t`，通过后 reload |
| 所有组成功，文件内容都没变 | 仍检查并 reload，以便重试上一轮失败的重载 |
| 任意一组失败，其余组成功 | `pull` 最终返回失败，跳过检查和 reload；成功组的文件不回滚 |
| `nginx -t` 失败 | 跳过 reload，文件不回滚 |
| reload 失败 | 任务返回失败，文件不回滚；修复后重跑完整任务 |

例如 A、B、C 三组中 B 下载失败，A 和 C 仍会处理并安装成功；最终整批返回失败，不执行统一 reload。通知合并 A、C 的替换结果、B 的失败阶段和原因，以及“成功 2 组，失败 1 组”和重载已跳过的服务状态。通知规则见 [钉钉通知](#钉钉通知)。

## 配置

每台机器使用一份 [配置模板](deploy/config.toml.example)。上传端填写 `[push]`，业务机填写 `[pull]`，不用的整个区块可以删除，同机运行两种任务时可以同时填写。每条命令只校验自己的区块。配置文件由运行用户持有，权限设为 `0600`。ACME 账户、CA、域名和 DNS 凭证由 acme.sh 独立管理。

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
| `pull` 内容相同或仅校正私钥权限，且任务成功 | 不发送通知；启用选项时仍检查和重载 |
| 上传来源目录、组名、文件读取、证书校验、加密或 OSS 上传失败 | 发送失败阶段和原因；有组处理结果时包含批次汇总 |
| 某组下载、解密、校验或安装失败 | 发送失败告警；与其他成功替换的组一并汇总，说明重载是否跳过 |
| `nginx -t` 失败或 reload 失败 | 发送对应阶段的失败告警和错误输出，即使证书内容未变也通知 |
| reload 成功 | 已有替换通知中显示 reload 成功；全部内容未变时不单独发成功消息 |
| 获取锁失败、锁冲突、任务超时或取消 | 发送失败阶段和原因；占锁明确说明本轮跳过 |
| `push` 叶子证书距到期严格少于 `15 × 24` 小时 | 每次运行告警，不依赖本轮是否续期、内容是否变化或上传是否成功 |
| `push` 证书已经过期 | 发送过期告警；证书校验仍失败，不上传过期证书 |

消息包含机器名、操作、整轮结果、成功/失败组数、文件替换数量，以及适用时的 Nginx 状态、失败阶段和脱敏原因；证书事件另含到期时间和剩余时长，时间显示为 UTC+8。下载端顺序为“安装文件 → 可选的 `nginx -t` → reload → 汇总通知”。普通 `pull` 会说明未请求重载；带选项时明确区分检查失败、重载失败、因同步失败跳过或重载成功。文件安装失败可能已部分替换时会提示检查或重跑修复，不把失败描述为已自动回滚。

每轮结束发送本轮收集的事件，部分组失败时已成功组仍通知。大批事件分条发送，每条最多 12000 字节。HTTP 200 且响应 `errcode=0` 才记录发送成功；网络错误、HTTP 429/5xx 最多尝试三次。通知发送使用独立上下文，整轮发送最多 15 秒，任务超时或取消不会直接取消告警发送。错误文本隐藏配置中的密钥、OSS/机器人凭证、URL 查询参数和私钥 PEM，并限制长度。

配置读取或校验失败不发送告警。通知通道失败只记日志，不回滚文件、不改变任务退出状态；未配置 Webhook 时只记录本地日志。当前不维护持久通知队列，失败的替换成功通知不会在下次“内容未变化”时补发；临期和重复执行仍失败的操作会在下轮再次生成告警。

## 运行和恢复

上传失败后可重跑 push，已有有效的导出文件可以继续使用。下载或校验失败时，重新运行 pull 修复后再重载。若文件替换中途退出，重跑完整下载任务以恢复一对可用文件。Nginx 检查或重载失败时，修复服务配置后重跑任务。

备份 certsync 的 TOML 配置和必要的业务文件，acme.sh 的账户及工作目录按其独立运维方案备份。其他失败和服务端证书到期告警接入现有监控。格式和失败边界见 [设计文档](docs/DESIGN.md)。

## 验证

```sh
go test -race ./...
go vet ./...
```

默认测试使用临时目录、本地模拟 OSS 和测试 CA，不申请真实证书、不操作真实 Bucket。上线前仍需在实际环境验收 acme.sh、OSS 权限和 nginx。

需要用自己的配置实测 OSS 和钉钉时，显式启用以下用例。配置需要同时包含 `[push]` 和 `[pull]`，使用相同的加密密钥、Bucket 和前缀；来源目录中应有 `[pull].groups` 第一组的证书，该证书须覆盖根域名及对应通配域名，两端均配置可用的钉钉机器人：

```sh
CERTSYNC_LIVE_CONFIG=/path/to/test-config.toml \
CERTSYNC_LIVE_SEND_NOTIFICATIONS=1 \
CERTSYNC_LIVE_REPORT=/tmp/certsync-live-report.json \
go test -race -count=1 -timeout 15m -run '^TestLiveConfiguredDistribution$' -v ./...
```

用例在 `<oss_prefix>/certsync-live-test/<批次>/` 下上传、下载，使用临时本地目录，前后核对原配置和证书文件保持不变。覆盖同一真实证书的 5 个组、3 套独立测试证书，以及缺失对象、错误密钥、密文损坏、安装失败、部分/全部失败、临期/过期、锁冲突和超时等场景。测试 CA 仅在用例内信任，不改变正式程序的证书校验。Nginx 命令使用模拟执行器，真实 OSS 和钉钉接口用于验证数据往返与通知接收；预计发送 14 条带批次标签的测试消息。

默认保留 OSS 测试对象用于复查。只有显式设置 `CERTSYNC_LIVE_CLEANUP=1` 才尝试清理本次测试子前缀中的对象，且需要对应的 `oss:DeleteObject` 权限；报告会列出保留或未清理的对象。没有上述实测环境变量时，该用例直接跳过。

## 代码结构

Go 源码直接放在根目录，使用一个 main 包，构建方式为 `go build .`：

| 文件 | 职责 |
|---|---|
| main.go / cli.go | 入口和命令编排 |
| task.go / task_unix.go | 内置任务锁、超时、Nginx 检查重载及最终通知汇总 |
| config.go | TOML 配置加载和校验 |
| crypto.go | 证书包加解密 |
| cert.go | 证书和私钥校验 |
| oss.go | OSS 上传下载 |
| install.go | 文件比较和替换 |
| notify.go | 钉钉通知、失败告警、错误脱敏及签发端有效期告警 |
| *_test.go | 自动测试及仅测试使用的证书生成器 |
| deploy/ | 配置、cron 和日志轮转模板 |
| docs/ | 设计文档 |
