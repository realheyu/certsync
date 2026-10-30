# certsync 设计文档

| | |
|---|---|
| 版本 | v0.4(设计定稿,待评审;v0.2:依赖更新/toml/certbot 命名/路径清单;v0.3:验证体系强化/多通道告警;v0.4:补齐 OnFailure 兜底、webhook 鉴权头) |
| 日期 | 2026-10-30 |
| 状态 | 设计定稿,待评审;通过后进入 Phase 0(§15) |
| 读者 | 运维 / 开发 |

---

## 1. 背景与动机

现状:单机用 acme.sh 签发泛域名证书(`example.com + *.example.com`,阿里云 DNS-01 验证)。
随着需要在多台服务器上使用同一张证书,每台机器各自签发的模式暴露出三个问题:

1. **限额**:Let's Encrypt 对"域名列表完全相同的证书"每 7 天最多签发 5 张、无豁免,所有账号合并计算(官方限额文档原文,附录A①),机器多于 5 台必然撞限。
2. **密钥分发**:泛域名只能 DNS-01 验证,每台机器各自签就要持有阿里云 DNS 写权限密钥——任何一台失陷,整个域名的 DNS 都可被篡改。
3. **无统一视图**:各自续期、各自失败,证书过期事故只能在单台上静默发生。

此外,为兼容不信任 ISRG Root X1 的老设备(约 2024-09-30 DST Root X3 交叉签名过期后,老华为/老安卓等;根与链的时间线以 LE 官方证书链页为准,附录A③),未来可能整体切换 CA(ZeroSSL 或购买的商业 DV 证书)。分散签发会让换 CA 的成本乘以 N。

**结论:集中签发 + OSS 加密中转 + 各服务器自动拉取部署**,整套系统用一个 Go 单二进制 `certsync` 实现,签发端内嵌 lego(ACME 库),彻底替代 acme.sh + 脚本。

### 1.1 为什么不是别的方案(已否决项)

| 备选方案 | 否决原因 |
|---|---|
| 每台机器各自 acme.sh/lego | 重复证书限额 5 张/周;DNS 密钥到处放 |
| Caddy 每台自动 HTTPS | 同上;且集中供给证书后 Caddy 相对 nginx 无剩余优势 |
| certmagic(Go 库) | 面向长驻进程的后台续期模型,不适合定时任务形态 |
| cert-manager | 只能运行在 Kubernetes 内,当前是普通服务器 |
| 云厂商免费证书 | 每年张数有限、有效期短,泛域名不免费 |
| Python 实现 | 分发需每台装运行时;Go 单二进制 scp 即部署 |

---

## 2. 目标与非目标

### 目标

- G1 一台签发机自动维护一张泛域名证书,到期前自动续期(默认提前 30 天)
- G2 私钥端到端加密(AES-256-GCM)后才落 OSS,任何 OSS 侧泄露不直接泄露私钥
- G3 业务服务器自动拉取、校验、原子安装到 nginx 并热加载,失败自动回滚
- G4 全链路无人值守:关键事件(成功/失败/临期)推送 webhook 告警
- G5 CA 可插拔:切换 Let's Encrypt / ZeroSSL(EAB)/ 其他 ACME CA 只改签发端配置,分发链路零改动
- G6 单静态二进制,支持 linux/amd64 与 linux/arm64,统一版本管理
- G7 幂等与自愈:重复执行无副作用;单点故障(签发机宕机、OSS 对象误删)有明确恢复路径

### 非目标

- 不做 Web UI、不做多租户
- v1 只管理**一张证书组**(一组域名);多证书组留作扩展(§16)
- 不管理证书之外的任何配置(nginx 配置仍由现有体系管理)
- 不做 KMS 集成(v1 用预置对称密钥,KMS 见 §16 扩展)

---

## 3. 总体架构

```
                      ┌────────────────────────── 签发机(1 台)──────────────────────────┐
                      │                                                                │
  systemd timer 每日  │  certsync renew                                                │
  ─────────────────►  │   ├─ 读本地证书,剩余 > renew_before_days? → 跳过退出           │
                      │   ├─ lego / ACME CA(LE 或 ZeroSSL,DNS-01)                    │
                      │   │    └─ 阿里云 DNS API 写 TXT 记录(仅此机器持有该密钥)      │
                      │   ├─ 新证书写入本地 state(/var/lib/certsync/certs/…)          │
                      │   └─ AES-256-GCM 加密 → 上传 OSS(上传账号,只写)              │
                      └──────────────────────────────┬─────────────────────────────────┘
                                                     │ HTTPS
                                                     ▼
                                      ┌──────────────────────────┐
                                      │ 阿里云 OSS(私有 Bucket)  │
                                      │ certsync/certs/<domain>/  │
                                      │   ├─ fullchain.pem.enc    │
                                      │   ├─ privkey.pem.enc      │
                                      │   └─ meta.json(明文)     │
                                      └──────────────────────────┘
                                                     │ HTTPS
      ┌──────────────────────────────────────────────┼──────────────────────────────────────────────┐
      ▼                                              ▼                                              ▼
┌───── 业务机 A(nginx)─────┐              ┌───── 业务机 B(nginx)─────┐                    ┌──── 业务机 N ────┐
│ systemd timer 每 6 小时   │              │                          │                    │                  │
│ certsync pull            │              │ certsync pull(同左)      │                    │ certsync pull    │
│  ├─ 读 meta.json         │              └──────────────────────────┘                    └──────────────────┘
│  ├─ 指纹相同? → 跳过     │
│  ├─ 下载+解密(拉取账号,只读)                                          │
│  ├─ 校验:有效期/SAN 覆盖/证书私钥配对/指纹与 meta 一致                │
│  ├─ 原子替换文件(私钥 0600)+ 备份旧文件                             │
│  └─ nginx -t → systemctl reload nginx;任一步失败 → 回滚备份 + 告警   │
└─────────────────────────────┘
```

三类角色,同一二进制、不同子命令:

| 角色 | 机器 | 命令 | 触发 |
|---|---|---|---|
| 签发 | 1 台 | `certsync renew` | systemd timer,每日 |
| 拉取部署 | N 台 | `certsync pull` | systemd timer,每 6 小时 |
| 运维(手动) | 任意 | `keygen` / `issue` / `push` / `status` / `version` | 手动 |

### 命令一览

| 命令 | 作用 | 典型场景 |
|---|---|---|
| `certsync keygen --out <file>` | 生成 32 字节主密钥(base64 写入 0600 文件) | 初始化、密钥轮换 |
| `certsync issue` | 强制向 CA 申请新证书并落盘、加密上传 | 首次部署、测试(`--staging`) |
| `certsync renew` | 检查剩余有效期,到窗口才触发 issue;否则直接退出 | 每日 timer |
| `certsync push` | 不联系 CA,把本地 state 里的证书重新加密上传 | OSS 对象误删修复、换密钥后重加密 |
| `certsync pull [--domain x]` | 拉取、校验、安装、reload | 各业务机 timer |
| `certsync status` | 打印各 target 本地证书的域名、到期时间、剩余天数 | 人工巡检 |
| `certsync version` | 输出版本(编译时注入) | 排查多机版本 |

**`--staging` 隔离规则**:使用独立 ACME 账户与独立 state 子目录(`state/staging/`),OSS 上传目标强制替换为 `<prefix>-staging/`——staging 证书由非受信 CA 签发,绝不允许进入正式分发链路,否则全网客户端立刻报"证书不可信"。

---

## 4. 证书生命周期

```
申请 ──► 本地 state ──► 加密上传 OSS ──► 业务机安装 ──► 有效期流逝
              │              │                  │
              │   到期前 30 天:renew 重新触发    │
              │   (issue → push,对象原地覆盖)   │
              └────────── CA 吊销/换 CA:同 issue 流程,内容变化 → 指纹变化 → 全网自动更新
```

关键性质:

- **OSS 对象键固定、内容原地覆盖**,`meta.json` 中的证书指纹(证书 DER 的 SHA-256)是全网唯一比对依据
- **指纹 = 版本**:业务机本地已装证书的指纹与 meta 一致即跳过,实现幂等
- 吊销、换 CA、换密钥对业务机全部透明——指纹变了就更新,没变就什么都不做

---

## 5. OSS 存储设计

### 5.1 对象布局

```
<prefix>/certs/<primary_domain>/
├── fullchain.pem.enc   # AES-256-GCM 加密的 fullchain(叶子+中间证书,PEM)
├── privkey.pem.enc     # AES-256-GCM 加密的私钥 PEM
└── meta.json           # 明文,含指纹等元数据(不含敏感信息)
```

`<primary_domain>` = 证书组第一个域名(即 CN),如 `example.com`;业务机 pull 配置里的 `domain` 必须与之一致。

### 5.2 meta.json 结构

```json
{
  "domain": "example.com",
  "fingerprint": "3f9c…(sha256 of cert DER, hex)",
  "not_before": "2026-10-29T00:00:00Z",
  "not_after": "2027-01-27T00:00:00Z",
  "sans": ["example.com", "*.example.com"],
  "issuer": "E6",
  "updated_at": 1790000000
}
```

### 5.3 写入顺序(一致性约定)

上传顺序固定为 **fullchain.pem.enc → privkey.pem.enc → meta.json**,meta.json 最后写,作为"提交点":

- pull 端以 meta.fingerprint 为准,下载后校验证书指纹与之一致才安装
- 任何"上传到一半"的中间态(新 meta 未写 / 新对象写一半)都会被指纹校验拒绝,业务机继续用本地旧证书,下一轮重试
- OSS 无事务,此约定保证最终一致且永不装入损坏数据

### 5.4 Bucket 配置要求

- **私有读写**(default),禁止公共读
- 开启**版本控制**(误覆盖/误删可恢复)与**访问日志**
- 可选开启服务端加密 SSE-KMS(纵深防御,非依赖项——客户端加密才是主要防线)
- 仅存放证书密文与二进制分发产物(§11),不做他用

---

## 6. 安全设计

### 6.1 加密方案

- 算法:**AES-256-GCM**,每次加密随机 12 字节 nonce 前置于密文(同一密钥永不重用 nonce,GCM 认证标签保证篡改可检测)
- 主密钥:32 字节,base64 存储,`certsync keygen` 生成
- 分发:**带外渠道**(手工 scp / 现有密钥管理流程)放到每台机器 `/etc/certsync/certsync.key`(0600, root:root);亦可用环境变量 `CERTSYNC_KEY` 注入(优先级高于文件)
- 授权范围:主密钥只在签发机与业务机的内存中出现;OSS、日志、告警中永远只有密文

### 6.2 RAM 账号最小权限

上传端(签发机专用子账号,仅 `PutObject`):

```json
{
  "Version": "1",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["oss:PutObject"],
    "Resource": ["acs:oss:*:*:<bucket>/certsync/certs/*"]
  }]
}
```

拉取端(业务机公用子账号,仅 `GetObject`):

```json
{
  "Version": "1",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["oss:GetObject"],
    "Resource": ["acs:oss:*:*:<bucket>/certsync/certs/*"]
  }]
}
```

两个账号均禁止控制台登录、独立 AccessKey、泄露可单独撤销互不影响。

### 6.3 威胁模型

| 失陷点 | 暴露内容 | 影响 | 缓解 |
|---|---|---|---|
| OSS Bucket | 证书与私钥的 GCM 密文 | 无法解密 | 客户端加密 + 版本控制 + 日志 |
| 任一业务机 | 该机明文证书私钥 + 只读 RAM 凭证 + 主密钥 | 该证书需吊销重签;主密钥需轮换 | 最小权限;机器加固;§6.4 轮换流程 |
| 签发机(最严重) | DNS 写密钥 + OSS 写凭证 + 明文证书 | 可篡改 DNS / 投毒分发 | 签发机单独加固:仅开放必要出网、无业务、密钥仅此一份;被入侵时的预案是吊销证书 + 换 DNS 密钥 + 全量轮换 |
| 主密钥泄露 | OSS 密文可被解密 | 视同私钥泄露 | §6.4 轮换流程 |

### 6.4 主密钥轮换流程

1. `certsync keygen` 生成新密钥,带外分发到**所有**机器,暂存为 `certsync.key.new`
2. 签发机执行 `certsync push --key-file /etc/certsync/certsync.key.new`:用新密钥重加密并覆盖 OSS 对象
3. 各机器将 `certsync.key.new` 改名替换 `certsync.key`(可一台台做)
4. 过渡期内旧密钥机器 pull 解密失败 → **保留本地旧证书 + 告警,不安装任何东西**,换完密钥后下一轮自动恢复正常
5. 确认全网 `certsync pull` 成功后,从源头销毁旧密钥副本

证书本身未变,指纹不变,轮换不触发任何 reload。

### 6.5 路径清单与文件权限

程序涉及的**全部**路径按机器角色梳理如下(文件命名统一参考 certbot:`fullchain.pem` = 叶子+中间证书、`privkey.pem` = 私钥,语义即文件名;标 ★ = 含敏感数据):

**通用(签发机/业务机一致)**

| 路径 | 权限 | 内容 | 谁写 | 说明 |
|---|---|---|---|---|
| `/usr/local/bin/certsync` | 0755 root | 二进制 | 部署/升级(§11.1) | oneshot 形态,替换即升级 |
| `/etc/certsync/config.toml` | 0644 root | 配置 | 人工 | 不含密钥值,可入配置仓库 |
| `/etc/certsync/certsync.env` ★ | 0600 root | AK/SK、钉钉加签密钥、邮箱密码等敏感环境变量 | 人工 | systemd `EnvironmentFile` 注入(§11.2) |
| `/etc/certsync/certsync.key` ★ | 0600 root | AES 主密钥(base64) | 带外分发 | 轮换见 §6.4;env `CERTSYNC_KEY` 优先 |
| `/run/certsync.lock` | — | flock 锁 | 每次运行 | 仅锁不含数据;tmpfs,重启自清 |
| stdout | — | 日志(slog 文本) | 每次运行 | journald 收集,不另落日志文件(§12.3) |

**签发机 state(`/var/lib/certsync/`,整体 0700,定期打包备份——恢复能力见 §13)**

```
/var/lib/certsync/
├── accounts/<email>/
│   ├── account.key    ★0600  # ACME 账户私钥,首次注册生成;丢失=重新注册,不影响已签发证书
│   └── account.json     0600  # 注册信息(registration URI 等)
└── certs/<primary_domain>/
    ├── fullchain.pem    0644  # 叶子+中间证书,issue 时覆盖写
    ├── privkey.pem    ★ 0600  # 证书私钥,issue 时覆盖写
    └── resource.json    0644  # lego Resource 存档(CertURL 等,吊销时用)
```

签发机本地不保留历史版本,历史由 OSS 版本控制兜底(§5.4);文件名与 OSS 明文体、业务机落地体三方同名,排查时一眼对上。

**业务机(安装产物)**

| 路径 | 权限 | 内容 | 说明 |
|---|---|---|---|
| `<pull.targets[].cert_file>`,默认 `/etc/nginx/certs/<domain>/fullchain.pem` | 0644 root | 安装的证书 | 原子替换(§7.2);路径可配置,共存期也可直接指向 acme.sh 原路径 |
| `<pull.targets[].key_file>`,默认 `/etc/nginx/certs/<domain>/privkey.pem` | 0600 root | 安装的私钥 | 同上 |
| `/var/lib/certsync/backup/<domain>/<时间戳>/{fullchain.pem,privkey.pem}` | 0644/0600 | 旧证书备份 | 保留最近 10 份(§7.2) |

业务机**无其他状态文件**:pull 跳过判断所需的"已装指纹"从本地已装证书现算,不单独存档。

**OSS 对象**(完整布局与写入顺序见 §5):`<prefix>/certs/<domain>/{fullchain.pem.enc, privkey.pem.enc, meta.json}`——前两者为 GCM 密文,meta.json 明文。

**内存与环境变量中的敏感数据**(盘上上述位置之外再无副本):`ALICLOUD_ACCESS_KEY/SECRET`、`OSS_ACCESS_KEY_ID/SECRET`、`CERTSYNC_KEY`、`DINGTALK_SECRET`、`ALERT_MAIL_USER/PASS`(env 注入);主密钥与解密后的证书私钥仅在进程内存中短暂存在,永不写日志(§6.1)。

---

## 7. 可靠性设计

### 7.1 安装前的校验链(全部通过才落盘)

1. GCM 解密成功(认证标签验证,密文被篡改/密钥不对直接失败)
2. 证书 PEM 可解析(x509);fullchain 结构合法:首块为叶子证书,且至少含一张中间证书(兜住 Bundle 未开启/链不完整的错误签发)
3. 当前时间在 `not_before ~ not_after` 内(要求各机 NTP 正常)
4. 证书 SAN 覆盖目标域名(精确或 `*.example.com` 通配匹配;通配只匹配一层子域)
5. **证书与私钥配对**(双方公钥 `Equal` 比较)
6. 证书指纹 == meta.fingerprint(防半更新状态)

任何一步失败:拒绝安装、保留现状、告警退出。

### 7.2 原子安装与回滚

```
写临时文件(与目标同目录,保证 rename 原子性)
  → 备份旧文件到 backup_dir/<domain>/<时间戳>/{fullchain.pem,privkey.pem}(保留最近 10 份)
  → rename 落位(证书 0644 / 私钥 0600)
  → 执行 check_cmd(nginx -t)
  → 执行 reload_cmd(systemctl reload nginx)
  → 探测确认(默认开):本机 127.0.0.1:443 以 SNI 握手,实际服务证书指纹 == meta 指纹
  → 任一步失败:从备份恢复原文件(或删除新增文件)→ 告警;例外——仅探测不一致时**不回滚文件**(文件已通过全部内容校验,不一致几乎必是 nginx 配置引用了别的路径或 reload 未生效,回滚无意义),只告警
```

说明:reload 失败时 nginx 内存里仍是旧证书,磁盘回滚即对齐;"配置错误 → 服务器下线"被 `nginx -t` 前置拦截。

### 7.3 并发与幂等

- 每台机器 `flock /run/certsync.lock`(LOCK_EX | LOCK_NB),抢不到锁直接退出——timer 重叠/手工与 timer 并发都安全
- 指纹相同即跳过所有写操作——重复执行零副作用
- 签发端 renew 到窗口外直接退出,不产生 ACME 订单——避免无谓消耗限额

### 7.4 重试与超时

- OSS 请求:指数退避重试(1s/2s/4s,3 次),单请求 30s 超时
- ACME:依赖 lego 内部重试;renew 本身每日跑,持续失败会每日告警
- 告警 webhook:10s 超时,失败仅记日志不阻塞主流程

### 7.5 时钟依赖

证书有效期校验依赖本机时钟,所有机器必须运行 NTP(chrony/systemd-timesyncd),部署清单包含此项检查。

---

## 8. 配置设计

`/etc/certsync/config.toml`(同一份模板,按机器裁剪;签发机用 acme/alidns/oss 段,业务机用 oss/crypto/pull 段):

```toml
# ─── 签发机 ───────────────────────────────────────────────
[acme]
ca_server = ""             # 空 = Let's Encrypt 正式;--staging 覆盖为测试环境
email = "ops@example.com"
domains = ["example.com", "*.example.com"]  # 第一个域名为存储主键
renew_before_days = 30     # 剩余天数低于此值触发续期

[acme.eab]                 # ZeroSSL 等需要外部账户绑定的 CA 才填
kid = ""
hmac = ""

[alidns]                   # 仅签发机需要;留空则读环境变量
access_key = ""            # env: ALICLOUD_ACCESS_KEY
secret_key = ""            # env: ALICLOUD_SECRET_KEY

# ─── 通用 ─────────────────────────────────────────────────
[oss]
endpoint = "oss-cn-hangzhou.aliyuncs.com"
region = "cn-hangzhou"     # V2 SDK 必填(V4 签名用)
bucket = "my-cert-bucket"
prefix = "certsync"           # --staging 时强制替换为 certsync-staging(§3)
access_key = ""            # env: OSS_ACCESS_KEY_ID(签发机=上传账号,业务机=拉取账号)
secret_key = ""            # env: OSS_ACCESS_KEY_SECRET

[crypto]
key_file = "/etc/certsync/certsync.key"    # 或 env: CERTSYNC_KEY(base64,优先)

[state]
dir = "/var/lib/certsync"
lock_file = "/run/certsync.lock"

# ─── 业务机 ───────────────────────────────────────────────
[pull]
check_cmd  = ["nginx", "-t"]               # 空数组 = 跳过检查(不建议)
reload_cmd = ["systemctl", "reload", "nginx"]
backup_dir = "/var/lib/certsync/backup"
expire_alert_days = 15                     # 剩余低于此值,每轮 pull 都告警
post_reload_probe = true                   # reload 后本机 127.0.0.1 SNI 探测实际服务证书指纹(§7.2)

[[pull.targets]]                           # 数组段,多证书组时重复此块(§16)
domain = "example.com"                     # 必须等于 acme.domains[0]
cert_file = "/etc/nginx/certs/example.com/fullchain.pem"   # 落地路径可按环境调整
key_file  = "/etc/nginx/certs/example.com/privkey.pem"

[alert]                    # 多通道:已配置的通道并行扇出同一事件;全空 = 不告警(§12.2)

[alert.webhook]            # 通用 JSON POST(自建接收端;不用就整段删除)
url = ""

[alert.webhook.headers]    # 自定义请求头(鉴权 token 等),随请求发送
Authorization = ""         # 例 "Bearer xxx"

[alert.dingtalk]           # 钉钉群自定义机器人
webhook = ""               # https://oapi.dingtalk.com/robot/send?access_token=…
secret = ""                # env: DINGTALK_SECRET(机器人安全设置选"加签"时必填)
at_mobiles = []            # 告警 @ 的手机号(可空)

[alert.mail]               # SMTP 邮件
host = ""                  # 例 smtp.example.com
port = 465                 # 465=隐式TLS / 587=STARTTLS / 25=仅限内网中继
username = ""              # env: ALERT_MAIL_USER
password = ""              # env: ALERT_MAIL_PASS
from = "certsync@example.com"
to = ["ops@example.com"]
```

配置加载顺序:toml 值 → 空则取环境变量(表内标注)→ 仍空报错退出。密文级敏感值**建议全部走环境变量**(由 systemd `EnvironmentFile=/etc/certsync/certsync.env` 注入,0600),toml 可提交到配置仓库。

---

## 9. 技术选型

| 用途 | 选择 | 钉死版本 | 说明 |
|---|---|---|---|
| ACME | `github.com/go-acme/lego/v5`(库形态) | v5.6.0 | Traefik 同款,alidns provider 内置;v5 为当前主线(v4 已停止演进),支持 ARI / ACME profiles;替代 acme.sh |
| OSS | `github.com/aliyun/alibabacloud-oss-go-sdk-v2` | v1.6.1 | 官方新一代 SDK(完全重写的 V2,官方手册即此版);旧 `aliyun-oss-go-sdk/v3` 已被其取代 |
| 证书解析/校验 | 标准库 `crypto/x509` | — | SAN/有效期/密钥配对,不 shell 调 openssl |
| 加密 | 标准库 `crypto/aes` + `cipher.NewGCM` | — | 见 §6.1 |
| CLI | `github.com/spf13/cobra` | v1.10.2 | 子命令 + flag |
| 配置 | `github.com/BurntSushi/toml` | v1.6.0 | 仅解码(配置只读不写);零第三方依赖,事实标准 |
| 日志 | 标准库 `log/slog` | — | 文本格式到 stdout,由 journal 收集 |
| 邮件告警 | 标准库 `net/smtp` | — | 465 隐式 TLS 自行 tls.Dial 后接 NewClient,几十行;不引第三方库 |
| 文件锁 | `golang.org/x/sys/unix` `Flock` | v0.49.0 | |
| 重试 | 自实现 20 行指数退避 | — | 减少供应链面 |
| 构建 | Makefile(GOOS/GOARCH 交叉编译),版本 `-ldflags` 注入;CI 跑 `staticcheck` + `gosec` + `govulncheck`(依赖已知漏洞)+ `gitleaks`(密钥泄露扫描) | — | 工具碰私钥,值得安全扫描;发布产物加 SBOM 与签名,见 §11.1 |

Go 版本:**1.27**(2026-08 发布的当前稳定线);`go.mod` 钉死直接依赖版本,上表"钉死版本"为 2026-10-30 经 Go module proxy 核实的最新正式版。

---

## 10. 项目结构

```
certsync/
├── main.go                    # 入口,注入 version
├── internal/
│   ├── cli/                   # cobra 命令:root/keygen/issue/renew/push/pull/status
│   ├── config/                # toml 加载、默认值、env 回退
│   ├── cryptoutil/            # AES-GCM、keygen、密钥加载
│   ├── certutil/              # 解析、指纹、SAN 覆盖、密钥配对、续期窗口
│   ├── store/                 # OSS 读写、meta.json、上传顺序约定
│   ├── acme/                  # lego 封装:账户管理、DNS-01、Obtain(ObtainRequest 必须 Bundle: true,否则 res.Certificate 只含叶子证书,链不完整)
│   ├── deploy/                # 原子替换、备份、check/reload、回滚
│   └── alert/                 # webhook 通知
├── deploy/
│   ├── certsync-renew.service / certsync-renew.timer      # 签发机
│   ├── certsync-pull.service / certsync-pull.timer        # 业务机
│   ├── config.example.toml
│   └── certsync.env.example
├── Makefile
├── DESIGN.md                  # 本文档
└── README.md                  # 快速上手(实施阶段编写)
```

---

## 11. 部署方案

### 11.1 二进制分发

- CI 产出 `certsync-linux-amd64` / `certsync-linux-arm64` + `SHA256SUMS` + cosign 签名 + SBOM(syft)
- 存放于同一 OSS Bucket 的 `dist/` 前缀(走拉取账号的只读权限之外单独授权,或直接复用手工分发)
- 安装脚本:下载 → sha256 校验 → `cosign verify`(哈希文件本身也可能被篡改,签名才是终审)→ `install -m 755` 到 `/usr/local/bin/certsync` → `certsync version`
- 升级:替换二进制即可(oneshot/timer 形态无常驻进程,下一轮 timer 自动用新版);多机版本差异通过 `certsync version` 巡检

### 11.2 systemd 单元

签发机 `/etc/systemd/system/certsync-renew.{service,timer}`:

```ini
# service
[Unit]
Description=certsync - renew ACME certificate
After=network-online.target
Wants=network-online.target
OnFailure=certsync-fail@%n.service

[Service]
Type=oneshot
EnvironmentFile=-/etc/certsync/certsync.env
ExecStart=/usr/local/bin/certsync renew
```

```ini
# timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
```

业务机 `certsync-pull.{service,timer}`:同结构,`ExecStart=/usr/local/bin/certsync pull`,timer 为:

```ini
[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
Persistent=true
```

业务机 pull 的 service 同样挂 `OnFailure=certsync-fail@%n.service`。**失败兜底单元**(主流程因配置错/网络不通/二进制损坏而失败时,进程内告警代码可能根本没执行到,由 systemd 层补一刀):

```ini
# certsync-fail@.service(模板单元)
[Unit]
Description=certsync failure hook for %i

[Service]
Type=oneshot
EnvironmentFile=-/etc/certsync/certsync.env
ExecStart=/usr/local/bin/certsync on-failure %i
```

`certsync on-failure` 是刻意保持极短的代码路径:只读告警配置、发送 `unit_failed` 事件,不触碰 ACME/OSS/deploy 任何逻辑。二进制整体缺失时此钩子同样起不来,但 systemd 在 journal 留痕可巡检(§12.3),业务侧另有 `expiry_warning` 生命线(§12.1)——三层兜底互不依赖。

### 11.3 单机安装清单

1. `/usr/local/bin/certsync`(0755)
2. `/etc/certsync/config.toml`(0644,按角色裁剪)
3. `/etc/certsync/certsync.env`(0600,RAM AK/SK、ALICLOUD AK/SK、钉钉加签密钥、邮箱密码)
4. `/etc/certsync/certsync.key`(0600,带外分发)
5. `mkdir -p /var/lib/certsync`(0700);确认 NTP 运行中
6. 按角色 enable 对应 timer

`certsync.env` 只放 config.toml 中标注了 env 回退的敏感值,一行一个 `KEY=value`(systemd EnvironmentFile 语法)。两类机器**变量名相同、值必须是不同 RAM 账号**(上传/拉取),严禁一份拷全网;`CERTSYNC_KEY` 虽可放 env 且优先级更高,但设计默认走独立 key 文件,不放这里:

```bash
# ── 签发机 ──
ALICLOUD_ACCESS_KEY=…       # alidns DNS-01(lego)
ALICLOUD_SECRET_KEY=…
OSS_ACCESS_KEY_ID=…         # OSS 上传 RAM 账号(仅 oss:PutObject)
OSS_ACCESS_KEY_SECRET=…
DINGTALK_SECRET=…           # 告警凭证按已配置的通道放,未配置的通道不放
ALERT_MAIL_USER=…
ALERT_MAIL_PASS=…

# ── 业务机 ──
OSS_ACCESS_KEY_ID=…         # OSS 拉取 RAM 账号(仅 oss:GetObject),与签发机同变量名、不同账号
OSS_ACCESS_KEY_SECRET=…
DINGTALK_SECRET=…
ALERT_MAIL_USER=…
ALERT_MAIL_PASS=…
```

---

## 12. 监控与告警

### 12.1 事件表

| event | 端 | 含义 | 默认级别 |
|---|---|---|---|
| `issue_ok` | 签发 | 新证书签发并上传成功 | info |
| `issue_fail` | 签发 | 签发或上传失败(**每日重试+每日告警**) | error |
| `renew_skipped` | 签发 | 未到续期窗口(仅 debug 日志,不推送) | - |
| `install_ok` | 业务 | 安装并 reload 成功(指纹变化才发) | info |
| `install_fail` | 业务 | 校验失败/回滚发生 | error |
| `expiry_warning` | 业务 | 剩余天数 < expire_alert_days(每轮都发,**这是兜底生命线**) | error |

`expiry_warning` 独立于签发链路存在:即使签发端整体瘫痪,各业务机仍会持续喊"证书快过期了",把静默失败变成显式事故预警。

### 12.2 通道与适配

事件产生后**同时扇出到所有已配置的通道**(`[alert.webhook]` / `[alert.dingtalk]` / `[alert.mail]`,全空 = 不告警;邮件主题 `[certsync] <级别> <event> <host> <域名>`,正文为下方 payload)。webhook 通道支持 `[alert.webhook.headers]` 自定义请求头(鉴权);header 值明文存于 toml(0644 可见),自建接收端应配合内网/IP 白名单,更高安全要求走钉钉/邮件通道。

通用通道 payload(JSON POST):

```json
{
  "event": "install_fail",
  "host": "web-01",
  "domain": "example.com",
  "detail": "nginx -t failed: …",
  "time": "2026-10-29T12:00:00+08:00"
}
```

钉钉群自定义机器人的协议要点(踩坑点提前写死,实现按此验收):

- **加签**:机器人安全设置选"加签"时 `secret` 必填,请求需附加 `timestamp`(毫秒)与 `sign`(HMAC-SHA256,密钥与被签串均为 `"<timestamp>\n<secret>"`,结果 base64 后 urlencode)。**timestamp 与钉钉服务器时差超过 1 小时直接拒绝——NTP 是硬前提,与 §7.5 证书有效期校验共用同一依赖**
- **响应语义**:HTTP 200 ≠ 成功,必须校验 body 的 `errcode == 0`(关键词不匹配、签名错误、限流都以 200 + errcode 返回;实现只看 HTTP 状态码 = 告警静默丢失)
- **关键词过滤**:机器人若配"自定义关键词",消息文本必须包含该词——告警模板首词固定为 `certsync`,机器人侧把关键词配成 `certsync` 即可
- **限流**:单机器人 20 条/分钟,超限封禁 10 分钟;各机 timer 已带 `RandomizedDelaySec` 天然错峰,常态足够;机器数 > 20 且同时故障的极端场景需按机房拆多个机器人
- 消息用 markdown 类型,`at_mobiles` 非空时带上 @ 列表

企微群机器人与钉钉同构(`[alert.wecom]`,token 参数与格式微差),需要时按钉钉同款方式接入,不影响核心。

### 12.3 巡检

- `certsync status`:各 target 域名/到期时间/剩余天数
- `journalctl -u certsync-pull.service --since -24h`
- **外部视角**(巡检的本质是验证 nginx 实际在服务的证书,而非只看磁盘文件):任意外部机器 `openssl s_client -connect <域名>:443 -servername <域名> </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 -enddate`,与 meta.json 指纹比对
- **CA 侧独立审计**:证书一旦签发必然进入 CT 日志,`crt.sh/?q=<域名>` 可查——"签发成功"不依赖 certsync 自己的报告
- OSS 侧通过版本控制 + 日志审计对象变更

---

## 13. 失败场景与处置

| 场景 | 系统行为 | 人工动作 |
|---|---|---|
| CA/DNS API 故障,签发失败 | 旧证书继续服务;每日重试 + 每日 `issue_fail` 告警 | 30 天窗口内修复即可,无紧迫性 |
| 签发后 OSS 上传失败 | 证书在本地 state;下轮 renew 重试(未到窗口会先尝试 push) | 手动 `certsync push` |
| OSS 对象被误删 | pull 报 not found,告警;本地证书不受影响 | 签发机 `certsync push` 重建(或版本控制找回) |
| 上传中途断掉(meta 与对象不一致) | pull 指纹校验拒绝安装 | 无需处理,下轮上传覆盖自愈 |
| 某业务机主密钥没换/输错 | 解密失败,保留旧证书,`install_fail` 告警 | 修该机密钥 |
| nginx 配置本身有错 | `nginx -t` 拦截,回滚,`install_fail` 告警 | 修 nginx 配置,与证书无关 |
| reload 失败 | 回滚磁盘文件告警;nginx 内存中仍是旧证书,服务未断 | 手工 `nginx -t` 排查 |
| 业务机连续多轮拉取失败 | 本地证书持续老化,临期触发 `expiry_warning` | 按 15 天缓冲修复 |
| **签发机宕机/丢失** | 证书仍全网有效;最长 30 天无续期 | 新机:恢复 state 备份 → 装 certsync → 完事;无备份则重新注册 ACME 账户 + `issue`(证书会立即重签,指纹变化自动全网分发) |
| 主密钥泄露 | — | 执行 §6.4 轮换流程 |

---

## 14. CA 兼容性策略(华为老设备问题)

- 默认 Let's Encrypt;配置 `acme.ca_server` + `acme.eab` 即可切 ZeroSSL(免费额度以官网为准)或任何 ACME CA——**只改签发机配置,分发链路与业务机零改动**
- 决策依据:先实测老设备占比,占比可忽略则不切
- 购买的商业 DV 证书(阿里云 DigiCert 等)手工导入:将 fullchain 存为签发机 `state/certs/<domain>/fullchain.pem`、私钥存为 `state/certs/<domain>/privkey.pem`,执行 `certsync push` 即入分发链路,业务机自动更新——**手动导入与自动签发共用同一条管道**
- 切换灰度:业务机 pull 支持 `--domain` 过滤,可指定单台先换证书观察老机型表现

---

## 15. 实施计划与迁移

### Phase 0:开发 + 验收(分层:CI 可重复 → staging → 演练)

**CI 层(任何人 `go test ./...` 可复现,不触外网)**

- [ ] 单元测试:AES-GCM 往返/防篡改、SAN 通配匹配、密钥配对、fullchain 结构校验(首块叶子+至少一张中间证书)、部署回滚(伪命令)
- [ ] 本地 ACME E2E:CI 内起 pebble(LE 官方 ACME 测试服务器)+ challtestsrv(应答 DNS-01),完整走 issue→push→pull→安装→探测——签发逻辑的回归不依赖真实 CA

**staging 层(真实 CA、非受信证书,走 §3 的 `--staging` 隔离链路)**

- [ ] LE staging 端到端:issue → OSS(-staging 前缀)→ 测试机 pull → nginx reload → 探测指纹一致 → curl 验证
- [ ] 产物证书过 zlint(CA 签发同款 lint 工具,要求 0 error);testssl.sh 验证链完整
- [ ] `nginx -t` 故意失败 → 确认回滚生效;构造探测指纹不一致 → 确认只告警、不误回滚(§7.2 例外路径)
- [ ] 断网 pull → 确认无副作用;告警全部事件真实触达

**演练层(§13 的失败场景不是纸面推演,逐条实走)**

- [ ] OSS 对象误删 → `push` 恢复
- [ ] 签发机 state 全毁 → 备份重建、无备份重注册账户,两条恢复路各走一遍
- [ ] 主密钥轮换全流程(§6.4),含过渡期旧密钥机器"保留旧证书 + 告警"的行为验证

### Phase 1:正式环境共存(观察期)

- 签发机用正式 CA `issue` 一次,但 acme.sh 的 cron **继续运行**
- certsync pull 先只接入 1~2 台非核心业务机
- 观察 1 个续期周期(60~90 天)或至少 2 周

### Phase 2:切换

- [ ] `systemctl disable --now` acme.sh 的 cron(保留 acme.sh 安装,作为回滚手段)
- [ ] 全量业务机接入 pull timer
- [ ] 验证 `certsync version` 全网一致、`certsync status` 到期时间正常

### Phase 3:收尾

- acme.sh 观察 1 个月无异常后卸载;归档本文档与 runbook

### 回滚预案

任意阶段出问题:`systemctl enable --now` 恢复 acme.sh cron + 各机回挂 acme.sh 产物即可。certsync 是纯增量部署,不修改 acme.sh 任何状态,两者可无限期共存。

---

## 16. 未来扩展(按需)

- **多证书组**:config 增加 certs 数组,pull 按 domain 路由到组;当前单组够用
- **KMS 信封加密**:主密钥托管阿里云 KMS,业务机用实例 RAM 角色换取数据密钥,消灭手工分发;接口已按"密钥加载器"隔离,替换实现不动主体
- **自更新**:从 OSS dist/ 拉新版本自替换(校验 sha256 + 签名)
- **Prometheus metrics**:pull 成功/失败计数、证书剩余天数 gauge、blackbox TLS 探测(从外部探测 nginx 实际服务的证书,与磁盘文件状态解耦)
- **Kubernetes**:上 K8s 后整体退役,换 cert-manager(§1.1)
- **ZeroSSL/多 CA 自动降级**:主 CA 限额时自动切备用(依赖 ARI,暂无必要)

---

## 附录A:决策依据与独立验证

正文标注的论断,其一手出处与"任何人可复现"的验证方式:

| # | 论断/决策 | 一手素材 | 独立验证 |
|---|---|---|---|
| ① | 同组域名 7 天 5 张、无豁免;staging 限额显著更高 | LE 官方 https://letsencrypt.org/docs/rate-limits/ | 打开该页比对原文 |
| ② | 泛域名仅 DNS-01 可验证;ACME 语义;ARI 续期建议 | RFC 8555;ARI = RFC 9773(2025-09 发布) | rfc-editor.info 阅读原文 |
| ③ | 老设备不信任 ISRG Root X1 的时间线(DST Root X3 交叉签名 2024-09-30 到期) | LE 官方 https://letsencrypt.org/certificates/ | 读该页 + 老设备真机实测(§14 决策前置) |
| ④ | `Bundle: true` 时 `res.Certificate`=叶子+中间;alidns 读 `ALICLOUD_*` 环境变量 | lego 源码 `certificate/certificates.go`、`providers/dns/alidns/alidns.go` | clone 后 grep;E2E 后数产物 PEM 块数(§7.1 已固化为安装校验) |
| ⑤ | OSS SDK V2 凭证环境变量名、region 必填 | SDK 源码 + 官方 V2 手册(§9 引用) | grep 源码 / 读手册 |
| ⑥ | 依赖钉死版本为最新正式版 | Go module proxy | `go list -m <模块>@latest`,任何人可查 |
| ⑦ | "签发成功"这一事实 | CA 侧 CT 日志(与 certsync 无关的第三方) | crt.sh 查询域名,证书必然在册 |
| ⑧ | "nginx 在服务正确证书" | 传输层实测,而非文件状态 | §12.3 openssl s_client 指纹比对 |

## 附录B:术语

| 术语 | 含义 |
|---|---|
| ACME | CA 自动化证书协议,Let's Encrypt/ZeroSSL 均实现 |
| DNS-01 / HTTP-01 | 域名验证方式;泛域名只支持 DNS-01 |
| EAB | External Account Binding,ZeroSSL 等要求的账户绑定凭证 |
| SAN | 证书中的主题备用名称,即证书覆盖的域名列表 |
| 指纹 | 证书 DER 编码的 SHA-256,本文中即"证书版本号" |
| ARI | ACME Renewal Info,CA 建议的续期时间,可错峰规避限额 |
