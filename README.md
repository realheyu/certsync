# certsync

集中签发 + OSS 加密中转 + 各服务器自动拉取部署的泛域名证书管理系统,单个 Go 静态二进制,替代 acme.sh + 分发脚本。

```
签发机(1 台)                      阿里云 OSS(私有桶)                业务机(N 台)
certsync renew ──lego/DNS-01──►  certsync/certs/<域名>/  ──pull──►  原子安装 + nginx reload
每日 timer,到期前 30 天才签         fullchain.pem.enc(加密)           每 6 小时 timer,指纹相同即跳过
                                  privkey.pem.enc(加密)
                                  meta.json(明文,指纹=版本号)
```

- 私钥 AES-256-GCM 端到端加密后才上 OSS,bucket 泄露不泄露私钥
- 指纹 = 版本号:吊销、换 CA、换密钥对全部业务机透明,幂等零副作用
- CA 可插拔(Let's Encrypt / ZeroSSL EAB / 商业证书手工导入共用同一条管道)
- 告警多通道:钉钉群机器人 / SMTP 邮件 / 通用 webhook

完整设计(架构、安全模型、失败场景、验收清单)见 [docs/DESIGN.md](docs/DESIGN.md)。

## 命令

| 命令 | 作用 |
|---|---|
| `certsync keygen --out <file>` | 生成 32 字节主密钥(0600,带外分发) |
| `certsync issue [--staging]` | 向 CA 申领证书,落盘并加密上传(staging 走隔离链路) |
| `certsync renew` | 到续期窗口(默认剩余 <30 天)才触发 issue,否则直接退出 |
| `certsync push` | 不联系 CA,把本地证书重新加密上传(误删恢复/换密钥重加密) |
| `certsync pull [--domain x]` | 拉取、六重校验、原子安装、reload、探测确认 |
| `certsync status` | 各证书域名/到期时间/剩余天数 |
| `certsync on-failure <unit>` | systemd OnFailure 兜底钩子(设计 §11.2) |

## 快速开始

```bash
# 构建(或从 OSS dist/ 下载并校验 SHA256)
make build-linux-amd64

# 1. 生成主密钥,带外放到每台机器 /etc/certsync/certsync.key(0600)
./certsync keygen --out certsync.key

# 2. 配置(签发机用 acme/alidns 段,业务机用 pull 段;凭证走 certsync.env)
install -m 644 deploy/config.example.toml /etc/certsync/config.toml
install -m 600 deploy/certsync.env.example /etc/certsync/certsync.env   # 按角色填 AK/SK

# 3. 部署 systemd 单元并启用 timer
#    签发机:certsync-renew + certsync-backup + certsync-fail@
#    业务机:certsync-pull  + certsync-fail@
cp deploy/*.service deploy/*.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now certsync-renew.timer  # 业务机: certsync-pull.timer

# 4. 首签(先 staging 验收,再正式)
certsync issue --staging && certsync issue
```

## 状态

设计定稿 v0.4,待评审;实施计划见设计文档 §15(Phase 0 验收 → 共存观察 → 切换)。
