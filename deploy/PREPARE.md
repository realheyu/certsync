# 部署准备与切换

本项目现在采用 acme.sh 签发、Go 分发。详细环境变量及首次申请命令见 [设计文档](../docs/DESIGN.md)。本清单是人工部署说明，不会自动修改云资源或服务。

## 1. 准备资源

- [ ] 一台签发机，安装受控版本的 acme.sh，并关闭其默认 cron；ACME_HOME 指向它的安装和状态目录。
- [ ] Linux 业务机安装系统 CA 根证书、cron、flock、GNU timeout；确认 nginx 检查及 reload 命令。
- [ ] 私有 OSS Bucket；签发账号仅允许上传前缀下的 PutObject，下载账号仅允许所需组对象的 GetObject；分别验证权限。
- [ ] DNS 凭证只在签发机配置；Ali_Key / Ali_Secret 是 acme.sh 的变量名。
- [ ] 机器时间同步，允许 CA、DNS、OSS 所需网络连接，配置日志和外部到期监控。
- [ ] 需要钉钉通知的机器配置 DINGTALK_WEBHOOK；启用加签时同时填 DINGTALK_SECRET，关键词验证允许 certsync，IP 验证允许该机器出口 IP，并允许访问钉钉 HTTPS 接口。

## 2. 安装工具和环境

构建适合机器架构的二进制，例如 `make build-linux-amd64`；安装为 /usr/local/bin/certsync，权限 0755。

```sh
install -d -m 700 /etc/certsync
# 签发机：
install -m 600 deploy/issuer.env.example /etc/certsync/issuer.env
install -m 755 deploy/certsync-issuer-job /usr/local/sbin/certsync-issuer-job
# 业务机：
install -m 600 deploy/pull.env.example /etc/certsync/pull.env
```

按角色填写 env，不能把同一份上传凭证分发到业务机。`openssl rand -base64 32` 生成一次 CERTSYNC_KEY，两端填写相同值。不要把真实配置、密钥或导出私钥提交 Git。

只有环境变量参与配置；Go 不自动 source 文件。手工执行时：

```bash
set -a
. /etc/certsync/pull.env
set +a
flock -n /run/certsync-pull.lock timeout 1800 /usr/local/bin/certsync pull
```

签发机配置 CERTSYNC_SOURCE_DIR 总目录和 OSS_PREFIX，将各组证书导出到总目录下的域名子目录；再执行一次 push 批量上传。首次注册、申请和导出步骤见设计文档。不要上传 acme.sh 内部工作目录，不要使用 --force 重签来重试上传。

组名支持小写普通域名 `example.com` 和通配域名 `*.example.com`。例如 `CERTSYNC_GROUPS='*.example.com,other.com'` 精确选择两个同名子目录；`*` 不匹配其他组。通配组必须包含对应通配符 SAN，根域名 SAN 可同时存在。Shell 中含 `*` 的名称和路径须加引号；OSS RAM 策略中的 `*` 仍是匹配符，授权时须核对范围。

已有普通域名组继续兼容，无需改名或重新申请证书。如果选择改为通配组名，需将 acme.sh 导出路径改为 `"$CERTSYNC_SOURCE_DIR/*.example.com/"`、重新 push，并更新业务机的 `CERTSYNC_GROUPS` 及 Nginx 路径。acme.sh 的 `--install-cert -d` 仍填写已保存的主域名；签发机自身使用证书时也要同步路径并保留所需 reload 命令。旧目录与 OSS 对象不会自动重命名或删除。

## 3. 非核心机验收

- [ ] `certsync version` 可执行，旧的 issue/renew/keygen/status 命令不再存在。
- [ ] 混合放入普通域名组和通配域名组，一次 push 生成不同组的独立 JSON 加密对象，设置 CERTSYNC_GROUPS 后一次 pull 到输出总目录的各组子目录，确认组名中的 `*` 保留、内容正确及私钥 0600 权限。
- [ ] 制造一组缺私钥、错误目录名或上传失败，其他组仍处理，命令汇总并非零退出；空总目录不会返回成功。
- [ ] 错误加密密钥、缺失 OSS 对象、网络失败不覆盖已有证书。
- [ ] 某组下载或校验失败时保留该组旧文件，后面的有效组仍安装，最终非零退出；空列表、重复组、路径以及非首位或非完整标签的星号（如 `api.*.example.com`、`foo*.example.com`）不能作为下载组名。
- [ ] 通配组拒绝仅含根域名或具体子域名 SAN 的证书；只含对应通配符 SAN 的证书也能通过，无需额外包含根域名 SAN。选择 `*.example.com` 组不会下载同名根域名组或其他子域名组。
- [ ] 删除某组本地私钥后，再次 pull 能修复；不变内容不会重新写证书，不删除未选择组的目录。
- [ ] nginx 已配置引用 CERTSYNC_OUTPUT_DIR/<组名>/ 的两个文件；整批 pull 成功后统一 nginx -t → reload 通过。
- [ ] 外部 TLS 检查确认服务证书正确；程序本身不探测服务、不回滚文件。
- [ ] 模拟 reload 失败后，修复配置并重跑整个任务，确认即使内容未变也会重试 reload。
- [ ] 钉钉验证：首次安装、内容变化或修复缺失文件后通知；内容未变不通知。消息应明确文件替换成功且尚未确认 reload，失败组不得报成功。
- [ ] 签发端每次 push 检查少于 15 天有效期，上传失败也告警；过期证书告警但拒绝上传。恰好 15 天不告警，尚未配置 Webhook 时只输出本地警告。
- [ ] 钉钉发送失败能从日志发现，分发和外层 reload 继续；通知失败不会自动回滚或持久排队。

## 4. 启用定时任务

关闭旧 certsync renew/pull 任务、重复的 acme.sh 默认 cron 和其他写相同文件的分发任务，再安装本角色模板：

```sh
# 二选一，安装前核对内容：
install -m 644 deploy/cron.issuer.example /etc/cron.d/certsync
# install -m 644 deploy/cron.pull.example /etc/cron.d/certsync
```

手动签发、导出、push 使用 /run/certsync-issuer.lock，手动 pull、检查、reload 使用 /run/certsync-pull.lock，与 cron 共用；锁应覆盖整段操作。签发机一个任务统一续期并批量上传，不为每组重复运行同一个 ACME_HOME 的 cron；业务机一份 env 设置 CERTSYNC_GROUPS、OSS_PREFIX 和输出总目录，一个锁覆盖整批拉取和统一 reload。

## 5. 运行和恢复

- 上传失败：保留有效导出文件，一组失败不阻止其余组；重新 push 或等每日任务重传所有有效组。
- 某组下载或校验失败：该组旧文件保留，继续其他组，整批非零退出；检查日志修复后重跑，全部成功再统一 reload。
- 文件替换中断：两文件不保证同时切换；避免其他任务在中途重启服务，重新 pull 后再检查和 reload。
- nginx 失败：外层返回失败，不自动回滚文件；修复后重跑完整任务。
- 备份：acme.sh 账户/工作目录、env 和必要的业务文件纳入现有机器备份。备份包含敏感数据。
- 告警：钉钉仅提供替换成功通知和签发端少于 15 天有效期告警，发送失败只记日志且不改变退出码；其他失败和外部证书到期监控接入现有体系。失败的替换成功通知不会在下次文件未变时补发；临期事件会随每次 push 再次尝试。可选安装 logrotate.example。

旧 OSS 的三个文件与新 bundle.enc 不兼容。先在独立对象和非核心机验证，再切换生产；新工具不会删除旧对象或备份。

单组上传迁移到批量上传时：移除签发机 env 中的 CERTSYNC_DOMAINS、OSS_OBJECT_KEY，改设 OSS_PREFIX；来源目录改成总目录，各组导出到对应子目录。业务机移除 OSS_OBJECT_KEY、CERTSYNC_DOMAINS，改用 OSS_PREFIX、CERTSYNC_GROUPS，并将 CERTSYNC_OUTPUT_DIR 改成总目录；原对象及 JSON 加密包格式不变。已导出旧变量的 shell 应 unset OSS_OBJECT_KEY CERTSYNC_DOMAINS 或重新打开 shell。本地删目录不会自动删除远程对象。
