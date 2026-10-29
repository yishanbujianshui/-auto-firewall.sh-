# 更新日志

## v2.2.1（2026-10-29）—— 真机运行时修复

### 修复（均在 Ubuntu 26.04 / ufw 0.36.2 实机复现）
- **规则删除语法错误（最严重）**：`ufw delete <port>/<proto>` 在 ufw 0.36 无效（输出用法、规则仍在），导致动态端口回收、白名单删除、`uninstall --purge` 全部失效。现统一生成 `delete allow ...`。
- **portless / any 规则无法识别**：`ufw status` 把无端口协议显示为 `Anywhere/esp`、any 显示为裸 `Anywhere`，旧解析只认 `22/tcp` 形式，导致白名单每 5 分钟重复添加同类规则、规则无限膨胀。现正确归一到 `-/esp`、`-/any`。
- **显式 `/v4` 规则重复添加**：`ufw status` 不输出 `(v4)` 标记，`443/tcp/v4` 永远匹配不到已有规则；新增 `ufw_rule_exists` 的 `/v4` 回退匹配。
- **双栈 purge 二次删除报错**：同时存在 `K` 与 `K/v6` 两条 status 记录时，删除 `K` 已连带删除 v6，现跳过 `/v6` 变体。
- **icmp/协议号/sctp 不被 ufw 支持**：`ufw 0.36` 仅支持 tcp/udp/ipv6/esp/ah/igmp/gre/vrrp；此前 `icmp` 白名单每轮报错。现用 `ufw --dry-run` 探测协议能力，不支持时明确提示并跳过（ICMP 由 ufw `before.rules` 默认放行）。
- **dry-run 改写 ports.state**：`port-check --dry-run` 会重写状态文件，造成规则与 state 脱节、孤儿规则永不回收；现 dry-run 不写状态。
- **放行失败仍写入 state**：失败端口进入 state 后下一轮不再重试；现仅记录已真实放行（或已存在）的动态端口。
- **`detect_ssh_ports` 在 `set -e/pipefail` 下崩溃**：无 sshd 监听且无 `Port` 配置时，`grep` 无匹配使管道返回 1，直接终止脚本；已显式兜底，恒回退 22。
- **日志轮转对单行超长日志无效**：`tail -n 500` 保留单条 1MB+ 行后仍超限；新增按字节兜底截断（cron.log 同样生效）。
- **首次初始化覆盖已有白名单**：`init_ufw` 无条件重新生成白名单，会冲掉刚迁移的 v1 配置；现仅在文件不存在时生成。
- **cron/快捷命令硬编码 `/opt`**：自定义 `AUTO_FW_HOME` 部署时 cron 指向错误路径；现统一使用 `${SCRIPT_DIR}`。追加 crontab 前补换行，避免与上一行粘连。
- **dry-run 仍变更服务**：`svc_exec`（systemctl/service）未受 dry-run 约束，`uninstall --purge --dry-run` 会真的停用 fail2ban；现加 dry-run 日志短路。
- **`unban` 非幂等**：对未封禁 IP 返回非 0；现幂等返回 0。
- **TUI Dry-run 演练混入历史日志**：改为只显示本次演练新增的 `[DRYRUN]` 行。

### 测试
- 新增 `tests/runtime_compat.bats`（11 项）覆盖上述格式/语法/状态一致性回归。
- 新增 `tests/verify-runtime.sh`：真机运行时场景（真实监听端口动态放行/回收、白名单幂等、fail2ban 联动与真实封禁、并发锁、日志轮转、dry-run、幂等重装、purge）共 61 项。
- `tests/verify-full.sh` 移除硬编码 SSH 端口 5522，改为按本机自适应；`tests/run.sh` 增加 SC2329 豁免说明。
- Ubuntu 26.04 / WSL2 实测：shellcheck 0 findings、bats 全绿、方案2 60/60、方案3 61/61。

## v2.2.0（2026-09-25）

### 修复
- **Docker/UFW 修复改为守护进程级检测**：此前仅凭 `command -v docker` 判断，导致 Docker 引擎被卸载、CLI 残留的机器上 after.rules 引用永不存在的 `DOCKER-USER` 链，iptables-restore 整体失败、ufw 开机无法加载（实机事故：防火墙静默失效 3 个多月，Fail2ban 封禁形同虚设）。现在：守护进程未运行时跳过插入，并自动清理历史失效修复块（先备份）；新插入块自声明 `:DOCKER-USER - [0:0]` 链，彻底消除加载顺序依赖。
- **cron.log 纳入日志轮转**：`rotate_log` 此前只处理 `auto-firewall.log`，cron `>>` 重定向的 `cron.log` 无人管理可无限增长（实机观察 20MB）；现与主日志共用 1MB/500 行阈值。
- **v1→v2 迁移收编孤儿动态规则**：v2 回收是 state 驱动的，v1 遗留的 `comment=auto-firewall` 规则不在 state 中则永不回收（实机残留 3552 条）。迁移时新增 `adopt_v1_orphan_rules`，扫描 ufw 现存带标规则并入 state，由下一次 port-check 按差分决定回收。

### 变更
- `fix_docker_ufw` 路径改用 `AUTO_FW_UFW_ETC_DIR` seam（可测试），`ufw reload` 改走 `ufw_exec`（支持 dry-run）。
- 新增 bats 用例：`tests/docker_fix.bats`（4 项）、`tests/log_rotation.bats`（3 项）、`tests/migration.bats` 补充迁移收编（3 项）。

## v2.1.0（2026-09-25）

### 新增 / 变更
- **SSH 端口自动探测**：不再写死 22。保护范围 = sshd_config 的 `Port` 指令 ∪ 实际监听且进程名含 sshd 的端口，均无结果时回退 22；适用于回收/白名单删除/purge 三处保护点。
- **TUI 改为原生 ANSI 实现，彻底移除 dialog 依赖**：方向键/j k 导航、数字/字母快捷执行、Enter 确认、q 退出；msgbox/inputbox/confirm/编辑均自绘；install 不再安装 dialog；非交互终端仍降级为文本帮助。
- 测试 seam `AUTO_FW_TUI_TEST=1` 支持 bats 管道驱动 TUI（新增按键映射/菜单渲染/导航/确认等 9 项用例）。
- `config edit`/`tui_edit_file` 健壮性：mktemp 失败/空路径 fail-fast，编辑器非零退出不保存（防误截断配置文件）。

### 修复
- 清除全部 10 条 shellcheck style 级告警（SC2155/SC2034/SC2129/SC2001/SC2015×2 等）；`shellcheck -S style` 现 0 违规。

## v2.0.0（2026-09-24）

### 新增
- **v2 端口描述符模型**：IPv6 地址族（`/v4`、`/v6`）、端口区间（`8000:8100/tcp`）、无端口协议（`icmp`、`-/esp`、协议号 `-/50`）、`any` 全协议；v1 写法完全兼容。
- **无损升级**：`.schema_version` 标记 + 逐级迁移 + 变更前自动备份 + 失败自动还原；无法解析的非注释行原样保留。
- **TUI 图形管理界面**（`menu` 子命令，基于 dialog）：仪表盘 / 检测 / 清理 / 配置管理 / 恢复默认 / 封禁管理 / 实时日志 / Dry-run 演练 / 版本 / 卸载。
- **命令行快捷命令 `x`/`X`**：安装至 `/etc/profile.d`，`x` 开界面、`x <子命令>` 替代 `sudo bash auto-firewall.sh <子命令>`。
- **配置管理** `config add/del/list/edit`（校验/去重/受保护项/写前备份）与 `reset-config`（恢复默认）。
- **两档卸载** `uninstall` / `uninstall --purge [--force-ssh]`（SSH 防锁死、删前备份移至 /root、GAP-D 语义提示）。
- `ban <IP>` / `unban <IP>` 手动封禁、`version`、`log [N]` 子命令。
- 全局 flag `--dry-run`（`[DRYRUN]` 日志）/ `--yes`，可置于命令前后。
- bats-core 测试套件（`tests/`，含 IPv6 扫描、迁移回滚、差分、config、uninstall 等）+ `tests/run.sh`。

### 变更 / 修复
- 端口扫描单遍解析，ufw 规则表每次运行仅读一次（缓存 + 按 `auto-firewall*` comment 精确回收，含 `ufw show added` 回退思路），移除 `grep -qw` 脆弱匹配。
- 外部命令全部薄封装（`ufw_exec`/`ss_probe`/`run_cmd` 等）并以数组传参，防命令注入；变更型子命令统一加锁。
- Fail2ban：botsearch/bad-request 改用 `error.log`、404/ufw 用 `access.log`；无 MTA 时 action 降级；jail 按日志存在性启用；配置比对改为幂等重建。
- `/etc/default/ufw` 的 `IPV6=yes` 确保在 `ufw enable` 之前设置。
- 备份目录仅保留最近 10 份且权限 700；shellcheck 清理。

## v1（初始版本）

- UFW + Fail2ban + Docker 三重防线，cron 自动化。
