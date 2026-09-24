# 更新日志

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
