# 防火墙自动管理脚本 (auto-firewall.sh) v2

适用于 **Ubuntu / Debian** 云端 VPS 的一键防火墙自动化脚本，集成 **UFW + Fail2ban + Docker** 三重防线，新增 **TUI 图形管理界面、无损升级、配置管理与卸载** 能力。

## 功能总览

| 功能 | 说明 |
|------|------|
| UFW 自动初始化 | 默认拒绝入站/放行出站，扫描监听端口生成白名单（启用前自动开启 IPv6） |
| 端口动态管理 | Cron 每 5 分钟差分：自动放行新端口、回收失效端口（仅回收脚本自己加的规则） |
| **v2 端口模型** | 支持 **IPv6/地址族、端口区间、icmp/esp 等无端口协议、协议号**（v1 写法完全兼容） |
| Docker 兼容修复 | 自动修补 Docker 绕过 UFW 的安全漏洞（iptables DOCKER-USER 链） |
| Fail2ban 联动 | sshd + nginx 多 jail（日志归位 access/error），无 MTA 自动降级为纯封禁 |
| **无损升级** | 配置带 `schema-version`，升级时逐级迁移 + 自动备份 + 失败还原，旧配置零损坏 |
| **TUI 管理界面** | **原生 ANSI 实现（零外部依赖）**：仪表盘/检测/清理/配置/日志/Dry-run 演练等，方向键+数字快捷操作 |
| **快捷命令 `x`** | `x` 打开管理界面；`x <子命令>` 完全替代 `sudo bash auto-firewall.sh <子命令>` |
| **配置管理** | `config add/del/list/edit` 白名单增删查改（校验+去重+保护+备份），`reset-config` 恢复默认 |
| **手动封禁** | `ban <IP>` / `unban <IP>` |
| **两档卸载** | `uninstall` 只删脚本足迹；`--purge` 连脚本防火墙规则/fail2ban/Docker 修复一起清理（SSH 防锁死） |
| 系统自动清理 | 每小时 APT/Journal/tmp/日志轮转；备份仅保留最近 10 份 |

## 快速开始

```bash
# 一键安装（自动迁移旧配置、写快捷命令、配置 cron、初始化 UFW/Fail2ban；TUI 原生实现无需 dialog）
sudo bash auto-firewall.sh install
```

安装后**重新登录**（或 `source /etc/profile.d/auto-firewall.sh`）即可使用快捷命令：

```bash
x                 # 打开 TUI 图形管理界面（非交互终端自动降级为帮助）
x status          # 查看状态（等价 sudo bash auto-firewall.sh status）
x port-check      # 立即执行端口检测
x config add port 8000:8100/tcp   # 添加端口白名单
x reset-config    # 恢复默认配置（备份+确认后）
x version         # 版本信息
```

## 子命令一览

`install / menu / port-check / fail2ban-check / cleanup / status / config / reset-config / ban / unban / version / log / uninstall / help`

全局 flag（可放命令前后）：`--dry-run`（只记录不执行，日志带 `[DRYRUN]`）、`--yes/-y`（免交互确认）；`uninstall` 专用 `--purge`、`--force-ssh`。

## 端口白名单 v2 语法（向后兼容）

```
22/tcp              # 双栈 SSH（v1 写法原样可用）
8000:8100/tcp       # 端口区间
443/tcp/v6          # 仅 IPv6
53/udp
icmp                # 无端口协议（等价 -/icmp）
-/esp               # IPsec ESP（或协议号 -/50）
```

> 注：区间 / icmp / 协议号等**无法被 ss/netstat 自动发现**，只能作为白名单（始终放行、永不自动回收）；自动扫描管理的是 tcp/udp 单端口动态规则。

## 配置文件

| 文件 | 说明 |
|------|------|
| `/opt/auto-firewall/port-whitelist.conf` | 端口白名单（v2 语法，首行含 `# schema-version`） |
| `/opt/auto-firewall/ip-whitelist.conf` | IP 白名单（Fail2ban ignoreip；内置回环/内网段不可删） |
| `/opt/auto-firewall/ports.state` | 动态端口状态（脚本自动维护） |
| `/opt/auto-firewall/.schema_version` | 配置 schema 版本（无损升级依据） |
| `/opt/auto-firewall/backup/` | 配置快照（自动保留最近 10 份，目录权限 700） |

修改配置推荐 `x config add/del/list/edit`（自动校验、备份、去重），或直接编辑文件后等 cron 同步。

## 无损升级说明

- 每次变更前自动全量备份到 `backup/<时间戳>/`；
- 检测到旧版本配置（含"从未有版本标记"的存量安装）时逐级迁移，**注释与无法解析的自定义行原样保留**；
- 迁移失败自动从备份还原，原配置不受影响。
- 与 `reset-config` 的区别：迁移=保留你的配置换新格式；恢复默认=回到全新安装状态（两者都会先备份）。

## Cron 定时任务

| 周期 | 任务 | 说明 |
|------|------|------|
| 每 5 分钟 | `port-check` | 端口差分放行/回收 |
| 每 15 分钟 | `fail2ban-check` | Fail2ban 检测 + jail 配置幂等同步 |
| 每 1 小时 | `cleanup` | 系统/日志/备份清理 |

## 卸载

```bash
x uninstall              # 默认档：只删脚本足迹（profile.d 快捷命令、cron 区块、/opt/auto-firewall）
                         #   ⚠ 系统 ufw/fail2ban 仍在运行（封禁未停止），避免误开防护空洞
x uninstall --purge      # 彻底档：另删脚本加的 ufw 规则(22 默认保留)/还原 Docker 修复/停用并清理 fail2ban
                         #   非交互须加 --yes；删前备份移至 /root/auto-firewall-uninstall-backup-*
```

软件包（ufw/fail2ban）默认不卸载，如需：`sudo apt-get remove --purge ufw fail2ban`。

## 测试

```bash
# 单测（纯函数 + 桩集成，无需 root；bats-core + shellcheck）
bash tests/run.sh

# 端到端：需在 Linux（如 WSL Debian）执行
sudo apt-get install -y bats shellcheck ufw fail2ban iproute2
```

Windows 下仅编辑代码；`ufw/ss` 相关测试必须在 Linux 跑。

## 兼容性

Debian 12 (bookworm) ✅ / Ubuntu 22.04+ ✅ / Ubuntu 24.04 ✅；其他 Debian 系需存在 `/etc/debian_version`。

## 安全建议

1. 安装后立即把你的可信公网 IP 加入 `ip-whitelist.conf`（或 `x config add ip <IP>`），防 Fail2ban 误封；
2. 破坏性操作先用 `--dry-run` 演练（日志有 `[DRYRUN]` 前缀）；
3. 建议配合 SSH 密钥登录；SSH 保护端口为**自动探测**（sshd_config 的 Port 指令 + 实际监听的 sshd 进程，均无结果时回退 22），自定义端口的用户同样受“永不回收 / 不可移出白名单 / purge 默认不删”三重保护；
4. TUI 中文界面依赖 UTF-8 locale（脚本会自动尝试 `C.UTF-8`，失败时按提示 `dpkg-reconfigure locales`）。

## License

MIT
