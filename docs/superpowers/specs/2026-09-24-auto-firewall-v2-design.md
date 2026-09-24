# auto-firewall.sh v2 增强设计（协议扩展 / 无损升级 / TUI / 测试）

- 状态：已定稿（对应实现计划 docs/superpowers/plans/2026-09-24-auto-firewall-v2.md）
- 日期：2026-09-24
- 目标文件：`auto-firewall.sh`（单文件 Bash）
- 兼容性基线：Debian 12 (bookworm) / Ubuntu 22.04+ / Ubuntu 24.04，WSL Debian 验证

## 1. 背景与目标

现有脚本以 `port/proto` 字符串建模端口，仅覆盖 tcp/udp，无版本概念，无测试。本次增强：

1. **协议/端口全维度建模**：IPv6 与监听地址族、端口区间、icmp/原始协议号。
2. **无损升级机制**：版本标记 + 逐级迁移 + 备份回滚，旧配置零损坏。
3. **其他补强**：扫描/ufw 性能、成员判断正确性、Fail2ban jail 正确性、dry-run、shellcheck。
4. **命令行图形化管理界面**：基于 `dialog` 的 TUI；快捷命令 `X`/`x` 作为 `sudo bash auto-firewall.sh` 的命令行替代来启动。
5. **测试**：bats-core 纯函数单测 + WSL Debian 完整运行验证。
6. **卸载功能**：`uninstall` 子命令，两档（保守 / `--purge` 彻底），带确认、备份与 SSH 防锁死。
7. **配置管理**：完善“修改配置”（`config` 增删/编辑/查看）与新增“恢复默认配置”（`reset-config`），均写入前校验与备份。
8. **运维辅助与安全地基**：`ban`/`unban`/`version`/`log` 子命令、全局 flag 解析、变更命令统一加锁、IO 校验与注入防护、备份保留、README/help 同步（见 §2.4–§2.5、§7.3、§9）。

已确认的三个决策点：
- (A) icmp/raw/区间只能作为**白名单**（用户声明、永不自动回收），无法被 ss/netstat 自动发现——认可。
- (B) v2 行语法**保留 `port/proto` 顺序**、扩展 `:区间` 与 `/addr`；旧写法仍兼容——接受。
- (3) D 节补强项**全部纳入**。
- (4) 快捷键调整：`X`/`x` 是**命令行快捷命令**，替代 `sudo bash auto-firewall.sh`（敲 `x` 即开界面、`x <子命令>` 即跑对应动作），而非界面内的按键。

## 2. 核心模型：统一端口描述符

### 2.1 规范化描述符（内部表示）

在代码内部用一个规范化 key 及结构化字段表示一条端口规则：

| 字段 | 取值 | 说明 |
|------|------|------|
| `proto` | `tcp`\|`udp`\|`icmp`\|`esp`\|`ah`\|`gre`\|`any`\|`<1-255>` | 协议 |
| `port_from` | 数字或空 | 起始端口（portless 协议为空） |
| `port_to` | 数字、空、或等于 from | 结束端口（区间时 > from） |
| `family` | `4`\|`6`\|`all` | 地址族，默认 `all` |
| `source` | `whitelist`\|`dynamic` | 白名单端口永不回收 |

**规范化 key（用于 state 文件与去重/成员判断）**：
```
<port-spec>/<proto>[/<addr>]
```
- `port-spec`：`<n>` 或 `<start>:<end>`；portless 协议用 `-`
- `proto`：见上表
- `addr`（可选）：`v4`|`v6`；省略即 `all`

示例：
```
22/tcp              # 双栈 SSH（等价旧格式）
8000:8100/tcp       # 端口区间，白名单专用
443/tcp/v6          # 仅 IPv6
53/udp
icmp                # 等价 -/icmp/all
-/esp               # IPsec ESP
```

### 2.2 纯函数：parse_descriptor

`parse_descriptor "<line>"` → 输出规范化字段（以分隔串或全局变量）。规则：
- 去除行内 `#` 注释与首尾空白。
- 剥离可选 `/<addr>` 后缀，验证为 `v4|v6`，否则报错。
- 按最后一段取 `proto`；若首段为 `-` → portless；否则解析 `port` 或 `start:end`。
- 端口范围校验：`0 < n <= 65535`，`start <= end`。
- 非法输入 → 返回非 0，调用方记录并跳过（不崩溃）。
- 兼容：旧行 `22/tcp` 与 `53/udp  # dns` 原样解析成功。

### 2.3 纯函数：build_ufw_args

`build_ufw_args "<descriptor-key>"` → 打印对应的 ufw 参数串，映射：

| 描述符 | ufw 参数 |
|--------|----------|
| `22/tcp` | `allow 22/tcp` |
| `8000:8100/tcp` | `allow 8000:8100/tcp` |
| `443/tcp/v6` | `allow 443/tcp`（配合 `-6` 前缀 / v6 语义） |
| `icmp` | `allow proto icmp from any to any` |
| `esp` / 协议号 | `allow proto <proto-or-num> from any to any` |

family=v4/v6 通过 ufw 的 v4/v6 目标地址或 `ufw allow` 的 family 处理；实现细节在计划阶段确定，但对外的 build 函数输出必须可单测断言。

**`any` 协议语义（GAP-4）**：ufw 无 `proto any`。`any` 归一化为“无端口全协议”规则：`build_ufw_args` 输出 `allow from <src> to <dst>`（不带 `port`、不带 `proto`），绝不生成 `proto any`；单测需断言这一点。

### 2.4 安全与 IO 规范（G1/G4）
- **IO 读取器按 v2 语法重写**：`read_whitelist` 等原基于 `^[0-9]+/(tcp|udp)` 的解析必须改走 `parse_descriptor`，以支持区间/portless/addr；同时跳过 `# schema-version` 等注释头行。
- **注入防护**：所有外部输入（`config add`、`--editbox` 保存、menu/TUI 参数、IP）均先经 `parse_descriptor`/IP 正则白名单校验；向 `ufw`/`fail2ban-client` 传参一律用数组 `"${args[@]}"`，严禁字符串拼接、`eval`、`sh -c`。

### 2.5 并发与部分失败策略（G2/G3）
- **变更型子命令统一加锁**：`port-check`/`config`/`reset-config`/`uninstall`/`ban`/`unban` 均 `acquire_lock`，与 cron 串行。
- **多步 ufw 尽力而为**：每条规则独立幂等，失败继续处理其余、结束时若有失败则非零退并汇总 `_err`（不做整体事务回滚）。

### 2.6 可测试性架构（GAP-A）
- **路径基址可覆盖**：`SCRIPT_DIR` 改为 `SCRIPT_DIR="${AUTO_FW_HOME:-/opt/auto-firewall}"`（不再硬 readonly），`STATE_FILE`/`LOG_FILE`/`VERSION_FILE`/`WHITELIST_FILE` 等均派生自它；bats 用 `AUTO_FW_HOME=$(mktemp -d)` 指向临时目录，不触碰真实系统。
- **外部命令薄封装**：`ufw`/`fail2ban-client`/`ss`/`systemctl`/`service`/`apt-get` 一律经函数封装（如 `ss_probe`、`ufw_exec`），变更类走 `run_cmd`；bats 通过 PATH 桩或函数覆盖注入，实现 `port_check`/`backup_configs`/`generate_whitelist` 的无 root、无真实防火墙集成测试。

## 3. 扫描与 UFW 应用

### 3.1 扫描（port_check / generate_whitelist 共用）

- 一次 `ss -tlnup` 采集 tcp+udp 监听，**单遍 awk** 解析出 `addr:port proto family`，杜绝每行多次 fork。
- 回退 `netstat -tlnup`（同样单遍解析）。
- 排除 `127.0.0.1`、`::1` 回环监听。
- 公网 IPv6 `[::]:port`、link-local 归入 family=`6`；`0.0.0.0:port` 归入 family=`4`；双栈 `*:port`/同时出现 → `all`。
- 扫描得到的**永远是单端口 tcp/udp 动态规则**（区间/icmp/raw 不会来自扫描）。
- **IPv6 地址解析（GAP-2）**：必须剥离 zone id（`fe80::1%eth0` → `fe80::1`）、将 `[::]`/`*` 识为双栈、link-local(`fe80::/10`) 归 family=6 但默认不作为对外放行目标（仅记录）；地址与端口切分用“最后一个冒号”规则以兼容 IPv6。

### 3.2 ufw 规则表缓存

- 每次 `port_check` 运行**只解析一次** `ufw status numbered`/verbose，构建：
  `规范化key(+family) -> {present:bool, marker:auto-firewall|auto-firewall-whitelist|none}`
- 放行/跳过/回收判定全部查该内存表，替代循环内反复 `ufw status` 与 `grep "^port/proto"` 的脆弱匹配。**（GAP-C）**：marker/comment 一律从 `ufw status numbered`（输出稳定含行尾 `# <comment>`）解析；若某 ufw 版本 numbered 不渲染 comment，则回退 `ufw show added` 获取脚本添加的规则集，避免“读不到 marker → 永不回收”的静默失效。

### 3.3 差分逻辑

- **放行**：当前监听（非白名单）且表中不存在 → `ufw allow ... comment 'auto-firewall'`。
- **确保白名单**：白名单每条描述符（可含区间/icmp/raw）逐一确保存在，marker=`auto-firewall-whitelist`。
- **回收**：`prev_dynamic` 中存在、当前不监听、不在白名单、marker 为 `auto-firewall` → `ufw --force delete`。
- **SSH 保护**：白名单中含 ssh 或端口 22 的记录永不回收。
- **成员判断**：用关联数组精确匹配，彻底移除 `grep -qw`。
- 更新 `ports.state`：仅记录非白名单动态端口，v2 规范化 key，带版本头。

## 4. 无损升级机制

### 4.1 版本常量与标记文件

```
readonly SCRIPT_VERSION="2.0.0"
readonly STATE_SCHEMA_VERSION=2
readonly VERSION_FILE="${SCRIPT_DIR}/.schema_version"
```
各生成的 conf 文件首行加 `# schema-version: 2`。

### 4.2 迁移注册表

`run_migrations()`：
1. 读 `VERSION_FILE`；缺失但已有配置 → 视为 `1`（现有隐式版本）；全新（无任何配置）→ 直接生成 v2、写标记、不迁移。
2. 从 `from` 逐级执行 `migrate_v<N>_to_v<N+1>` 直到 `STATE_SCHEMA_VERSION`。
3. 每级迁移前 `backup_configs()` 全量备份到 `/opt/auto-firewall/backup/<timestamp>/`。

### 4.3 migrate_v1_to_v2

- `ports.state`：旧 `22/tcp` → 补 addr 规范化（默认双栈，保持 `22/tcp`）；确保带版本头。
- `port-whitelist.conf`：逐行 `parse_descriptor`（v1 容错）→ 用 v2 语法回写，保留全部注释与用户自定义行、服务名注释。
  - **非注释且解析不了的行（GAP-1）：原样保留、绝不丢弃**（避免静默删用户自定义）；仅当行能解析时才改写为 v2 语法。
- 更新 `VERSION_FILE`。
- **幂等**：以 `VERSION_FILE` 为准；已是目标版本则跳过。

### 4.4 回滚保证（"无损"核心）

- 迁移在临时目录生成新文件，全部成功后原子 `mv` 覆盖。
- 任一步骤失败 → 从 `backup/<timestamp>/` 还原、`_err` 报错、非 0 退出；原配置不受影响。
- `install` 在初始化/生成前先调用 `run_migrations`。

## 5. 其他补强（全部纳入）

- **Fail2ban jail 正确性**：`nginx-botsearch`/`nginx-bad-request` 改用 `error.log`（与语义匹配）；`nginx-404`/`nginx-ufw` 用 `access.log`。`detect_nginx_logpath` 返回 access 与 error 两个路径。
- **MTA 降级**：无 sendmail/postfix 时，`action` 由 `%(action_mwl)s` 降级为 `%(action_)s`（仅封禁不邮件），避免静默失败。各 nginx jail 仅在其依赖日志文件存在时启用。
- **--dry-run 全局模式**：新增 `DRY_RUN` 开关（环境变量 `AUTO_FW_DRYRUN=1` 或参数 `--dry-run`）；`ufw`/`fail2ban` 变更动作经统一 `run_cmd` 包装，dry-run 下只记录不执行。**GAP-5**：dry-run 下 `run_cmd` 向日志行统一加 `[DRYRUN]` 前缀，便于审计。
- **shellcheck 清理**：补全引号、拆分 `local x=$(...)` 以免吞返回值、清理无用 `|| true`。
- **status 增强**：展示 family、区间、白名单来源、schema 版本。
- **IPV6=yes**：install 时确保 `/etc/default/ufw` 开启 IPv6（因新托管 v6）。**（GAP-B）顺序**：必须在 `init_ufw` 执行 `ufw enable` **之前**写入 `IPV6=yes` 并重载，否则老机器迁移到 v2 后首次启用不会下发 IPv6 规则。
- **备份保留策略（G5）**：`backup_configs()` 写 `/opt/auto-firewall/backup/` 时，仅保留最近 10 份时间戳快照（超出按时间删最旧）；迁移/重置/uninstall 备份均走此函数。**GAP-6**：`backup/` 目录权限收紧为 `700`（含配置快照）。
- **文档同步（G7）**：重写 README.md（特性表 / 快捷命令 / config / reset / uninstall / 双档）与 `show_help`，覆盖全部子命令与新特性；新增 `CHANGELOG.md` 记录 v1→v2 变更。

## 6. 命令行图形化管理界面（TUI）

### 6.1 依赖

`dialog` 纳入 install 检测；缺失时 `apt-get install -y dialog`。非交互/无 dialog 时优雅降级为文本 `help`。

**UTF-8 locale（GAP-3）**：因 TUI 与日志含中文，install/menu 入口检测 `LC_ALL`/`LANG`，非 UTF-8 时优先 `export LC_ALL=C.UTF-8`（Debian 内置）；若仍不可用则提醒用户 `dpkg-reconfigure locales` 生成 UTF-8 locale，避免 dialog 乱码。

### 6.2 命令行快捷方式（替代 `sudo bash auto-firewall.sh`）

`x` / `X` 是**命令行层面的快捷命令**（不是界面内按键）。`install` 时在 `/etc/profile.d/auto-firewall.sh` 写入等价函数：

```bash
afw_shortcut() {
    if [[ $# -eq 0 ]]; then
        sudo bash /opt/auto-firewall/auto-firewall.sh menu
    else
        sudo bash /opt/auto-firewall/auto-firewall.sh "$@"
    fi
}
x() { afw_shortcut "$@"; }
X() { afw_shortcut "$@"; }
```

- 终端直接敲 `x` 或 `X` → 以 root 打开 dialog 管理界面。
- `x port-check` / `x status` / `x cleanup` / `x fail2ban-check` → 完全等价于原 `sudo bash auto-firewall.sh <子命令>`，成为该命令的通用替代。
- `menu` 子命令直接渲染主菜单（不再有"待机屏 + `read -rsn1` 按键门"）。
- 非交互/无 dialog 时 `menu` 降级为文本 help。
- **安装范围（已定稿）**：写入系统级 `/etc/profile.d/auto-firewall.sh`，登录 shell 生效；用户可按需 `unset -f x X` 覆盖。`install` 幂等：写入前先清除旧的 `# BEGIN/END auto-firewall-shortcut` 区块再重写。

### 6.3 dialog 主菜单项

| 项 | 动作 |
|----|------|
| 总览仪表盘 | ufw 状态、动态/白名单端口、Fail2ban 各 jail 封禁计数、内存/磁盘 |
| 端口检测 | 调用 `port_check`，进度条 + 结果 `--msgbox` |
| Fail2ban 检测 | 调用 `fail2ban_check` |
| 系统清理 | 调用 `cleanup` |
| 配置管理（增删/编辑） | 端口/IP 白名单结构化增删或 `--editbox` 文本编辑，写入前校验、备份（见 §7.1） |
| 恢复默认配置 | 调用 `reset-config`（`all/ports/ip/fail2ban`），确认后重建默认（见 §7.2） |
| Fail2ban 封禁管理 | 列出当前 banned IP，选择解封（`fail2ban-client set <jail> banip/unbanip`）；封禁走 `ban <ip>`、解封走 `unban <ip>` 子命令（与 §7.3 共用） |
| 实时日志 | `--tailbox` 展示 `auto-firewall.log` |
| Dry-run 演练 | 以 DRY_RUN 执行 port-check 并展示"将要执行"的动作 |
| 卸载脚本与配置 | 调用 `uninstall`（二次确认；`--purge` 需额外确认与 SSH 风险警示） |
| 版本与日志 | `version` 概览 / `log` tail 日志 |
| 退出 | 退出管理界面（回到 shell） |

所有对系统的变更仍走第 5 节的 `run_cmd`，与 CLI 行为一致；TUI 仅为前端，不复制业务逻辑。

## 7. 配置管理（修改与恢复默认）

两类能力，均为 CLI 子命令 + TUI 菜单项 + `x` 快捷方式；所有写入前先 `backup_configs()` 快照，采用“临时文件→校验→原子 mv”，绝不写入半损坏内容。

### 7.1 修改配置（config）
新增 `config` 子命令族与 TUI“配置管理”分区，提供三种编辑方式：
- **结构化增删**（推荐，经校验）：
  - `config add port <spec>` / `config del port <spec>`：写入 `port-whitelist.conf`；`<spec>` 先经 `parse_descriptor` 校验，非法即拒绝并报错；去重。
  - `config add ip <cidr>` / `config del ip <cidr>`：写入 `ip-whitelist.conf`；经 IPv4/IPv6/CIDR 正则校验；内置回环/内网默认项不可删（删除时拒绝并提示）。
- **整文件文本编辑**：`config edit [ports|ip]` → 用 `$EDITOR`（非交互/无 TTY 回退 `dialog --editbox`）打开；保存时逐行 `parse_descriptor`/IP 校验，收集非法行→`dialog --yesno` 让用户选择“忽略非法行保存 / 放弃修改”；变更生效。
- **查看**：`config list [ports|ip]` 规范化展示（含 family/区间/来源）。
- **生效联动**：端口白名单变更后可选立即 `apply_whitelist` 放行；IP 白名单变更触发 `rebuild_f2b_jail` + `fail2ban reload`。是否立即生效由交互确认决定（非交互默认仅写入，由下一轮 cron 生效），避免意外改动运行中防火墙。

### 7.2 恢复默认配置（reset-config）
新增 `reset-config` 子命令，把可编辑配置恢复到“全新安装”默认，**不卸载脚本、不改 schema 版本**：
- 范围（可 `all|ports|ip|fail2ban` 限定，默认 `all`）：
  - ports：删除现有 `port-whitelist.conf` → `generate_whitelist` 基于当前监听重新扫描生成（含 22，安全）；清空动态 `ports.state` 并触发一次 `port_check` 重建。
  - ip：`init_ip_whitelist --force` 重新生成内置默认（回环 + A/B/C 内网段）。
  - fail2ban：`rebuild_f2b_jail` 按当前 IP 白名单重建 jail.local，**并 `fail2ban reload`**（GAP-7）使改动即时生效。
- 前置改造：`init_ip_whitelist` 新增 `--force`（覆盖已存在文件），`generate_whitelist` 已可覆盖。
- 安全：执行前 `backup_configs()` + `dialog --yesno` 确认；因默认端口来自“当前监听扫描”，不会关掉正在使用端口，避免 SSH 锁死。`--dry-run` 预览。
- 与“无损升级”区分：reset 是回到默认，migration 是保留用户配置换新版式——两者互不混淆。

### 7.3 Fail2ban 手动封禁 / 解封（G11）
- `ban <ip> [时长]`：`ufw insert 1 deny from <ip> ... comment 'auto-firewall-manual'`（默认时长取 `F2B_BANTIME`），供紧急拉黑。
- `unban <ip>`：删除对应 deny 规则。
- 均经 IP 合法性校验 + `acquire_lock` + `run_cmd`（dry-run 兼容）。

## 8. 卸载功能（脚本与配置）

新增 `uninstall` 子命令（`main` 分发；`x uninstall` 亦可；TUI 菜单含"卸载"项）。分两档，默认保守避免远程锁死：

### 8.1 默认 uninstall（仅移除脚本自身足迹）
- 删除 `/etc/profile.d/auto-firewall.sh`（`x`/`X` 快捷函数）。
- 从 `/etc/crontab` 移除 `# BEGIN/END auto-firewall` 区块。
- 删除 `/opt/auto-firewall/`（配置、state、logs、backup、`.schema_version`）。
- **保留** ufw 规则、fail2ban 配置、Docker after.rules、已装软件包（ufw/fail2ban/dialog）——不动系统防火墙状态，避免误删 22 端口规则导致 SSH 锁死。
- **语义澄清（GAP-D）**：默认档保留 fail2ban jail，即自动封禁仍在运行；卸载时明确提示“系统级 ufw/fail2ban 仍在生效，如需连同封禁一并停用请改用 `uninstall --purge`”，并写入 README。

### 8.2 uninstall --purge（彻底清理，含防火墙足迹）
在默认基础上追加：
- 删除**脚本添加的** ufw 规则：仅匹配 comment 含 `auto-firewall` / `auto-firewall-whitelist` 的规则。
  - **SSH 保护**：端口 22（或白名单含 ssh）的放行规则默认**不删**，除非 `--purge --force-ssh`。
- 还原 Docker 修复：从最新 `after.rules.bak.<ts>` 备份恢复，或剥离 `# BEGIN/END auto-firewall DOCKER-USER fix` 标记区块。
- 移除 fail2ban 生成文件：`jail.local`、`action.d/ufw.conf`、`filter.d/nginx-ufw.conf`、`filter.d/nginx-404.conf`；`systemctl disable --now fail2ban`。
- 仅当脚本当初装了 `dialog` 且无其他依赖时，可选 `apt-get remove -y dialog`（默认不卸软件包）。

### 8.3 安全与交互
- 执行前强制确认：交互模式弹 `dialog --yesno`（`--purge` 二次确认并警示 SSH 风险）；非交互必须显式传 `--yes`，否则中止。
- `--purge` 前先 `backup_configs()` 快照到 `/opt/auto-firewall/backup/pre-uninstall-<ts>/`，并在删 `/opt/auto-firewall` 前将该备份移至 `/root/auto-firewall-uninstall-backup-<ts>/` 保留。
- 幂等：文件/区块不存在时静默跳过。
- dry-run 兼容：`--purge --dry-run` 只打印将删除/还原的内容。

## 9. CLI 参数约定、版本与日志（G6/G8/G9/G10）

- **全局 flag 解析（G6）**：`--dry-run` / `--yes` / `--purge` / `--force-ssh` 等可出现在子命令前后；`main` 先用一个循环扫描 argv 剥离全局 flag 存入变量，再将剩余 positional 参数分发子命令（`menu` 子命令因此可为 `menu --purge` 形式）。
- **install 生效提示（G8）**：`do_install` 结束打印一行——“快捷命令 `x`/`X` 已写入 /etc/profile.d，请重新登录或 `source /etc/profile.d/auto-firewall.sh` 以生效”。
- **version 子命令（G9）**：`version`（`x version`）打印 `SCRIPT_VERSION`、`STATE_SCHEMA_VERSION`、系统发行版与 ufw/fail2ban/dialog 版本。
- **log 子命令（G10）**：`log [N]`（`x log`）在终端 `tail -n N`（默认 100）展示 `auto-firewall.log`，与 TUI 实时日志对应。

## 10. 测试方案

### 10.1 脚本可 source 化

末尾 `main "$@"` 改为守卫：
```
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
```
使 bats 能 `source auto-firewall.sh` 加载函数而不执行。

### 10.2 bats-core 单元测试（tests/）

针对纯函数，无需 root/网络：
- `parse_descriptor.bats`：单端口/区间/portless/v4/v6/旧格式/畸形输入。
- `scanner_parse.bats`：喂入 `ss` 原始输出样本（含 `[::]:22`、`fe80::1%eth0`、`0.0.0.0:80`）→ 断言 family/去重/zone-id 剥离正确（GAP-2）。
- `build_ufw_args.bats`：每类描述符 → 期望 ufw 参数串。
- `whitelist_io.bats`：`read_whitelist` 去重、注释剥离、v1 容错。
- `migration.bats`：给定 v1 文件夹具 → 运行 `migrate_v1_to_v2` → 断言 v2 输出、注释保留、回滚路径（构造失败）。
- `diff_logic.bats`：桩 `ss`/`ufw status` 输入，断言"应放行/应回收"集合。
- `dry_run.bats`：`run_cmd` 在 DRY_RUN 下不真正执行。
- `config_io.bats`：`config add/del` 合法性校验、去重、回环/内网默认项不可删、非法行拒绝。
- `reset_config.bats`：`reset-config` 重扫默认端口与 IP 默认、含 22、不丢 schema 版本。
- `flag_parse.bats`：全局 `--dry-run/--yes/--purge/--force-ssh` 在子命令前/后均可正确剥离。
- `backup_retention.bats`：>10 份快照时 `backup_configs()`/`cleanup` 仅保留最近 10 份。

### 10.3 静态与集成

- `shellcheck auto-firewall.sh` 纳入 `tests/run.sh`（须 0 error）。
- 提供可选 GitHub Actions：shellcheck + bats（ubuntu-latest）。
- **WSL Debian 完整运行**（实现阶段执行）：
  1. `wsl -d Debian` 内 `apt-get install -y dialog bats shellcheck ufw fail2ban iproute2`。
  2. `bash tests/run.sh` 全绿。
  3. `sudo bash auto-firewall.sh install` → 验证目录/配置/cron 生成。
  4. 造一个 v1 配置 → `install` → 验证无损迁移与备份。
  5. `port-check` / `status` / `fail2ban-check` / `cleanup` 各跑一遍。
  6. 重新登录 shell 使 `/etc/profile.d` 生效后，命令行输入 `x` → 验证 dialog 界面渲染与只读项（总览/日志）；`x status` 等快捷子命令等价性；变更项在 dry-run 下验证；确认 `x`/`X` 函数正确注入且无命令冲突。
  7. 卸载验证：`uninstall --dry-run` 预览 → 默认档实卸后校验 cron/profile.d//opt 已清理且防火墙未被误删；`--purge --dry-run` 预览及备份落盘。
  8. 配置管理：`config add port 8000:8100/tcp`、非法值拒绝、`config edit` 非法行处理；`reset-config --dry-run` 预览与实执行后校验恢复默认且 22 仍在（无锁死）。
  9. 辅助子命令：`version`/`log`/`ban <ip>`/`unban <ip>` 各验证；造 >10 份备份→`cleanup` 校验仅留最近 10 份。

### 10.4 环境约束

bats/ufw/ss 测试须在 Linux（WSL Debian）执行；Windows Git Bash 仅编辑代码。会在文档中明确说明。

## 11. 影响面与兼容性

- 新增只读常量与函数，不改变现有 CLI 子命令签名（向后兼容）。
- 配置格式升级由迁移自动完成，用户旧配置无损。
- `menu`/TUI 为新增面，移除或不可用时降级为 help，不影响 cron。
- `install` 会新增 `/etc/profile.d/auto-firewall.sh`（`x`/`X` 快捷函数）；需配套提供卸载途径（重装前幂等覆盖，或 `install` 时先清理旧区块）。
- 迁移与备份写入 `backup/`（纳入 `.gitignore`）。
- 新增 `uninstall`（默认档 / `--purge`）：默认档不动系统防火墙，`--purge` 才清理脚本 ufw/fail2ban/docker 足迹，均带备份与 SSH 防锁死。
- 新增 `config`（增删/编辑/查看）与 `reset-config`（恢复默认）；均写入前校验与备份，非法输入不入库。
- 新增 `ban`/`unban`/`version`/`log` 子命令；变更型命令统一加锁；`main` 支持全局 flag 前置/后置解析；所有 ufw/fail2ban 传参数组化防注入。

## 12. 非目标（YAGNI）

- 不做多机集中管理/远程控制台。
- 不做 web 界面。
- 不引入非 Debian 系支持。
- 不自动发现 icmp/raw/区间（协议本质决定，见 1 节）。
- 不做 ufw 规则变更的整体事务回滚（每条独立幂等，见 §2.5）。
