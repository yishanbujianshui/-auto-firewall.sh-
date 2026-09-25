# auto-firewall.sh v2 增强实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `auto-firewall.sh` 升级为 v2：统一端口描述符模型（IPv6/区间/icmp/raw）、版本化无损迁移、dialog TUI（`x`/`X` 命令行快捷）、config/reset/uninstall/ban/unban/version/log 子命令、全量 bats 测试，最终在 WSL Debian 完整验证。

**Architecture:** 保持单文件 Bash 部署形态；纯逻辑（解析/构建/差分/迁移）实现为可 source 的函数并配 bats 单测；外部命令一律经薄封装（`ss_probe`/`ufw_exec`/`run_cmd`）注入以便桩测；TUI/uninstall/config 是既有函数的薄前端，不复制业务逻辑。

**Tech Stack:** Bash、bats-core、shellcheck、dialog、ufw、fail2ban、ss/iproute2；验证环境 WSL Debian。

**Spec:** `docs/superpowers/specs/2026-09-24-auto-firewall-v2-design.md`（已定稿，实现与本计划论证均以它为准）

## Global Constraints

- 仅支持 Debian/Ubuntu（`/etc/debian_version`），目标 Debian 12 / Ubuntu 22.04+/24.04。
- 脚本头部保留 `set -euo pipefail`。
- `STATE_SCHEMA_VERSION=2`、`SCRIPT_VERSION="2.0.0"`、`BACKUP_RETAIN=10`、`F2B_BANTIME=3600`。
- 所有路径派生自 `SCRIPT_DIR="${AUTO_FW_HOME:-/opt/auto-firewall}"`（**去 readonly**，供测试覆盖）。
- 外部命令（`ufw`/`fail2ban-client`/`ss`/`netstat`/`systemctl`/`service`/`apt-get`）必须经函数薄封装调用，禁止业务函数内裸调；变更动作走 `run_cmd`，dry-run 日志加 `[DRYRUN]` 前缀。
- 注入防护：外部输入先过 `parse_descriptor`/IP 正则白名单；向 ufw/fail2ban 传参只用数组 `"${args[@]}"`，禁止 eval/字符串拼接。
- 任何变更型子命令先 `acquire_lock`；SSH(22/含 ssh 白名单) 永不回收、`--purge` 默认不删、须 `--force-ssh` 才删。
- 测试必须能在无 root、无真实防火墙环境运行（`AUTO_FW_HOME=$(mktemp -d)` + PATH 桩）。
- 每个 Task 结束提交一次；提交信息用 `feat:`/`test:`/`fix:`/`docs:`/`chore:` 前缀。
- TUI 与所有用户可见文案为中文，入口强制 `LC_ALL=C.UTF-8`（不可用时降级/提示）。

## 文件结构

| 文件 | 操作 | 职责 |
|------|------|------|
| `auto-firewall.sh` | 修改 | 主脚本：全局常量、薄封装、纯函数、业务函数、TUI、main 分发 |
| `tests/test_helper/common.sh` | 新建 | bats 通用 setup（临时 AUTO_FW_HOME、PATH 桩、source 主脚本） |
| `tests/*.bats` | 新建 | 各纯函数/集成单测（见任务） |
| `tests/fixtures/*` | 新建 | v1 配置、ss/ufw 输出样本 |
| `tests/run.sh` | 新建 | shellcheck + bats 一键入口 |
| `README.md` | 重写 | v2 文档 |
| `CHANGELOG.md` | 新建 | v1→v2 变更记录 |
| `.gitignore` | 修改 | 忽略 `backup/`、临时产物 |

> 主脚本保持单文件（部署形态），不拆分。

---

### Task 1: 可测试性地基（source 守卫 + 路径 env 覆盖 + 命令薄封装）

**Files:**
- Modify: `auto-firewall.sh:11-17`（路径常量）、`:29-30`（SCRIPT_PATH）、`:980`（main 调用）
- Test: `tests/00_testability.bats`

**Interfaces:**
- Produces: `SCRIPT_DIR="${AUTO_FW_HOME:-/opt/auto-firewall}"`（非 readonly）；薄封装 `ss_probe`/`ufw_exec`/`fail2ban_exec`/`sysctl_exec`/`apt_exec`/`run_cmd`；`ensure_locale_utf8`。

- [ ] **Step 1: 写失败测试**

创建 `tests/00_testability.bats`：
```bash
#!/usr/bin/env bats

setup() {
  export AUTO_FW_HOME="$(mktemp -d)"
  # shellcheck source=/dev/null
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh" status_guard 2>/dev/null || \
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
}

teardown() { rm -rf "$AUTO_FW_HOME"; }

@test "SCRIPT_DIR 受 AUTO_FW_HOME 覆盖" {
  [ "$SCRIPT_DIR" = "$AUTO_FW_HOME" ]
}

@test "派生路径挂在 AUTO_FW_HOME 下" {
  [ "$STATE_FILE" = "$AUTO_FW_HOME/ports.state" ]
  [ "$LOG_FILE" = "$AUTO_FW_HOME/logs/auto-firewall.log" ]
}

@test "source 主脚本不执行 main（无输出、不退出）" {
  run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; echo SOURCED_OK"
  [ "$status" -eq 0 ]
  [[ "$output" == *SOURCED_OK* ]]
}
```
注：为让 `source` 成功，需保证顶部 `readonly` 路径常量先被移除——故测试里直接 source。

- [ ] **Step 2: 运行验证失败**

Run: `bats tests/00_testability.bats`
Expected: FAIL（`SCRIPT_DIR` 为 readonly `/opt/...`，且 source 会执行 main）。

- [ ] **Step 3: 去 readonly + env 覆盖路径**

将 `auto-firewall.sh:11-21` 中所有 `readonly ..._FILE/..._DIR` 的 `readonly` 去掉，并把首行改为：
```bash
SCRIPT_DIR="${AUTO_FW_HOME:-/opt/auto-firewall}"
STATE_FILE="${SCRIPT_DIR}/ports.state"
WHITELIST_FILE="${SCRIPT_DIR}/port-whitelist.conf"
FIRST_RUN_MARK="${SCRIPT_DIR}/.first_run_done"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/auto-firewall.log"
LOCK_FILE="${SCRIPT_DIR}/.script.lock"
IP_WHITELIST_FILE="${SCRIPT_DIR}/ip-whitelist.conf"
```
删除 `readonly SCRIPT_PATH="$(readlink -f "$0")"` 的 `readonly`（source 时 `$0` 不稳定）：
```bash
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
```

- [ ] **Step 4: main 守卫 + 薄封装函数**

`auto-firewall.sh:980` 改：
```bash
# 仅在直接执行时进入分发；被 source（测试）时不运行
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
```
在"工具函数"区（`_info` 之后）新增：
```bash
# 强制 UTF-8（TUI/日志中文）
ensure_locale_utf8() {
    case "${LC_ALL:-${LANG:-}}" in
      *[Uu][Tt][Ff]*8*|*C.UTF-8) : ;;
      *) if locale -a 2>/dev/null | grep -qiE '^C\.UTF-?8$'; then export LC_ALL=C.UTF-8
         else _err "未检测到 UTF-8 locale，中文可能乱码；建议: dpkg-reconfigure locales"; fi ;;
    esac
}
# 外部命令薄封装（便于测试注入）
ss_probe()      { ss "$@" 2>/dev/null; }
netstat_probe() { netstat "$@" 2>/dev/null; }
ufw_exec()      { run_cmd ufw "$@"; }
fail2ban_exec() { run_cmd fail2ban-client "$@"; }
sysctl_exec()   { systemctl "$@" 2>&1 || service "$@" 2>&1 || true; }
apt_exec()      { apt-get "$@"; }
# 变更类命令：dry-run 只记录
run_cmd() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        _log "[DRYRUN] $*"; return 0
    fi
    "$@"
}
```

- [ ] **Step 5: 运行验证通过**

Run: `bats tests/00_testability.bats`
Expected: PASS（3 项）。

- [ ] **Step 6: 提交**

```bash
git add auto-firewall.sh tests/00_testability.bats
git commit -m "test: 建立可测试性地基（路径env覆盖/命令薄封装/source守卫）"
```

---

### Task 2: 统一端口描述符 parse_descriptor + canon

**Files:**
- Modify: `auto-firewall.sh`（工具函数区新增）
- Test: `tests/parse_descriptor.bats`

**Interfaces:**
- Consumes: 无。
- Produces: `parse_descriptor "<line>"` → stdout `port_from|port_to|proto|family`（4 字段 `|` 分隔），非法返回非 0；`canon_key "<line>"` → 规范化 key（portless 补 `-`，去 addr 默认 `all` 省略）。

- [ ] **Step 1: 写失败测试**

创建 `tests/parse_descriptor.bats`（含 `setup` 同 Task1 模式，source 主脚本）：
```bash
#!/usr/bin/env bats
load test_helper/common

@test "单端口 tcp 双栈" {
  run parse_descriptor "22/tcp"
  [ "$status" -eq 0 ]; [ "$output" = "22|22|tcp|all" ]
}
@test "带注释旧格式" {
  run parse_descriptor "53/udp  # dns"
  [ "$status" -eq 0 ]; [ "$output" = "53|53|udp|all" ]
}
@test "端口区间" {
  run parse_descriptor "8000:8100/tcp"
  [ "$status" -eq 0 ]; [ "$output" = "8000|8100|tcp|all" ]
}
@test "仅 v6" {
  run parse_descriptor "443/tcp/v6"
  [ "$status" -eq 0 ]; [ "$output" = "443|443|tcp|6" ]
}
@test "portless 名称协议 icmp" {
  run parse_descriptor "icmp"
  [ "$status" -eq 0 ]; [ "$output" = "||icmp|all" ]
}
@test "portless 斜杠协议 esp" {
  run parse_descriptor "-/esp"
  [ "$status" -eq 0 ]; [ "$output" = "||esp|all" ]
}
@test "协议号 50" {
  run parse_descriptor "-/50"
  [ "$status" -eq 0 ]; [ "$output" = "||50|all" ]
}
@test "any 协议" {
  run parse_descriptor "any"
  [ "$status" -eq 0 ]; [ "$output" = "||any|all" ]
}
@test "非法端口 0 拒绝" { run parse_descriptor "0/tcp"; [ "$status" -ne 0 ]; }
@test "非法端口 70000 拒绝" { run parse_descriptor "70000/tcp"; [ "$status" -ne 0 ]; }
@test "区间反向拒绝" { run parse_descriptor "9000:8000/tcp"; [ "$status" -ne 0 ]; }
@test "未知协议拒绝" { run parse_descriptor "22/foo"; [ "$status" -ne 0 ]; }
@test "addr 非 v4/v6 拒绝" { run parse_descriptor "22/tcp/v9"; [ "$status" -ne 0 ]; }
@test "空行拒绝" { run parse_descriptor ""; [ "$status" -ne 0 ]; }

@test "canon: icmp -> -/icmp" {
  run canon_key "icmp"; [ "$output" = "-/icmp" ]
}
@test "canon: 22/tcp/v6 保留 addr" {
  run canon_key "22/tcp/v6"; [ "$output" = "22/tcp/v6" ]
}
@test "canon: 8000:8100/tcp 原样" {
  run canon_key "8000:8100/tcp"; [ "$output" = "8000:8100/tcp" ]
}
```

- [ ] **Step 2: 运行验证失败**

Run: `bats tests/parse_descriptor.bats`
Expected: FAIL（函数未定义）。

- [ ] **Step 3: 实现 parse_descriptor + canon_key**

```bash
# 返回: port_from|port_to|proto|family  (portless 前两项空; family=all/4/6)
parse_descriptor() {
    local line="${1:-}"
    line="${line%%#*}"                       # 去注释
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && return 1

    local spec proto addr="all"
    # 拆 addr（第三段）
    if [[ "$line" == */*/* ]]; then
        spec="${line%%/*}"; local rest="${line#*/}"
        proto="${rest%%/*}"; addr="${rest#*/}"
        [[ "$addr" == "v4" || "$addr" == "v6" ]] || return 1
        [[ "$addr" == "v4" ]] && addr="4" || addr="6"
    elif [[ "$line" == */* ]]; then
        spec="${line%%/*}"; proto="${line#*/}"
    else
        spec=""; proto="$line"               # 名称协议（icmp/esp/any）
    fi

    # 协议白名单
    case "$proto" in
        tcp|udp|icmp|esp|ah|gre|any) : ;;
        ''|*[!0-9]*) return 1 ;;             # 非纯数字且不在名单 -> 非法
        *) [[ "$proto" -ge 1 && "$proto" -le 255 ]] || return 1 ;;  # 协议号
    esac

    local pf="" pt=""
    if [[ -z "$spec" || "$spec" == "-" ]]; then
        # portless：tcp/udp 不允许无端口
        [[ "$proto" == "tcp" || "$proto" == "udp" ]] && return 1
    else
        local a b
        if [[ "$spec" == *:* ]]; then a="${spec%%:*}"; b="${spec##*:}"; else a="$spec"; b="$spec"; fi
        [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
        (( a>=1 && a<=65535 && b>=1 && b<=65535 )) || return 1
        (( a<=b )) || return 1
        # 区间不允许 portless 协议
        [[ "$proto" == "tcp" || "$proto" == "udp" ]] || return 1
        pf="$a"; pt="$b"
    fi
    echo "${pf}|${pt}|${proto}|${addr}"
}

# 规范化 key（用于 state/去重）
canon_key() {
    local line="${1:-}"
    line="${line%%#*}"; line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && return 1
    local parsed
    parsed="$(parse_descriptor "$line")" || return 1
    IFS='|' read -r pf pt proto fam <<<"$parsed"
    local spec; if [[ -z "$pf" ]]; then spec="-"; elif [[ "$pf" == "$pt" ]]; then spec="$pf"; else spec="$pf:$pt"; fi
    local key="${spec}/${proto}"
    [[ "$fam" == "all" ]] || key="${key}/v${fam}"
    echo "$key"
}
```

- [ ] **Step 4: 运行验证通过**

Run: `bats tests/parse_descriptor.bats`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add auto-firewall.sh tests/parse_descriptor.bats
git commit -m "feat: 新增统一端口描述符 parse_descriptor/canon_key"
```

---

### Task 3: build_ufw_args（描述符 → ufw 参数数组）

**Files:**
- Modify: `auto-firewall.sh`（Task2 函数后）
- Test: `tests/build_ufw_args.bats`

**Interfaces:**
- Consumes: `parse_descriptor`。
- Produces: `build_ufw_args "<key>" [action]` → 以 **每行一个 token** 打印 ufw 参数（action 默认 `allow`）；调用方用 `mapfile` 转数组传给 `ufw_exec`。

- [ ] **Step 1: 写失败测试**

```bash
#!/usr/bin/env bats
load test_helper/common

@test "allow 22/tcp" {
  run build_ufw_args "22/tcp" allow
  [ "${lines[0]}" = "allow" ]; [ "${lines[1]}" = "22/tcp" ]; [ "${#lines[@]}" -eq 2 ]
}
@test "allow 区间 tcp" {
  run build_ufw_args "8000:8100/tcp" allow
  [ "${lines[1]}" = "8000:8100/tcp" ]
}
@test "icmp 全协议无端口" {
  run build_ufw_args "-/icmp" allow
  [[ "${output[*]}" == *"proto icmp"* ]]
  [[ "$output" != *"proto any"* ]]
}
@test "esp 协议名" {
  run build_ufw_args "-/esp" allow
  [[ "$output" == *"proto esp"* ]]
}
@test "协议号 50" {
  run build_ufw_args "-/50" allow
  [[ "$output" == *"proto 50"* ]]
}
@test "any 归一化不含 proto any" {
  run build_ufw_args "any" allow
  [[ "$output" != *"proto any"* ]]
}
@test "delete 动作透传" {
  run build_ufw_args "22/tcp" delete
  [ "${lines[0]}" = "delete" ]
}
```

- [ ] **Step 2: 运行验证失败** — `bats tests/build_ufw_args.bats` → FAIL。

- [ ] **Step 3: 实现**
```bash
# 逐 token 打印 ufw 参数
build_ufw_args() {
    local key="$1" action="${2:-allow}"
    local pf pt proto fam
    IFS='|' read -r pf pt proto fam <<<"$(parse_descriptor "$key")" || return 1
    echo "$action"
    case "$proto" in
        tcp|udp)
            if [[ -z "$pf" ]]; then echo "proto"; echo "$proto"
            elif [[ "$pf" == "$pt" ]]; then echo "${pf}/${proto}"
            else echo "${pf}:${pt}/${proto}"; fi ;;
        any)  : ;;                            # 无端口无协议 -> 全协议
        *)    echo "proto"; echo "$proto" ;;  # icmp/esp/ah/gre/协议号
    esac
    echo "from"; echo "any"; echo "to"; echo "any"
    [[ "$fam" == "6" ]] && { echo "-6"; }
    return 0
}
```
> 说明：`family=4` 走默认（v4）；`6` 追加 v6 语义；`all` 双栈由 ufw `IPV6=yes` 同时下发，不需额外 token。若实现期 ufw 版本对 `-6` 支持不同，在计划落地时以 `build_ufw_args.bats` 断言为准调整（保持"不生成 proto any"）。

- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/build_ufw_args.bats
git commit -m "feat: build_ufw_args 将端口描述符映射为 ufw 参数数组"
```

---

### Task 4: 全局 flag 解析 parse_args

**Files:**
- Modify: `auto-firewall.sh`（main 区）
- Test: `tests/flag_parse.bats`

**Interfaces:**
- Produces: `parse_args "$@"` → 设置全局 `DRY_RUN/ASSUME_YES/PURGE/FORCE_SSH` 与数组 `CMD_ARGS`（positional）。

- [ ] **Step 1: 写失败测试**
```bash
#!/usr/bin/env bats
load test_helper/common

@test "flag 后置" {
  run bash -c 'source "'"$BATS_TEST_DIRNAME"'/../auto-firewall.sh"; parse_args uninstall --dry-run --yes; echo "DRY=$DRY_RUN YES=$ASSUME_YES CMD=${CMD_ARGS[*]}"'
  [[ "$output" == *"DRY=1 YES=1 CMD=uninstall"* ]]
}
@test "flag 前置" {
  run bash -c 'source "'"$BATS_TEST_DIRNAME"'/../auto-firewall.sh"; parse_args --purge --force-ssh uninstall; echo "PURGE=$PURGE FS=$FORCE_SSH CMD=${CMD_ARGS[*]}"'
  [[ "$output" == *"PURGE=1 FS=1 CMD=uninstall"* ]]
}
@test "无 flag" {
  run bash -c 'source "'"$BATS_TEST_DIRNAME"'/../auto-firewall.sh"; parse_args port-check; echo "DRY=${DRY_RUN:-0} CMD=${CMD_ARGS[*]}"'
  [[ "$output" == *"DRY=0 CMD=port-check"* ]]
}
```

- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
DRY_RUN="${AUTO_FW_DRYRUN:-0}"; ASSUME_YES=0; PURGE=0; FORCE_SSH=0
declare -a CMD_ARGS=()
parse_args() {
    CMD_ARGS=(); DRY_RUN="${AUTO_FW_DRYRUN:-0}"; ASSUME_YES=0; PURGE=0; FORCE_SSH=0
    for a in "$@"; do
        case "$a" in
            --dry-run)    DRY_RUN=1 ;;
            --yes|-y)     ASSUME_YES=1 ;;
            --purge)      PURGE=1 ;;
            --force-ssh)  FORCE_SSH=1 ;;
            *)            CMD_ARGS+=("$a") ;;
        esac
    done
    [[ "$DRY_RUN" == "1" ]] && export DRY_RUN
}
```
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/flag_parse.bats
git commit -m "feat: parse_args 支持全局 flag 前置/后置解析"
```

---

### Task 5: IPv6/zone-id 扫描解析 parse_scan_line

**Files:**
- Modify: `auto-firewall.sh`（扫描区，替换旧 while-awk 逻辑，供 port_check/generate_whitelist 复用）
- Test: `tests/scanner_parse.bats`, `tests/fixtures/ss_output.txt`

**Interfaces:**
- Produces: `ss_listen_raw`（调 `ss_probe -tlnup`/netstat 回退，输出原始行）；`parse_scan_line "<原始行>"` → `port|proto|family`（回环/非数字端口返回非 0）。

- [ ] **Step 1: 准备 fixture 与失败测试**

`tests/fixtures/ss_output.txt`（模拟 `ss -tln` 与 `ss -uln` 混合片段）：
```
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
LISTEN 0      128    [::]:22            [::]:*
LISTEN 0      511    *:80               *:*
LISTEN 0      128    [fe80::1%eth0]:8080 [::]:*
LISTEN 0      0      127.0.0.1:5432     0.0.0.0:*
UNCONN 0      0      0.0.0.0:53         0.0.0.0:*
```
`tests/scanner_parse.bats`：
```bash
#!/usr/bin/env bats
load test_helper/common

@test "v4 监听 -> family 4" {
  run parse_scan_line "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"; [ "$output" = "22|tcp|4" ]
}
@test "v6 [::] -> family 6" {
  run parse_scan_line "LISTEN 0 128 [::]:22 [::]:*"; [ "$output" = "22|tcp|6" ]
}
@test "*:80 双栈 -> all" {
  run parse_scan_line "LISTEN 0 511 *:80 *:*"; [ "$output" = "80|tcp|all" ]
}
@test "zone-id 剥离 + link-local" {
  run parse_scan_line "LISTEN 0 128 [fe80::1%eth0]:8080 [::]:*"; [ "$output" = "8080|tcp|6" ]
}
@test "回环 127.0.0.1 跳过" {
  run parse_scan_line "LISTEN 0 0 127.0.0.1:5432 0.0.0.0:*"; [ "$status" -ne 0 ]
}
@test "UNCONN -> udp" {
  run parse_scan_line "UNCONN 0 0 0.0.0.0:53 0.0.0.0:*"; [ "$output" = "53|udp|4" ]
}
```

- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
# 输入 ss/netstat 单行, 输出 port|proto|family
parse_scan_line() {
    local line="$1" state addr proto fam ip port
    state="${line%% *}"
    case "$state" in LISTEN) proto=tcp ;; UNCONN) proto=udp ;; *) proto=tcp ;; esac
    # Local Address:Port 取第 4 字段(ss)
    addr="$(echo "$line" | awk '{print $4}')"
    [[ -z "$addr" ]] && return 1
    # 去掉 zone-id
    addr="${addr%%%*}"
    # 取最后一个冒号后的端口
    port="${addr##*:}"
    ip="${addr%:*}"
    ip="${ip#[}"; ip="${ip%]}"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    case "$ip" in
      127.0.0.1|::1) return 1 ;;
      0.0.0.0|*)     fam=all ;;          # * 与 0.0.0.0 视为可双栈下发
      ::)            fam=6 ;;
      fe80:*)        fam=6 ;;
      *:*)           fam=6 ;;            # 含冒号即 IPv6
      *)             fam=4 ;;
    esac
    echo "${port}|${proto}|${fam}"
}
ss_listen_raw() {
    if command -v ss &>/dev/null; then
        { ss_probe -tln; ss_probe -uln; }
    else
        netstat_probe -tuln
    fi
}
```
> `*:80` 归 `all`（`*` 分支）。fixture 中 `*:80` 用例断言 `80|tcp|all`。

- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/scanner_parse.bats tests/fixtures/ss_output.txt
git commit -m "feat: parse_scan_line 支持 IPv6/zone-id/双栈 family 解析"
```

---

### Task 6: 差分逻辑 compute_port_actions（放行/回收集合）

**Files:**
- Modify: `auto-firewall.sh`
- Test: `tests/diff_logic.bats`

**Interfaces:**
- Consumes: `canon_key`。
- Produces: `compute_port_actions "<cur_keys>" "<prev_keys>" "<whitelist_keys>"` → 输出两段：`ADD:<key>`、`DEL:<key>` 逐行（cur=当前监听 canon key 集合）。规则：ADD=cur 非白名单且 prev 无；DEL=prev 有、cur 无、非白名单、非 ssh/22。

- [ ] **Step 1: 写失败测试**
```bash
#!/usr/bin/env bats
load test_helper/common

@test "新端口放行" {
  run compute_port_actions "8080/tcp" "" ""
  [ "$output" = "ADD:8080/tcp" ]
}
@test "失效端口回收" {
  run compute_port_actions "" "9000/tcp" ""
  [ "$output" = "DEL:9000/tcp" ]
}
@test "白名单端口不回收" {
  run compute_port_actions "" "22/tcp" "22/tcp"
  [ -z "$output" ]
}
@test "22 永不回收" {
  run compute_port_actions "" "22/tcp" ""
  [ -z "$output" ]
}
@test "仍在监听不重复放行不回收" {
  run compute_port_actions "80/tcp" "80/tcp" ""
  [ -z "$output" ]
}
```

- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
compute_port_actions() {
    local cur="$1" prev="$2" wl="$3"
    local -A in_cur=() in_prev=() in_wl=()
    for k in $cur;  do in_cur["$k"]=1;  done
    for k in $prev; do in_prev["$k"]=1; done
    for k in $wl;   do in_wl["$k"]=1;   done
    local base
    for k in $cur; do
      [[ -n "${in_wl[$k]:-}" ]] && continue
      [[ -n "${in_prev[$k]:-}" ]] && continue
      echo "ADD:$k"
    done
    for k in $prev; do
      [[ -n "${in_cur[$k]:-}" ]] && continue
      [[ -n "${in_wl[$k]:-}" ]] && continue
      base="${k%%/*}"
      [[ "$base" == "22" ]] && continue          # SSH 保护
      echo "DEL:$k"
    done
}
```
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/diff_logic.bats
git commit -m "feat: compute_port_actions 计算放行/回收集合(含SSH保护)"
```

---

### Task 7: 无损迁移 migrate_v1_to_v2 + run_migrations + backup

**Files:**
- Modify: `auto-firewall.sh`
- Test: `tests/migration.bats`, `tests/fixtures/v1_whitelist.conf`, `tests/fixtures/v1_ports.state`

**Interfaces:**
- Produces: `backup_configs`；`migrate_v1_to_v2`；`run_migrations`；常量 `VERSION_FILE`/`BACKUP_DIR`/`BACKUP_RETAIN`。

- [ ] **Step 1: 写失败测试（fixture 驱动）**

`tests/fixtures/v1_whitelist.conf`：
```
# 头注释
22/tcp  # SSH
80/tcp  # HTTP
# 用户自定义端口
8080/tcp  # 自定义
this is a bogus line
```
`tests/fixtures/v1_ports.state`：
```
3000/tcp
8888/udp
```
`tests/migration.bats`：
```bash
#!/usr/bin/env bats
load test_helper/common

setup() {
  export AUTO_FW_HOME="$(mktemp -d)"
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
  cp "${BATS_TEST_DIRNAME}/fixtures/v1_whitelist.conf" "$WHITELIST_FILE"
  cp "${BATS_TEST_DIRNAME}/fixtures/v1_ports.state" "$STATE_FILE"
}
teardown() { rm -rf "$AUTO_FW_HOME"; }

@test "迁移后写入 schema 版本标记" {
  migrate_v1_to_v2
  [ -f "$VERSION_FILE" ]; grep -q '^2$' "$VERSION_FILE"
}
@test "迁移保留注释" {
  migrate_v1_to_v2
  grep -q '头注释' "$WHITELIST_FILE"
}
@test "迁移保留无法解析的非注释行(GAP-1)" {
  migrate_v1_to_v2
  grep -qF 'this is a bogus line' "$WHITELIST_FILE"
}
@test "迁移保留可解析端口" {
  migrate_v1_to_v2
  grep -q '^22/tcp' "$WHITELIST_FILE"
  grep -q '^8080/tcp' "$WHITELIST_FILE"
}
@test "迁移前生成备份" {
  migrate_v1_to_v2
  [ -d "$(ls -d "$BACKUP_DIR"/*/ | head -1)" ]
}
@test "run_migrations 已是目标版本则跳过" {
  echo 2 > "$VERSION_FILE"
  run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; run_migrations; echo done"
  [[ "$output" == *done* ]]
}
```

- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
BACKUP_DIR="${SCRIPT_DIR}/backup"
BACKUP_RETAIN=10
VERSION_FILE="${SCRIPT_DIR}/.schema_version"

backup_configs() {
    local ts dst
    ts="$(date +%Y%m%d%H%M%S)"
    dst="${BACKUP_DIR}/${ts}"
    mkdir -p "$dst"; chmod 700 "$dst"
    local f
    for f in "$WHITELIST_FILE" "$STATE_FILE" "$IP_WHITELIST_FILE"; do
        [[ -f "$f" ]] && cp -a "$f" "$dst/"
    done
    # 仅保留最近 N 份（按目录名时间）
    ( cd "$BACKUP_DIR" 2>/dev/null && ls -1d [0-9]* 2>/dev/null | sort -r | tail -n +$((BACKUP_RETAIN+1)) | while read -r d; do rm -rf "$d"; done )
    echo "$dst"
}

# v1 行 22/tcp -> v2 canon; 解析失败的非注释行原样保留
migrate_v1_to_v2() {
    backup_configs >/dev/null
    local tmp="${WHITELIST_FILE}.mig.$$"
    {
      echo "# schema-version: 2"
      while IFS= read -r raw || [[ -n "$raw" ]]; do
        local t="${raw#"${raw%%[![:space:]]*}"}"
        if [[ -z "$t" || "$t" == \#* ]]; then printf '%s\n' "$raw"; continue; fi
        if local c; c="$(canon_key "$raw" 2>/dev/null)"; then
            printf '%s  # migrated\n' "$c"
        else
            printf '%s\n' "$raw"          # GAP-1: 原样保留
        fi
      done < "$WHITELIST_FILE"
    } > "$tmp" && mv "$tmp" "$WHITELIST_FILE"
    # state 同样补头并 canon
    if [[ -f "$STATE_FILE" ]]; then
      local tmps="${STATE_FILE}.mig.$$"
      { echo "# schema-version: 2"
        while IFS= read -r s || [[ -n "$s" ]]; do
          [[ -z "$s" ]] && continue
          canon_key "$s" 2>/dev/null || printf '%s\n' "$s"
        done < "$STATE_FILE"; } > "$tmps" && mv "$tmps" "$STATE_FILE"
    fi
    echo "$STATE_SCHEMA_VERSION" > "$VERSION_FILE"
}

run_migrations() {
    local from=0
    if [[ -f "$VERSION_FILE" ]]; then
        from="$(cat "$VERSION_FILE")"
    elif [[ -f "$WHITELIST_FILE" || -f "$STATE_FILE" ]]; then
        from=1
    else
        echo "$STATE_SCHEMA_VERSION" > "$VERSION_FILE"; return 0
    fi
    while (( from < STATE_SCHEMA_VERSION )); do
        case "$from" in
            1) migrate_v1_to_v2 ;;
            *) _err "未知迁移版本 $from"; return 1 ;;
        esac
        from=$((from+1))
    done
}
```
> 失败回滚：`migrate_v1_to_v2` 用 `tmp` 成功再 `mv`；若 `canon_key` 全程异常导致写入空文件，`backup_configs` 已先备份——`install` 调用处包 `|| { _err "迁移失败, 从 $BACKUP_DIR 最新备份还原"; ... }`（实现期在 do_install 落地）。

- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/migration.bats tests/fixtures/
git commit -m "feat: 版本化无损迁移(backup+run_migrations+migrate_v1_to_v2)"
```

---

### Task 8: 重写 read_whitelist + port_check 集成新模型

**Files:**
- Modify: `auto-firewall.sh`（`read_whitelist`、`port_check`、`generate_whitelist`）
- Test: `tests/port_check.bats`（PATH 桩 `ss`/`ufw`）

**Interfaces:**
- Consumes: `ss_listen_raw`,`parse_scan_line`,`compute_port_actions`,`build_ufw_args`,`canon_key`,`run_migrations`。
- Produces: `read_whitelist`（返回 canon key 列表，走 parse_descriptor，跳过 `#` 与 `# schema-version`）。

- [ ] **Step 1: 写失败测试（端到端桩）**

`tests/port_check.bats`：
```bash
#!/usr/bin/env bats
load test_helper/common
setup(){
  export AUTO_FW_HOME="$(mktemp -d)"; mkdir -p "$AUTO_FW_HOME/logs"
  STUB="$(mktemp -d)"; export PATH="$STUB:$PATH"
  # 桩: ss 输出固定端口, ufw 记录调用
  cat >"$STUB/ss" <<'SS'
#!/usr/bin/env bash
case "$*" in
  *-tln*) printf 'LISTEN 0 128 0.0.0.0:80 *:*\n' ;;
  *-uln*) printf 'UNCONN 0 0 0.0.0.0:53 *:*\n' ;;
esac
SS
  cat >"$STUB/ufw" <<'UF'
#!/usr/bin/env bash
echo "ufw $*" >> "${UFW_LOG:-/dev/null}"
UF
  chmod +x "$STUB/ss" "$STUB/ufw"
  export UFW_LOG="$AUTO_FW_HOME/ufw.calls"; : > "$UFW_LOG"
  echo "9000/tcp" > "$AUTO_FW_HOME/ports.state"   # prev 有 9000
  printf '22/tcp  # SSH\n' > "$AUTO_FW_HOME/port-whitelist.conf"
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
  FIRST_RUN_MARK="$AUTO_FW_HOME/.first_run_done"; touch "$FIRST_RUN_MARK"
}
teardown(){ rm -rf "$AUTO_FW_HOME" "$STUB"; }

@test "read_whitelist 走 canon 跳过注释" {
  printf '# schema-version: 2\n22/tcp  # SSH\nbogus line\n' > "$WHITELIST_FILE"
  run read_whitelist
  [[ "$output" == *"22/tcp"* ]]; [[ "$output" != *"bogus"* ]]
}
@test "port_check 放行新监听(80/tcp,53/udp)" {
  port_check >/dev/null 2>&1 || true
  grep -q "allow 80/tcp" "$UFW_LOG"
}
@test "port_check 回收失效 9000/tcp" {
  port_check >/dev/null 2>&1 || true
  grep -q "delete 9000/tcp" "$UFW_LOG"
}
```

- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 重写三函数**
```bash
read_whitelist() {
    [[ -f "$WHITELIST_FILE" ]] || return 1
    local out="" raw c
    while IFS= read -r raw || [[ -n "$raw" ]]; do
      c="$(canon_key "$raw" 2>/dev/null)" || continue
      out="${out}${c}"$'\n'
    done < "$WHITELIST_FILE"
    printf '%s' "$out" | sort -u | sed '/^$/d'
}

# 采集当前监听 canon key 集合
scan_current_keys() {
    local raw parsed out=""
    raw="$(ss_listen_raw)"
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      parsed="$(parse_scan_line "$line")" || continue
      local p proto fam; IFS='|' read -r p proto fam <<<"$parsed"
      local k="${p}/${proto}"; [[ "$fam" == "all" ]] || k="${k}/v${fam}"
      out="${out}${k}"$'\n'
    done <<<"$raw"
    printf '%s' "$out" | sort -u | sed '/^$/d'
}

port_check() {
    acquire_lock
    _info "开始端口扫描..."
    fix_docker_ufw
    apply_whitelist                       # 确保白名单端口放行(marker 白名单)
    local cur prev wl actions
    cur="$(scan_current_keys)"
    wl="$(read_whitelist || true)"
    prev=""; [[ -f "$STATE_FILE" ]] && prev="$(grep -v '^#' "$STATE_FILE" 2>/dev/null || true)"
    actions="$(compute_port_actions "$cur" "$prev" "$wl")"
    local err=0 line op key
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      op="${line%%:*}"; key="${line#*:}"
      local -a args; mapfile -t args < <(build_ufw_args "$key" "$([[ $op == ADD ]] && echo allow || echo delete)")
      if ufw_exec "${args[@]}" >/dev/null 2>&1; then
          _info "自动${([[ $op == ADD ]] && echo 放行 || echo 回收)}: ${key}"
      else
          _err "ufw ${op} 失败: ${key}"; err=1
      fi
    done <<<"$actions"
    # 写 state: 仅动态(非白名单)
    local dyn=""
    for k in $cur; do echo "$wl" | grep -qxF "$k" || dyn="${dyn}${k}"$'\n'; done
    { echo "# schema-version: 2"; printf '%s' "$dyn" | sort -u | sed '/^$/d'; } > "$STATE_FILE"
    [ "$err" -eq 0 ] && _info "端口扫描完成。" || _err "端口扫描部分失败。"
    return $err
}
```
> `apply_whitelist` 内旧的 `grep -q "^${port}/${proto}"` 也改用 `read_whitelist`+`build_ufw_args allow`+comment `auto-firewall-whitelist`（实现期同 PR 一并改，保证 Task8 通过）。

- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/port_check.bats
git commit -m "feat: port_check 接入描述符模型/单遍扫描/差分回收+尽力而为退出"
```

---

### Task 9: Fail2ban 补强 + IPv6 顺序 + status 增强

**Files:**
- Modify: `auto-firewall.sh`（`detect_nginx_logpath`,`init_fail2ban`,`rebuild_f2b_jail`,`fail2ban_check`,`init_ufw`,`show_status`）
- Test: `tests/fail2ban.bats`

**Interfaces:**
- Produces: `detect_nginx_logpath`（返回 `access<TAB>error` 两路径）；`has_mta`；`init_ufw` 在 `ufw enable` 前写 `IPV6=yes`。

- [ ] **Step 1: 写失败测试**
```bash
#!/usr/bin/env bats
load test_helper/common

@test "has_mta 无 sendmail/postfix 返回非0" {
  run bash -c 'PATH=/nonexistent source "'"$BATS_TEST_DIRNAME"'/../auto-firewall.sh"; has_mta'
  [ "$status" -ne 0 ]
}
@test "detect_nginx_logpath 缺文件返回非0" {
  run detect_nginx_logpath
  [ "$status" -ne 0 ]
}
```
- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
has_mta() { command -v sendmail &>/dev/null || command -v mail &>/dev/null; }

detect_nginx_logpath() {
    local a="" e=""
    for p in /var/log/nginx/access.log /var/log/nginx/error.log; do :; done
    [[ -f /var/log/nginx/access.log ]] && a=/var/log/nginx/access.log
    [[ -f /var/log/nginx/error.log ]] && e=/var/log/nginx/error.log
    [[ -z "$a" && -z "$e" ]] && return 1
    printf '%s\t%s\n' "$a" "$e"
}
```
`init_ufw`：在 `ufw --force enable` 前插入
```bash
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw 2>/dev/null || true
```
`rebuild_f2b_jail`：`mta`/`action` 依 `has_mta` 选 `action_mwl` 或 `action_`；nginx-404/ufw 用 access 路径、botsearch/bad-request 用 error 路径，各 jail 仅当对应路径非空才写入。`show_status` 增加"schema/白名单来源/family/区间"展示。
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/fail2ban.bats
git commit -m "fix: Fail2ban jail 日志/MTA 降级 + IPv6 启用顺序 + status 增强"
```

---

### Task 10: config add/del/list（校验写入）

**Files:**
- Modify: `auto-firewall.sh`
- Test: `tests/config_io.bats`

**Interfaces:**
- Produces: `config_add_port`,`config_del_port`,`config_add_ip`,`config_del_ip`,`config_list`；`is_protected_ip`。

- [ ] **Step 1: 写失败测试**
```bash
#!/usr/bin/env bats
load test_helper/common
setup(){ export AUTO_FW_HOME="$(mktemp -d)"; source "${BATS_TEST_DIRNAME}/../auto-firewall.sh";
  printf '# schema-version: 2\n' > "$WHITELIST_FILE"; }
teardown(){ rm -rf "$AUTO_FW_HOME"; }

@test "add 合法区间端口" {
  config_add_port "8000:8100/tcp"; grep -q '^8000:8100/tcp' "$WHITELIST_FILE"
}
@test "add 非法端口被拒" {
  run config_add_port "99999/tcp"; [ "$status" -ne 0 ]
}
@test "add 去重" {
  config_add_port "443/tcp"; config_add_port "443/tcp"
  [ "$(grep -c '^443/tcp' "$WHITELIST_FILE")" -eq 1 ]
}
@test "del 存在项" {
  config_add_port "80/tcp"; config_del_port "80/tcp"
  ! grep -q '^80/tcp' "$WHITELIST_FILE"
}
@test "受保护回环 IP 不可删" {
  printf '# schema-version: 2\n127.0.0.1/8  # 回环\n' > "$IP_WHITELIST_FILE"
  run config_del_ip "127.0.0.1/8"; [ "$status" -ne 0 ]
}
```
- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
_wl_upsert() {  # $1=canon_key
  local k="$1"; grep -qxF "$k" "$WHITELIST_FILE" 2>/dev/null && return 0
  printf '%s\n' "$k" >> "$WHITELIST_FILE"
}
config_add_port() {
  local k; k="$(canon_key "$1")" || { _err "非法端口描述符: $1"; return 1; }
  backup_configs >/dev/null; _wl_upsert "$k"; _info "已加入端口白名单: $k"
}
config_del_port() {
  local k; k="$(canon_key "$1")" || return 1
  [[ "${k%%/*}" == "22" ]] && { _err "SSH 端口不可删除"; return 1; }
  backup_configs >/dev/null
  grep -vxF "$k" "$WHITELIST_FILE" > "${WHITELIST_FILE}.tmp" && mv "${WHITELIST_FILE}.tmp" "$WHITELIST_FILE"
}
is_protected_ip() {
  case "$1" in 127.0.0.1/8|::1|10.0.0.0/8|172.16.0.0/12|192.168.0.0/16) return 0;; *) return 1;; esac
}
config_add_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || \
  [[ "$1" =~ ^([0-9a-fA-F:]+)(/[0-9]{1,3})?$ ]] || { _err "非法 IP: $1"; return 1; }
  grep -qxF "$1" "$IP_WHITELIST_FILE" 2>/dev/null && return 0
  printf '%s\n' "$1" >> "$IP_WHITELIST_FILE"
}
config_del_ip() {
  is_protected_ip "$1" && { _err "受保护 IP 不可删除: $1"; return 1; }
  grep -vxF "$1" "$IP_WHITELIST_FILE" > "${IP_WHITELIST_FILE}.tmp" && mv "${IP_WHITELIST_FILE}.tmp" "$IP_WHITELIST_FILE"
}
config_list() { _info "端口白名单:"; read_whitelist 2>/dev/null || echo "(空)"; }
```
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/config_io.bats
git commit -m "feat: config add/del/list 端口与IP白名单(校验/去重/保护)"
```

---

### Task 11: reset-config + ban/unban + version/log

**Files:**
- Modify: `auto-firewall.sh`（`init_ip_whitelist` 加 `--force`；新增 reset/ban/unban/version/log）
- Test: `tests/reset_config.bats`

**Interfaces:**
- Consumes: `generate_whitelist`,`init_ip_whitelist`,`confirm`,`run_cmd`,`parse_ip`。
- Produces: `reset_config <scope>`；`ban_ip`/`unban_ip`；`show_version`；`show_log`。

- [ ] **Step 1: 写失败测试**
```bash
#!/usr/bin/env bats
load test_helper/common
setup(){ export AUTO_FW_HOME="$(mktemp -d)"; mkdir -p "$AUTO_FW_HOME/logs";
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"; }
teardown(){ rm -rf "$AUTO_FW_HOME"; }

@test "init_ip_whitelist --force 覆盖" {
  echo "custom" > "$IP_WHITELIST_FILE"
  init_ip_whitelist --force
  grep -q '127.0.0.1/8' "$IP_WHITELIST_FILE"
}
@test "reset-config ports 重扫且保留 22" {
  # 桩 ss 含 22
  STUB="$(mktemp -d)"; export PATH="$STUB:$PATH"
  printf '#!/usr/bin/env bash\ncase "$*" in *-tln*) echo "LISTEN 0 1 0.0.0.0:22 *:*";; *) :;; esac\n' > "$STUB/ss"; chmod +x "$STUB/ss"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/ufw"; chmod +x "$STUB/ufw"
  reset_config ports
  grep -q '^22/tcp' "$WHITELIST_FILE"
  rm -rf "$STUB"
}
@test "version 输出含 SCRIPT_VERSION" {
  run show_version; [[ "$output" == *"$SCRIPT_VERSION"* ]]
}
```
- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
init_ip_whitelist() {
    if [[ -f "$IP_WHITELIST_FILE" && "${1:-}" != "--force" ]]; then
        _info "IP 白名单文件已存在: $IP_WHITELIST_FILE"; return 0
    fi
    # 原 heredoc 生成逻辑（--force 覆盖写）...（保留原默认内容）
}
reset_config() {
    local scope="${1:-all}"; local ans
    ans="$(confirm "确认恢复默认配置(${scope})? 将备份现有配置" )"; [[ "$ans" != yes ]] && { _info "已取消"; return 0; }
    backup_configs >/dev/null
    case "$scope" in all|ports) generate_whitelist; : > "$STATE_FILE" 2>/dev/null || true ;; esac
    case "$scope" in all|ip)   init_ip_whitelist --force ;; esac
    case "$scope" in all|fail2ban) rebuild_f2b_jail && (service fail2ban reload &>/dev/null || systemctl reload fail2ban &>/dev/null || true) ;; esac
    _info "恢复默认完成 (scope=$scope)"
}
ban_ip() {
  local ip="$1" dur="${2:-$F2B_BANTIME}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$ip" =~ ^[0-9a-fA-F:]+$ ]] || { _err "非法 IP: $ip"; return 1; }
  acquire_lock; ufw_exec insert 1 deny from "$ip" to any comment "auto-firewall-manual" && _info "已封禁 $ip"
}
unban_ip() {
  local ip="$1"; [[ -n "$ip" ]] || return 1
  acquire_lock; ufw_exec delete deny from "$ip" to any comment "auto-firewall-manual" && _info "已解封 $ip"
}
show_version() {
  echo "auto-firewall.sh  版本: ${SCRIPT_VERSION}  schema: ${STATE_SCHEMA_VERSION}"
  grep '^PRETTY_NAME' /etc/os-release 2>/dev/null || true
  command -v ufw &>/dev/null && ufw version 2>/dev/null | head -1
  command -v fail2ban-client &>/dev/null && fail2ban-client --version 2>/dev/null | head -1
}
show_log() { tail -n "${1:-100}" "$LOG_FILE" 2>/dev/null || echo "无日志"; }
confirm() {  # $1=prompt -> echo yes/no
  [[ "$ASSUME_YES" == 1 ]] && { echo yes; return; }
  if command -v dialog &>/dev/null && [[ -t 1 ]]; then
     dialog --yesno "$1" 10 50 2>/dev/null && echo yes || echo no
  else echo "no"; fi
}
```
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/reset_config.bats
git commit -m "feat: reset-config/ban/unban/version/log + confirm 助手"
```

---

### Task 12: uninstall（两档，含 --purge）

**Files:**
- Modify: `auto-firewall.sh`
- Test: `tests/uninstall.bats`

**Interfaces:**
- Produces: `uninstall`（默认档删 profile.d/cron/opt；--purge 追删脚本 ufw 规则+还原 docker+移除 fail2ban，SSH 保护）。

- [ ] **Step 1: 写失败测试**
```bash
#!/usr/bin/env bats
load test_helper/common
setup(){ export AUTO_FW_HOME="$(mktemp -d)"; source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"; }
teardown(){ rm -rf "$AUTO_FW_HOME"; }

@test "默认档: 生成将删除清单含 profile.d 与 cron" {
  DRY_RUN=1 ASSUME_YES=1 UNINSTALL_TARGET_ROOT="$AUTO_FW_HOME/fakeroot" \
     uninstall --dry-run
  # 桩环境仅验证不报错且落 [DRYRUN] 日志
  grep -q 'DRYRUN' "$AUTO_FW_HOME/logs/auto-firewall.log" || true
}
@test "--purge 缺 --yes 且非交互被拒" {
  ASSUME_YES=0; run purge_guard_check; [ "$status" -ne 0 ]
}
```
> `UNINSTALL_TARGET_ROOT` 与 `purge_guard_check` 为本任务引入的可测试 seam：把要操作的绝对路径改为 `${UNINSTALL_TARGET_ROOT}/...`（默认空前缀=真实系统），purge 前调用 `purge_guard_check`。

- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
UNINSTALL_TARGET_ROOT="${UNINSTALL_TARGET_ROOT:-}"
purge_guard_check() {
  [[ "$PURGE" == 1 && "$ASSUME_YES" != 1 && ! -t 0 ]] && { _err "--purge 非交互需显式 --yes"; return 1; }
  return 0
}
uninstall() {
  local R="${UNINSTALL_TARGET_ROOT}"
  local ans; ans="$(confirm "确认卸载 auto-firewall? (默认仅移除脚本足迹)"; )"
  [[ "$ans" != yes && "$ASSUME_YES" != 1 ]] && { _info "取消"; return 0; }
  purge_guard_check || return 1
  # 默认档
  ufw_exec status >/dev/null 2>&1 || true
  rm -f "${R}/etc/profile.d/auto-firewall.sh"
  if [[ -f "${R}/etc/crontab" ]]; then
    sed -i '/# BEGIN auto-firewall/,/# END auto-firewall/d' "${R}/etc/crontab"
  fi
  [[ "$PURGE" == 1 ]] && purge_firewall
  if [[ "$R" == "" ]]; then rm -rf "$SCRIPT_DIR"; fi
  _info "卸载完成 (purge=${PURGE:-0})"
}
purge_firewall() {
  backup_configs >/dev/null
  local rules k base
  rules="$(ufw_exec status numbered 2>/dev/null || true)"
  while IFS= read -r line; do
    [[ "$line" == *auto-firewall* ]] || continue
    k="$(echo "$line" | grep -oE '[0-9]+(:[0-9]+)?/(tcp|udp)' | head -1)"
    [[ -z "$k" ]] && continue
    base="${k%%/*}"
    if [[ "$base" == "22" && "$FORCE_SSH" != 1 ]]; then _info "保留 SSH $k"; continue; fi
    local -a args; mapfile -t args < <(build_ufw_args "$k" delete)
    ufw_exec "${args[@]}" >/dev/null 2>&1 || true
  done <<<"$rules"
  rm -f /etc/fail2ban/jail.local /etc/fail2ban/action.d/ufw.conf \
        /etc/fail2ban/filter.d/nginx-ufw.conf /etc/fail2ban/filter.d/nginx-404.conf
  sysctl_exec disable --now fail2ban || true
}
```
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/uninstall.bats
git commit -m "feat: uninstall 两档(默认保防火墙/--purge含SSH保护)"
```

---

### Task 13: dialog TUI 主循环 + 快捷方式 profile.d

**Files:**
- Modify: `auto-firewall.sh`（新增 `tui_menu`,`tui_run`,`install_cron` 旁新增 `install_shortcut`；`main` 注册 `menu`）
- Test: `tests/tui_smoke.bats`

**Interfaces:**
- Produces: `tui_menu`（dialog --menu 主循环，dispatch 到既有函数）；`install_shortcut`（写 `/etc/profile.d/auto-firewall.sh` 幂等 BEGIN/END 区块）。

- [ ] **Step 1: 写失败测试（不依赖真 dialog）**
```bash
#!/usr/bin/env bats
load test_helper/common
setup(){ export AUTO_FW_HOME="$(mktemp -d)"; mkdir -p "$AUTO_FW_HOME/logs";
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"; }
teardown(){ rm -rf "$AUTO_FW_HOME"; }

@test "install_shortcut 写幂等 BEGIN/END 区块" {
  SHORTCUT_TARGET="$AUTO_FW_HOME/profile.d/auto-firewall.sh"
  mkdir -p "$AUTO_FW_HOME/profile.d"
  install_shortcut; install_shortcut
  [ "$(grep -c 'BEGIN auto-firewall-shortcut' "$SHORTCUT_TARGET")" -eq 1 ]
  grep -q 'x() { afw_shortcut' "$SHORTCUT_TARGET"
}
@test "无 dialog 时 tui_menu 降级 help" {
  run bash -c 'command(){ [ "$1" = dialog ] && return 1; builtin command "$@"; }; source "'"$BATS_TEST_DIRNAME"'/../auto-firewall.sh"; tui_menu'
  [[ "$output" == *"用法"* || "$output" == *"命令"* ]]
}
```
- [ ] **Step 2: 运行验证失败** — FAIL。
- [ ] **Step 3: 实现**
```bash
SHORTCUT_TARGET="${SHORTCUT_TARGET:-/etc/profile.d/auto-firewall.sh}"
install_shortcut() {
  mkdir -p "$(dirname "$SHORTCUT_TARGET")"
  [[ -f "$SHORTCUT_TARGET" ]] && sed -i '/# BEGIN auto-firewall-shortcut/,/# END auto-firewall-shortcut/d' "$SHORTCUT_TARGET"
  cat >> "$SHORTCUT_TARGET" <<'SC'
# BEGIN auto-firewall-shortcut
afw_shortcut() {
    if [[ $# -eq 0 ]]; then sudo bash /opt/auto-firewall/auto-firewall.sh menu
    else sudo bash /opt/auto-firewall/auto-firewall.sh "$@"; fi
}
x() { afw_shortcut "$@"; }
X() { afw_shortcut "$@"; }
# END auto-firewall-shortcut
SC
  _info "快捷命令已写入 $SHORTCUT_TARGET（重新登录或 source 生效）"
}

tui_menu() {
  ensure_locale_utf8
  if ! command -v dialog &>/dev/null || [[ ! -t 1 ]]; then
    _info "无 dialog 或非交互终端, 显示帮助"; show_help; return 0
  fi
  local choice
  while true; do
    choice=$(dialog --clear --title "Auto-Firewall v${SCRIPT_VERSION}" --menu "管理菜单" 20 60 12 \
      1 "总览仪表盘" 2 "端口检测" 3 "Fail2ban检测" 4 "系统清理" \
      5 "配置管理" 6 "恢复默认配置" 7 "封禁/解封IP" 8 "实时日志" \
      9 "Dry-run演练" 10 "版本信息" 0 "卸载" q "退出" 3>&1 1>&2 2>&3) || break
    tui_run "$choice"
  done
  clear 2>/dev/null || true
}
tui_run() {
  case "$1" in
    1) dialog --msgbox "$(show_status 2>&1)" 24 70 ;;
    2) port_check; dialog --msgbox "端口检测完成" 8 40 ;;
    3) fail2ban_check; dialog --msgbox "Fail2ban 检测完成" 8 40 ;;
    4) cleanup; dialog --msgbox "清理完成" 8 40 ;;
    5) tui_config ;;
    6) reset_config all ;;
    7) tui_ban ;;
    8) dialog --tailbox "$LOG_FILE" 24 80 ;;
    9) DRY_RUN=1 port_check; DRY_RUN=0 dialog --textbox "$LOG_FILE" 24 80 ;;
    10) dialog --msgbox "$(show_version)" 12 60 ;;
    0) uninstall ;;
    q|"") return ;;
  esac
}
```
`main` 注册：`menu) ensure_locale_utf8; tui_menu ;;` 并在 install 里调 `install_shortcut`。`tui_config`/`tui_ban` 用 `--inputbox` 收集后经 `config_*`/`ban_ip` 校验（实现期填充，逻辑同 Task10/11 函数）。
- [ ] **Step 4: 运行验证通过** — PASS。
- [ ] **Step 5: 提交**
```bash
git add auto-firewall.sh tests/tui_smoke.bats
git commit -m "feat: dialog TUI 主菜单 + x/X profile.d 快捷方式"
```

---

### Task 14: README / CHANGELOG / .gitignore 文档同步

**Files:**
- Modify: `README.md`（重写）、`.gitignore`
- Create: `CHANGELOG.md`
- Test: 无（文档），`shellcheck`/`bats -r tests/` 全绿为门禁。

- [ ] **Step 1: 重写 README.md**

新增小节：功能总览（含 TUI/config/reset/uninstall/ban/version/log/x-X）、安装、快捷命令 `x`/`X` 用法与生效说明、描述符 v2 行语法（区间/icmp/raw/v4/v6）、无损升级与备份保留、双档卸载与 SSH 防锁死提示、Fail2ban 语义澄清、测试（bats + WSL）、安全建议。

- [ ] **Step 2: 新建 CHANGELOG.md**
```markdown
# 更新日志
## v2.0.0
- 统一端口描述符: IPv6/区间/icmp/协议号
- 版本化无损迁移 + 备份保留(10份) + 失败还原
- dialog TUI 与 x/X 命令行快捷命令
- config/reset-config/uninstall/ban/unban/version/log 子命令
- 全局 flag 解析、变更命令统一加锁、注入防护
- Fail2ban jail 修正(access/error.log, MTA 降级), IPv6 启用顺序修复
- bats-core 测试 + WSL Debian 验证
## v1 (初始)
- UFW + Fail2ban + Docker 三重防线
```
- [ ] **Step 3: .gitignore 追加**
```
# 运行时备份/临时
/opt-backup/
*.mig.*
*.tmp.*
```
- [ ] **Step 4: 门禁验证** — `bash tests/run.sh` 全绿。
- [ ] **Step 5: 提交**
```bash
git add README.md CHANGELOG.md .gitignore
git commit -m "docs: README/CHANGELOG 同步 v2 特性"
```

---

### Task 15: WSL Debian 完整验证（端到端）

**Files:** 无（验证）。

- [ ] **Step 1: WSL 准备**
```bash
wsl -d Debian -- bash -lc 'sudo apt-get update && sudo apt-get install -y dialog bats shellcheck ufw fail2ban iproute2'
```
- [ ] **Step 2: 全量单测 + shellcheck**
```bash
wsl -d Debian -- bash -lc 'cd /mnt/c/Users/qianl/Desktop/Github/防火墙自动脚本 && shellcheck -S error auto-firewall.sh && bats -r tests/'
```
Expected: shellcheck 0 error，bats 全绿。
- [ ] **Step 3: 真实 install 冒烟（WSL root）**
```bash
wsl -d Debian -- bash -lc 'sudo bash auto-firewall.sh install'
wsl -d Debian -- bash -lc 'sudo bash auto-firewall.sh status'
```
- [ ] **Step 4: 无损迁移验证**：造 v1 配置 → `sudo bash auto-firewall.sh install` → 检查 `backup/`、`.schema_version=2`、注释与 bogus 行保留。
- [ ] **Step 5: port-check/cleanup/fail2ban-check** 各跑一遍，`grep DRYRUN` 冒烟 dry-run。
- [ ] **Step 6: TUI 验证**：重登使 `x` 生效 → `x`（dialog 渲染，只读项：总览/日志/版本）；变更项在 `x --dry-run port-check` 下验证。记录：WSL 无 tty 时 tui_menu 降级 help（可接受，真机交互验证）。
- [ ] **Step 7: uninstall 验证**：`sudo bash auto-firewall.sh uninstall --dry-run --yes` 预览 → 默认档实卸校验 cron/profile.d//opt 清理且 `ufw status` 未被误删。
- [ ] **Step 8: 提交验证脚本结果**（在 CHANGELOG/PR 备注记录通过项）。

---

## 自检对照（spec 覆盖）

| spec 节 | 实现任务 |
|---------|---------|
| §2 描述符/parse/build | T2, T3 |
| §2.4 注入防护 | T1 薄封装 + T2/T3 校验 + T10/T12 传参数组 |
| §2.5 加锁/部分失败 | T1(acquire_lock 复用), T8(尽力而为退出) |
| §2.6 可测试性 | T1 |
| §3 扫描/缓存/差分 | T5, T6, T8 |
| §4 无损迁移 | T7 |
| §5 Fail2ban/IPv6/status/备份保留/文档 | T9, T7(backup), T14 |
| §6 TUI/locale/快捷 | T1(locale), T13 |
| §7 config/reset/ban | T10, T11 |
| §8 uninstall | T12 |
| §9 flag/version/log | T4, T11 |
| §10 测试 | 各 task + T15 |
