#!/bin/bash
#===============================================================================
# 防火墙自动管理脚本 - 适用于 Ubuntu / Debian 云端 VPS
# 功能: ufw自动安装 | 端口动态放行/回收 | 白名单管理 | Docker兼容修复 | 系统清理
# 部署: sudo bash auto-firewall.sh install
# 手册: sudo bash auto-firewall.sh help
#===============================================================================
set -euo pipefail

#---- 全局配置 ----------------------------------------------------------------
# 版本与 schema（spec §4.1）
readonly SCRIPT_VERSION="2.0.0"
readonly STATE_SCHEMA_VERSION=2
# 路径基址: 支持 AUTO_FW_HOME 环境变量覆盖（bats 测试隔离用, spec §2.6 GAP-A）
SCRIPT_DIR="${AUTO_FW_HOME:-/opt/auto-firewall}"
STATE_FILE="${SCRIPT_DIR}/ports.state"
WHITELIST_FILE="${SCRIPT_DIR}/port-whitelist.conf"
FIRST_RUN_MARK="${SCRIPT_DIR}/.first_run_done"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/auto-firewall.log"
LOCK_FILE="${SCRIPT_DIR}/.script.lock"
IP_WHITELIST_FILE="${SCRIPT_DIR}/ip-whitelist.conf"
VERSION_FILE="${SCRIPT_DIR}/.schema_version"
readonly MAX_LOG_SIZE=$((1024 * 1024))       # 日志超过1MB自动截断
readonly LOG_RETAIN_LINES=500                 # 截断后保留最后500行
readonly MEM_FREE_THRESHOLD=20                # 空闲内存低于此百分比才释放缓存
# 系统路径支持 env seam（bats 隔离注入, spec §2.6）
FAIL2BAN_JAIL_CONF="${AUTO_FW_F2B_JAIL_CONF:-/etc/fail2ban/jail.local}"
FAIL2BAN_FILTER_DIR="${AUTO_FW_F2B_FILTER_DIR:-/etc/fail2ban/filter.d}"
FAIL2BAN_ACTION_DIR="${AUTO_FW_F2B_ACTION_DIR:-/etc/fail2ban/action.d}"
UFW_DEFAULT_FILE="${AUTO_FW_UFW_DEFAULT:-/etc/default/ufw}"
NGINX_LOG_DIR="${AUTO_FW_NGINX_LOG_DIR:-/var/log/nginx}"
readonly F2B_BANTIME=3600                     # 封禁时长（秒），默认1小时
readonly F2B_FINDTIME=600                     # 统计窗口（秒），默认10分钟
readonly F2B_MAXRETRY=5                       # 最大重试次数

# 脚本自身路径（适配软链接; 被 source 时取 BASH_SOURCE）
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"

#---- 工具函数 ----------------------------------------------------------------
_log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" || true; }
_err()  { _log "[ERROR] $*" >&2; }
_info() { _log "[INFO]  $*"; }

# 强制 UTF-8 locale，保 dialog/日志中文不乱码（spec GAP-3）
ensure_locale_utf8() {
    case "${LC_ALL:-${LANG:-}}" in
        *[Uu][Tt][Ff]*8*) : ;;
        *)
            if locale -a 2>/dev/null | grep -qiE '^C\.UTF-?8$'; then
                export LC_ALL=C.UTF-8
            else
                _err "未检测到 UTF-8 locale，中文可能乱码；建议执行: dpkg-reconfigure locales"
            fi ;;
    esac
}

#---- 外部命令薄封装（便于 bats 通过 PATH 桩/函数覆盖注入, spec §2.6）--------
ss_probe()      { ss "$@" 2>/dev/null; }
netstat_probe() { netstat "$@" 2>/dev/null; }
apt_exec()      { command apt-get "$@"; }
# 变更类命令统一入口: dry-run 只记录不执行（spec §5 GAP-5）
run_cmd() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        _log "[DRYRUN] $*"
        return 0
    fi
    "$@"
}
ufw_exec()      { run_cmd ufw "$@"; }
fail2ban_exec() { run_cmd fail2ban-client "$@"; }
# 服务管理封装（systemctl 优先, 回退 service）
svc_exec()      { systemctl "$@" 2>&1 || service "$@" 2>&1 || true; }

#---- 端口描述符模型 v2（spec §2）----------------------------------------------
# 行语法: <port-spec>/<proto>[/<addr>], 如 22/tcp, 8000:8100/tcp, 443/tcp/v6,
#          icmp, -/esp, -/50, any
# 输出: <port_from>|<port_to>|<proto>|<family>  (portless 前两项空; family=all/4/6)
parse_descriptor() {
    local line="${1:-}"
    line="${line%%#*}"
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && return 1

    local spec proto addr="all"
    if [[ "$line" == */*/* ]]; then
        spec="${line%%/*}"; local rest="${line#*/}"
        proto="${rest%%/*}"; addr="${rest#*/}"
        case "$addr" in
            v4) addr="4" ;;
            v6) addr="6" ;;
            *)  return 1 ;;
        esac
    elif [[ "$line" == */* ]]; then
        spec="${line%%/*}"; proto="${line#*/}"
    else
        spec=""; proto="$line"                 # 名称协议（icmp/esp/any 等）
    fi

    # 协议白名单/协议号
    case "$proto" in
        tcp|udp|icmp|esp|ah|gre|any) : ;;
        ''|*[!0-9]*) return 1 ;;
        *) { (( proto >= 1 && proto <= 255 )); } || return 1 ;;
    esac

    local pf="" pt=""
    if [[ -z "$spec" || "$spec" == "-" ]]; then
        # portless: tcp/udp 必须带端口
        [[ "$proto" == "tcp" || "$proto" == "udp" ]] && return 1
    else
        local a b
        if [[ "$spec" == *:* ]]; then a="${spec%%:*}"; b="${spec##*:}"; else a="$spec"; b="$spec"; fi
        [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
        (( a >= 1 && a <= 65535 && b >= 1 && b <= 65535 )) || return 1
        (( a <= b )) || return 1
        # 端口只允许 tcp/udp
        [[ "$proto" == "tcp" || "$proto" == "udp" ]] || return 1
        pf="$a"; pt="$b"
    fi
    echo "${pf}|${pt}|${proto}|${addr}"
}

# 规范化 key（用于 state/去重/成员判断）; portless 补 '-', family=all 省略 addr
canon_key() {
    local parsed
    parsed="$(parse_descriptor "${1:-}")" || return 1
    local pf pt proto fam
    IFS='|' read -r pf pt proto fam <<<"$parsed"
    local spec
    if [[ -z "$pf" ]]; then spec="-"
    elif [[ "$pf" == "$pt" ]]; then spec="$pf"
    else spec="${pf}:${pt}"; fi
    local key="${spec}/${proto}"
    [[ "$fam" == "all" ]] || key="${key}/v${fam}"
    echo "$key"
}

# 逐 token 打印 ufw 参数（每行一个, 调用方 mapfile 转数组, 防注入）
# 双栈 tcp/udp 用简写 "<port>/<proto>"; 显式族/portless 用 "proto X from any to Y [port N]"
# any 协议不生成 proto any（GAP-4）
build_ufw_args() {
    local key="$1" action="${2:-allow}"
    local parsed
    parsed="$(parse_descriptor "$key")" || return 1
    local pf pt proto fam
    IFS='|' read -r pf pt proto fam <<<"$parsed"
    local port_spec=""
    if [[ -n "$pf" ]]; then
        if [[ "$pf" == "$pt" ]]; then port_spec="$pf"; else port_spec="${pf}:${pt}"; fi
    fi
    echo "$action"
    case "$proto" in
        any)
            echo "from"; echo "any"; echo "to"; echo "any" ;;
        tcp|udp)
            if [[ "$fam" == "all" ]]; then
                echo "${port_spec}/${proto}"
            else
                local dst="0.0.0.0/0"
                [[ "$fam" == "6" ]] && dst="::/0"
                echo "proto"; echo "$proto"
                echo "from"; echo "any"; echo "to"; echo "$dst"
                echo "port"; echo "$port_spec"
            fi ;;
        *)
            echo "proto"; echo "$proto"
            echo "from"; echo "any"; echo "to"; echo "any" ;;
    esac
    return 0
}

#---- 监听扫描 v2（spec §3.1, GAP-2）------------------------------------------
# 输入 ss/netstat 单行 -> 输出 "port|proto|family"; 回环/无效行返回非0
# 兼容: ss(Netid=LISTEN/UNCONN) 与 netstat(Proto=tcp/udp/tcp6/udp6) 两种格式
parse_scan_line() {
    local line="${1:-}"
    local -a f
    read -r -a f <<<"$line"
    (( ${#f[@]} >= 4 )) || return 1

    local proto
    case "${f[0]}" in
        tcp*) proto=tcp ;;
        udp*) proto=udp ;;
        LISTEN) proto=tcp ;;
        UNCONN) proto=udp ;;
        *) return 1 ;;
    esac

    # 取第一个以 ":数字" 结尾的字段 = Local Address:Port
    local fld addr=""
    for fld in "${f[@]}"; do
        if [[ "$fld" =~ :[0-9]+$ ]]; then addr="$fld"; break; fi
    done
    [[ -n "$addr" ]] || return 1

    local port="${addr##*:}"
    local ip="${addr%:*}"
    ip="${ip#\[}"; ip="${ip%\]}"      # 去 IPv6 方括号
    ip="${ip%%%*}"                     # 去 zone id (fe80::1%eth0 -> fe80::1)
    [[ "$port" =~ ^[0-9]+$ ]] || return 1

    local fam
    case "$ip" in
        127.0.0.1|::1)  return 1 ;;    # 回环不纳入动态管理
        \*)             fam="all" ;;
        0.0.0.0)        fam="4" ;;
        ::)             fam="6" ;;
        fe80:*)         fam="6" ;;     # link-local 仅记录
        *:*:*)          fam="6" ;;     # 多段冒号 -> IPv6
        *)              fam="4" ;;
    esac
    echo "${port}|${proto}|${fam}"
}

# 采集监听原始行（经 ss_probe/netstat_probe 封装, 便于测试桩入）
ss_listen_raw() {
    if command -v ss &>/dev/null; then
        { ss_probe -tln; ss_probe -uln; }
    elif command -v netstat &>/dev/null; then
        netstat_probe -tuln
    else
        return 1
    fi
}

# 差分计算（spec §3.3）: 入参为空格分隔的 canon key 集合
# 输出逐行 "ADD:<key>" / "DEL:<key>"; 白名单与 SSH(22) 永不回收, 白名单不重复 ADD
compute_port_actions() {
    local cur="$1" prev="$2" wl="$3"
    local -A in_cur=() in_prev=() in_wl=()
    local k base
    for k in $cur;  do in_cur["$k"]=1;  done
    for k in $prev; do in_prev["$k"]=1; done
    for k in $wl;   do in_wl["$k"]=1;   done
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "错误: 此脚本必须以 root 身份执行，请使用 sudo。" >&2
        exit 1
    fi
}

check_debian_family() {
    if [[ ! -f /etc/debian_version ]]; then
        _err "此脚本仅支持 Debian / Ubuntu 系统。"
        exit 1
    fi
    _info "系统类型: $(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d= -f2 | tr -d '"')"
}

# 检测端口扫描工具（ss 优先，不存在则回退 netstat）
detect_port_scanner() {
    if command -v ss &>/dev/null; then
        echo "ss"
    elif command -v netstat &>/dev/null; then
        echo "netstat"
    else
        _err "未找到 ss 或 netstat 命令，正在安装 iproute2..."
        apt_exec update -qq && apt_exec install -y -qq iproute2
        if command -v ss &>/dev/null; then
            echo "ss"
        else
            _err "安装 iproute2 失败，无法继续。"
            exit 1
        fi
    fi
}

# 日志轮转
rotate_log() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ $size -gt $MAX_LOG_SIZE ]]; then
            tail -n "$LOG_RETAIN_LINES" "$LOG_FILE" > "${LOG_FILE}.tmp"
            mv "${LOG_FILE}.tmp" "$LOG_FILE"
            _info "日志已轮转（超过 1MB，已截断至最后 ${LOG_RETAIN_LINES} 行）"
        fi
    fi
}

# 非阻塞文件锁
acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        _info "上一次脚本运行尚未结束，跳过本次执行。"
        exit 0
    fi
}

#---- 无损升级 v2（spec §4）------------------------------------------------
BACKUP_DIR="${SCRIPT_DIR}/backup"
readonly BACKUP_RETAIN=10                      # 仅保留最近 N 份快照（G5/GAP-6）

# 全量快照配置到 backup/<ts>/, 修剪至最近 BACKUP_RETAIN 份; 输出快照目录
backup_configs() {
    local ts dst
    ts="$(date +%Y%m%d%H%M%S)"
    dst="${BACKUP_DIR}/${ts}"
    mkdir -p "$dst" || return 1
    chmod 700 "$BACKUP_DIR" "$dst" 2>/dev/null || true
    local f
    for f in "$WHITELIST_FILE" "$STATE_FILE" "$IP_WHITELIST_FILE" "$VERSION_FILE"; do
        [[ -f "$f" ]] && cp -a "$f" "$dst/" 2>/dev/null || true
    done
    # 保留策略: 目录名按时间戳降序, 删除超出部分
    local -a dirs=()
    mapfile -t dirs < <(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r)
    local i
    for (( i=BACKUP_RETAIN; i<${#dirs[@]}; i++ )); do
        rm -rf "${BACKUP_DIR:?}/${dirs[$i]}"
    done
    echo "$dst"
}

# v1 -> v2: 白名单/state 换发为 v2 语法; 注释与无法解析的行原样保留（GAP-1）
migrate_v1_to_v2() {
    backup_configs >/dev/null || { _err "备份失败, 中止迁移"; return 1; }
    local raw c comment
    if [[ -f "$WHITELIST_FILE" ]]; then
        local tmp="${WHITELIST_FILE}.mig.$$"
        {
            echo "# schema-version: 2"
            while IFS= read -r raw || [[ -n "$raw" ]]; do
                local trimmed="${raw#"${raw%%[![:space:]]*}"}"
                if [[ -z "$trimmed" || "$trimmed" == \#* ]]; then
                    printf '%s\n' "$raw"
                elif c="$(canon_key "$raw" 2>/dev/null)"; then
                    comment=""
                    [[ "$raw" == *\#* ]] && comment="${raw#*#}"
                    printf '%s  #%s\n' "$c" "$comment"
                else
                    printf '%s\n' "$raw"      # 非注释但解析不了: 保留不丢
                fi
            done < "$WHITELIST_FILE"
        } > "$tmp" && mv "$tmp" "$WHITELIST_FILE"
    fi
    if [[ -f "$STATE_FILE" ]]; then
        local tmps="${STATE_FILE}.mig.$$" s
        {
            echo "# schema-version: 2"
            while IFS= read -r s || [[ -n "$s" ]]; do
                [[ -z "$s" ]] && continue
                canon_key "$s" 2>/dev/null || printf '%s\n' "$s"
            done < "$STATE_FILE"
        } > "$tmps" && mv "$tmps" "$STATE_FILE"
    fi
    echo "$STATE_SCHEMA_VERSION" > "$VERSION_FILE"
    _info "配置已从 v1 迁移至 v2"
}

# 迁移注册表: 逐级升级至 STATE_SCHEMA_VERSION; 失败时从最新备份还原
run_migrations() {
    local from=0
    if [[ -f "$VERSION_FILE" ]]; then
        from="$(tr -cd '0-9' < "$VERSION_FILE")"
        from="${from:-0}"
    elif [[ -f "$WHITELIST_FILE" || -f "$STATE_FILE" || -f "$IP_WHITELIST_FILE" ]]; then
        from=1                                  # 存量安装无版本标记 -> 隐式 v1
    else
        echo "$STATE_SCHEMA_VERSION" > "$VERSION_FILE"
        _info "全新环境, 直接写入 schema v${STATE_SCHEMA_VERSION}"
        return 0
    fi
    while (( from < STATE_SCHEMA_VERSION )); do
        case "$from" in
            1) migrate_v1_to_v2 || { _err "迁移 v1->v2 失败, 尝试从备份还原"; restore_latest_backup; return 1; } ;;
            *) _err "未知 schema 版本 ${from}, 无迁移路径"; return 1 ;;
        esac
        from="$(tr -cd '0-9' < "$VERSION_FILE" 2>/dev/null)"
        [[ -n "$from" ]] || { _err "迁移未写入版本号"; restore_latest_backup; return 1; }
    done
    return 0
}

# 从最新备份还原配置（仅恢复迁移涉及的三个文件）
restore_latest_backup() {
    local latest
    latest="$(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r | head -1)"
    [[ -z "$latest" ]] && { _err "无可用备份, 请手工检查 ${BACKUP_DIR}"; return 1; }
    local src="${BACKUP_DIR}/${latest}" f
    for f in port-whitelist.conf ports.state ip-whitelist.conf .schema_version; do
        [[ -f "${src}/${f}" ]] && cp -a "${src}/${f}" "${SCRIPT_DIR}/${f}"
    done
    _info "已从备份 ${latest} 还原配置"
}

#---- IP 白名单管理 ------------------------------------------------------------
# 读取 IP 白名单（去注释、去空行），返回空格分隔的 IP/CIDR 列表
read_ip_whitelist() {
    if [[ ! -f "$IP_WHITELIST_FILE" ]]; then
        echo "127.0.0.1/8 ::1"
        return 0
    fi
    local ips
    ips=$(grep -v '^[[:space:]]*#' "$IP_WHITELIST_FILE" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' | LC_ALL=C sort -u | tr '\n' ' ' || true)
    # 合并默认值与文件内容，去重
    local all_ips
    all_ips=$(echo "127.0.0.1/8 ::1 ${ips}" | tr ' ' '\n' | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [[ -z "${all_ips// }" ]]; then
        echo "127.0.0.1/8 ::1"
    else
        echo "$all_ips"
    fi
}

# 生成默认 IP 白名单文件（--force 覆盖, spec §7.2 前置改造）
init_ip_whitelist() {
    if [[ -f "$IP_WHITELIST_FILE" && "${1:-}" != "--force" ]]; then
        _info "IP 白名单文件已存在: $IP_WHITELIST_FILE"
        return 0
    fi
    cat > "$IP_WHITELIST_FILE" <<'WL_EOF'
# schema-version: 2
# ============================================
# 防火墙自动脚本 - IP 白名单配置
#
# 格式: IP地址或CIDR网段  # 说明
# 示例: 1.2.3.4            # 公司出口IP
#       10.0.0.0/8          # 内网地址段
#
# 白名单中的 IP 不会被 Fail2ban 自动封禁。
# 支持 IPv4/IPv6 及 CIDR 网段格式。
# 一行一个 IP 或网段，# 开头为注释。
# ============================================
127.0.0.1/8  # 本机回环（禁止删除）
::1          # 本机回环 IPv6（禁止删除）
10.0.0.0/8   # A类内网
172.16.0.0/12 # B类内网（含Docker默认网桥）
192.168.0.0/16 # C类内网
# --- 在下方添加你的可信 IP/网段 ---
# 1.2.3.4  # 示例: 公司/家庭出口IP
WL_EOF
    chmod 644 "$IP_WHITELIST_FILE"
    _info "IP 白名单文件已生成: $IP_WHITELIST_FILE"
}

#---- 配置管理 config（spec §7.1, G8/GAP-注入防护）---------------------------
# IP/CIDR 合法性校验（IPv4 逐段 0-255 + 掩码 0-32; IPv6 宽松字符集 + 掩码 0-128）
valid_ip_spec() {
    local v="${1:-}" ip bits
    [[ -z "$v" || "$v" == /* ]] && return 1
    ip="${v%%/*}"; bits=""
    [[ "$v" == */* ]] && bits="${v##*/}"
    if [[ -n "$bits" ]]; then
        [[ "$bits" =~ ^[0-9]+$ ]] || return 1
        if [[ "$ip" == *:* ]]; then (( bits <= 128 )) || return 1
        else (( bits <= 32 )) || return 1; fi
    fi
    if [[ "$ip" == *:* ]]; then
        [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
        return 0
    fi
    local o
    local -a oct
    IFS='.' read -r -a oct <<< "$ip"
    (( ${#oct[@]} == 4 )) || return 1
    for o in "${oct[@]}"; do
        [[ "$o" =~ ^[0-9]{1,3}$ ]] || return 1
        (( o <= 255 )) || return 1
    done
    return 0
}

# 内置受保护 IP（回环+内网段, 不可删）
is_protected_ip() {
    local v="${1:-}"
    v="${v%%[[:space:]]*}"
    case "$v" in
        127.0.0.1/8|::1|10.0.0.0/8|172.16.0.0/12|192.168.0.0/16) return 0 ;;
        *) return 1 ;;
    esac
}

config_add_port() {
    local k
    k="$(canon_key "${1:-}")" || { _err "非法端口描述符: ${1:-}"; return 1; }
    backup_configs >/dev/null || { _err "备份失败, 取消变更"; return 1; }
    _wl_has_key "$WHITELIST_FILE" "$k" && { _info "已存在: $k"; return 0; }
    printf '%s  # 手动添加\n' "$k" >> "$WHITELIST_FILE"
    _info "已加入端口白名单: $k（port-check 或 cron 周期生效）"
}

# 按首字段匹配条目（行尾可能带注释, grep -x 全行匹配不适用）
_wl_has_key() {
    awk -v k="$2" '$1==k{f=1} END{exit f?0:1}' "$1" 2>/dev/null
}

config_del_port() {
    local k
    k="$(canon_key "${1:-}")" || { _err "非法端口描述符: ${1:-}"; return 1; }
    [[ "${k%%/*}" == "22" ]] && { _err "SSH 端口不可移出白名单"; return 1; }
    local tmp="${WHITELIST_FILE}.tmp.$$"
    awk -v k="$k" '$1!=k' "$WHITELIST_FILE" > "$tmp"
    backup_configs >/dev/null || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$WHITELIST_FILE"
    _info "已从端口白名单移除: $k"
}

config_add_ip() {
    valid_ip_spec "${1:-}" || { _err "非法 IP/CIDR: ${1:-}"; return 1; }
    backup_configs >/dev/null || { _err "备份失败, 取消变更"; return 1; }
    _wl_has_key "$IP_WHITELIST_FILE" "${1%%[[:space:]]*}" && { _info "已存在: $1"; return 0; }
    printf '%s  # 手动添加\n' "$1" >> "$IP_WHITELIST_FILE"
    _info "已加入 IP 白名单: $1（fail2ban-check 会同步到 jail.local）"
}

config_del_ip() {
    is_protected_ip "${1:-}" && { _err "受保护的默认项, 不可删除: $1"; return 1; }
    local tmp="${IP_WHITELIST_FILE}.tmp.$$"
    awk -v k="${1%%[[:space:]]*}" '$1!=k' "$IP_WHITELIST_FILE" > "$tmp"
    backup_configs >/dev/null || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$IP_WHITELIST_FILE"
    _info "已从 IP 白名单移除: $1"
}

config_list() {
    case "${1:-ports}" in
        ports) echo "[端口白名单（canon key）]"; read_whitelist 2>/dev/null | grep -v '^#' || echo "  (空)" ;;
        ip)    echo "[IP 白名单]"; grep -vE '^[[:space:]]*(#|$)' "$IP_WHITELIST_FILE" 2>/dev/null || echo "  (空)" ;;
        *)     _err "未知类型: $1（ports|ip）"; return 1 ;;
    esac
}

# 整文件文本编辑: $EDITOR 修改临时副本, 保存前逐行校验, 非法行拒写（CLI 严格模式）
config_edit() {
    local which="${1:-ports}" file tmp line bad=0 badlist=""
    case "$which" in
        ports) file="$WHITELIST_FILE" ;;
        ip)    file="$IP_WHITELIST_FILE" ;;
        *)     _err "未知类型: $which"; return 1 ;;
    esac
    [[ -f "$file" ]] || { _err "配置文件不存在: $file"; return 1; }
    [[ -t 1 ]] || { _err "非交互终端, 请用 config add/del"; return 1; }
    tmp="$(mktemp)"
    cp "$file" "$tmp"
    "${EDITOR:-nano}" "$tmp"
    while IFS= read -r line || [[ -n "$line" ]]; do
        local t="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$t" || "$t" == \#* ]] && continue
        if [[ "$which" == "ports" ]]; then
            canon_key "$line" >/dev/null 2>&1 || { badlist+="${line}"$'\n'; (( bad++ )); }
        else
            valid_ip_spec "${t%%[[:space:]]*}" || { badlist+="${line}"$'\n'; (( bad++ )); }
        fi
    done < "$tmp"
    if (( bad )); then
        _err "发现 ${bad} 条非法行, 未保存:"
        printf '%s' "$badlist" >&2
        rm -f "$tmp"; return 1
    fi
    backup_configs >/dev/null || { rm -f "$tmp"; return 1; }
    cat "$tmp" > "$file" && rm -f "$tmp"
    _info "配置已更新: $file"
}

# config 子命令分发（main 传入 CMD_ARGS[1..]）
# 注: case 分支中函数失败不会自动传播退出码(bash 语义), 必须显式 rc=$? 捕获
config_main() {
    local sub="${1:-list}" rc=0; shift || true
    case "$sub" in
        add)
            [[ -z "${1:-}" || -z "${2:-}" ]] && { _err "用法: config add port|ip <值>"; return 1; }
            case "$1" in
                port) config_add_port "$2" || rc=$? ;;
                ip)   config_add_ip "$2" || rc=$? ;;
                *)    _err "未知类型: $1（port|ip）"; return 1 ;;
            esac ;;
        del)
            [[ -z "${1:-}" || -z "${2:-}" ]] && { _err "用法: config del port|ip <值>"; return 1; }
            case "$1" in
                port) config_del_port "$2" || rc=$? ;;
                ip)   config_del_ip "$2" || rc=$? ;;
                *)    _err "未知类型: $1（port|ip）"; return 1 ;;
            esac ;;
        list) config_list "${1:-ports}" || rc=$? ;;
        edit) config_edit "${1:-ports}" || rc=$? ;;
        *)    _err "未知 config 子命令: $sub"; return 1 ;;
    esac
    return "$rc"
}

#---- 恢复默认 / 手动封禁 / 版本 / 日志（spec §7.2/§7.3/§9）----------------
# 交互确认: ASSUME_YES 短路; dialog 仅在有 TTY 时; 否则拒绝（G8 安全默认）
confirm() {
    local prompt="$1"
    [[ "${ASSUME_YES:-0}" == "1" ]] && return 0
    if command -v dialog &>/dev/null && [[ -t 1 ]]; then
        dialog --title "确认" --yesno "$prompt" 12 60 2>/dev/null
        return $?
    fi
    _err "非交互环境需显式传 --yes 才能执行: ${prompt}"
    return 1
}

# 恢复默认配置: 不卸载脚本、不改 schema; ports 靠“当前监听重扫”故不会关掉在用端口
reset_config() {
    local scope="${1:-all}"
    case "$scope" in all|ports|ip|fail2ban) : ;; *) _err "未知范围: $scope（all|ports|ip|fail2ban）"; return 1 ;; esac
    confirm "确认恢复默认配置（${scope}）? 现有配置将先备份" || { _info "已取消"; return 1; }
    acquire_lock
    backup_configs >/dev/null || { _err "备份失败, 中止恢复"; return 1; }
    case "$scope" in
        all|ports)
            generate_whitelist
            printf '# schema-version: 2\n' > "$STATE_FILE"
            port_check || _err "重建动态端口时存在错误"
            ;;
    esac
    case "$scope" in
        all|ip) init_ip_whitelist --force ;;
    esac
    case "$scope" in
        all|fail2ban)
            rebuild_f2b_jail
            svc_exec reload fail2ban
            ;;
    esac
    _info "恢复默认完成（scope=${scope}）"
}

# 手动封禁/解封（spec §7.3）: fail2ban 在线时优先走 jail(尊重 bantime), 否则 ufw 持续 deny
ban_ip() {
    local ip="${1:-}" dur="${2:-$F2B_BANTIME}"
    [[ -n "$ip" ]] || { _err "用法: ban <IP>"; return 1; }
    valid_ip_spec "${ip%%/*}" || { _err "非法 IP/CIDR: $ip"; return 1; }
    acquire_lock
    if svc_active fail2ban && fail2ban_exec set sshd banip "$ip" >/dev/null 2>&1; then
        _info "已通过 fail2ban 封禁: $ip（参考 bantime=${dur}s）"
    else
        ufw_exec insert 1 deny from "$ip" to any comment "auto-firewall-manual" \
            && _info "已通过 UFW 封禁: $ip（持续至 unban）"
    fi
}

unban_ip() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || { _err "用法: unban <IP>"; return 1; }
    valid_ip_spec "${ip%%/*}" || { _err "非法 IP/CIDR: $ip"; return 1; }
    acquire_lock
    fail2ban_exec set sshd unbanip "$ip" >/dev/null 2>&1 || true
    ufw_exec delete deny from "$ip" to any comment "auto-firewall-manual" \
        && _info "已解封: $ip"
}

show_version() {
    echo "auto-firewall.sh  版本: ${SCRIPT_VERSION}  配置schema: ${STATE_SCHEMA_VERSION}"
    grep '^PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' | sed 's/^/系统: /' || true
    command -v ufw &>/dev/null && echo "ufw: $(ufw --version 2>/dev/null | head -1)" || echo "ufw: 未安装"
    command -v fail2ban-client &>/dev/null && echo "fail2ban: $(fail2ban-client --version 2>&1 | head -1)" || echo "fail2ban: 未安装"
    command -v dialog &>/dev/null && echo "dialog: $(dialog --version 2>&1 | head -1)" || echo "dialog: 未安装"
}

show_log() {
    local n="${1:-100}"
    [[ "$n" =~ ^[0-9]+$ ]] || { _err "行数需为数字: $n"; return 1; }
    [[ -f "$LOG_FILE" ]] || { echo "无日志: $LOG_FILE"; return 0; }
    tail -n "$n" "$LOG_FILE"
}

#---- 卸载 uninstall（spec §8）------------------------------------------------
# 安装/还原的系统路径根（测试 seam; 默认真实系统）
UFW_ETC_DIR="${AUTO_FW_UFW_ETC_DIR:-/etc/ufw}"
UNINSTALL_TARGET_ROOT="${AUTO_FW_UNINSTALL_ROOT:-}"

# 还原 Docker/UFW 修复（仅 --purge）
restore_docker_after_rules() {
    local f="${UFW_ETC_DIR}/after.rules" bak
    [[ -f "$f" ]] || return 0
    if grep -qF "# BEGIN auto-firewall DOCKER-USER fix" "$f" 2>/dev/null; then
        run_cmd cp "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        bak="$(find "$UFW_ETC_DIR" -maxdepth 1 -name 'after.rules.bak.*' ! -newer "$f" 2>/dev/null | sort -r | head -1)"
        if [[ -n "$bak" && -f "$bak" ]]; then
            run_cmd cp "$bak" "$f" && _info "已从备份还原 after.rules"
        else
            run_cmd sed -i '/# BEGIN auto-firewall DOCKER-USER fix/,/# END auto-firewall DOCKER-USER fix/d' "$f" \
                && _info "已剥离 DOCKER-USER 修复区块"
        fi
        ufw_exec reload >/dev/null 2>&1 || true
    fi
    return 0
}

# --purge 附加动作: 删脚本标记的 ufw 规则(SSH 保护)/还原 docker 修复/清理 fail2ban
purge_firewall() {
    refresh_ufw_table
    local k err=0
    local -a args
    for k in "${!UFW_EXIST[@]}"; do
        case "${UFW_MARKER[$k]:-none}" in
            auto-firewall|auto-firewall-whitelist|auto-firewall-manual) : ;;
            *) continue ;;
        esac
        if [[ "${k%%/*}" == "22" && "$FORCE_SSH" != "1" ]]; then
            _info "保留 SSH 规则: $k（确需删除请加 --force-ssh）"
            continue
        fi
        mapfile -t args < <(build_ufw_args "$k" delete)
        if (( ${#args[@]} == 0 )); then
            _err "无法解析规则 key: $k"; err=1; continue
        fi
        ufw_exec "${args[@]}" >/dev/null 2>&1 || { _err "删除规则失败: $k"; err=1; }
    done
    restore_docker_after_rules
    run_cmd rm -f "$FAIL2BAN_JAIL_CONF" "${FAIL2BAN_ACTION_DIR}/ufw.conf" \
        "${FAIL2BAN_FILTER_DIR}/nginx-ufw.conf" "${FAIL2BAN_FILTER_DIR}/nginx-404.conf"
    svc_exec disable --now fail2ban
    return $err
}

# 两档卸载: 默认仅删脚本足迹(系统防火墙/fail2ban 保持现状); --purge 含防火墙足迹
uninstall() {
    acquire_lock
    local R="$UNINSTALL_TARGET_ROOT"
    confirm "卸载 auto-firewall? 默认仅移除脚本足迹, 不改动系统防火墙与 fail2ban" || { _info "已取消"; return 1; }
    if [[ "$PURGE" == "1" ]]; then
        confirm "【危险】--purge 将删除本脚本添加的防火墙规则、还原 Docker 修复并停用 fail2ban。SSH(22) 规则默认保留" || { _info "已取消"; return 1; }
        if [[ "$ASSUME_YES" != "1" && ! -t 0 ]]; then
            _err "非交互执行 --purge 必须显式传 --yes"
            return 1
        fi
        local keep=""
        keep="$(backup_configs)" || { _err "备份失败, 中止卸载"; return 1; }
        purge_firewall || _err "部分防火墙残留清理失败, 继续卸载"
        # 卸载前备份移出被删目录, 长期保留（dry-run 不执行）
        if [[ "$DRY_RUN" != "1" && -z "$R" && -n "$keep" ]]; then
            local dest="/root/auto-firewall-uninstall-backup-$(date +%Y%m%d%H%M%S)"
            mkdir -p "$dest" && cp -a "$keep"/. "$dest/" \
                && _info "卸载前备份已保存: $dest"
        fi
    fi
    run_cmd rm -f "${R}/etc/profile.d/auto-firewall.sh"
    if [[ -f "${R}/etc/crontab" ]]; then
        run_cmd sed -i '/# BEGIN auto-firewall/,/# END auto-firewall/d' "${R}/etc/crontab"
    fi
    run_cmd rm -rf "${SCRIPT_DIR:?}"
    _info "卸载完成。提示: 系统级 ufw/fail2ban 仍在生效（封禁未停止）, 如需一并停用请改用 uninstall --purge（GAP-D）"
}

#---- 图形化管理界面 TUI（spec §6.3; 仅前端, 业务逻辑全部复用既有函数）------
ufw_read() { ufw "$@" 2>/dev/null; }    # 只读查询, 不经 run_cmd

tui_msg()  { dialog --backtitle "auto-firewall v${SCRIPT_VERSION}" --title "$1" --msgbox "$2" 18 72 2>/dev/null; }
tui_input(){ dialog --title "$1" --inputbox "$2" 10 60 3>&1 1>&2 2>&3; }
tui_dlg()  { dialog --clear --backtitle "auto-firewall v${SCRIPT_VERSION}" "$@" 3>&1 1>&2 2>&3; }

# 编辑对话框 + 逐行校验 + 非法行处理（spec §7.1 交互约定）
tui_edit_file() {
    local which="${1:-ports}" file tmp out line t bad=0 badlist=""
    case "$which" in ports) file="$WHITELIST_FILE" ;; ip) file="$IP_WHITELIST_FILE" ;; *) return 1 ;; esac
    tmp="$(mktemp)"
    cat "$file" > "$tmp"
    if ! out="$(tui_dlg --title "编辑 ${file}（保存前逐行校验）" --editbox "$tmp" 20 76)"; then
        rm -f "$tmp"; return 0
    fi
    rm -f "$tmp"
    while IFS= read -r line || [[ -n "$line" ]]; do
        t="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$t" || "$t" == \#* ]] && continue
        if [[ "$which" == "ports" ]]; then
            canon_key "$line" >/dev/null 2>&1 || { bad=$((bad+1)); badlist+="${line}"$'\n'; }
        else
            valid_ip_spec "${t%%[[:space:]]*}" || { bad=$((bad+1)); badlist+="${line}"$'\n'; }
        fi
    done <<<"$out"
    if (( bad )); then
        if dialog --title "校验" --yesno "发现 ${bad} 条非法行:\n${badlist}\n忽略非法行并保存?" 16 70 2>/dev/null; then
            backup_configs >/dev/null || return 1
            local kept=""
            while IFS= read -r line || [[ -n "$line" ]]; do
                t="${line#"${line%%[![:space:]]*}"}"
                if [[ -z "$t" || "$t" == \#* ]]; then kept+="${line}"$'\n'; continue; fi
                if [[ "$which" == "ports" ]]; then
                    canon_key "$line" >/dev/null 2>&1 && kept+="${line}"$'\n'
                else
                    valid_ip_spec "${t%%[[:space:]]*}" && kept+="${line}"$'\n'
                fi
            done <<<"$out"
            printf '%s' "$kept" > "$file"
            tui_msg "已保存（非法行已丢弃）" "$file"
        else
            tui_msg "已放弃" "修改未保存"
        fi
    else
        backup_configs >/dev/null || return 1
        printf '%s\n' "$out" > "$file"
        tui_msg "已保存" "$file"
    fi
}

tui_config() {
    local choice v out
    while true; do
        choice="$(tui_dlg --title "配置管理" --menu "v2 语法: 22/tcp, 8000:8100/tcp, 443/tcp/v6, icmp" 14 70 7 \
            1 "添加端口白名单" 2 "删除端口白名单" 3 "添加 IP 白名单" 4 "删除 IP 白名单" \
            5 "查看当前白名单" 6 "编辑端口白名单文件" 7 "编辑 IP 白名单文件" q "返回主菜单")" || return 0
        case "$choice" in
            1) v="$(tui_input "添加端口" "格式: 端口/协议[/族]")" || continue
               out="$(config_add_port "$v" 2>&1)" || true; tui_msg "结果" "$out" ;;
            2) v="$(tui_input "删除端口" "输入要移除的条目:")" || continue
               out="$(config_del_port "$v" 2>&1)" || true; tui_msg "结果" "$out" ;;
            3) v="$(tui_input "添加 IP" "IP 或 CIDR:")" || continue
               out="$(config_add_ip "$v" 2>&1)" || true; tui_msg "结果" "$out" ;;
            4) v="$(tui_input "删除 IP" "输入要移除的 IP:")" || continue
               out="$(config_del_ip "$v" 2>&1)" || true; tui_msg "结果" "$out" ;;
            5) out="$(config_list ports 2>&1; echo; config_list ip 2>&1)"; tui_msg "当前白名单" "$out" ;;
            6) tui_edit_file ports ;;
            7) tui_edit_file ip ;;
            q|"") return 0 ;;
        esac
    done
}

tui_ban() {
    local choice ip out
    choice="$(tui_dlg --title "封禁管理" --menu "手动封禁/解封" 10 60 3 \
        1 "封禁 IP" 2 "解封 IP" 3 "查看当前封禁")" || return 0
    case "$choice" in
        1) ip="$(tui_input "封禁 IP" "输入要封禁的 IP:")" || return 0
           out="$(ban_ip "$ip" 2>&1)" || true; tui_msg "结果" "$out" ;;
        2) ip="$(tui_input "解封 IP" "输入要解封的 IP:")" || return 0
           out="$(unban_ip "$ip" 2>&1)" || true; tui_msg "结果" "$out" ;;
        3) out="$(fail2ban_read status 2>/dev/null || echo 'fail2ban 未运行')\n手动封禁:\n$(ufw_read status | grep auto-firewall-manual || echo '  (无)')"
           tui_msg "封禁状态" "$out" ;;
    esac
}

tui_run() {
    local out err=0
    case "$1" in
        1) out="$(show_status 2>&1)"; tui_msg "总览仪表盘" "$out" ;;
        2) out="$(port_check 2>&1)" || err=1; tui_msg "端口检测$([[ $err == 1 ]] && echo 部分失败)" "$out" ;;
        3) out="$(fail2ban_check 2>&1)" || err=1; tui_msg "Fail2ban 检测" "$out" ;;
        4) out="$(cleanup 2>&1)"; tui_msg "系统清理" "$out" ;;
        5) tui_config ;;
        6) if dialog --title "恢复默认" --yesno "确认恢复默认配置(all)? 将先备份" 10 60 2>/dev/null; then
               out="$(ASSUME_YES=1 reset_config all 2>&1)" || true; tui_msg "恢复默认" "$out"
           fi ;;
        7) tui_ban ;;
        8) dialog --title "实时日志" --tailbox "$LOG_FILE" 24 80 2>/dev/null ;;
        9) out="$(DRY_RUN=1 port_check 2>&1)" || true
           out="$(grep '\[DRYRUN\]' "$LOG_FILE" | tail -30)"
           tui_msg "Dry-run 将要执行的动作(最近30条)" "$out" ;;
        10) out="$(show_version 2>&1)"; tui_msg "版本信息" "$out" ;;
        0) uninstall ;;
        q|"") return 0 ;;
    esac
}

tui_menu() {
    if ! command -v dialog &>/dev/null || [[ ! -t 1 ]]; then
        _info "无 dialog 或非交互终端, 降级为文本帮助"
        show_help
        return 0
    fi
    ensure_locale_utf8
    local choice
    while true; do
        choice="$(tui_dlg --title "管理菜单" --menu "请选择操作" 20 66 12 \
            1 "总览仪表盘" 2 "端口检测" 3 "Fail2ban检测" 4 "系统清理" \
            5 "配置管理(增删/编辑)" 6 "恢复默认配置" 7 "封禁/解封 IP" 8 "实时日志" \
            9 "Dry-run 演练" 10 "版本信息" 0 "卸载脚本与配置" q "退出")" || break
        tui_run "$choice" || _err "菜单动作返回错误"
    done
    clear 2>/dev/null || true
}

#---- Fail2ban + Nginx + UFW 集成 ---------------------------------------------
# 检测 Nginx 日志路径（spec §5: 输出 access 与 error 两行, 供不同 jail 归位）
detect_nginx_logpath() {
    local a="" e="" p
    for p in "$NGINX_LOG_DIR/access.log" "$NGINX_LOG_DIR/access_log"; do
        [[ -f "$p" ]] && { a="$p"; break; }
    done
    if [[ -z "$a" ]] && command -v nginx &>/dev/null; then
        p="$(nginx -T 2>/dev/null | grep -oP 'access_log\s+\K[^;]+' | head -1 || true)"
        [[ -n "$p" && -f "$p" ]] && a="$p"
    fi
    [[ -f "$NGINX_LOG_DIR/error.log" ]] && e="$NGINX_LOG_DIR/error.log"
    [[ -z "$a" && -z "$e" ]] && return 1
    echo "$a"
    echo "$e"
}

# 是否有邮件传输代理（决定 fail2ban action 降级, spec §5）
has_mta() { command -v sendmail &>/dev/null || command -v postfix &>/dev/null || command -v mail &>/dev/null; }

# 只读查询不走 run_cmd（dry-run 仍需真实状态）
fail2ban_read() { fail2ban-client "$@" 2>/dev/null; }
svc_active()  { systemctl is-active --quiet "$1" 2>/dev/null || service "$1" status &>/dev/null; }

# 初始化/更新 Fail2ban + Nginx 集成
init_fail2ban() {
    _info "正在配置 Fail2ban + Nginx + UFW 集成..."

    # 1. 安装 fail2ban
    if ! command -v fail2ban-client &>/dev/null; then
        _info "fail2ban 未安装，正在安装..."
        apt_exec update -qq && apt_exec install -y -qq fail2ban
    fi

    # 2. 初始化 IP 白名单文件
    init_ip_whitelist

    # 3. 创建 UFW ban action（若不存在）
    local ufw_action="${FAIL2BAN_ACTION_DIR}/ufw.conf"
    if [[ ! -f "$ufw_action" ]]; then
        cat > "$ufw_action" <<'UFWACT'
# Fail2ban UFW action - 通过 ufw 封禁/解封 IP
[Definition]
actionstart  =
actionstop   =
actioncheck  =
actionban    = ufw insert 1 deny from <ip> to any comment 'fail2ban-<name>'
actionunban  = ufw delete deny from <ip> to any comment 'fail2ban-<name>'
UFWACT
        _info "已创建 UFW ban action: $ufw_action"
    fi

    # 4. 创建 Nginx 综合过滤器（检测恶意扫描、漏洞探测）
    local nginx_filter="${FAIL2BAN_FILTER_DIR}/nginx-ufw.conf"
    if [[ ! -f "$nginx_filter" ]]; then
        cat > "$nginx_filter" <<'NGFILTER'
# Nginx 恶意请求综合过滤器
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) .*(\.env|\.git|wp-admin|wp-login|phpmyadmin|adminer|config\.php|\.aws|\.htaccess|\.htpasswd|jenkins|solr|actuator|\.DS_Store|xmlrpc).*".* [45][0-9][0-9] .*$
            ^<HOST> -.*"(GET|POST|HEAD).*(/cgi-bin/|\.cgi$|\.sh$|cmd\.exe|win\.ini|passwd).*".* [45][0-9][0-9] .*$
            ^<HOST> -.*"(GET|POST).*(/api/|/graphql|/wp-json).*".* 429 .*$
ignoreregex =
NGFILTER
        _info "已创建 Nginx 防护过滤器: $nginx_filter"
    fi

    # 5. 创建 nginx-404 过滤器（若系统默认不存在则补充）
    local n404_filter="${FAIL2BAN_FILTER_DIR}/nginx-404.conf"
    if [[ ! -f "$n404_filter" ]]; then
        cat > "$n404_filter" <<'N404FILTER'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*".* 404 .*$
ignoreregex = /favicon\.ico$|/robots\.txt$|/apple-touch-icon.*$
N404FILTER
    fi

    # 6. 生成/更新 jail.local 配置
    rebuild_f2b_jail

    # 7. 确保 fail2ban 开机启动并运行
    svc_exec enable fail2ban
    svc_exec restart fail2ban
    _info "Fail2ban 配置完成。"
}

# 重建 fail2ban jail.local（合并 IP 白名单; 各 nginx jail 按日志存在性启用; 无 MTA 降级）
rebuild_f2b_jail() {
    local ignore_ips
    ignore_ips="$(read_ip_whitelist)"
    local -a loglines=()
    mapfile -t loglines < <(detect_nginx_logpath 2>/dev/null || true)
    local nginx_access="${loglines[0]:-}"
    local nginx_error="${loglines[1]:-}"

    local default_action="%(action_)s"
    has_mta && default_action="%(action_mwl)s"

    local nginx_jails=""
    if [[ -n "$nginx_access" ]]; then
        nginx_jails="${nginx_jails}
[nginx-ufw]
enabled  = true
filter   = nginx-ufw
logpath  = ${nginx_access}
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
action   = ufw[name=nginx-ufw, protocol=all]

[nginx-404]
enabled  = true
port     = http,https
filter   = nginx-404
logpath  = ${nginx_access}
maxretry = 20
findtime = ${F2B_FINDTIME}
bantime  = $((F2B_BANTIME / 2))
action   = ufw[name=nginx-404x, protocol=all]
"
    fi
    if [[ -n "$nginx_error" ]]; then
        nginx_jails="${nginx_jails}
[nginx-bad-request]
enabled  = true
port     = http,https
filter   = nginx-bad-request
logpath  = ${nginx_error}
maxretry = 3
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
action   = ufw[name=nginx-badreq, protocol=all]

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = ${nginx_error}
maxretry = 3
findtime = ${F2B_FINDTIME}
bantime  = $((F2B_BANTIME * 2))
action   = ufw[name=nginx-bot, protocol=all]
"
    fi

    local out="${FAIL2BAN_JAIL_OUT_OVERRIDE:-$FAIL2BAN_JAIL_CONF}"
    cat > "$out" <<JAILEOF
# Fail2ban 配置 - 由 auto-firewall.sh 自动管理
# 修改 IP 白名单: 编辑 ${IP_WHITELIST_FILE} 后运行 fail2ban-check
[DEFAULT]
ignoreip = ${ignore_ips}
bantime  = ${F2B_BANTIME}
findtime = ${F2B_FINDTIME}
maxretry = ${F2B_MAXRETRY}
banaction = ufw
banaction_allports = ufw
destemail = root
mta = sendmail
protocol = tcp
chain = INPUT
action = ${default_action}

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
findtime = ${F2B_FINDTIME}
bantime  = $((F2B_BANTIME * 4))
action   = ufw[name=ssh, protocol=all]
${nginx_jails}
JAILEOF

    _info "Fail2ban jail.local 已更新（ignoreip: ${ignore_ips}）"
}

#---- fail2ban 运行时检测 -----------------------------------------------------
fail2ban_check() {
    acquire_lock
    _info "开始 Fail2ban 状态检测..."

    # 1. 确保 fail2ban 已安装和运行
    if ! command -v fail2ban-client &>/dev/null; then
        _info "fail2ban 未安装，正在初始化..."
        init_fail2ban
        _info "Fail2ban 检测完成（已完成初始化）。"
        return 0
    fi

    # 确保服务运行
    if ! svc_active fail2ban; then
        _info "fail2ban 未运行，正在启动..."
        svc_exec start fail2ban
    fi

    # 2. 检测 Docker 是否新安装（自适应）
    fix_docker_ufw

    # 3+4. 幂等同步: 先在临时路径重生成 jail, 与现行配置比对, 有差异才替换+重载
    #       （同时覆盖 “nginx 日志路径变化” 与 “IP 白名单变化” 两类变更检测）
    local tmp_jail="${STATE_FILE}.jail.tmp.$$" need_reload=false
    if FAIL2BAN_JAIL_OUT_OVERRIDE="$tmp_jail" rebuild_f2b_jail; then
        if [[ ! -f "$FAIL2BAN_JAIL_CONF" ]] || ! cmp -s "$tmp_jail" "$FAIL2BAN_JAIL_CONF"; then
            _info "jail.local 与白名单/日志路径不同步, 正在更新..."
            mv "$tmp_jail" "$FAIL2BAN_JAIL_CONF"
            need_reload=true
        else
            rm -f "$tmp_jail"
        fi
    else
        rm -f "$tmp_jail"
        _err "jail 预生成失败, 跳过同步"
        need_reload=false
    fi

    if [[ "$need_reload" == "true" ]]; then
        svc_exec reload fail2ban
        _info "Fail2ban 配置已更新并重载。"
    fi

    # 5. 输出当前封禁统计（遍历各 jail 汇总）
    local total_banned
    total_banned=$(fail2ban_read status \
        | awk '/Jail list:/{sub(/.*Jail list:[ \t]*/,""); gsub(/,/,""); for(i=1;i<=NF;i++) print $i}' \
        | while read -r j; do
            [[ -z "$j" ]] && continue
            fail2ban_read status "$j" | grep -oP 'Total banned:\s*\K\d+' || echo 0
        done | awk '{s+=$1} END {print s+0}' || true)
    _info "Fail2ban 运行正常，当前累计封禁 IP 数: ${total_banned:-0}"
    _info "Fail2ban 检测完成。"
}

#---- ufw 初始化 --------------------------------------------------------------
# GAP-B(spec §5): 必须在 ufw enable 之前确保 /etc/default/ufw IPV6=yes,
# 否则存量机器迁移到 v2 后首次启用不会下发 IPv6 规则
ensure_ipv6_before_enable() {
    if [[ -f "$UFW_DEFAULT_FILE" ]]; then
        if grep -q '^IPV6=' "$UFW_DEFAULT_FILE"; then
            sed -i 's/^IPV6=.*/IPV6=yes/' "$UFW_DEFAULT_FILE"
        else
            echo "IPV6=yes" >> "$UFW_DEFAULT_FILE"
        fi
    fi
    ufw_exec reload &>/dev/null || true
    ufw_exec enable &>/dev/null || true
}

init_ufw() {
    _info "正在初始化 UFW 防火墙..."

    # 安装 ufw
    if ! command -v ufw &>/dev/null; then
        _info "ufw 未安装，正在安装..."
        apt_exec update -qq && apt_exec install -y -qq ufw
    fi

    # GAP-B: 先开 IPv6 再启用防火墙
    ensure_ipv6_before_enable

    # 重置到干净状态并启用
    _info "配置默认策略: 拒绝入站 / 放行出站..."
    ufw_exec --force disable &>/dev/null || true
    ufw_exec --force enable  &>/dev/null || true
    ufw_exec default deny incoming
    ufw_exec default allow outgoing

    # Docker 兼容性修复
    fix_docker_ufw

    # 生成白名单（扫描当前监听端口）
    generate_whitelist

    # 放行所有白名单端口
    _info "正在放行白名单端口..."
    apply_whitelist

    # 标记首次运行完成
    touch "$FIRST_RUN_MARK"
    _info "UFW 初始化完成。"
}

#---- Docker + UFW 兼容性修复 ------------------------------------------------
fix_docker_ufw() {
    if ! command -v docker &>/dev/null; then
        _info "未检测到 Docker，跳过 Docker/UFW 兼容性修复。"
        return 0
    fi

    _info "检测到 Docker，正在修复 Docker 绕过 UFW 的安全问题..."

    local AFTER_RULES="/etc/ufw/after.rules"
    local MARKER="# BEGIN auto-firewall DOCKER-USER fix"

    # 已经修复过则跳过
    if grep -qF "$MARKER" "$AFTER_RULES" 2>/dev/null; then
        _info "Docker/UFW 兼容性修复已存在，跳过。"
        return 0
    fi

    # 备份原始文件
    cp "$AFTER_RULES" "${AFTER_RULES}.bak.$(date +%Y%m%d%H%M%S)"

    # 在 *filter 段末尾（COMMIT 之前）插入 DOCKER-USER 链规则
    # 这样 UFW 规则对 Docker 暴露的端口也能生效
    local insert_rules="${MARKER}
# 让 DOCKER-USER 链接受 UFW 的过滤规则，修复 Docker 端口绕过 UFW 的问题
:ufw-user-input - [0:0]
-A DOCKER-USER -j ufw-user-input
-A DOCKER-USER -j RETURN
# END auto-firewall DOCKER-USER fix"

    # 在 *filter 段的 COMMIT 之前插入
    if grep -q '^*filter' "$AFTER_RULES"; then
        awk -v rules="$insert_rules" '
            /^COMMIT/ && in_filter { print rules; in_filter=0 }
            /^\*filter/ { in_filter=1 }
            { print }
        ' "$AFTER_RULES" > "${AFTER_RULES}.tmp"
        mv "${AFTER_RULES}.tmp" "$AFTER_RULES"
    else
        # 没有 *filter 段，直接追加
        echo -e "\n${insert_rules}" >> "$AFTER_RULES"
    fi

    # 重启 ufw 应用更改
    ufw reload &>/dev/null || true
    _info "Docker/UFW 兼容性修复完成。"
}

#---- 白名单管理 v2（spec §2.4/§3）---------------------------------------------
# 基于当前监听生成默认白名单（均为动态 tcp/udp 单端口）
generate_whitelist() {
    _info "正在生成初始端口白名单..."
    local keys k base port proto svc raw
    keys="$(scan_current_keys || true)"
    raw="$(ss_listen_raw 2>/dev/null || true)"
    {
        echo "# schema-version: 2"
        cat <<'GWHDR'
# ============================================
# 防火墙自动脚本 - 端口白名单配置（v2 语法）
#
# 格式: 端口/协议[/地址族]  # 服务名
#   22/tcp              # SSH（双栈）
#   8000:8100/tcp       # 端口区间
#   443/tcp/v6          # 仅 IPv6
#   icmp 或 -/esp       # 无端口协议
#
# 白名单端口始终放行且不受自动回收影响。
GWHDR
        echo "# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# ============================================"
        echo ""
        echo "# --- 自动检测到的端口（基于首次运行时的监听状态）---"
    } > "$WHITELIST_FILE"
    for k in $keys; do
        base="${k%%/*}"; port="${base%%:*}"
        proto="${k#*/}"; proto="${proto%%/*}"
        svc="$(awk -v p=":${port} " 'index($0,p){ if (match($0,/\(\("[^"]+"/)){s=substr($0,RSTART+3);sub(/".*/,"",s);print s;exit} }' <<<"$raw")"
        [[ -z "$svc" ]] && svc="auto-detected"
        echo "${k}  # ${svc}" >> "$WHITELIST_FILE"
    done
    echo "" >> "$WHITELIST_FILE"
    echo "# --- 用户自定义端口（可在此添加）---" >> "$WHITELIST_FILE"
    echo "# 8080/tcp  # 示例: 自定义Web服务" >> "$WHITELIST_FILE"
    _info "白名单已生成: $WHITELIST_FILE"
}

# 读取白名单 -> canon key 逐行; 跳过注释/版本头/无法解析行（spec §2.4）
read_whitelist() {
    [[ -f "$WHITELIST_FILE" ]] || return 1
    local raw k
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        k="$(canon_key "$raw" 2>/dev/null)" || continue
        echo "$k"
    done < "$WHITELIST_FILE" | sort -u
}

#---- ufw 规则表缓存（spec §3.2, GAP-C）----------------------------------------
# 注: 用 -gA 强制全局(脚本可能被 bats 在函数内 source, 普通 declare 会变成局部);
#     声明与空赋值分开, `declare -A X=()` 会丢失关联属性(bash 怪癖)
declare -gA UFW_EXIST
declare -gA UFW_MARKER
UFW_EXIST=()
UFW_MARKER=()

# 解析 ufw status 输出填充 EXIST/MARKER; 只读操作不走 run_cmd(dry-run 仍需真实状态)
refresh_ufw_table() {
    UFW_EXIST=(); UFW_MARKER=()
    local line tok key marker famtok
    while IFS= read -r line; do
        [[ "$line" != *ALLOW* ]] && continue
        line="${line#"${line%%[^ ]*}"}"                       # 去前导空白
        line="$(sed 's/^\[[0-9]*\][[:space:]]*//' <<<"$line")" # 去 numbered 前缀
        marker="none"
        case "$line" in
            *auto-firewall-whitelist*) marker="auto-firewall-whitelist" ;;
            *auto-firewall-manual*)    marker="auto-firewall-manual" ;;
            *auto-firewall*)           marker="auto-firewall" ;;
        esac
        tok="${line%% *}"
        famtok=""
        case "$line" in *"(v6)"*) famtok="/v6" ;; esac
        key=""
        if [[ "$tok" =~ ^[0-9]+(:[0-9]+)?/(tcp|udp)$ ]]; then
            key="${tok}${famtok}"
        elif [[ "$tok" =~ ^(icmp|esp|ah|gre|sctp|any)$ ]]; then
            key="-/${tok}"
        fi
        [[ -z "$key" ]] && continue
        UFW_EXIST["$key"]=1
        [[ "$marker" != "none" ]] && UFW_MARKER["$key"]="$marker"
    done < <(ufw status 2>/dev/null || true) || true   # 末行 continue 会使 while 返回非0, set -e 下需显式吞掉
}

# 采集当前监听 canon key 集合; v4-only 归一为双栈简写 key(避免 v1->v2 规则抖动)
scan_current_keys() {
    local raw line parsed p proto fam
    local -A v4=() v6=()
    raw="$(ss_listen_raw)" || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        parsed="$(parse_scan_line "$line")" || continue
        IFS='|' read -r p proto fam <<<"$parsed"
        case "$fam" in
            4)   v4["${p}/${proto}"]=1 ;;
            6)   v6["${p}/${proto}"]=1 ;;
            all) v4["${p}/${proto}"]=1; v6["${p}/${proto}"]=1 ;;
        esac
    done <<<"$raw"
    local k
    for k in "${!v4[@]}"; do echo "$k"; done
    for k in "${!v6[@]}"; do
        [[ -n "${v4[$k]:-}" ]] || echo "${k}/v6"
    done | sort -u
}

# 放行所有白名单端口（幂等: 查缓存表; 数组传参防注入）
apply_whitelist() {
    local whitelist
    whitelist="$(read_whitelist 2>/dev/null || true)"
    if [[ -z "$whitelist" ]]; then
        _info "白名单为空，跳过端口放行。"
        return 0
    fi
    refresh_ufw_table
    local entry err=0
    local -a args
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        [[ -n "${UFW_EXIST[$entry]:-}" ]] && continue
        mapfile -t args < <(build_ufw_args "$entry" allow)
        if (( ${#args[@]} == 0 )); then
            _err "非法白名单条目: ${entry}"; err=1; continue
        fi
        if ufw_exec "${args[@]}" comment "auto-firewall-whitelist" >/dev/null 2>&1; then
            _info "白名单放行: ${entry}"
        else
            _err "白名单放行失败: ${entry}"; err=1
        fi
    done <<<"$whitelist"
    return $err
}

#---- 端口检测与动态管理（v2）--------------------------------------------------
port_check() {
    acquire_lock
    _info "开始端口扫描..."

    # 0. Docker 环境自适应检测
    fix_docker_ufw

    # 1. 确保白名单端口都已放行
    apply_whitelist || _err "白名单放行存在错误"

    # 2. 采集当前监听 / 白名单 / 上次状态
    local cur wl prev
    cur="$(scan_current_keys || true)"
    wl="$(read_whitelist 2>/dev/null || true)"
    prev=""
    [[ -f "$STATE_FILE" ]] && prev="$(grep -v '^#' "$STATE_FILE" 2>/dev/null | tr '\n' ' ')"

    # 3. 规则表缓存 + 差分执行（尽力而为, 结束汇总退出, spec §2.5）
    refresh_ufw_table
    local actions line op key err=0
    actions="$(compute_port_actions "$(echo "$cur" | tr '\n' ' ')" "$prev" "$(echo "$wl" | tr '\n' ' ')")"
    local -a args
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        op="${line%%:*}"; key="${line#*:}"
        mapfile -t args < <(build_ufw_args "$key" "$([[ "$op" == "ADD" ]] && echo allow || echo delete)")
        if (( ${#args[@]} == 0 )); then
            _err "非法 key: ${key}"; err=1; continue
        fi
        if [[ "$op" == "ADD" ]]; then
            [[ -n "${UFW_EXIST[$key]:-}" ]] && continue
            if ufw_exec "${args[@]}" comment "auto-firewall" >/dev/null 2>&1; then
                _info "自动放行: ${key}"
            else
                _err "放行失败: ${key}"; err=1
            fi
        else
            # 仅回收脚本自动添加的动态规则
            if [[ "${UFW_MARKER[$key]:-}" == "auto-firewall" ]]; then
                if ufw_exec "${args[@]}" >/dev/null 2>&1; then
                    _info "自动回收: ${key}"
                else
                    _err "回收失败: ${key}"; err=1
                fi
            fi
        fi
    done <<<"$actions"

    # 4. 更新状态文件: 仅记录非白名单动态端口
    local k dyn=""
    for k in $cur; do
        if [[ -n "$wl" ]] && echo "$wl" | grep -qxF "$k"; then continue; fi
        dyn="${dyn}${k}"$'\n'
    done
    { echo "# schema-version: 2"; printf '%s' "$dyn" | sort -u | sed '/^$/d'; } > "$STATE_FILE"

    if (( err )); then
        _err "端口扫描部分失败。"
        return 1
    fi
    _info "端口扫描完成。"
}

#---- 系统清理 ----------------------------------------------------------------
cleanup() {
    acquire_lock
    _info "开始系统清理..."

    local freed=0

    # 1. APT 包管理缓存清理
    if command -v apt-get &>/dev/null; then
        apt_exec clean &>/dev/null || true
        apt_exec autoremove --purge -y &>/dev/null || true
        _info "APT 缓存已清理。"
    fi

    # 2. Systemd Journal 日志清理（不存在则跳过）
    if command -v journalctl &>/dev/null; then
        journalctl --vacuum-time=7d &>/dev/null || true
        _info "Systemd Journal 已清理（保留7天）。"
    else
        _info "journalctl 不存在，跳过 Journal 清理。"
    fi

    # 3. 内存缓存释放（仅在空闲内存低于阈值时执行）
    local mem_free_pct
    mem_free_pct=$(awk '/MemTotal/ {total=$2} /MemAvailable/ {avail=$2} END {if(total>0) printf "%.0f", avail*100/total; else print 100}' /proc/meminfo 2>/dev/null \
        || awk '/MemTotal/ {total=$2} /MemFree/ {free=$2} /^Buffers:/ {buffers=$2} /^Cached:/ {cached=$2} END {if(total>0) printf "%.0f", (free+buffers+cached)*100/total; else print 100}' /proc/meminfo 2>/dev/null \
        || echo 100)
    if [[ $mem_free_pct -lt $MEM_FREE_THRESHOLD ]]; then
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        freed=1
        _info "内存缓存已释放（空闲内存 ${mem_free_pct}% < ${MEM_FREE_THRESHOLD}%）。"
    else
        _info "空闲内存充足（${mem_free_pct}%），跳过缓存释放。"
    fi

    # 4. 清理 /tmp 中超过24小时的临时文件
    local tmp_cleaned
    tmp_cleaned=$(find /tmp -type f -mtime +1 -name '*.tmp' -delete -print 2>/dev/null | wc -l || true)
    tmp_cleaned=$((tmp_cleaned + $(find /tmp -type f -atime +1 -name '*.log' -delete -print 2>/dev/null | wc -l || true)))
    if [[ $tmp_cleaned -gt 0 ]]; then
        _info "/tmp 清理了 ${tmp_cleaned} 个过期临时文件。"
    fi

    # 5. 脚本自身日志轮转
    rotate_log

    # 6. Fail2ban 日志轮转（>10MB 截断至最后 2000 行）
    if [[ -f /var/log/fail2ban.log ]]; then
        local f2b_size
        f2b_size=$(stat -c%s /var/log/fail2ban.log 2>/dev/null || echo 0)
        if [[ $f2b_size -gt 10485760 ]]; then
            tail -n 2000 /var/log/fail2ban.log > /tmp/fail2ban.log.tmp
            mv /tmp/fail2ban.log.tmp /var/log/fail2ban.log
            _info "Fail2ban 日志已轮转。"
        fi
    fi

    _info "系统清理完成。"
}

#---- Cron 部署 ---------------------------------------------------------------
# profile.d 快捷命令目标（测试 seam, spec §6.2）
SHORTCUT_TARGET="${AUTO_FW_SHORTCUT_TARGET:-/etc/profile.d/auto-firewall.sh}"

# 写入 x/X 命令行快捷命令（替代 sudo bash auto-firewall.sh）, 幂等区块
install_shortcut() {
    mkdir -p "$(dirname "$SHORTCUT_TARGET")"
    if [[ -f "$SHORTCUT_TARGET" ]]; then
        sed -i '/# BEGIN auto-firewall-shortcut/,/# END auto-firewall-shortcut/d' "$SHORTCUT_TARGET"
    fi
    cat >> "$SHORTCUT_TARGET" <<'SC'
# BEGIN auto-firewall-shortcut
afw_shortcut() {
    if [[ $# -eq 0 ]]; then
        sudo bash /opt/auto-firewall/auto-firewall.sh menu
    else
        sudo bash /opt/auto-firewall/auto-firewall.sh "$@"
    fi
}
x() { afw_shortcut "$@"; }
X() { afw_shortcut "$@"; }
# END auto-firewall-shortcut
SC
    chmod 644 "$SHORTCUT_TARGET"
    _info "快捷命令 x/X 已写入 $SHORTCUT_TARGET"
}

install_cron() {
    _info "正在配置 Crontab 定时任务..."

    local cron_jobs
    # 使用 read -r -d '' 读取多行字符串
    IFS= read -r -d '' cron_jobs <<'CRONEOF' || true
# BEGIN auto-firewall - 请勿手动编辑此区块
*/5 * * * *  root /opt/auto-firewall/auto-firewall.sh port-check     >> /opt/auto-firewall/logs/cron.log 2>&1
*/15 * * * * root /opt/auto-firewall/auto-firewall.sh fail2ban-check >> /opt/auto-firewall/logs/cron.log 2>&1
0   * * * *  root /opt/auto-firewall/auto-firewall.sh cleanup        >> /opt/auto-firewall/logs/cron.log 2>&1
# END auto-firewall
CRONEOF

    # 移除旧的 cron 条目
    if [[ -f /etc/crontab ]]; then
        sed -i '/# BEGIN auto-firewall/,/# END auto-firewall/d' /etc/crontab
        echo "$cron_jobs" >> /etc/crontab
    else
        echo "$cron_jobs" > /etc/crontab
    fi

    # 确保 cron 服务运行（Debian 可能默认未启用）
    if command -v systemctl &>/dev/null; then
        systemctl enable cron &>/dev/null || systemctl enable cronie &>/dev/null || true
        systemctl start cron  &>/dev/null || systemctl start cronie  &>/dev/null || true
    elif command -v service &>/dev/null; then
        service cron start &>/dev/null || true
    fi

    _info "Cron 定时任务已配置:"
    _info "  - 端口检测:     每5分钟"
    _info "  - Fail2ban检测:  每15分钟"
    _info "  - 系统清理:     每小时"
}

#---- 帮助信息 ----------------------------------------------------------------
show_help() {
    cat <<EOF
防火墙自动管理脚本 auto-firewall.sh v${SCRIPT_VERSION}

用法: sudo bash auto-firewall.sh <命令> [全局flag]
     或安装后直接敲快捷命令: x [命令]（替代 sudo bash auto-firewall.sh）

命令:
  install                安装(目录/迁移/dialog/快捷命令/cron/首次初始化)
  menu                   打开 dialog 图形管理界面(需 TTY; 非交互降级为帮助)
  port-check             扫描端口并自动放行/回收
  fail2ban-check         检测 Fail2ban, 幂等同步 jail 配置
  cleanup                系统清理 + 日志/备份轮转
  status                 文本状态总览
  config add <port|ip> V 新增白名单条目(经 v2 校验/去重/备份)
  config del <port|ip> V 删除条目(SSH/内置默认 IP 受保护不可删)
  config list [ports|ip] 查看白名单
  config edit [ports|ip] 用 \$EDITOR 编辑, 保存前逐行校验
  reset-config [范围]     恢复默认配置 all|ports|ip|fail2ban(备份+确认)
  ban <IP>               手动封禁(fail2ban 在线走 jail, 否则 ufw deny)
  unban <IP>             解除手动封禁
  version                版本与依赖信息
  log [N]                查看最近 N 行日志(默认100)
  uninstall              卸载(默认不动系统防火墙); --purge 含 ufw/fail2ban/docker 足迹
  help                   本帮助

全局 flag(可在命令前/后): --dry-run(只记录不执行,[DRYRUN]日志) --yes/-y(免交互确认)
  uninstall 专用: --purge --force-ssh(连 SSH 规则一起删, 危险)

端口白名单 v2 语法(保留 v1 兼容):
  22/tcp            双栈 SSH    | 8000:8100/tcp  端口区间
  443/tcp/v6        仅 IPv6     | icmp 或 -/esp  无端口协议

文件: /opt/auto-firewall/{auto-firewall.sh,port-whitelist.conf,ip-whitelist.conf,ports.state,.schema_version,backup/,logs/}
Cron: */5 port-check | */15 fail2ban-check | 0 * cleanup
卸载提示: 默认档后系统级 ufw/fail2ban 仍在生效, 需停用请用 uninstall --purge
EOF
}

#---- 查看状态 ----------------------------------------------------------------
show_status() {
    echo "=========================================="
    echo "  防火墙自动脚本 - 运行状态"
    echo "=========================================="
    echo ""

    echo "  版本: ${SCRIPT_VERSION}  schema: ${STATE_SCHEMA_VERSION}"
    echo ""

    echo "[UFW 状态]"
    ufw status verbose 2>/dev/null || echo "  UFW 未安装或未启用"
    echo ""

    echo "[白名单端口（v2 语法: 端口/协议[/族], 含区间与无端口协议）] ($WHITELIST_FILE)"
    if [[ -f "$WHITELIST_FILE" ]]; then
        read_whitelist 2>/dev/null || echo "  (空)"
    else
        echo "  (白名单文件不存在)"
    fi
    echo ""

    echo "[动态追踪端口] ($STATE_FILE)"
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE" 2>/dev/null || echo "  (空)"
    else
        echo "  (状态文件不存在)"
    fi
    echo ""

    echo "[上次日志]"
    tail -5 "$LOG_FILE" 2>/dev/null || echo "  无日志"
    echo ""

    echo "[Fail2ban 状态]"
    if command -v fail2ban-client &>/dev/null; then
        fail2ban-client status 2>/dev/null || echo "  Fail2ban 服务异常"
    else
        echo "  Fail2ban 未安装"
    fi
    echo ""

    echo "[IP 白名单] ($IP_WHITELIST_FILE)"
    if [[ -f "$IP_WHITELIST_FILE" ]]; then
        grep -E '^[[:space:]]*[0-9a-fA-F.:/]+' "$IP_WHITELIST_FILE" 2>/dev/null | grep -v '^[[:space:]]*#' | sed 's/[[:space:]]*#.*//' | grep -v '^[[:space:]]*$' || echo "  (空)"
    else
        echo "  (IP 白名单文件不存在)"
    fi
}

#---- 安装部署 ----------------------------------------------------------------
do_install() {
    check_root
    check_debian_family

    _info "正在安装防火墙自动脚本..."

    # 创建目录结构
    mkdir -p "$SCRIPT_DIR" "$LOG_DIR"
    chmod 755 "$SCRIPT_DIR" "$LOG_DIR"

    # 无损升级: 先完成配置迁移再初始化（spec §4）
    run_migrations || { _err "配置迁移失败, 安装中止（原配置未受影响）"; exit 1; }

    # 复制自身到目标位置（如果不在目标位置）
    if [[ "$SCRIPT_PATH" != "${SCRIPT_DIR}/auto-firewall.sh" ]]; then
        cp "$SCRIPT_PATH" "${SCRIPT_DIR}/auto-firewall.sh"
        chmod 700 "${SCRIPT_DIR}/auto-firewall.sh"
        _info "脚本已安装到 ${SCRIPT_DIR}/auto-firewall.sh"
    fi

    # 确保日志文件存在
    touch "$LOG_FILE" "${LOG_DIR}/cron.log"
    chmod 644 "$LOG_FILE" "${LOG_DIR}/cron.log"

    # 首次初始化 ufw
    if [[ ! -f "$FIRST_RUN_MARK" ]]; then
        init_ufw
    else
        _info "首次运行已完成，跳过初始化。"
        _info "如需重新生成白名单，请删除 ${FIRST_RUN_MARK} 后重新运行 install。"
    fi

    # 初始化 Fail2ban（首次时安装，后续仅做配置同步）
    if ! command -v fail2ban-client &>/dev/null || [[ ! -f "$FAIL2BAN_JAIL_CONF" ]]; then
        init_fail2ban
    else
        _info "Fail2ban 已配置，跳过初始化（使用 fail2ban-check 命令检测变更）。"
    fi

    # 安装 Cron
    install_cron

    # TUI 依赖 dialog（失败不致命, 降级为文本帮助）
    if ! command -v dialog &>/dev/null; then
        _info "安装 dialog（TUI 依赖）..."
        apt_exec update -qq && apt_exec install -y -qq dialog \
            || _err "dialog 安装失败, menu 将降级为文本帮助"
    fi

    # 命令行快捷命令 x/X（spec §6.2）
    install_shortcut

    _info "安装完成！"
    echo ""
    echo "=============================================="
    echo "  防火墙自动脚本已成功部署！"
    echo "=============================================="
    echo "  Cron 已配置:"
    echo "    端口检测:     每 5 分钟"
    echo "    Fail2ban检测:  每 15 分钟"
    echo "    系统清理:     每 1 小时"
    echo ""
    echo "  配置文件:"
    echo "    端口白名单: ${WHITELIST_FILE}"
    echo "    IP 白名单:  ${IP_WHITELIST_FILE}"
    echo ""
    echo "  快捷命令: x（需重新登录或 source ${SHORTCUT_TARGET} 生效）"
    echo ""
    echo "  手动运行:"
    echo "    sudo bash auto-firewall.sh port-check"
    echo "    sudo bash auto-firewall.sh fail2ban-check"
    echo "    sudo bash auto-firewall.sh cleanup"
    echo "    sudo bash auto-firewall.sh status"
    echo "    sudo bash auto-firewall.sh menu"
    echo "=============================================="
}

#---- 入口 --------------------------------------------------------------------
# 全局 flag 状态（parse_args 填充, spec §9 G6）
DRY_RUN="${AUTO_FW_DRYRUN:-0}"
ASSUME_YES=0
PURGE=0
FORCE_SSH=0
declare -a CMD_ARGS=()

# 剥离全局 flag（可在子命令前/后/中）, 剩余 positional 存入 CMD_ARGS
parse_args() {
    CMD_ARGS=()
    DRY_RUN="${AUTO_FW_DRYRUN:-0}"; ASSUME_YES=0; PURGE=0; FORCE_SSH=0
    local a
    for a in "$@"; do
        case "$a" in
            --dry-run)   DRY_RUN=1 ;;
            --yes|-y)    ASSUME_YES=1 ;;
            --purge)     PURGE=1 ;;
            --force-ssh) FORCE_SSH=1 ;;
            *)           CMD_ARGS+=("$a") ;;
        esac
    done
    if [[ "$DRY_RUN" == "1" ]]; then export DRY_RUN; fi
}

main() {
    parse_args "$@"
    local cmd="${CMD_ARGS[0]:-help}"
    local rc=0

    # 这些命令需要 root
    case "$cmd" in
        install|port-check|cleanup|fail2ban-check|config|reset-config|uninstall|ban|unban|menu)
            check_root
            init_dirs
            ;;
    esac

    # 注: 子命令失败需用 `|| rc=$?` 显式捕获, case 分支不会自动传播退出码
    case "$cmd" in
        install)        do_install || rc=$? ;;
        port-check)     port_check || rc=$? ;;
        fail2ban-check) fail2ban_check || rc=$? ;;
        cleanup)        cleanup || rc=$? ;;
        status)         show_status || rc=$? ;;
        menu)
            if command -v dialog &>/dev/null && [[ -t 1 ]]; then
                ensure_locale_utf8
                tui_menu || rc=$?
            else
                _info "dialog 不可用或非交互终端, 降级为文本帮助"
                show_help
            fi ;;
        config)         config_main "${CMD_ARGS[@]:1}" || rc=$? ;;
        reset-config)   reset_config "${CMD_ARGS[1]:-all}" || rc=$? ;;
        ban)            ban_ip "${CMD_ARGS[1]:-}" "${CMD_ARGS[2]:-}" || rc=$? ;;
        unban)          unban_ip "${CMD_ARGS[1]:-}" || rc=$? ;;
        version)        show_version || rc=$? ;;
        log)            show_log "${CMD_ARGS[1]:-100}" || rc=$? ;;
        uninstall)      uninstall || rc=$? ;;
        help|--help|-h) show_help ;;
        *)
            echo "错误: 未知命令 '$cmd'" >&2
            show_help
            exit 1
            ;;
    esac
    return "$rc"
}

# 初始化目录（需要 root 的命令调用）
init_dirs() {
    mkdir -p "$SCRIPT_DIR" "$LOG_DIR"
    touch "$LOG_FILE" 2>/dev/null || true
}

# 仅在直接执行时进入分发; 被 bats source 时不运行（spec §10.1）
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
