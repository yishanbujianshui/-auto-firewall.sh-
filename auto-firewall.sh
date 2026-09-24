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
readonly FAIL2BAN_JAIL_CONF="/etc/fail2ban/jail.local"
readonly FAIL2BAN_FILTER_DIR="/etc/fail2ban/filter.d"
readonly FAIL2BAN_ACTION_DIR="/etc/fail2ban/action.d"
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

# 生成默认 IP 白名单文件
init_ip_whitelist() {
    if [[ -f "$IP_WHITELIST_FILE" ]]; then
        _info "IP 白名单文件已存在: $IP_WHITELIST_FILE"
        return 0
    fi
    cat > "$IP_WHITELIST_FILE" <<'WL_EOF'
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

#---- Fail2ban + Nginx + UFW 集成 ---------------------------------------------
# 检测 Nginx 日志路径
detect_nginx_logpath() {
    local candidate_paths=(
        "/var/log/nginx/access.log"
        "/var/log/nginx/access_log"
    )
    for p in "${candidate_paths[@]}"; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    # 尝试从 nginx 配置中提取
    if command -v nginx &>/dev/null; then
        local from_conf
        from_conf=$(nginx -T 2>/dev/null | grep -oP 'access_log\s+\K[^;]+' | head -1 || true)
        if [[ -n "$from_conf" && -f "$from_conf" ]]; then
            echo "$from_conf"
            return 0
        fi
    fi
    return 1
}

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
    if command -v systemctl &>/dev/null; then
        systemctl enable fail2ban &>/dev/null || true
    fi
    service fail2ban restart &>/dev/null || systemctl restart fail2ban &>/dev/null || true
    _info "Fail2ban 配置完成。"
}

# 重建 fail2ban jail.local（合并 IP 白名单）
rebuild_f2b_jail() {
    local ignore_ips
    ignore_ips=$(read_ip_whitelist)
    local nginx_log
    nginx_log=$(detect_nginx_logpath 2>/dev/null || true)

    local nginx_jails=""
    if [[ -n "$nginx_log" ]]; then
        nginx_jails="
[nginx-ufw]
enabled  = true
filter   = nginx-ufw
logpath  = ${nginx_log}
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
action   = ufw[name=nginx-ufw, protocol=all]

[nginx-bad-request]
enabled  = true
port     = http,https
filter   = nginx-bad-request
logpath  = ${nginx_log}
maxretry = 3
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
action   = ufw[name=nginx-badreq, protocol=all]

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = ${nginx_log}
maxretry = 3
findtime = ${F2B_FINDTIME}
bantime  = $((F2B_BANTIME * 2))
action   = ufw[name=nginx-bot, protocol=all]

[nginx-404]
enabled  = true
port     = http,https
filter   = nginx-404
logpath  = ${nginx_log}
maxretry = 20
findtime = ${F2B_FINDTIME}
bantime  = $((F2B_BANTIME / 2))
action   = ufw[name=nginx-404x, protocol=all]
"
    fi

    cat > "$FAIL2BAN_JAIL_CONF" <<JAILEOF
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
action = %(action_mwl)s

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
    if ! service fail2ban status &>/dev/null && ! systemctl is-active --quiet fail2ban &>/dev/null; then
        _info "fail2ban 未运行，正在启动..."
        service fail2ban start &>/dev/null || systemctl start fail2ban &>/dev/null || true
    fi

    # 2. 检测 Docker 是否新安装（自适应）
    fix_docker_ufw

    # 3. 检测 Nginx 日志路径是否变化
    local current_log
    current_log=$(detect_nginx_logpath 2>/dev/null || true)
    local configured_log=""
    if [[ -f "$FAIL2BAN_JAIL_CONF" ]]; then
        configured_log=$(awk '/^\[nginx-ufw\]/{found=1; next} /^\[/{found=0} found && /logpath/{sub(/.*logpath[[:space:]]*=[[:space:]]*/,""); print; exit}' "$FAIL2BAN_JAIL_CONF" 2>/dev/null | xargs || true)
    fi

    # 4. 检测 IP 白名单是否变化
    local current_ignore
    current_ignore=$(read_ip_whitelist)
    local configured_ignore=""
    if [[ -f "$FAIL2BAN_JAIL_CONF" ]]; then
        configured_ignore=$(grep -oP '^ignoreip\s*=\s*\K.+' "$FAIL2BAN_JAIL_CONF" 2>/dev/null | xargs || true)
    fi

    local need_rebuild=false
    if [[ "$current_log" != "$configured_log" ]]; then
        _info "Nginx 日志路径已变化: '${configured_log}' -> '${current_log}'"
        need_rebuild=true
    fi
    if [[ "$current_ignore" != "$configured_ignore" ]]; then
        _info "IP 白名单已变化，正在同步..."
        need_rebuild=true
    fi

    if $need_rebuild; then
        rebuild_f2b_jail
        if service fail2ban reload &>/dev/null || systemctl reload fail2ban &>/dev/null; then
            :
        else
            service fail2ban restart &>/dev/null || systemctl restart fail2ban &>/dev/null || true
        fi
        _info "Fail2ban 配置已更新并重载。"
    fi

    # 5. 输出当前封禁统计（遍历各 jail 汇总）
    local total_banned
    total_banned=$(fail2ban-client status 2>/dev/null \
        | awk '/Jail list:/{sub(/.*Jail list:[ \t]*/,""); gsub(/,/,""); for(i=1;i<=NF;i++) print $i}' \
        | while read -r j; do
            [[ -z "$j" ]] && continue
            fail2ban-client status "$j" 2>/dev/null | grep -oP 'Total banned:\s*\K\d+' || echo 0
        done | awk '{s+=$1} END {print s+0}' || true)
    _info "Fail2ban 运行正常，当前累计封禁 IP 数: ${total_banned:-0}"
    _info "Fail2ban 检测完成。"
}

#---- ufw 初始化 --------------------------------------------------------------
init_ufw() {
    _info "正在初始化 UFW 防火墙..."

    # 安装 ufw
    if ! command -v ufw &>/dev/null; then
        _info "ufw 未安装，正在安装..."
        apt_exec update -qq && apt_exec install -y -qq ufw
    fi

    # 重置到干净状态并启用
    _info "配置默认策略: 拒绝入站 / 放行出站..."
    ufw --force disable &>/dev/null || true
    ufw --force enable  &>/dev/null || true
    ufw default deny incoming
    ufw default allow outgoing

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

#---- 白名单管理 --------------------------------------------------------------
generate_whitelist() {
    _info "正在生成初始端口白名单..."
    local scanner
    scanner=$(detect_port_scanner)

    local header
    header="# ============================================
# 防火墙自动脚本 - 端口白名单配置
# 
# 格式: 端口号/协议  # 服务名称
# 示例: 8080/tcp  # 自定义Web服务
# 
# 白名单中的端口将始终在防火墙中保持放行状态。
# 不会被脚本自动回收，如需回收请从此文件删除后重启脚本。
# 支持 TCP 和 UDP 两种协议。
# 
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================"

    echo "$header" > "$WHITELIST_FILE"
    echo "" >> "$WHITELIST_FILE"
    echo "# --- 自动检测到的端口（基于首次运行时的监听状态）---" >> "$WHITELIST_FILE"

    # 扫描监听端口，使用临时文件避免在循环中多次调用
    local raw_ports
    if [[ "$scanner" == "ss" ]]; then
        # ss 输出格式: LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))
        raw_ports=$(ss -tlnp 2>/dev/null; ss -ulnp 2>/dev/null)
    else
        raw_ports=$(netstat -tlnp 2>/dev/null; netstat -ulnp 2>/dev/null)
    fi

    local seen=""
    # 使用进程替换避免子shell导致变量不持久化
    while IFS= read -r line; do
        # 提取地址和端口（ss格式: 0.0.0.0:22 或 [::]:22）
        local addr
        addr=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i~/^[][0-9a-fA-F.:*]+:[0-9]+$/) {print $i; exit}}')
        [[ -z "$addr" ]] && continue

        local port
        port=$(echo "$addr" | rev | cut -d: -f1 | rev)
        # 端口必须为纯数字
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        # 判断协议（tcp 或 udp）
        local proto="tcp"
        if echo "$line" | grep -qi 'udp'; then
            proto="udp"
        fi

        local key="${port}/${proto}"
        # 排除回环地址和已记录条目
        local ip_part
        ip_part=$(echo "$addr" | sed 's/:[0-9]*$//' | tr -d '[]')
        if [[ "$ip_part" == "127.0.0.1" || "$ip_part" == "::1" ]]; then
            continue
        fi

        # 去重
        if echo "$seen" | grep -qw "$key"; then
            continue
        fi
        seen="${seen} ${key}"

        # 获取服务名
        local service_name
        service_name=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
        [[ -z "$service_name" ]] && service_name="unknown"

        echo "${port}/${proto}  # ${service_name}" >> "$WHITELIST_FILE"
    done < <(echo "$raw_ports")

    echo "" >> "$WHITELIST_FILE"
    echo "# --- 用户自定义端口（可在此添加）---" >> "$WHITELIST_FILE"
    echo "# 8080/tcp  # 示例: 自定义Web服务" >> "$WHITELIST_FILE"

    _info "白名单已生成: $WHITELIST_FILE"
}

# 读取白名单端口列表
read_whitelist() {
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        return 1
    fi
    grep -E '^[0-9]+/(tcp|udp)' "$WHITELIST_FILE" 2>/dev/null \
        | awk '{print $1}' \
        | sort -u
}

# 放行所有白名单端口
apply_whitelist() {
    local whitelist
    whitelist=$(read_whitelist || true)
    if [[ -z "$whitelist" ]]; then
        _info "白名单为空，跳过端口放行。"
        return 0
    fi

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local port proto
        port=$(echo "$entry" | cut -d/ -f1)
        proto=$(echo "$entry" | cut -d/ -f2)

        # 检查是否已有相同规则
        if ufw status | grep -q "^${port}/${proto}"; then
            continue
        fi

        ufw allow "${port}/${proto}" comment 'auto-firewall-whitelist' &>/dev/null || true
        _info "白名单放行: ${port}/${proto}"
    done <<< "$whitelist"
}

#---- 端口检测与动态管理 ------------------------------------------------------
port_check() {
    acquire_lock
    _info "开始端口扫描..."

    # 0. Docker 环境自适应检测（后续安装 Docker 时自动修复 UFW 兼容性）
    fix_docker_ufw

    local scanner
    scanner=$(detect_port_scanner)

    # 1. 确保白名单端口都已放行
    apply_whitelist

    # 2. 扫描当前监听端口
    local current_ports=""
    local scan_output
    if [[ "$scanner" == "ss" ]]; then
        scan_output=$(ss -tlnp 2>/dev/null; ss -ulnp 2>/dev/null)
    else
        scan_output=$(netstat -tlnp 2>/dev/null; netstat -ulnp 2>/dev/null)
    fi

    # 使用进程替换避免子shell导致变量不持久化
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local addr
        addr=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i~/^[][0-9a-fA-F.:*]+:[0-9]+$/) {print $i; exit}}')
        [[ -z "$addr" ]] && continue

        local port
        port=$(echo "$addr" | rev | cut -d: -f1 | rev)
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        local ip_part
        ip_part=$(echo "$addr" | sed 's/:[0-9]*$//' | tr -d '[]')
        [[ "$ip_part" == "127.0.0.1" || "$ip_part" == "::1" ]] && continue

        local proto="tcp"
        echo "$line" | grep -qi 'udp' && proto="udp"

        local key="${port}/${proto}"
        if ! echo "$current_ports" | grep -qw "$key"; then
            current_ports="${current_ports} ${key}"
        fi
    done < <(echo "$scan_output")

    # 3. 读取白名单（这些端口不受动态回收影响）
    local whitelist
    whitelist=$(read_whitelist 2>/dev/null || true)

    # 4. 读取上次状态
    local prev_ports=""
    if [[ -f "$STATE_FILE" ]]; then
        prev_ports=$(cat "$STATE_FILE")
    fi

    # 5. 放行新出现的非白名单端口
    if [[ -n "$current_ports" ]]; then
        for entry in $current_ports; do
            local port proto
            port=$(echo "$entry" | cut -d/ -f1)
            proto=$(echo "$entry" | cut -d/ -f2)

            # 白名单端口跳过（已经在上面的 apply_whitelist 处理了）
            if echo "$whitelist" | grep -qw "$entry"; then
                continue
            fi

            # 检查 ufw 是否已有此规则
            if ufw status | grep -q "^${port}/${proto}"; then
                continue
            fi

            ufw allow "${port}/${proto}" comment 'auto-firewall' &>/dev/null || true
            _info "自动放行: ${port}/${proto}"
        done
    fi

    # 6. 回收已不再监听的端口（仅回收脚本自动添加的，不影响白名单和手动规则）
    if [[ -n "$prev_ports" ]]; then
        for entry in $prev_ports; do
            local port proto
            port=$(echo "$entry" | cut -d/ -f1)
            proto=$(echo "$entry" | cut -d/ -f2)

            # 白名单端口不回收
            if echo "$whitelist" | grep -qw "$entry"; then
                continue
            fi

            # 当前仍在监听则不回收
            if echo "$current_ports" | grep -qw "$entry"; then
                continue
            fi

            # SSH 端口保护：如果端口号在白名单中且服务含 ssh，绝不回收
            if echo "$whitelist" | grep -q "^${port}/${proto}.*ssh" 2>/dev/null; then
                _info "SSH 端口 ${port}/${proto} 已保护，不回收。"
                continue
            fi

            # 仅删除带有 auto-firewall 标记的规则
            if ufw status | grep -q "^${port}/${proto}.*auto-firewall"; then
                ufw --force delete allow "${port}/${proto}" &>/dev/null || true
                _info "自动回收: ${port}/${proto}"
            fi
        done
    fi

    # 7. 更新状态文件（只记录非白名单的动态端口）
    local new_state=""
    if [[ -n "$current_ports" ]]; then
        for entry in $current_ports; do
            if ! echo "$whitelist" | grep -qw "$entry"; then
                new_state="${new_state}${entry}
"
            fi
        done
    fi
    echo "$new_state" | sort -u > "$STATE_FILE"

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
    cat <<'EOF'
防火墙自动管理脚本 - auto-firewall.sh

用法: sudo bash auto-firewall.sh <命令>

命令:
  install        安装脚本（创建目录、配置cron、首次初始化）
  port-check     扫描端口并自动放行/回收（通常由 cron 调用）
  fail2ban-check 检测Fail2ban状态、同步IP白名单（通常由 cron 调用）
  cleanup        系统清理 + 日志轮转（通常由 cron 调用）
  status         查看当前 ufw/Fail2ban 状态和白名单
  help           显示此帮助信息

文件:
  /opt/auto-firewall/auto-firewall.sh    主脚本
  /opt/auto-firewall/port-whitelist.conf 端口白名单
  /opt/auto-firewall/ip-whitelist.conf   IP 白名单（不会被自动封禁）
  /opt/auto-firewall/ports.state         自动管理的端口状态
  /opt/auto-firewall/logs/               日志目录

端口白名单格式:
  端口号/协议  # 服务名称
  22/tcp       # SSH
  443/tcp      # HTTPS

IP 白名单格式:
  IP地址/CIDR  # 说明
  1.2.3.4      # 公司出口IP
  10.0.0.0/8   # 内网段

Cron 定时:
  */5  * * * *  port-check     (每5分钟检测端口)
  */15 * * * *  fail2ban-check (每15分钟检测Fail2ban)
  0    * * * *  cleanup        (每小时清理)
EOF
}

#---- 查看状态 ----------------------------------------------------------------
show_status() {
    echo "=========================================="
    echo "  防火墙自动脚本 - 运行状态"
    echo "=========================================="
    echo ""

    echo "[UFW 状态]"
    ufw status verbose 2>/dev/null || echo "  UFW 未安装或未启用"
    echo ""

    echo "[白名单端口] ($WHITELIST_FILE)"
    if [[ -f "$WHITELIST_FILE" ]]; then
        grep -E '^[0-9]+/(tcp|udp)' "$WHITELIST_FILE" 2>/dev/null || echo "  (空)"
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
    echo "  手动运行:"
    echo "    sudo bash auto-firewall.sh port-check"
    echo "    sudo bash auto-firewall.sh fail2ban-check"
    echo "    sudo bash auto-firewall.sh cleanup"
    echo "    sudo bash auto-firewall.sh status"
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

    # 这些命令需要 root
    case "$cmd" in
        install|port-check|cleanup|fail2ban-check)
            check_root
            init_dirs
            ;;
    esac

    case "$cmd" in
        install)        do_install ;;
        port-check)     port_check ;;
        fail2ban-check) fail2ban_check ;;
        cleanup)        cleanup ;;
        status)         show_status ;;
        help|--help|-h) show_help ;;
        *)
            echo "错误: 未知命令 '$cmd'" >&2
            show_help
            exit 1
            ;;
    esac
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
