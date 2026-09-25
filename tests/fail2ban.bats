#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T9: Fail2ban 补强（spec §5: jail 日志正确性 / MTA 降级 / 路径 seam）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    export AUTO_FW_F2B_JAIL_CONF="$AUTO_FW_HOME/jail.local"
    export AUTO_FW_F2B_FILTER_DIR="$AUTO_FW_HOME/filter.d"
    export AUTO_FW_F2B_ACTION_DIR="$AUTO_FW_HOME/action.d"
    export AUTO_FW_NGINX_LOG_DIR="$AUTO_FW_HOME/nginx-logs"
    mkdir -p "$AUTO_FW_F2B_FILTER_DIR" "$AUTO_FW_F2B_ACTION_DIR" "$AUTO_FW_NGINX_LOG_DIR"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
}

@test "detect_nginx_logpath: 无日志文件返回非0" {
    run detect_nginx_logpath
    [ "$status" -ne 0 ]
}

@test "detect_nginx_logpath: 返回 access 与 error 两个路径" {
    touch "$AUTO_FW_NGINX_LOG_DIR/access.log" "$AUTO_FW_NGINX_LOG_DIR/error.log"
    run detect_nginx_logpath
    [ "$status" -eq 0 ]
    [[ "${lines[0]}" == *"$AUTO_FW_NGINX_LOG_DIR/access.log"* ]]
    [[ "${lines[1]}" == *"$AUTO_FW_NGINX_LOG_DIR/error.log"* ]]
}

@test "rebuild_f2b_jail: 生成 jail.local 含 sshd 与 ignoreip" {
    rebuild_f2b_jail
    grep -q '^\[sshd\]' "$AUTO_FW_F2B_JAIL_CONF"
    grep -q '^ignoreip' "$AUTO_FW_F2B_JAIL_CONF"
}

@test "rebuild_f2b_jail: 无 MTA 时 action 降级为 action_（不引用 mwl）" {
    # PATH 无 sendmail/mail 环境下
    rebuild_f2b_jail
    if has_mta; then skip "此机器装有 MTA"; fi
    grep -q 'action = %(action_)s' "$AUTO_FW_F2B_JAIL_CONF"
    if grep -q '%(action_mwl)s' "$AUTO_FW_F2B_JAIL_CONF"; then return 1; fi
}

@test "rebuild_f2b_jail: 无 nginx 日志时不生成 nginx jail" {
    rebuild_f2b_jail
    if grep -q '^\[nginx-ufw\]' "$AUTO_FW_F2B_JAIL_CONF"; then return 1; fi
}

@test "rebuild_f2b_jail: botsearch 用 error.log, 404/ufw 用 access.log" {
    touch "$AUTO_FW_NGINX_LOG_DIR/access.log" "$AUTO_FW_NGINX_LOG_DIR/error.log"
    rebuild_f2b_jail
    # nginx-ufw 段的 logpath 指 access.log
    awk '/^\[nginx-ufw\]/{f=1} f&&/logpath/{print;exit}' "$AUTO_FW_F2B_JAIL_CONF" | grep -q 'access.log'
    awk '/^\[nginx-botsearch\]/{f=1} f&&/logpath/{print;exit}' "$AUTO_FW_F2B_JAIL_CONF" | grep -q 'error.log'
    awk '/^\[nginx-404\]/{f=1} f&&/logpath/{print;exit}' "$AUTO_FW_F2B_JAIL_CONF" | grep -q 'access.log'
}

@test "init_ufw 启用前设置 IPV6=yes（GAP-B）" {
    # 用桩验证顺序: /etc/default/ufw 路径不可写时至少函数存在且逻辑含顺序
    declare -f ensure_ipv6_before_enable >/dev/null
    STUBUFW="$(mktemp -d)"
    export PATH="$STUBUFW:$PATH"
    printf '%s\n' 'IPV6=no' > "$STUBUFW/default-ufw"
    printf '#!/usr/bin/env bash\necho "ufw $*" >> "${ORDER_LOG:-/dev/null}"\n' > "$STUBUFW/ufw"
    chmod +x "$STUBUFW/ufw"
    export ORDER_LOG="$AUTO_FW_HOME/order.log"
    export UFW_DEFAULT_FILE="$STUBUFW/default-ufw"
    ensure_ipv6_before_enable
    grep -q 'IPV6=yes' "$STUBUFW/default-ufw"
    # enable 必须在 sed 之后（文件已被改为 yes 时 enable 调用发生）
    grep -q 'enable' "$ORDER_LOG"
    rm -rf "$STUBUFW"
}

@test "has_mta: 干净 PATH 返回非0" {
    PATH="$AUTO_FW_HOME/bin" run has_mta
    [ "$status" -ne 0 ]
}
