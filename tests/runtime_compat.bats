#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317,SC2314,SC2329
# 真机运行时兼容性回归（ufw 0.36 实测格式/语法/状态一致性）

setup() {
    export AUTO_FW_HOME STUB UFW_LOG
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    STUB="$(mktemp -d)"
    export PATH="$STUB:$PATH"
    UFW_LOG="$(mktemp)"; export UFW_LOG; : > "$UFW_LOG"

    # SSH 探测与 fail2ban 路径全部指向临时区
    export AUTO_FW_SSHD_CONFIG="$AUTO_FW_HOME/sshd_config"
    printf 'Port 22\n' > "$AUTO_FW_SSHD_CONFIG"
    export AUTO_FW_F2B_JAIL_CONF="$AUTO_FW_HOME/jail.local"
    export AUTO_FW_F2B_FILTER_DIR="$AUTO_FW_HOME/filter.d"
    export AUTO_FW_F2B_ACTION_DIR="$AUTO_FW_HOME/action.d"
    export AUTO_FW_UFW_ETC_DIR="$AUTO_FW_HOME/ufw-etc"
    export AUTO_FW_CRONTAB="$AUTO_FW_HOME/crontab"
    mkdir -p "$AUTO_FW_F2B_FILTER_DIR" "$AUTO_FW_F2B_ACTION_DIR" "$AUTO_FW_UFW_ETC_DIR"

    # 通用 ufw 桩: status 输出真实格式; 其余命令记录
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
if [[ "$1" == "status" ]]; then
cat <<'EOF'
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere                   # auto-firewall-whitelist
8444/tcp                   ALLOW       Anywhere
443/tcp (v6)               ALLOW       Anywhere (v6)              # auto-firewall
Anywhere/esp               ALLOW       Anywhere/esp               # auto-firewall-whitelist
Anywhere/esp (v6)          ALLOW       Anywhere/esp (v6)          # auto-firewall-whitelist
Anywhere                   ALLOW       Anywhere
Anywhere (v6)              ALLOW       Anywhere (v6)
EOF
    exit 0
fi
echo "ufw $*" >> "${UFW_LOG:-/dev/null}"
exit 0
UF
    chmod +x "$STUB/ufw"
    # 服务管理桩: 避免触碰真机
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/systemctl"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/service"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/fail2ban-client"
    chmod +x "$STUB/systemctl" "$STUB/service" "$STUB/fail2ban-client"

    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    LOCK_FILE="$AUTO_FW_HOME/.script.lock"
    fix_docker_ufw() { return 0; }
}

teardown() { rm -rf "$AUTO_FW_HOME" "$STUB" "$UFW_LOG"; }

@test "status 解析: portless Anywhere/esp 与裸 Anywhere(any)" {
    refresh_ufw_table
    [ -n "${UFW_EXIST[22/tcp]:-}" ]
    [ -n "${UFW_EXIST[443/tcp/v6]:-}" ]
    [ -n "${UFW_EXIST[-/esp]:-}" ]
    [ -n "${UFW_EXIST[-/any]:-}" ]
}

@test "status 解析: 显式 /v4 规则经 fallback 判为已存在" {
    refresh_ufw_table
    ufw_rule_exists "8444/tcp/v4"
    ufw_rule_exists "8444/tcp"
    run ! ufw_rule_exists "9999/tcp/v4"
}

@test "status 解析: portless 规则不会被重复放行" {
    printf '# schema-version: 2\n-/esp  # 手工\nany  # 手工\n' > "$WHITELIST_FILE"
    run apply_whitelist
    [ "$status" -eq 0 ]
    run grep -E "allow proto esp|allow from any to any" "$UFW_LOG"
    [ -z "$output" ]
}

@test "icmp: ufw 不支持时跳过且不报错" {
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
case "$1" in
  status) printf '%s\n' "Status: active" ;;
  --dry-run) exit 1 ;;            # 模拟 "Unsupported protocol"
  *) echo "ufw $*" >> "${UFW_LOG:-/dev/null}" ;;
esac
UF
    chmod +x "$STUB/ufw"
    printf '# schema-version: 2\nicmp  # 诊断\n' > "$WHITELIST_FILE"
    run apply_whitelist
    [ "$status" -eq 0 ]
    run grep "allow proto icmp" "$UFW_LOG"
    [ -z "$output" ]
    grep -q "跳过白名单 .*icmp" "$LOG_FILE"
}

@test "port_check --dry-run 不改写 ports.state" {
    cat > "$STUB/ss" <<'SS'
#!/usr/bin/env bash
printf '%s\n' "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))"
SS
    chmod +x "$STUB/ss"
    printf '# schema-version: 2\n9999/tcp\n' > "$STATE_FILE"
    DRY_RUN=1 run port_check
    [ "$status" -eq 0 ]
    grep -qx "9999/tcp" "$STATE_FILE"
    run grep -qx "80/tcp" "$STATE_FILE"
    [ -z "$output" ]
    grep -q '\[DRYRUN\] ufw allow 80/tcp' "$LOG_FILE"
}

@test "放行失败的端口不写入 state（下轮可重试）" {
    cat > "$STUB/ss" <<'SS'
#!/usr/bin/env bash
printf '%s\n' "tcp LISTEN 0 128 0.0.0.0:8081 0.0.0.0:* users:((\"app\",pid=1,fd=3))"
SS
    chmod +x "$STUB/ss"
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
case "$1" in
  status) printf '%s\n' "Status: active" ;;
  allow) echo "ufw $*" >> "${UFW_LOG:-/dev/null}"; exit 1 ;;
  *) echo "ufw $*" >> "${UFW_LOG:-/dev/null}"; exit 0 ;;
esac
UF
    chmod +x "$STUB/ufw"
    printf '# schema-version: 2\n' > "$STATE_FILE"
    run port_check
    [ "$status" -ne 0 ]
    run grep -qx "8081/tcp" "$STATE_FILE"
    [ -z "$output" ]
}

@test "purge: 双栈规则只删一次（跳过 /v6 变体）" {
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
if [[ "$1" == "status" ]]; then
cat <<'EOF'
80/tcp                     ALLOW       Anywhere                   # auto-firewall-whitelist
80/tcp (v6)                ALLOW       Anywhere (v6)              # auto-firewall-whitelist
EOF
    exit 0
fi
echo "ufw $*" >> "${UFW_LOG:-/dev/null}"
exit 0
UF
    chmod +x "$STUB/ufw"
    run purge_firewall
    [ "$status" -eq 0 ]
    [ "$(grep -c 'delete allow 80/tcp' "$UFW_LOG")" -eq 1 ]
    run grep "::/0" "$UFW_LOG"
    [ -z "$output" ]
}

@test "install_cron: 使用安装目录路径且不与上一行粘连" {
    printf 'MAILTO=ops' > "$CRONTAB_FILE"        # 故意不带换行
    install_cron
    grep -qx 'MAILTO=ops' "$CRONTAB_FILE"
    grep -q "^\\*/5 .* ${AUTO_FW_HOME}/auto-firewall.sh port-check" "$CRONTAB_FILE"
    run grep -q "/opt/auto-firewall" "$CRONTAB_FILE"
    [ -z "$output" ]
}

@test "unban: 未找到封禁规则也返回 0（幂等）" {
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
case "$1" in
  status) printf '%s\n' "Status: active" ;;
  delete) exit 1 ;;
  *) exit 0 ;;
esac
UF
    chmod +x "$STUB/ufw"
    run unban_ip 203.0.113.9
    [ "$status" -eq 0 ]
    grep -q "未找到该 IP 的手动封禁规则" "$LOG_FILE"
}

@test "svc_exec: dry-run 不执行服务变更" {
    MARK="$AUTO_FW_HOME/systemctl.called"
    printf '#!/usr/bin/env bash\ntouch "%s"\n' "$MARK" > "$STUB/systemctl"
    chmod +x "$STUB/systemctl"
    DRY_RUN=1 run svc_exec restart fail2ban
    [ "$status" -eq 0 ]
    [ ! -e "$MARK" ]
    grep -q '\[DRYRUN\] service restart fail2ban' "$LOG_FILE"
}

@test "generate_whitelist: 始终包含探测到的 SSH 端口" {
    cat > "$STUB/ss" <<'SS'
#!/usr/bin/env bash
printf '%s\n' "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))"
SS
    chmod +x "$STUB/ss"
    printf 'Port 2222\n' > "$AUTO_FW_SSHD_CONFIG"
    generate_whitelist
    grep -q '^80/tcp' "$WHITELIST_FILE"
    grep -q '^2222/tcp' "$WHITELIST_FILE"
}
