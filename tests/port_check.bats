#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T8: port_check / read_whitelist / apply_whitelist 集成（桩 ss/ufw）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME UFW_LOG STUB
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    STUB="$(mktemp -d)"
    export PATH="$STUB:$PATH"
    export UFW_LOG="$AUTO_FW_HOME/ufw.calls"
    : > "$UFW_LOG"

    # 桩 ss: 22 双栈 + 80(all) + 53/udp + 回环postgres(应排除)
    cat > "$STUB/ss" <<'SS'
#!/usr/bin/env bash
cat <<'EOF'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      128    [::]:22             [::]:*        users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0      511    *:80                *:*           users:(("nginx",pid=2,fd=6))
udp   UNCONN 0      0      0.0.0.0:53          0.0.0.0:*     users:(("named",pid=3,fd=4))
tcp   LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*     users:(("postgres",pid=9,fd=6))
EOF
SS
    # 桩 ufw: status 返回固定规则表; 变更调用记录到 UFW_LOG
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
case "$1" in
  status)
    printf '%s\n' \
      "Status: active" \
      "22/tcp                     ALLOW       auto-firewall-whitelist" \
      "9000/tcp                   ALLOW       auto-firewall" \
      "3306/tcp                   ALLOW       (out) v1 manual"
    ;;
  *) echo "ufw $*" >> "${UFW_LOG:-/dev/null}" ;;
esac
UF
    chmod +x "$STUB/ss" "$STUB/ufw"

    printf '# schema-version: 2\n22/tcp  # SSH\nicmp  # 诊断\n' > "$AUTO_FW_HOME/port-whitelist.conf"
    printf '9000/tcp\n' > "$AUTO_FW_HOME/ports.state"
    touch "$AUTO_FW_HOME/.first_run_done"

    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    LOCK_FILE="$AUTO_FW_HOME/.script.lock"
    # WSL interop 的 docker.exe 会误入 Docker 修复分支: 本任务不测它, 覆盖为跳过
    printf '#!/usr/bin/env bash\nexit 1\n' > "$STUB/docker"
    chmod +x "$STUB/docker"
    fix_docker_ufw() { return 0; }
}

teardown() {
    rm -rf "$AUTO_FW_HOME" "$STUB"
}

@test "read_whitelist 输出 canon key 并跳过注释/版本头" {
    run read_whitelist
    [[ "$output" == *"22/tcp"* ]]
    [[ "$output" == *"-/icmp"* ]]
    [[ "$output" != *"schema-version"* ]]
}

@test "scan_current_keys 采集监听: 双栈合并/回环排除/udp 识别" {
    run scan_current_keys
    [[ "$output" == *"80/tcp"* ]]
    [[ "$output" == *"53/udp"* ]]
    [[ "$output" == *"22/tcp"* ]]
    [[ "$output" != *"5432"* ]]
}

@test "port_check 放行新监听 80/tcp 与 53/udp" {
    port_check
    grep -q "allow 80/tcp comment auto-firewall$" "$UFW_LOG"
    grep -q "allow 53/udp comment auto-firewall$" "$UFW_LOG"
}

@test "port_check 回收失效且带 auto-firewall 标记的 9000/tcp" {
    port_check
    grep -q "delete 9000/tcp" "$UFW_LOG"
}

@test "port_check 不动 manual(无标记)规则 3306" {
    port_check
    run grep "3306" "$UFW_LOG"
    [ -z "$output" ]
}

@test "已存在的白名单 22/tcp 不重复 allow" {
    port_check
    run grep "allow 22/tcp" "$UFW_LOG"
    [ -z "$output" ]
}

@test "apply_whitelist 补齐缺失的 icmp 白名单(portless)" {
    port_check
    grep -q "allow proto icmp from any to any comment auto-firewall-whitelist" "$UFW_LOG"
}

@test "state 更新: 记录动态端口且排除白名单" {
    port_check
    grep -qx "80/tcp" "$STATE_FILE"
    grep -qx "53/udp" "$STATE_FILE"
    run grep -x "22/tcp" "$STATE_FILE"
    [ -z "$output" ]
    head -1 "$STATE_FILE" | grep -q '^# schema-version: 2$'
}

@test "dry-run: 只记录不真正调用 ufw 变更" {
    DRY_RUN=1
    port_check
    [ ! -s "$UFW_LOG" ]
    grep -q '\[DRYRUN\] ufw allow 80/tcp' "$LOG_FILE"
}
