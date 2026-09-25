#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T11: reset-config / ban / unban / version / log / confirm（spec §7.2/§7.3/§9）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME STUB UFW_LOG
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    STUB="$(mktemp -d)"
    export PATH="$STUB:$PATH"
    export UFW_LOG="$AUTO_FW_HOME/ufw.calls"; : > "$UFW_LOG"
    printf '#!/usr/bin/env bash\ncase "$*" in\n *-tln*) printf "Netid State Recv-Q Send-Q Local Address:Port Peer\\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\\ntcp LISTEN 0 511 0.0.0.0:8081 0.0.0.0:*\\n";;\n *-uln*) printf "Netid State Recv-Q Send-Q Local Address:Port Peer\\n";;\n *) :;;\nesac\n' > "$STUB/ss"
    printf '#!/usr/bin/env bash\ncase "$1" in status) echo "Status: active";; *) echo "ufw $*" >> "${UFW_LOG:-/dev/null}";; esac\n' > "$STUB/ufw"
    chmod +x "$STUB/ss" "$STUB/ufw"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    LOCK_FILE="$AUTO_FW_HOME/.script.lock"
    fix_docker_ufw() { return 0; }
    export ASSUME_YES=1
}

teardown() { rm -rf "$AUTO_FW_HOME" "$STUB"; }

@test "init_ip_whitelist --force 覆盖已有文件" {
    echo "custom-junk" > "$IP_WHITELIST_FILE"
    init_ip_whitelist --force
    grep -q '^127.0.0.1/8' "$IP_WHITELIST_FILE"
    if grep -q 'custom-junk' "$IP_WHITELIST_FILE"; then return 1; fi
}

@test "init_ip_whitelist 默认不覆盖" {
    echo "custom" > "$IP_WHITELIST_FILE"
    init_ip_whitelist
    grep -q '^custom$' "$IP_WHITELIST_FILE"
}

@test "reset-config ports: 重扫监听且保留 22（GAP-无锁死）" {
    printf '# schema-version: 2\n9999/tcp  # 旧的\n' > "$WHITELIST_FILE"
    echo 2 > "$VERSION_FILE"
    reset_config ports
    grep -q '^22/tcp' "$WHITELIST_FILE"
    grep -q '^8081/tcp' "$WHITELIST_FILE"
    if grep -q '^9999/tcp' "$WHITELIST_FILE"; then return 1; fi
}

@test "reset-config 不改变 schema 版本" {
    echo 2 > "$VERSION_FILE"
    reset_config ip
    grep -qx '2' "$VERSION_FILE"
}

@test "reset-config 生成备份" {
    printf '# schema-version: 2\n22/tcp  # SSH\n' > "$WHITELIST_FILE"
    reset_config ports
    [ "$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)" -ge 1 ]
}

@test "reset-config 非法 scope 报错" {
    run reset_config bogus
    [ "$status" -ne 0 ]
}

@test "ban: 合法 IP 走 ufw deny 带 manual 标记" {
    ban_ip 203.0.113.9
    grep -q "insert 1 deny from 203.0.113.9 to any comment auto-firewall-manual" "$UFW_LOG"
}

@test "ban: 非法 IP 拒绝" {
    run ban_ip "999.999.999.999"
    [ "$status" -ne 0 ]
    [ ! -s "$UFW_LOG" ]
}

@test "unban: 删除对应 deny" {
    ban_ip 198.51.100.2
    unban_ip 198.51.100.2
    grep -q "delete deny from 198.51.100.2 to any comment auto-firewall-manual" "$UFW_LOG"
}

@test "show_version 含版本与 schema" {
    run show_version
    [[ "$output" == *"${SCRIPT_VERSION}"* ]]
    [[ "$output" == *"schema"* ]]
}

@test "show_log 输出日志内容" {
    echo "line-A" >> "$LOG_FILE"
    echo "line-B" >> "$LOG_FILE"
    run show_log 10
    [[ "$output" == *"line-B"* ]]
}

@test "confirm: ASSUME_YES=1 直接通过" {
    ASSUME_YES=1 confirm "x?"
}

@test "confirm: 非交互且无 --yes 拒绝" {
    ASSUME_YES=0
    run confirm "x?"
    [ "$status" -ne 0 ]
}
