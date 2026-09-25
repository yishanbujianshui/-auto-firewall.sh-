#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T10: config add/del/list（spec §7.1）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    # SSH 探测 seam: 固定为 22, 不依赖宿主机真实 sshd_config
    export AUTO_FW_SSHD_CONFIG="$AUTO_FW_HOME/sshd_config"
    printf 'Port 22\n' > "$AUTO_FW_SSHD_CONFIG"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    printf '# schema-version: 2\n# 头注释\n' > "$WHITELIST_FILE"
    printf '# schema-version: 2\n127.0.0.1/8  # 本机回环（禁止删除）\n10.0.0.0/8   # A类内网\n' > "$IP_WHITELIST_FILE"
}

@test "add port: 合法区间写入 v2 语法" {
    config_add_port "8000:8100/tcp"
    grep -q '^8000:8100/tcp' "$WHITELIST_FILE"
}

@test "add port: 保留原注释与既有行" {
    config_add_port "443/tcp"
    grep -q '# 头注释' "$WHITELIST_FILE"
    grep -q '^# schema-version: 2$' "$WHITELIST_FILE"
    grep -q '^443/tcp' "$WHITELIST_FILE"
}

@test "add port: 非法值拒绝且不改文件" {
    run config_add_port "99999/tcp"
    [ "$status" -ne 0 ]
    if grep -q '99999' "$WHITELIST_FILE"; then return 1; fi
}

@test "add port: 去重幂等" {
    config_add_port "443/tcp"
    config_add_port "443/tcp"
    [ "$(grep -c '^443/tcp' "$WHITELIST_FILE")" -eq 1 ]
}

@test "add port: v1 旧写法被 canon 化" {
    config_add_port "icmp"
    grep -q '^-/icmp' "$WHITELIST_FILE"
}

@test "del port: 存在项删除" {
    config_add_port "80/tcp"
    config_del_port "80/tcp"
    if grep -q '^80/tcp' "$WHITELIST_FILE"; then return 1; fi
}

@test "del port: SSH 22 拒绝删除" {
    config_add_port "22/tcp"
    run config_del_port "22/tcp"
    [ "$status" -ne 0 ]
    grep -q '^22/tcp' "$WHITELIST_FILE"
}

@test "add ip: 合法 CIDR 写入" {
    config_add_ip "203.0.113.5"
    grep -q '^203.0.113.5' "$IP_WHITELIST_FILE"
}

@test "add ip: 非法拒绝" {
    run config_add_ip "999.1.1.1"
    [ "$status" -ne 0 ]
}

@test "del ip: 受保护默认项拒绝删除" {
    run config_del_ip "127.0.0.1/8"
    [ "$status" -ne 0 ]
    grep -q '^127.0.0.1/8' "$IP_WHITELIST_FILE"
    run config_del_ip "10.0.0.0/8"
    [ "$status" -ne 0 ]
}

@test "del ip: 用户项可删" {
    config_add_ip "198.51.100.7"
    config_del_ip "198.51.100.7"
    if grep -q '^198.51.100.7' "$IP_WHITELIST_FILE"; then return 1; fi
}

@test "变更写入前生成备份（backup_configs 被调用）" {
    config_add_port "7777/tcp"
    [ -d "$BACKUP_DIR" ]
    [ "$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)" -ge 1 ]
}

@test "config_list 输出 canon key" {
    config_add_port "6379/tcp"
    run config_list ports
    [[ "$output" == *"6379/tcp"* ]]
}
