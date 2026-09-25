#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# SSH 端口自适应探测（不写死 22）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME STUB
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs" "$AUTO_FW_HOME/sshd"
    STUB="$(mktemp -d)"
    export PATH="$STUB:$PATH"
    # 默认 ss 桩: 无任何 sshd 监听
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/ss"
    chmod +x "$STUB/ss"
    export AUTO_FW_SSHD_CONFIG="$AUTO_FW_HOME/sshd/sshd_config"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
}

teardown() { rm -rf "$AUTO_FW_HOME" "$STUB"; }

@test "detect_ssh_ports: 读取 sshd_config 的 Port 指令(多端口)" {
    printf 'Port 2222\nPort 22022\n#Port 22\n' > "$AUTO_FW_SSHD_CONFIG"
    run detect_ssh_ports
    [[ "$output" == *"2222"* ]]
    [[ "$output" == *"22022"* ]]
    [[ "$output" != *" 22 "* ]]
}

@test "detect_ssh_ports: 实际监听进程含 sshd" {
    printf '#!/usr/bin/env bash\ncase "$*" in\n *tlnp*) printf "Netid State Recv-Q Send-Q Local Address:Port Peer Process\\ntcp LISTEN 0 128 0.0.0.0:20200 0.0.0.0:* users:((\\"sshd\\",pid=9,fd=3))\\n";; *) :;; esac\n' > "$STUB/ss"
    chmod +x "$STUB/ss"
    run detect_ssh_ports
    [[ "$output" == *"20200"* ]]
}

@test "detect_ssh_ports: 无配置无监听回退 22" {
    rm -f "$AUTO_FW_SSHD_CONFIG"
    run detect_ssh_ports
    [ "$output" = "22" ]
}

@test "compute_port_actions: 自定义 SSH 端口不被回收" {
    run compute_port_actions "" "2222/tcp" "" "2222"
    [ -z "$output" ]
}

@test "compute_port_actions: 非 SSH 端口正常回收" {
    run compute_port_actions "" "2222/tcp" "" "22"
    [ "$output" = "DEL:2222/tcp" ]
}

@test "compute_port_actions: 默认保护 22（兼容旧行为）" {
    run compute_port_actions "" "22/tcp" ""
    [ -z "$output" ]
}

@test "config_del_port: 拒绝删除探测到的自定义 SSH 端口" {
    printf 'Port 2222\n' > "$AUTO_FW_SSHD_CONFIG"
    printf '# schema-version: 2\n2222/tcp  # SSH\n' > "$WHITELIST_FILE"
    run config_del_port "2222/tcp"
    [ "$status" -ne 0 ]
    grep -q '^2222/tcp' "$WHITELIST_FILE"
}

@test "config_del_port: 普通端口不受 SSH 保护影响" {
    printf 'Port 2222\n' > "$AUTO_FW_SSHD_CONFIG"
    printf '# schema-version: 2\n8080/tcp  # web\n' > "$WHITELIST_FILE"
    config_del_port "8080/tcp"
    if grep -q '^8080/tcp' "$WHITELIST_FILE"; then echo "仍存在"; return 1; fi
}
