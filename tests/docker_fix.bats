#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T15: Docker/UFW 兼容性修复 — 守护进程级检测、失效块清理、自声明链
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME STUB
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    export AUTO_FW_UFW_ETC_DIR="$AUTO_FW_HOME/ufw"
    mkdir -p "$AUTO_FW_UFW_ETC_DIR"
    STUB="$(mktemp -d)"
    export PATH="$STUB:$PATH"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/docker"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/ufw"
    chmod +x "$STUB/docker" "$STUB/ufw"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
}

teardown() {
    [[ -n "${AUTO_FW_HOME:-}" && "$AUTO_FW_HOME" == /tmp/* ]] && rm -rf "$AUTO_FW_HOME" "$STUB"
    return 0
}

# 含历史(v1 式)修复块的 after.rules —— 块内无 :DOCKER-USER 声明, 守护进程消失后会导致 ufw 加载失败
seed_stale_block() {
    cat > "$UFW_ETC_DIR/after.rules" <<'EOF'
*filter
:ufw-after-forward - [0:0]
# BEGIN auto-firewall DOCKER-USER fix
# 让 DOCKER-USER 链接受 UFW 的过滤规则，修复 Docker 端口绕过 UFW 的问题
:ufw-user-input - [0:0]
-A DOCKER-USER -j ufw-user-input
-A DOCKER-USER -j RETURN
# END auto-firewall DOCKER-USER fix
COMMIT
EOF
}

clean_template() {
    cat > "$UFW_ETC_DIR/after.rules" <<'EOF'
*filter
:ufw-after-forward - [0:0]
COMMIT
EOF
}

@test "守护进程未运行: 移除 after.rules 中的失效修复块并留备份" {
    seed_stale_block
    docker_daemon_running() { return 1; }
    fix_docker_ufw
    run ! grep -q "DOCKER-USER" "$UFW_ETC_DIR/after.rules"
    grep -q '^COMMIT$' "$UFW_ETC_DIR/after.rules"
    [ "$(find "$UFW_ETC_DIR" -name 'after.rules.bak.*' | wc -l)" -ge 1 ]
}

@test "守护进程未运行且无历史块: 文件保持不变" {
    clean_template
    local before
    before="$(cat "$UFW_ETC_DIR/after.rules")"
    docker_daemon_running() { return 1; }
    fix_docker_ufw
    [ "$(cat "$UFW_ETC_DIR/after.rules")" = "$before" ]
    [ "$(find "$UFW_ETC_DIR" -name 'after.rules.bak.*' | wc -l)" -eq 0 ]
}

@test "守护进程运行: 插入块自声明 :DOCKER-USER 链且位于 COMMIT 前" {
    clean_template
    docker_daemon_running() { return 0; }
    fix_docker_ufw
    grep -q '^:DOCKER-USER - \[0:0\]$' "$UFW_ETC_DIR/after.rules"
    grep -q '^-A DOCKER-USER -j ufw-user-input$' "$UFW_ETC_DIR/after.rules"
    local line_block line_commit
    line_block="$(grep -n 'BEGIN auto-firewall DOCKER-USER fix' "$UFW_ETC_DIR/after.rules" | cut -d: -f1)"
    line_commit="$(grep -n '^COMMIT$' "$UFW_ETC_DIR/after.rules" | head -1 | cut -d: -f1)"
    [ "$line_block" -lt "$line_commit" ]
}

@test "守护进程运行且块已存在: 幂等跳过不重复插入" {
    seed_stale_block
    docker_daemon_running() { return 0; }
    fix_docker_ufw
    [ "$(grep -c 'BEGIN auto-firewall DOCKER-USER fix' "$UFW_ETC_DIR/after.rules")" -eq 1 ]
}
