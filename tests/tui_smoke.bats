#!/usr/bin/env bats
# T13: profile.d 快捷方式 + TUI 降级（spec §6.1/§6.2）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME STUB
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs" "$AUTO_FW_HOME/profile.d"
    export AUTO_FW_SHORTCUT_TARGET="$AUTO_FW_HOME/profile.d/auto-firewall.sh"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
}

teardown() { rm -rf "$AUTO_FW_HOME"; }

@test "install_shortcut 生成 x/X 函数区块" {
    install_shortcut
    grep -q 'x() { afw_shortcut "$@"; }' "$AUTO_FW_SHORTCUT_TARGET"
    grep -q 'X() { afw_shortcut "$@"; }' "$AUTO_FW_SHORTCUT_TARGET"
    grep -q 'auto-firewall.sh menu' "$AUTO_FW_SHORTCUT_TARGET"
}

@test "install_shortcut 幂等: 重复执行不叠加区块" {
    install_shortcut
    install_shortcut
    install_shortcut
    [ "$(grep -c 'BEGIN auto-firewall-shortcut' "$AUTO_FW_SHORTCUT_TARGET")" -eq 1 ]
}

@test "install_shortcut 保留文件中其它内容" {
    echo "# 用户其它profile内容" > "$AUTO_FW_SHORTCUT_TARGET"
    install_shortcut
    grep -q '用户其它profile内容' "$AUTO_FW_SHORTCUT_TARGET"
}

@test "快捷函数体可被 bash 解析（语法正确性）" {
    install_shortcut
    run bash -n "$AUTO_FW_SHORTCUT_TARGET"
    [ "$status" -eq 0 ]
}

@test "无 TTY 时 tui_menu 降级为文本帮助（即使装了 dialog）" {
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh' 2>/dev/null; tui_menu"
    [[ "$output" == *"用法"* || "$output" == *"命令"* ]]
}
