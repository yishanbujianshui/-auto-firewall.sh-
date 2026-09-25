#!/usr/bin/env bats
# T13: profile.d 快捷方式 + 原生 ANSI TUI（无 dialog 依赖）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME
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
    install_shortcut; install_shortcut; install_shortcut
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

@test "脚本不再依赖 dialog" {
    if grep -q 'dialog' "${BATS_TEST_DIRNAME}/../auto-firewall.sh"; then echo "仍有 dialog 引用"; return 1; fi
}

@test "_tui_key 按键语义映射" {
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf 'j' | _tui_key"
    [ "$output" = "DOWN" ]
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf 'k' | _tui_key"
    [ "$output" = "UP" ]
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf $'\\e[B' | _tui_key"
    [ "$output" = "DOWN" ]
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf '\n' | _tui_key"
    [ "$output" = "ENTER" ]
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf '' | _tui_key"
    [ "$output" = "EOF" ]
}

@test "tui_menu 渲染全部菜单项(test seam)" {
    run bash -c "export AUTO_FW_TUI_TEST=1; source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf 'q' | tui_menu"
    [[ "$output" == *"管理台"* ]]
    [[ "$output" == *"总览仪表盘"* ]]
    [[ "$output" == *"配置管理"* ]]
    [[ "$output" == *"卸载脚本与配置"* ]]
    [[ "$output" == *"恢复默认配置"* ]]
}

@test "tui_menu 数字键快捷执行" {
    run bash -c "export AUTO_FW_TUI_TEST=1; source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; tui_run(){ echo \"RUN:\$1\"; return 0; }; printf '5q' | tui_menu"
    [[ "$output" == *"RUN:5"* ]]
}

@test "tui_menu 方向键导航 + Enter 执行" {
    # DOWN 一次选中 tag 2, Enter 执行
    run bash -c "export AUTO_FW_TUI_TEST=1; source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; tui_run(){ echo \"RUN:\$1\"; return 0; }; printf $'\\e[B\nq' | tui_menu"
    [[ "$output" == *"RUN:2"* ]]
}

@test "tui_menu 非交互且无 seam 时降级为文本帮助" {
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf 'q' | tui_menu"
    [[ "$output" == *"用法"* || "$output" == *"命令"* ]]
}

@test "tui_confirm y 通过 / n 与 EOF 拒绝" {
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf 'y' | tui_confirm t b"; [ "$status" -eq 0 ]
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf 'n' | tui_confirm t b"; [ "$status" -ne 0 ]
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; tui_confirm t b </dev/null"; [ "$status" -ne 0 ]
}

@test "tui_input 读取输入行" {
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf '80/tcp\n' | tui_input t p"
    [[ "$output" == *"80/tcp"* ]]
}

@test "tui_msg 渲染标题与正文且 Enter 返回" {
    run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh'; printf '\n' | tui_msg '标题X' '正文Y'"
    [[ "$output" == *"标题X"* ]]
    [[ "$output" == *"正文Y"* ]]
}
