#!/usr/bin/env bash
# bats 通用夹具：每个用例在隔离的 AUTO_FW_HOME 临时目录中加载主脚本。
# 用法（.bats 文件首行）: load test_helper/common

setup() {
    export AUTO_FW_HOME
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
}

teardown() {
    [[ -n "${AUTO_FW_HOME:-}" && "$AUTO_FW_HOME" == /tmp/* ]] && rm -rf "$AUTO_FW_HOME"
    return 0
}
