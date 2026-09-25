#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T1: 可测试性地基 —— 路径 env 覆盖 / source 守卫 / 命令薄封装

setup() {
  export AUTO_FW_HOME
  AUTO_FW_HOME="$(mktemp -d)"
}

teardown() { rm -rf "$AUTO_FW_HOME"; }

@test "SCRIPT_DIR 受 AUTO_FW_HOME 覆盖" {
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
  [ "$SCRIPT_DIR" = "$AUTO_FW_HOME" ]
}

@test "派生路径挂在 AUTO_FW_HOME 下" {
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
  [ "$STATE_FILE" = "$AUTO_FW_HOME/ports.state" ]
  [ "$LOG_FILE" = "$AUTO_FW_HOME/logs/auto-firewall.log" ]
  [ "$WHITELIST_FILE" = "$AUTO_FW_HOME/port-whitelist.conf" ]
  [ "$VERSION_FILE" = "$AUTO_FW_HOME/.schema_version" ]
}

@test "source 主脚本不执行 main（无副作用、可加载函数）" {
  run bash -c "source '${BATS_TEST_DIRNAME}/../auto-firewall.sh' && echo SOURCED_OK"
  [ "$status" -eq 0 ]
  [[ "$output" == *SOURCED_OK* ]]
}

@test "薄封装函数存在: run_cmd/ss_probe/ufw_exec/apt_exec/svc_exec" {
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
  for fn in run_cmd ss_probe ufw_exec apt_exec svc_exec ensure_locale_utf8; do
    declare -f "$fn" >/dev/null || { echo "missing: $fn" >&2; return 1; }
  done
}

@test "run_cmd 在 DRY_RUN=1 时只记录不执行" {
  source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
  mkdir -p "$AUTO_FW_HOME/logs"
  export DRY_RUN=1
  marker="$AUTO_FW_HOME/should-not-exist"
  run_cmd touch "$marker"
  [ ! -e "$marker" ]
  grep -q '\[DRYRUN\]' "$LOG_FILE"
}
