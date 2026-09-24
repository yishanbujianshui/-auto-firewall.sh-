#!/usr/bin/env bats
# T4: 全局 flag 解析 parse_args（spec §9 G6）

load test_helper/common

@test "flag 后置: uninstall --dry-run --yes" {
  parse_args uninstall --dry-run --yes
  [ "$DRY_RUN" = "1" ]
  [ "$ASSUME_YES" = "1" ]
  [ "${CMD_ARGS[0]}" = "uninstall" ]
  [ "${#CMD_ARGS[@]}" -eq 1 ]
}

@test "flag 前置: --purge --force-ssh uninstall" {
  parse_args --purge --force-ssh uninstall
  [ "$PURGE" = "1" ]
  [ "$FORCE_SSH" = "1" ]
  [ "${CMD_ARGS[0]}" = "uninstall" ]
}

@test "flag 夹在中间也能剥离" {
  parse_args config add --dry-run port 80/tcp
  [ "$DRY_RUN" = "1" ]
  [ "${CMD_ARGS[*]}" = "config add port 80/tcp" ]
}

@test "无 flag: 默认值正确" {
  parse_args port-check
  [ "$DRY_RUN" = "0" ]
  [ "$ASSUME_YES" = "0" ]
  [ "$PURGE" = "0" ]
  [ "$FORCE_SSH" = "0" ]
  [ "${CMD_ARGS[0]}" = "port-check" ]
}

@test "短选项 -y 等价 --yes" {
  parse_args uninstall -y
  [ "$ASSUME_YES" = "1" ]
}

@test "DRY_RUN=1 时导出环境变量供子进程与 run_cmd 使用" {
  parse_args port-check --dry-run
  [ "$DRY_RUN" = "1" ]
  run bash -c 'echo ${DRY_RUN:-unset}'
  [ "$output" = "1" ]
}

@test "重复调用会重置上次的 flag" {
  parse_args uninstall --yes --purge
  parse_args status
  [ "$ASSUME_YES" = "0" ]
  [ "$PURGE" = "0" ]
}
