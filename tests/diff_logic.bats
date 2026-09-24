#!/usr/bin/env bats
# T6: compute_port_actions 放行/回收差分（spec §3.3）

load test_helper/common

@test "新端口放行" {
  run compute_port_actions "8080/tcp" "" ""
  [ "$output" = "ADD:8080/tcp" ]
}

@test "失效端口回收" {
  run compute_port_actions "" "9000/tcp" ""
  [ "$output" = "DEL:9000/tcp" ]
}

@test "白名单端口不回收" {
  run compute_port_actions "" "22/tcp" "22/tcp"
  [ -z "$output" ]
}

@test "22 端口即使不在白名单也永不回收（SSH 保护）" {
  run compute_port_actions "" "22/tcp" ""
  [ -z "$output" ]
}

@test "仍在监听不重复放行也不回收" {
  run compute_port_actions "80/tcp" "80/tcp" ""
  [ -z "$output" ]
}

@test "白名单端口即使正在监听也不产生 ADD（由 apply_whitelist 负责）" {
  run compute_port_actions "443/tcp" "" "443/tcp"
  [ -z "$output" ]
}

@test "混合场景: 一加一删一保持" {
  run compute_port_actions "80/tcp 8080/tcp" "80/tcp 9000/udp" ""
  # ADD 含 8080/tcp, DEL 含 9000/udp, 80/tcp 不出现
  [[ "$output" == *"ADD:8080/tcp"* ]]
  [[ "$output" == *"DEL:9000/udp"* ]]
  [[ "$output" != *"80/tcp"* ]]
}

@test "v6/v4 后缀 key 精确匹配不误伤" {
  # prev 有 443/tcp/v6 且当前只剩 443/tcp(all)：v6 应回收, all 不放行(prev无? all是新增)
  run compute_port_actions "443/tcp" "443/tcp/v6" ""
  [[ "$output" == *"ADD:443/tcp"* ]]
  [[ "$output" == *"DEL:443/tcp/v6"* ]]
}

@test "输出按行分隔可迭代" {
  run compute_port_actions "80/tcp 9000/tcp" "70/tcp" ""
  [ "${#lines[@]}" -eq 3 ]   # ADD 80, ADD 9000, DEL 70
}
