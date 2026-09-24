#!/usr/bin/env bats
# T3: build_ufw_args 描述符 -> ufw 参数（spec §2.3, GAP-4）

load test_helper/common

@test "allow 单端口 tcp" {
  run build_ufw_args "22/tcp" allow
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "allow" ]
  [ "${lines[1]}" = "22/tcp" ]
  [ "${lines[2]}" = "from" ]
  [ "${lines[3]}" = "any" ]
  [ "${lines[4]}" = "to" ]
  [ "${lines[5]}" = "any" ]
  [ "${#lines[@]}" -eq 6 ]
}

@test "allow 端口区间" {
  run build_ufw_args "8000:8100/tcp" allow
  [ "${lines[1]}" = "8000:8100/tcp" ]
}

@test "icmp -> proto icmp（GAP-4 不生成 proto any）" {
  run build_ufw_args "-/icmp" allow
  [[ "${output[*]}" == *"proto icmp"* ]]
  [[ "${output[*]}" != *"proto any"* ]]
}

@test "esp 协议名" {
  run build_ufw_args "-/esp" allow
  [[ "${output[*]}" == *"proto esp"* ]]
}

@test "协议号 50 -> proto 50" {
  run build_ufw_args "-/50" allow
  [[ "${output[*]}" == *"proto 50"* ]]
}

@test "any -> 无 proto 无端口（GAP-4）" {
  run build_ufw_args "any" allow
  [[ "${output[*]}" != *"proto"* ]]
  [ "${lines[0]}" = "allow" ]
}

@test "v6 端口族带 -6 标记" {
  run build_ufw_args "443/tcp/v6" allow
  [[ "${output[*]}" == *"-6"* ]]
}

@test "v4 与 all 相同参数（ufw 默认双栈由 IPV6=yes 保证）" {
  run build_ufw_args "80/tcp/v4" allow
  [[ "${output[*]}" != *"-6"* ]]
}

@test "delete 动作透传" {
  run build_ufw_args "22/tcp" delete
  [ "${lines[0]}" = "delete" ]
}

@test "非法 key 返回非0" {
  run build_ufw_args "bogus" allow
  [ "$status" -ne 0 ]
}
