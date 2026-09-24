#!/usr/bin/env bats
# T3: build_ufw_args 描述符 -> ufw 参数 token（spec §2.3, GAP-4）
# 编码约定: 双栈 tcp/udp 简写 "<port>/<proto>"; 显式族/portless 用
#   "proto <p> from any to <dst>[ port <n>]"; any 无 proto

load test_helper/common

# bats $output 为换行连接的标量, 转空格便于整串精确断言
join() { printf '%s' "${output//$'\n'/ }"; }

@test "allow 单端口 tcp 双栈 -> 简写" {
  run build_ufw_args "22/tcp" allow
  [ "$status" -eq 0 ]
  [ "$(join)" = "allow 22/tcp" ]
}

@test "allow 端口区间 双栈 -> 简写" {
  run build_ufw_args "8000:8100/tcp" allow
  [ "$(join)" = "allow 8000:8100/tcp" ]
}

@test "v6 -> proto tcp from any to ::/0 port N" {
  run build_ufw_args "443/tcp/v6" allow
  [ "$(join)" = "allow proto tcp from any to ::/0 port 443" ]
}

@test "v4 -> to 0.0.0.0/0" {
  run build_ufw_args "80/tcp/v4" allow
  [ "$(join)" = "allow proto tcp from any to 0.0.0.0/0 port 80" ]
}

@test "v6 区间 -> port start:end" {
  run build_ufw_args "8000:8100/tcp/v6" allow
  [ "$(join)" = "allow proto tcp from any to ::/0 port 8000:8100" ]
}

@test "icmp -> proto icmp, GAP-4 不生成 proto any" {
  run build_ufw_args "-/icmp" allow
  [ "$(join)" = "allow proto icmp from any to any" ]
}

@test "esp 协议名" {
  run build_ufw_args "-/esp" allow
  [ "$(join)" = "allow proto esp from any to any" ]
}

@test "协议号 50 -> proto 50" {
  run build_ufw_args "-/50" allow
  [ "$(join)" = "allow proto 50 from any to any" ]
}

@test "any -> 无 proto 无端口（GAP-4）" {
  run build_ufw_args "any" allow
  [ "$(join)" = "allow from any to any" ]
}

@test "udp 双栈简写" {
  run build_ufw_args "53/udp" allow
  [ "$(join)" = "allow 53/udp" ]
}

@test "delete 动作透传" {
  run build_ufw_args "22/tcp" delete
  [ "$(join)" = "delete 22/tcp" ]
}

@test "非法 key 返回非0" {
  run build_ufw_args "bogus" allow
  [ "$status" -ne 0 ]
}
