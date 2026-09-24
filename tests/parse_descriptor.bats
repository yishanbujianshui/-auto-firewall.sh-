#!/usr/bin/env bats
# T2: 统一端口描述符 parse_descriptor / canon_key（spec §2.1-§2.2）

load test_helper/common

@test "单端口 tcp 双栈" {
  run parse_descriptor "22/tcp"
  [ "$status" -eq 0 ]; [ "$output" = "22|22|tcp|all" ]
}

@test "带注释旧格式" {
  run parse_descriptor "53/udp  # dns"
  [ "$status" -eq 0 ]; [ "$output" = "53|53|udp|all" ]
}

@test "端口区间" {
  run parse_descriptor "8000:8100/tcp"
  [ "$status" -eq 0 ]; [ "$output" = "8000|8100|tcp|all" ]
}

@test "仅 v6" {
  run parse_descriptor "443/tcp/v6"
  [ "$status" -eq 0 ]; [ "$output" = "443|443|tcp|6" ]
}

@test "仅 v4" {
  run parse_descriptor "80/tcp/v4"
  [ "$status" -eq 0 ]; [ "$output" = "80|80|tcp|4" ]
}

@test "portless 名称协议 icmp" {
  run parse_descriptor "icmp"
  [ "$status" -eq 0 ]; [ "$output" = "||icmp|all" ]
}

@test "portless 斜杠协议 esp" {
  run parse_descriptor "-/esp"
  [ "$status" -eq 0 ]; [ "$output" = "||esp|all" ]
}

@test "协议号 50" {
  run parse_descriptor "-/50"
  [ "$status" -eq 0 ]; [ "$output" = "||50|all" ]
}

@test "any 协议" {
  run parse_descriptor "any"
  [ "$status" -eq 0 ]; [ "$output" = "||any|all" ]
}

@test "非法端口 0 拒绝" { run parse_descriptor "0/tcp"; [ "$status" -ne 0 ]; }
@test "非法端口 70000 拒绝" { run parse_descriptor "70000/tcp"; [ "$status" -ne 0 ]; }
@test "区间反向拒绝" { run parse_descriptor "9000:8000/tcp"; [ "$status" -ne 0 ]; }
@test "未知协议拒绝" { run parse_descriptor "22/foo"; [ "$status" -ne 0 ]; }
@test "addr 非 v4/v6 拒绝" { run parse_descriptor "22/tcp/v9"; [ "$status" -ne 0 ]; }
@test "空行拒绝" { run parse_descriptor ""; [ "$status" -ne 0 ]; }
@test "tcp 不允许无端口" { run parse_descriptor "-/tcp"; [ "$status" -ne 0 ]; }
@test "协议号 999 越界拒绝" { run parse_descriptor "-/999"; [ "$status" -ne 0 ]; }
@test "icmp 不允许带端口" { run parse_descriptor "80/icmp"; [ "$status" -ne 0 ]; }
@test "any 不允许带端口" { run parse_descriptor "80/any"; [ "$status" -ne 0 ]; }

@test "canon: icmp -> -/icmp" {
  run canon_key "icmp"; [ "$output" = "-/icmp" ]
}
@test "canon: 22/tcp/v6 保留 addr" {
  run canon_key "22/tcp/v6"; [ "$output" = "22/tcp/v6" ]
}
@test "canon: 8000:8100/tcp 原样" {
  run canon_key "8000:8100/tcp"; [ "$output" = "8000:8100/tcp" ]
}
@test "canon: 带注释 -> 纯 key" {
  run canon_key "22/tcp  # SSH"; [ "$output" = "22/tcp" ]
}
