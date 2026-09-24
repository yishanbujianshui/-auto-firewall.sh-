#!/usr/bin/env bats
# T5: parse_scan_line IPv6/zone-id/family 解析（spec §3.1, GAP-2）

load test_helper/common

@test "v4 监听 0.0.0.0:22 -> family 4" {
  run parse_scan_line "LISTEN 0      128    0.0.0.0:22        0.0.0.0:*"
  [ "$status" -eq 0 ]; [ "$output" = "22|tcp|4" ]
}

@test "v6 [::]:22 -> family 6" {
  run parse_scan_line "LISTEN 0      128    [::]:22           [::]:*"
  [ "$status" -eq 0 ]; [ "$output" = "22|tcp|6" ]
}

@test "*:80 -> family all" {
  run parse_scan_line "LISTEN 0      511    *:80              *:*"
  [ "$status" -eq 0 ]; [ "$output" = "80|tcp|all" ]
}

@test "zone-id 剥离 fe80::1%eth0 -> family 6" {
  run parse_scan_line "LISTEN 0      128    [fe80::1%eth0]:8080   [::]:*"
  [ "$status" -eq 0 ]; [ "$output" = "8080|tcp|6" ]
}

@test "回环 127.0.0.1 跳过" {
  run parse_scan_line "LISTEN 0      0      127.0.0.1:5432    0.0.0.0:*"
  [ "$status" -ne 0 ]
}

@test "回环 ::1 跳过" {
  run parse_scan_line "LISTEN 0      0      [::1]:631         [::]:*"
  [ "$status" -ne 0 ]
}

@test "UNCONN -> udp" {
  run parse_scan_line "UNCONN 0      0      0.0.0.0:53        0.0.0.0:*"
  [ "$status" -eq 0 ]; [ "$output" = "53|udp|4" ]
}

@test "netstat 风格 tcp 前缀行" {
  run parse_scan_line "tcp   0   0   0.0.0.0:443   0.0.0.0:*   LISTEN"
  [ "$status" -eq 0 ]; [ "$output" = "443|tcp|4" ]
}

@test "netstat 风格 udp6 行" {
  run parse_scan_line "udp6  0   0   [::]:5353   [::]:*"
  [ "$status" -eq 0 ]; [ "$output" = "5353|udp|6" ]
}

@test "具体绑定 IP 192.168.1.10:3000 -> family 4" {
  run parse_scan_line "LISTEN 0 64 192.168.1.10:3000 0.0.0.0:*"
  [ "$status" -eq 0 ]; [ "$output" = "3000|tcp|4" ]
}

@test "头部行/垃圾行返回非0" {
  run parse_scan_line "State  Recv-Q Send-Q Local Address:Port Peer"
  [ "$status" -ne 0 ]
  run parse_scan_line ""
  [ "$status" -ne 0 ]
}

@test "ss_listen_raw 存在且经 ss_probe 封装" {
  declare -f ss_listen_raw >/dev/null
  declare -f ss_probe >/dev/null
}
