#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T16: 双日志轮转 —— cron.log 由 cron `>>` 重定向写入, 不经 _log, 曾被 rotate_log 遗漏
load test_helper/common

@test "rotate_log 将超限的 auto-firewall.log 截断至保留行数" {
    seq 1 100000 | awk '{print "logline-0123456789-0123456789-0123456789"}' > "$LOG_FILE"
    [ "$(stat -c%s "$LOG_FILE")" -gt "$MAX_LOG_SIZE" ]
    rotate_log
    [ "$(wc -l < "$LOG_FILE")" -le "$((LOG_RETAIN_LINES + 2))" ]
}

@test "rotate_log 同样截断超限的 cron.log" {
    seq 1 100000 | awk '{print "cronline-0123456789-0123456789-012345678"}' > "$CRON_LOG_FILE"
    [ "$(stat -c%s "$CRON_LOG_FILE")" -gt "$MAX_LOG_SIZE" ]
    rotate_log
    [ "$(wc -l < "$CRON_LOG_FILE")" -le "$LOG_RETAIN_LINES" ]
}

@test "rotate_log 对小日志不做任何改动" {
    printf 'a\nb\n' > "$LOG_FILE"
    printf 'c\nd\n' > "$CRON_LOG_FILE"
    rotate_log
    [ "$(cat "$LOG_FILE")" = "$(printf 'a\nb')" ]
    [ "$(cat "$CRON_LOG_FILE")" = "$(printf 'c\nd')" ]
}
