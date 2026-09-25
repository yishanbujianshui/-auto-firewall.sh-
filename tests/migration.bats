#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T7: 版本化无损迁移（spec §4, GAP-1）
bats_require_minimum_version 1.5.0

load test_helper/common

setup() {
    export AUTO_FW_HOME
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    cp "${BATS_TEST_DIRNAME}/fixtures/v1_whitelist.conf" "$WHITELIST_FILE"
    cp "${BATS_TEST_DIRNAME}/fixtures/v1_ports.state" "$STATE_FILE"
}

@test "迁移后写入 schema 版本标记 = 2" {
    migrate_v1_to_v2
    [ -f "$VERSION_FILE" ]
    grep -qx '2' "$VERSION_FILE"
}

@test "迁移保留整行注释与头注释" {
    migrate_v1_to_v2
    grep -q '防火墙自动脚本 - 端口白名单配置' "$WHITELIST_FILE"
    grep -q '用户自定义端口' "$WHITELIST_FILE"
}

@test "迁移保留无法解析的非注释行（GAP-1 不丢数据）" {
    migrate_v1_to_v2
    grep -qF 'this is a bogus line' "$WHITELIST_FILE"
}

@test "迁移保留可解析端口及服务名注释" {
    migrate_v1_to_v2
    grep -q '^22/tcp.*OpenSSH' "$WHITELIST_FILE"
    grep -q '^8080/tcp' "$WHITELIST_FILE"
    grep -q '^80/tcp' "$WHITELIST_FILE"
}

@test "迁移生成版本头行" {
    migrate_v1_to_v2
    head -1 "$WHITELIST_FILE" | grep -q '^# schema-version: 2$'
}

@test "state 迁移: canon 化并带版本头" {
    migrate_v1_to_v2
    head -1 "$STATE_FILE" | grep -q '^# schema-version: 2$'
    grep -qx '3000/tcp' "$STATE_FILE"
    grep -qx '8888/udp' "$STATE_FILE"
}

@test "迁移前生成备份目录" {
    migrate_v1_to_v2
    [ -d "$BACKUP_DIR" ]
    [ "$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)" -ge 1 ]
}

@test "备份含原文件副本" {
    local before
    before="$(cat "$WHITELIST_FILE")"
    migrate_v1_to_v2
    local dst
    dst="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | sort | head -1)"
    grep -qF 'this is a bogus line' "${dst}/port-whitelist.conf"
}

@test "run_migrations: 无标记+有配置 视为 v1 并迁移" {
    run_migrations
    grep -qx '2' "$VERSION_FILE"
    grep -q '^# schema-version: 2$' "$WHITELIST_FILE"
}

@test "run_migrations: 已是目标版本则跳过（幂等）" {
    echo 2 > "$VERSION_FILE"
    local before
    before="$(cat "$WHITELIST_FILE")"
    run_migrations
    [ "$(cat "$WHITELIST_FILE")" = "$before" ]
}

@test "run_migrations: 全新环境直接写版本不迁移" {
    rm -f "$WHITELIST_FILE" "$STATE_FILE"
    run_migrations
    grep -qx '2' "$VERSION_FILE"
    [ ! -f "$WHITELIST_FILE" ]
}

# ---- v1 孤儿动态规则收编（实机事故: v1 残留数千条规则永不回收）----
@test "迁移收编: ufw 残留的 auto-firewall 孤儿规则并入 state" {
    refresh_ufw_table() {
        UFW_EXIST["9000/tcp"]=1;  UFW_MARKER["9000/tcp"]=auto-firewall
        UFW_EXIST["7777/udp/v6"]=1; UFW_MARKER["7777/udp/v6"]=auto-firewall
    }
    migrate_v1_to_v2
    grep -qx '9000/tcp' "$STATE_FILE"
    grep -qx '7777/udp/v6' "$STATE_FILE"
}

@test "迁移收编: whitelist/manual 标记的规则不收编" {
    refresh_ufw_table() {
        UFW_EXIST["80/tcp"]=1; UFW_MARKER["80/tcp"]=auto-firewall-whitelist
        UFW_EXIST["3306/tcp"]=1; UFW_MARKER["3306/tcp"]=none
    }
    migrate_v1_to_v2
    run ! grep -qx '80/tcp' "$STATE_FILE"
    run ! grep -qx '3306/tcp' "$STATE_FILE"
}

@test "迁移收编: 与 state 已有条目不重复" {
    refresh_ufw_table() {
        UFW_EXIST["3000/tcp"]=1; UFW_MARKER["3000/tcp"]=auto-firewall
    }
    migrate_v1_to_v2
    [ "$(grep -c '^3000/tcp$' "$STATE_FILE")" -eq 1 ]
}
