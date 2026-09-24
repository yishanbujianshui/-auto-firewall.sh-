#!/usr/bin/env bats
# T7: 备份保留策略（spec §5 G5/GAP-6）
bats_require_minimum_version 1.5.0

load test_helper/common

setup() {
    export AUTO_FW_HOME
    AUTO_FW_HOME="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    echo "22/tcp" > "$WHITELIST_FILE"
}

@test "backup/ 目录权限为 700（GAP-6）" {
    backup_configs >/dev/null
    [ "$(stat -c '%a' "$BACKUP_DIR")" = "700" ]
}

@test "超过保留数时修剪最旧快照" {
    local i
    for i in $(seq 1 12); do
        mkdir -p "$BACKUP_DIR/202001010000$(printf '%02d' "$i")"
    done
    backup_configs >/dev/null
    local count
    count="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)"
    [ "$count" -le "$BACKUP_RETAIN" ]
}

@test "修剪后保留的是时间最新的快照" {
    local i
    for i in $(seq 1 12); do
        mkdir -p "$BACKUP_DIR/202001010000$(printf '%02d' "$i")"
    done
    backup_configs >/dev/null
    # 最旧的 20200101000001 必须已被删除
    [ ! -d "$BACKUP_DIR/20200101000001" ]
}

@test "备份包含现有配置副本" {
    dst="$(backup_configs)"
    [ -f "${dst}/port-whitelist.conf" ]
    grep -qx '22/tcp' "${dst}/port-whitelist.conf"
}

@test "restore_latest_backup 能还原被迁移破坏的文件" {
    echo "22/tcp" > "$WHITELIST_FILE"
    local backup_content
    backup_configs >/dev/null
    echo "CORRUPTED" > "$WHITELIST_FILE"
    restore_latest_backup
    grep -qx '22/tcp' "$WHITELIST_FILE"
}
