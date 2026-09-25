#!/usr/bin/env bats
# shellcheck disable=SC1091,SC2016,SC2034,SC2153,SC2317
# T12: uninstall 两档（spec §8）
bats_require_minimum_version 1.5.0

setup() {
    export AUTO_FW_HOME STUB UFW_LOG FAKE_ROOT
    AUTO_FW_HOME="$(mktemp -d)"
    FAKE_ROOT="$(mktemp -d)"
    mkdir -p "$AUTO_FW_HOME/logs" "$FAKE_ROOT/etc/profile.d" "$AUTO_FW_HOME/f2b"
    STUB="$(mktemp -d)"
    export PATH="$STUB:$PATH"
    # UFW_LOG 必须在 AUTO_FW_HOME 之外(uninstall 会删整个 home)
    UFW_LOG="$(mktemp)"; export UFW_LOG; : > "$UFW_LOG"

    # 系统路径 seam 全部指向临时区
    export AUTO_FW_F2B_JAIL_CONF="$AUTO_FW_HOME/f2b/jail.local"
    export AUTO_FW_F2B_FILTER_DIR="$AUTO_FW_HOME/f2b/filter.d"
    export AUTO_FW_F2B_ACTION_DIR="$AUTO_FW_HOME/f2b/action.d"
    export AUTO_FW_UFW_ETC_DIR="$AUTO_FW_HOME/f2b/ufw"
    export AUTO_FW_UNINSTALL_ROOT="$FAKE_ROOT"
    # SSH 探测 seam: 固定 22, 不依赖宿主机
    export AUTO_FW_SSHD_CONFIG="$AUTO_FW_HOME/sshd_config"
    printf 'Port 22\n' > "$AUTO_FW_SSHD_CONFIG"
    mkdir -p "$AUTO_FW_F2B_FILTER_DIR" "$AUTO_FW_F2B_ACTION_DIR" "$AUTO_FW_UFW_ETC_DIR"

    # 假 /etc: crontab 含托管区块 + profile.d 含快捷脚本
    printf '%s\n' "LANG=en_US" "# BEGIN auto-firewall - 请勿手动编辑此区块" \
      "*/5 * * * * root /opt/auto-firewall/auto-firewall.sh port-check" "# END auto-firewall" > "$FAKE_ROOT/etc/crontab"
    echo "# shortcut" > "$FAKE_ROOT/etc/profile.d/auto-firewall.sh"

    # ufw 桩: status 提供带标记规则表; 变更记日志
    cat > "$STUB/ufw" <<'UF'
#!/usr/bin/env bash
case "$1" in
  status) printf '%s\n' \
    "9000/tcp                   ALLOW       auto-firewall" \
    "80/tcp                     ALLOW       auto-firewall-whitelist" \
    "22/tcp                     ALLOW       auto-firewall" \
    "8080/tcp                   ALLOW       something-else" ;;
  *) echo "ufw $*" >> "${UFW_LOG:-/dev/null}" ;;
esac
UF
    chmod +x "$STUB/ufw"

    : > "$AUTO_FW_HOME/ports.state"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../auto-firewall.sh"
    LOCK_FILE="$AUTO_FW_HOME/.script.lock"
}

teardown() { rm -rf "$AUTO_FW_HOME" "$STUB" "$FAKE_ROOT" "$UFW_LOG"; }

@test "默认档: 移除 profile.d 快捷脚本与 crontab 区块与 SCRIPT_DIR" {
    ASSUME_YES=1 uninstall
    [ ! -f "$FAKE_ROOT/etc/profile.d/auto-firewall.sh" ]
    if grep -q 'auto-firewall' "$FAKE_ROOT/etc/crontab"; then echo "crontab 区块未清理"; return 1; fi
    grep -q '^LANG=' "$FAKE_ROOT/etc/crontab"     # 保留其它 cron 内容
    [ ! -d "$SCRIPT_DIR" ]
}

@test "默认档: 不删除任何 ufw 规则（防火墙不动）" {
    ASSUME_YES=1 uninstall
    run grep "delete" "$UFW_LOG"
    [ -z "$output" ]
}

@test "--purge: 删除带标记规则但保留无标记规则" {
    ASSUME_YES=1 PURGE=1 uninstall
    grep -q "delete 9000/tcp" "$UFW_LOG"
    grep -q "delete 80/tcp" "$UFW_LOG"
    run grep "8080" "$UFW_LOG"
    [ -z "$output" ]
}

@test "--purge: SSH 22 规则默认保留（防锁死）" {
    ASSUME_YES=1 PURGE=1 uninstall
    run grep "delete 22/tcp" "$UFW_LOG"
    [ -z "$output" ]
}

@test "--purge --force-ssh: 才删 22" {
    ASSUME_YES=1 PURGE=1 FORCE_SSH=1 uninstall
    grep -q "delete 22/tcp" "$UFW_LOG"
}

@test "--purge: 移除 fail2ban 生成文件" {
    touch "$AUTO_FW_F2B_JAIL_CONF" "$AUTO_FW_F2B_FILTER_DIR/nginx-ufw.conf"
    ASSUME_YES=1 PURGE=1 uninstall
    [ ! -f "$AUTO_FW_F2B_JAIL_CONF" ]
    [ ! -f "$AUTO_FW_F2B_FILTER_DIR/nginx-ufw.conf" ]
}

@test "非交互无 --yes: 拒绝执行, 足迹保留" {
    ASSUME_YES=0
    run uninstall
    [ "$status" -ne 0 ]
    [ -f "$FAKE_ROOT/etc/profile.d/auto-firewall.sh" ]
    [ -d "$SCRIPT_DIR" ]
}

@test "dry-run: 只打印不删除" {
    ASSUME_YES=1 DRY_RUN=1 uninstall
    [ -f "$FAKE_ROOT/etc/profile.d/auto-firewall.sh" ]
    [ -d "$SCRIPT_DIR" ]
    grep -q '\[DRYRUN\]' "$LOG_FILE"
}
