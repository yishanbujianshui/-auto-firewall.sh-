#!/bin/bash
# 方案3: 真机运行时场景验证（root; 真实 ufw/fail2ban + 真实监听端口）
# 覆盖: 无损迁移 / 动态放行与回收 / 白名单幂等(族/portless/any/icmp) / manual 规则不动
#       / fail2ban 联动与真实封禁 / 并发锁 / 日志轮转 / dry-run 状态一致性 / 幂等重装 / purge 卸载
set -u
[[ $EUID -eq 0 ]] || { echo "错误: 需 root 运行 (sudo bash tests/verify-runtime.sh)"; exit 1; }
cd "$(dirname "$0")/.." || exit 1
S="$PWD/auto-firewall.sh"
HOME_DIR=/opt/auto-firewall
LOG="$HOME_DIR/logs/auto-firewall.log"
VER="$(awk -F'"' '/^readonly SCRIPT_VERSION=/{print $2}' "$S")"
SSHP="$(bash -c "source '$S'; detect_ssh_ports" | awk '{print $1}')"
PASS=0; FAIL=0; SKIP=0
ck() { # ck 描述 命令
    if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; PASS=$((PASS+1));
    else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi
}
skip() { echo "SKIP: $1"; SKIP=$((SKIP+1)); }
has_rule() { ufw status 2>/dev/null | grep -qE "$1"; }
cnt_rule() { ufw status 2>/dev/null | grep -cE "$1"; }
log_has() { grep -q "$1" "$LOG" 2>/dev/null; }

PIDS=()
start_tcp4() { # 起 0.0.0.0 上的 TCP 监听, 返回 PID 写入 LAST_PID
    python3 -m http.server "$1" --bind 0.0.0.0 >/dev/null 2>&1 &
    LAST_PID=$!; PIDS+=("$LAST_PID")
}
start_udp4() {
    python3 -c "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',$1)); time.sleep(300)" >/dev/null 2>&1 &
    LAST_PID=$!; PIDS+=("$LAST_PID")
}
start_tcp6() {
    # IPV6_V6ONLY=1 才是真正的 v6-only 监听, 否则 ss 显示 *:port（双栈）
    python3 -c "import socket,time; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s.bind(('::',$1)); s.listen(1); time.sleep(300)" >/dev/null 2>&1 &
    LAST_PID=$!; PIDS+=("$LAST_PID")
}
wait_listen() { # wait_listen tcp|udp 端口
    local _
    for _ in $(seq 1 60); do
        if [[ "$1" == tcp ]]; then
            ss -ltn 2>/dev/null | grep -q ":$2 " && return 0
        else
            ss -lun 2>/dev/null | grep -q ":$2 " && return 0
        fi
        sleep 0.1
    done
    return 1
}
stop_pid() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

restore_env() {
    local p
    for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
    sed -i '/# BEGIN auto-firewall/,/# END auto-firewall/d' /etc/crontab 2>/dev/null || true
    rm -f /etc/profile.d/auto-firewall.sh /etc/fail2ban/jail.local \
          /etc/fail2ban/filter.d/nginx-ufw.conf /etc/fail2ban/filter.d/nginx-404.conf \
          /etc/fail2ban/action.d/ufw.conf
    systemctl stop fail2ban >/dev/null 2>&1 || true
    ufw --force reset >/dev/null 2>&1 || true
    ufw disable >/dev/null 2>&1 || true
    rm -rf "$HOME_DIR"
}
trap restore_env EXIT

echo "########## A. 环境重置 + v1 无损迁移安装 ##########"
rm -rf "$HOME_DIR" /etc/profile.d/auto-firewall.sh /etc/fail2ban/jail.local
rm -f /etc/fail2ban/filter.d/nginx-ufw.conf /etc/fail2ban/filter.d/nginx-404.conf /etc/fail2ban/action.d/ufw.conf
sed -i '/# BEGIN auto-firewall/,/# END auto-firewall/d' /etc/crontab 2>/dev/null || true
ufw --force reset >/dev/null 2>&1; ufw enable >/dev/null 2>&1
mkdir -p "$HOME_DIR"
cp tests/fixtures/v1_whitelist.conf "$HOME_DIR/port-whitelist.conf"
cp tests/fixtures/v1_ports.state "$HOME_DIR/ports.state"
bash "$S" install > /tmp/rt_install.log 2>&1
ck "install(v1升级) rc=0" "[ $? -eq 0 ]"
ck "schema 迁移到 2" "[ \"\$(cat $HOME_DIR/.schema_version)\" = 2 ]"
ck "迁移保留版本头" "head -1 $HOME_DIR/port-whitelist.conf | grep -q 'schema-version: 2'"
ck "迁移保留无法解析行(GAP-1)" "grep -qx 'this is a bogus line' $HOME_DIR/port-whitelist.conf"
ck "迁移前已备份" "find $HOME_DIR/backup -maxdepth 1 -mindepth 1 -type d | grep -q ."
ck "编排 SSH 端口 ${SSHP} 入白名单" "grep -q '^${SSHP}/tcp' $HOME_DIR/port-whitelist.conf"
ck "启用前已开 IPv6" "grep -q '^IPV6=yes' /etc/default/ufw"
ck "cron 指向安装目录" "grep -q \"${HOME_DIR}/auto-firewall.sh port-check\" /etc/crontab"
ck "快捷命令指向安装目录" "grep -q \"${HOME_DIR}/auto-firewall.sh\\\" menu\" /etc/profile.d/auto-firewall.sh"
bash "$S" reset-config ports --yes >/dev/null 2>&1
ck "reset-config ports 保留 SSH" "grep -q '^${SSHP}/tcp' $HOME_DIR/port-whitelist.conf"

echo "########## B. 真实监听端口动态放行/回收 ##########"
: > "$LOG"
start_tcp4 18123; pid=$LAST_PID; wait_listen tcp 18123
bash "$S" port-check >/dev/null 2>&1
ck "TCP 新监听自动放行" "has_rule '^18123/tcp[[:space:]]+ALLOW.*auto-firewall'"
ck "state 记录 TCP 动态端口" "grep -qx '18123/tcp' $HOME_DIR/ports.state"
stop_pid "$pid"; sleep 0.3
bash "$S" port-check >/dev/null 2>&1
ck "TCP 停止后自动回收" "! has_rule '^18123/tcp'"
ck "state 移除已回收端口" "! grep -qx '18123/tcp' $HOME_DIR/ports.state"

start_udp4 18124; pid=$LAST_PID; wait_listen udp 18124
bash "$S" port-check >/dev/null 2>&1
ck "UDP 新监听自动放行" "has_rule '^18124/udp[[:space:]]+ALLOW.*auto-firewall'"
stop_pid "$pid"; sleep 0.3
bash "$S" port-check >/dev/null 2>&1
ck "UDP 停止后自动回收" "! has_rule '^18124/udp'"

if python3 -c "import socket; s=socket.socket(socket.AF_INET6); s.bind(('::1',0))" >/dev/null 2>&1; then
    start_tcp6 18125; pid=$LAST_PID; wait_listen tcp 18125
    bash "$S" port-check >/dev/null 2>&1
    ck "IPv6-only 监听生成 v6 规则" "has_rule '^18125/tcp \\(v6\\)[[:space:]]+ALLOW'"
    ck "IPv6-only 不生成 v4 规则" "! has_rule '^18125/tcp[[:space:]]+ALLOW'"
    stop_pid "$pid"; sleep 0.3
    bash "$S" port-check >/dev/null 2>&1
    ck "IPv6 停止后自动回收" "! has_rule '^18125/tcp'"
else
    skip "本机 IPv6 不可用, 跳过 v6-only 动态用例"
fi

echo "########## C. 白名单优先与 manual 规则保护 ##########"
bash "$S" config add port 18126/tcp >/dev/null 2>&1
start_tcp4 18126; pid=$LAST_PID; wait_listen tcp 18126
bash "$S" port-check >/dev/null 2>&1
stop_pid "$pid"; sleep 0.3
bash "$S" port-check >/dev/null 2>&1
ck "白名单端口停止后仍保留" "has_rule '^18126/tcp.*auto-firewall-whitelist'"
ck "白名单端口不入 state" "! grep -qx '18126/tcp' $HOME_DIR/ports.state"

ufw allow 18127/tcp >/dev/null 2>&1
start_tcp4 18127; pid=$LAST_PID; wait_listen tcp 18127
bash "$S" port-check >/dev/null 2>&1
stop_pid "$pid"; sleep 0.3
bash "$S" port-check >/dev/null 2>&1
ck "manual(无标记)规则不被回收" "has_rule '^18127/tcp[[:space:]]+ALLOW'"
ufw delete allow 18127/tcp >/dev/null 2>&1

echo "########## D. 白名单格式幂等（防止每 5 分钟重复加规则） ##########"
bash "$S" config add port 18128/tcp/v4 >/dev/null 2>&1
bash "$S" port-check >/dev/null 2>&1; bash "$S" port-check >/dev/null 2>&1
n=$(cnt_rule '^18128/tcp[[:space:]]+ALLOW')
ck "仅 v4 规则重复执行后仍为 1 条 (实际 ${n})" "[ $n -eq 1 ]"
ck "仅 v4 不生成 v6 规则" "! has_rule '^18128/tcp \\(v6\\)'"

bash "$S" config add port 18129/tcp/v6 >/dev/null 2>&1
bash "$S" port-check >/dev/null 2>&1; bash "$S" port-check >/dev/null 2>&1
n=$(cnt_rule '^18129/tcp \(v6\)[[:space:]]+ALLOW')
ck "仅 v6 规则重复执行后仍为 1 条 (实际 ${n})" "[ $n -eq 1 ]"
ck "仅 v6 不生成 v4 规则" "! has_rule '^18129/tcp[[:space:]]+ALLOW'"

bash "$S" config add port -/esp >/dev/null 2>&1
bash "$S" port-check >/dev/null 2>&1; bash "$S" port-check >/dev/null 2>&1
n=$(cnt_rule '^Anywhere/esp')
ck "portless esp 重复执行后仍为 2 条(v4+v6), 实际 ${n}" "[ $n -eq 2 ]"

bash "$S" config add port any >/dev/null 2>&1
bash "$S" port-check >/dev/null 2>&1; bash "$S" port-check >/dev/null 2>&1
n=$(cnt_rule '^Anywhere( \(v6\))?[[:space:]]+ALLOW')
ck "any 协议重复执行后仍为 2 条(v4+v6), 实际 ${n}" "[ $n -eq 2 ]"

bash "$S" config add port icmp >/dev/null 2>&1
bash "$S" port-check >/dev/null 2>&1
ck "icmp: ufw 不支持时 port-check 仍成功" "[ $? -eq 0 ]"
ck "icmp: 日志明确提示跳过" "log_has '跳过白名单 -/icmp'"
ck "icmp: 不产生失败规则" "! has_rule 'icmp'"

# 清理 any/esp/v4/v6 白名单条目与对应规则, 避免影响后续 fail2ban/封禁断言
bash "$S" config del port any >/dev/null 2>&1
bash "$S" config del port -/esp >/dev/null 2>&1
bash "$S" config del port 18128/tcp/v4 >/dev/null 2>&1
bash "$S" config del port 18129/tcp/v6 >/dev/null 2>&1
bash "$S" config del port icmp >/dev/null 2>&1
ufw delete allow from any to any >/dev/null 2>&1
ufw delete allow proto esp from any to any >/dev/null 2>&1
ufw delete allow proto tcp from any to 0.0.0.0/0 port 18128 >/dev/null 2>&1
ufw delete allow proto tcp from any to ::/0 port 18129 >/dev/null 2>&1

echo "########## E. Fail2ban 联动与真实封禁 ##########"
bash "$S" config add ip 203.0.113.10 >/dev/null 2>&1
bash "$S" fail2ban-check >/dev/null 2>&1
ck "fail2ban-check rc=0" "[ $? -eq 0 ]"
ck "jail.local ignoreip 同步新 IP" "grep -q '203.0.113.10' /etc/fail2ban/jail.local"
ck "jail.local 含 sshd jail" "grep -q '^\\[sshd\\]' /etc/fail2ban/jail.local"
ck "UFW ban action 已生成" "test -f /etc/fail2ban/action.d/ufw.conf"
ck "Nginx 过滤器已生成" "test -f /etc/fail2ban/filter.d/nginx-ufw.conf"
ck "fail2ban 服务运行中" "systemctl is-active --quiet fail2ban"
ck "sshd jail 在线" "timeout 10 fail2ban-client status sshd | grep -q 'Status for the jail: sshd'"

systemctl stop fail2ban >/dev/null 2>&1; sleep 1
bash "$S" ban 198.51.100.77 >/dev/null 2>&1
ck "fail2ban 离线时走 UFW 封禁" "ufw status | grep -q '198.51.100.77'"
bash "$S" unban 198.51.100.77 >/dev/null 2>&1
ck "解封后规则移除" "! ufw status | grep -q '198.51.100.77'"
bash "$S" unban 198.51.100.77 >/dev/null 2>&1
ck "重复解封幂等返回 0" "[ $? -eq 0 ]"
systemctl start fail2ban >/dev/null 2>&1; sleep 2
ck "fail2ban 已恢复运行" "systemctl is-active --quiet fail2ban"

echo "########## F. 并发锁 / 日志轮转 / dry-run ##########"
: > "$LOG"
flock "$HOME_DIR/.script.lock" -c 'sleep 3' &
lockpid=$!
sleep 0.5
bash "$S" port-check >/dev/null 2>&1
ck "并发执行被锁跳过(rc=0)" "[ $? -eq 0 ] && log_has '上一次脚本运行尚未结束'"
wait "$lockpid" 2>/dev/null || true

python3 -c "open('$LOG','a').write('x'*1200000)" 
before=$(stat -c%s "$LOG")
bash "$S" cleanup >/dev/null 2>&1; cleanup_rc=$?
after=$(stat -c%s "$LOG")
ck "cleanup rc=0" "[ $cleanup_rc -eq 0 ]"
ck "日志轮转到 1MB 以下 (${before}->${after})" "[ $after -lt 1048576 ]"
python3 -c "open('$HOME_DIR/logs/cron.log','a').write('y'*1200000)"
bash "$S" cleanup >/dev/null 2>&1
ck "cron.log 同样轮转" "[ \"\$(stat -c%s $HOME_DIR/logs/cron.log)\" -lt 1048576 ]"

start_tcp4 18130; pid=$LAST_PID; wait_listen tcp 18130
cp "$HOME_DIR/ports.state" /tmp/rt_state_before
bash "$S" port-check --dry-run >/dev/null 2>&1
ck "dry-run 不落 ufw 规则" "! has_rule '^18130/tcp'"
ck "dry-run 不改写 state" "cmp -s /tmp/rt_state_before $HOME_DIR/ports.state"
ck "dry-run 记录 [DRYRUN]" "log_has '\\[DRYRUN\\] ufw allow 18130/tcp'"
bash "$S" port-check >/dev/null 2>&1
ck "dry-run 后真实执行可正常放行" "has_rule '^18130/tcp.*auto-firewall'"
stop_pid "$pid"; sleep 0.3
bash "$S" port-check >/dev/null 2>&1
ck "真实执行后回收正常" "! has_rule '^18130/tcp'"

echo "########## G. 幂等重装 + purge 卸载 ##########"
bash "$S" install > /dev/null 2>&1
ck "二次 install rc=0" "[ $? -eq 0 ]"
ck "二次 install 不重复 cron 区块" "[ \"\$(grep -c 'BEGIN auto-firewall' /etc/crontab)\" -eq 1 ]"

bash "$S" config add port 18132/tcp >/dev/null 2>&1
bash "$S" port-check >/dev/null 2>&1
ck "卸载前存在白名单规则 18132" "has_rule '^18132/tcp.*auto-firewall-whitelist'"
bash "$S" uninstall --purge --yes >/dev/null 2>&1
ck "purge rc=0" "[ $? -eq 0 ]"
ck "purge 删除脚本目录" "! test -d $HOME_DIR"
ck "purge 删除脚本规则" "! has_rule '^18132/tcp'"
ck "purge 默认保留 SSH ${SSHP}" "has_rule '^${SSHP}/tcp[[:space:]]+ALLOW'"
ck "purge 停用 fail2ban" "! systemctl is-active --quiet fail2ban"
ck "purge 移除 cron 区块" "! grep -q 'BEGIN auto-firewall' /etc/crontab"
ck "purge 移除快捷命令" "! test -f /etc/profile.d/auto-firewall.sh"

echo "=============================="
echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (version $VER, ssh-port $SSHP)"
[ "$FAIL" -eq 0 ]
