#!/bin/bash
# 临时全量真机验证（root 运行; 验证后删除）
set -u
cd "$(dirname "$0")/.." || exit 1
S="$PWD/auto-firewall.sh"
VER="$(awk -F'"' '/^readonly SCRIPT_VERSION=/{print $2}' "$S")"   # 版本断言随脚本演进, 不再硬编码
PASS=0; FAIL=0
ck() { # ck 描述 命令
    if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; PASS=$((PASS+1));
    else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi
}
tui() { # tui 按键序列 -> 输出落盘 /root/O_last（避免 eval 二次展开 $O）; %b 保留按键序列中的转义
    printf '%b' "$1" | env AUTO_FW_TUI_TEST=1 bash "$S" menu > /root/O_last 2>&1
}

echo "########## A. 环境重置 + install ##########"
# WSL 环境自愈: Docker Desktop 开机向 WSL 内核注入 iptables-legacy 表, 使 nf_tables 版
# iptables 输出附加 "# Warning: iptables-legacy tables present" 警告行, 破坏 ufw 的解析
# (表现为 ufw status 空输出/enable 失败, ban 类断言全部误报)。卸载并重新加载 legacy 模块
# 即清空残留表; 仅在测试机执行, 会丢弃 legacy 表内容。
if lsmod 2>/dev/null | grep -qE '^iptable_(filter|nat)'; then
    rmmod iptable_security iptable_raw iptable_mangle iptable_nat iptable_filter ip_tables \
          ip6table_security ip6table_raw ip6table_mangle ip6table_nat ip6table_filter ip6_tables 2>/dev/null || true
    modprobe ip_tables 2>/dev/null || true
    modprobe ip6_tables 2>/dev/null || true
fi
rm -rf /opt/auto-firewall /etc/profile.d/auto-firewall.sh /etc/fail2ban/jail.local
sed -i '/# BEGIN auto-firewall/,/# END auto-firewall/d' /etc/crontab
ufw --force reset >/dev/null 2>&1; ufw enable >/dev/null 2>&1
bash "$S" install > /tmp/vinstall.log 2>&1
ck "install rc=0" "[ $? -eq 0 ]"
ck "schema=2" "[ \"\$(cat /opt/auto-firewall/.schema_version)\" = 2 ]"
ck "cron 区块存在" "grep -q 'BEGIN auto-firewall' /etc/crontab"
ck "profile.d 快捷命令" "grep -q 'x() { afw_shortcut' /etc/profile.d/auto-firewall.sh"
ck "白名单已生成(v2头)" "head -1 /opt/auto-firewall/port-whitelist.conf | grep -q 'schema-version: 2'"
ck "SSH探测=5522(本机真实)" "bash -c 'source $S; [ \"\$(detect_ssh_ports)\" = 5522 ]'"

echo "########## B. 全部 CLI 命令 ##########"
ck "status" "bash $S status | grep -q '运行状态'"
ck "version $VER" "bash $S version | grep -q \"$VER\""
ck "log" "bash $S log 5 >/dev/null"
ck "help" "bash $S help | grep -q 'config'"
ck "port-check" "bash $S port-check >/dev/null"
ck "state 已生成" "test -f /opt/auto-firewall/ports.state"
ck "config add port 区间" "bash $S config add port 9000:9100/tcp 2>/dev/null | grep -q '已加入'"
ck "config add 非法拒绝" "! bash $S config add port 99999/tcp >/dev/null 2>&1"
ck "config add ip" "bash $S config add ip 203.0.113.55 2>/dev/null | grep -q '已加入'"
ck "config del ip 保护拒绝" "! bash $S config del ip 127.0.0.1/8 >/dev/null 2>&1"
ck "config list ports" "bash $S config list ports | grep -q '9000:9100'"
ck "config list ip" "bash $S config list ip | grep -q '203.0.113.55'"
ck "config del port SSH拒绝" "! bash $S config del port 5522/tcp >/dev/null 2>&1"
ck "config del port 正常" "bash $S config del port 9000:9100/tcp 2>/dev/null | grep -q '移除'"
# shellcheck disable=SC2016  # 故意单引号: 由 eval 展开的编辑器脚本模板
printf '#!/bin/bash\necho "31338/tcp  # ed-test" >> "$1"\n' > /root/edv; chmod +x /root/edv
ck "config edit 保存成功" "env EDITOR=/root/edv script -qec \"bash $S config edit ports\" /dev/null >/dev/null 2>&1 && grep -q '^31338/tcp' /opt/auto-firewall/port-whitelist.conf"
# shellcheck disable=SC2016  # 故意单引号: 由 eval 展开的编辑器脚本模板
printf '#!/bin/bash\necho "bad !!!" >> "$1"\n' > /root/edv2; chmod +x /root/edv2
ck "config edit 非法行拒绝" "env EDITOR=/root/edv2 script -qec \"bash $S config edit ports\" /dev/null >/dev/null 2>&1; ! grep -q 'bad !!!' /opt/auto-firewall/port-whitelist.conf"
bash "$S" config del port 31338/tcp >/dev/null 2>&1; rm -f /root/edv /root/edv2
ck "ban 真实生效" "bash $S ban 198.51.100.66 >/dev/null 2>&1 && ufw status | grep -q '198.51.100.66'"
ck "unban 生效" "bash $S unban 198.51.100.66 >/dev/null 2>&1 && ! ufw status | grep -q '198.51.100.66'"
ck "fail2ban-check" "bash $S fail2ban-check >/dev/null"
ck "cleanup" "bash $S cleanup >/dev/null"
ck "reset-config ip" "bash $S reset-config ip --yes >/dev/null 2>&1 && grep -q '^127.0.0.1/8' /opt/auto-firewall/ip-whitelist.conf"
ck "reset-config ports 含5522" "bash $S reset-config ports --yes >/dev/null 2>&1 && grep -q '^5522/tcp' /opt/auto-firewall/port-whitelist.conf"
ck "dry-run 有标记日志" "bash $S config add port 6010/udp >/dev/null 2>&1 && bash $S port-check --dry-run >/dev/null 2>&1 && grep -q 'DRYRUN.*6010' /opt/auto-firewall/logs/auto-firewall.log && bash $S config del port 6010/udp >/dev/null 2>&1"
ck "未知命令 rc=1" "! bash $S nosuchcmd >/dev/null 2>&1"
ck "x/X 登录shell生效" "bash -lc 'type x >/dev/null && type X >/dev/null'"
ck "x status 等价" "bash -lc 'x status' 2>/dev/null | grep -q '运行状态'"

echo "########## C. TUI 全按键（输出落盘 /root/O_last）##########"
tui 'q';        ck "TUI 渲染主菜单12项" "grep -q '总览仪表盘' /root/O_last && grep -q '卸载脚本与配置' /root/O_last"
tui '1\n\nq';   ck "键1 总览仪表盘" "grep -q '运行状态' /root/O_last"
tui '2\n\nq';   ck "键2 端口检测" "grep -q '端口扫描完成' /root/O_last"
tui '3\n\nq';   ck "键3 Fail2ban检测" "grep -q 'Fail2ban' /root/O_last"
tui '4\n\nq';   ck "键4 系统清理" "grep -q '系统清理完成' /root/O_last"
tui '8\n\nq';   ck "键8 实时日志" "grep -q '实时日志' /root/O_last"
tui '9\n\nq';   ck "键9 Dry-run演练" "grep -q 'Dry-run' /root/O_last"
tui 'a\n\nq';   ck "键a 版本信息" "grep -q '$VER' /root/O_last"
tui '6n';       ck "键6 恢复默认: n 取消" "grep -qE '已取消|非交互' /root/O_last && grep -q 'schema-version' /opt/auto-firewall/port-whitelist.conf"
tui 'xn';       ck "键x 卸载: n 取消(未删)" "grep -qE '已取消|非交互' /root/O_last && test -d /opt/auto-firewall"
tui '516011/tcp\n\nqq'; ck "子菜单5-1 添加端口6011" "grep -q '^6011/tcp' /opt/auto-firewall/port-whitelist.conf"
tui '55\n\nqq'; ck "子菜单5-5 查看白名单" "grep -q '6011/tcp' /root/O_last"
tui '526011/tcp\n\nqq'; ck "子菜单5-2 删除端口6011" "! grep -q '^6011/tcp' /opt/auto-firewall/port-whitelist.conf"
tui '71198.51.100.88\n\nq'; ck "子菜单7-1 TUI封禁" "ufw status | grep -q '198.51.100.88'"
tui '73\n\nq';  ck "子菜单7-3 查看封禁" "grep -qE '198.51.100.88|封禁' /root/O_last"
tui '72198.51.100.88\n\nq'; ck "子菜单7-2 TUI解封" "! ufw status | grep -q '198.51.100.88'"
tui '\e[B\n\nq';   ck "DOWN+Enter 执行端口检测" "grep -q '端口扫描完成' /root/O_last"
tui '\e[B\e[A\n\nq'; ck "DOWN+UP 回到项1(总览)" "grep -q '运行状态' /root/O_last"
tui 'jk\n\nq';  ck "j/k vim式导航" "grep -q '运行状态' /root/O_last"
tui 'z\n\nq';   ck "无效键z忽略+Enter执行项1" "grep -q '运行状态' /root/O_last"
printf '\033' | env AUTO_FW_TUI_TEST=1 bash "$S" menu > /root/O_last 2>&1
ck "ESC 退出无报错" "! grep -qiE 'syntax error|unbound' /root/O_last"
ck "TUI 全程后系统完好" "test -d /opt/auto-firewall && grep -q 'BEGIN auto-firewall' /etc/crontab"

echo "########## D. 卸载 + 环境还原 ##########"
bash "$S" uninstall --dry-run --yes >/dev/null 2>&1
ck "uninstall --dry-run 未真删" "test -d /opt/auto-firewall"
bash "$S" uninstall --yes >/dev/null 2>&1
ck "默认档卸载: /opt 已删" "! test -d /opt/auto-firewall"
ck "默认档卸载: cron 区块已删" "! grep -q 'BEGIN auto-firewall' /etc/crontab"
ck "默认档卸载: profile.d 已删" "! test -f /etc/profile.d/auto-firewall.sh"
ck "默认档卸载: ufw 规则保留" "ufw status | grep -q auto-firewall"
ufw disable >/dev/null 2>&1; ufw --force reset >/dev/null 2>&1
rm -f /etc/fail2ban/jail.local /etc/fail2ban/filter.d/nginx-ufw.conf /etc/fail2ban/filter.d/nginx-404.conf /etc/fail2ban/action.d/ufw.conf
ck "环境已还原(ufw非active)" "! ufw status 2>/dev/null | head -1 | grep -q 'Status: active'"

echo "=============================="
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
