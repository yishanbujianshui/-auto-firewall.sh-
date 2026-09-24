#!/bin/bash
set -u
S="/mnt/c/Users/qianl/Desktop/Github/防火墙自动脚本/auto-firewall.sh"

echo "== 最小复现1: if 守卫内 main 返回非0 =="
cat > /tmp/t1.sh <<'EOS'
#!/bin/bash
set -euo pipefail
main() { local rc=0; false || rc=$?; return "$rc"; }
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
EOS
bash /tmp/t1.sh; echo "t1 rc: $?"

echo "== 最小复现2: case 分支内函数失败 || rc 捕获 =="
cat > /tmp/t2.sh <<'EOS'
#!/bin/bash
set -euo pipefail
sub() { return 1; }
disp() { local rc=0; case a in a) sub || rc=$? ;; esac; return "$rc"; }
main() { local rc=0; disp || rc=$?; return "$rc"; }
main "$@"
exit $?
EOS
bash /tmp/t2.sh; echo "t2 rc: $?"

echo "== 真实脚本 main 层 =="
( source "$S" diag 2>/tmp/srcerr; type main >/dev/null 2>&1 && { main log abc; echo "main rc: $?"; } || { echo "source失败:"; cat /tmp/srcerr | head -3; } )

echo "== 真实脚本 CLI =="
bash "$S" log abc >/dev/null 2>&1; echo "cli log rc: $?"
bash "$S" nosuch >/dev/null 2>&1; echo "cli unknown rc: $?"
