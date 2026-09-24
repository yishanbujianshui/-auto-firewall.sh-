#!/bin/bash
# 测试一键入口: shellcheck(0 error) + bats 全量
# 用法: bash tests/run.sh   (须在 Linux/WSL 执行)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0

echo "== shellcheck (error 级) =="
if shellcheck -S error auto-firewall.sh; then
    echo "shellcheck: OK"
else
    echo "shellcheck: FAILED"
    fail=1
fi

echo
echo "== bats =="
if bats -r tests/; then
    echo "bats: OK"
else
    echo "bats: FAILED"
    fail=1
fi

exit $fail
