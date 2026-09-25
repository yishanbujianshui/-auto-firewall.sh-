#!/bin/bash
# 测试一键入口: shellcheck(0 error) + bats 全量
# 用法: bash tests/run.sh   (须在 Linux/WSL 执行)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

fail=0

echo "== shellcheck (style 级, 全部 shell 文件) =="
if shellcheck -S style auto-firewall.sh tests/run.sh tests/test_helper/*.bash tests/*.bats; then
    echo "shellcheck: OK (0 findings)"
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
