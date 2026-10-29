#!/bin/bash
# 测试一键入口: shellcheck(0 error) + bats 全量
# 用法: bash tests/run.sh   (须在 Linux/WSL 执行)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

fail=0

echo "== shellcheck (style 级, 全部 shell 文件) =="
# SC2329: bats 用例中覆盖被测函数的桩不会被静态调用, 属预期（其余规则保持 style 级全开）
if shellcheck -S style --exclude=SC2329 auto-firewall.sh tests/run.sh tests/test_helper/*.bash tests/*.bats tests/verify-full.sh tests/verify-runtime.sh; then
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
