#!/bin/bash
#
# Integration test driver. Runs every test file in order in one shell, so a
# later test can use what an earlier one created, and reports a summary.
#
# Run a subset by naming the files, including the ones they depend on:
#   docker compose ... run --rm test-runner \
#       /opt/trustyca/tests/run.sh test_auth.sh test_cookies.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${TESTS_DIR}/lib.sh"

SUITE=("$@")
if [[ ${#SUITE[@]} -eq 0 ]]; then
    SUITE=(
        test_status.sh
        test_auth.sh
        test_cookies.sh
        test_operator.sh
    )
fi

PASSED=()
FAILED=()

for t in "${SUITE[@]}"; do
    CURRENT_TEST="$t"
    # underscored: the test files are sourced into this shell, so a plain
    # name here would be whatever the last test assigned to it
    __failures_before=$FAILURES
    echo
    echo "==========================================================="
    echo "*** ${t}"
    echo "==========================================================="
    # shellcheck disable=SC1090
    source "${TESTS_DIR}/${t}"
    rc=$?
    if [[ $rc -ne 0 || $FAILURES -ne $__failures_before ]]; then
        FAILED+=("$t")
    else
        PASSED+=("$t")
    fi
done

CURRENT_TEST=""
echo
echo "==========================================================="
echo "*** trustyca: integration test summary"
for t in "${PASSED[@]:-}"; do [[ -n "$t" ]] && echo "    PASS  ${t}"; done
for t in "${FAILED[@]:-}"; do [[ -n "$t" ]] && echo "    FAIL  ${t}"; done
echo "==========================================================="

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "*** trustyca: ${#FAILED[@]} test file(s) failed, ${FAILURES} assertion(s)" >&2
    exit 1
fi

echo "*** trustyca: integration tests succeeded"
