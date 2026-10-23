#!/bin/bash
#
# Waits for the trustyca service to answer, then execs the command given as
# arguments. The service image is distroless and can not run a health check
# of its own, so the wait happens here, in the test runner.

set -euo pipefail

TRUSTYCA_URL="${TRUSTYCA_URL:-https://api.local.trustyca.io:8880}"
TRUSTYCA_TRUSTED_CA="${TRUSTYCA_TRUSTED_CA:-/opt/trustyca/certs/trustyca_root.pem}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"

curl_opts=(--silent --show-error --fail --max-time 5 --cacert "$TRUSTYCA_TRUSTED_CA")

echo "*** trustyca: waiting for ${TRUSTYCA_URL} (up to ${READY_TIMEOUT}s)"

deadline=$(($(date +%s) + READY_TIMEOUT))
until curl "${curl_opts[@]}" "${TRUSTYCA_URL}/v1/status/server" >/dev/null 2>&1; do
    if [[ $(date +%s) -ge $deadline ]]; then
        echo "*** trustyca: ${TRUSTYCA_URL} did not become ready in ${READY_TIMEOUT}s" >&2
        exit 1
    fi
    echo "    not ready yet, retrying"
    sleep 3
done

echo "*** trustyca: server is up"

# The REST probe above says the listener answers; the CLI also dials the same
# port over gRPC. Wait for it here rather than letting the first test hit a
# dial timeout.
echo "*** trustyca: waiting for the gRPC end-point"
until trustyca -s "$TRUSTYCA_URL" -r "$TRUSTYCA_TRUSTED_CA" --timeout 10 version >/dev/null 2>&1; do
    if [[ $(date +%s) -ge $deadline ]]; then
        echo "*** trustyca: ${TRUSTYCA_URL} did not answer over gRPC in ${READY_TIMEOUT}s" >&2
        exit 1
    fi
    echo "    not ready yet, retrying"
    sleep 3
done

echo "*** trustyca: ready"
exec "$@"
