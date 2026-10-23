#!/bin/bash
#
# Brings up the integration test environment and runs the suite in it.
# Invoked by `make docker-citest`, and safe to run on its own once the images
# exist (`make docker docker-tester`).
#
# Environment:
#   ITEST_IMAGE         service image,     default effective-security/trustyca
#   ITEST_TESTER_IMAGE  test runner image, default effective-security/trustyca-tester
#   ITEST_IMAGE_TAG     tag of both,       default main
#   ITEST_PROJECT       compose project,   default trustyca-ci
#   ITEST_KEEP_UP       leave the stack running after the suite, for debugging

set -euo pipefail

cd "$(dirname "$0")"

export ITEST_IMAGE="${ITEST_IMAGE:-effective-security/trustyca}"
export ITEST_TESTER_IMAGE="${ITEST_TESTER_IMAGE:-effective-security/trustyca-tester}"
export ITEST_IMAGE_TAG="${ITEST_IMAGE_TAG:-main}"

PROJECT="${ITEST_PROJECT:-trustyca-ci}"
PROJ_ROOT="$(cd ../.. && pwd)"
CITEST_DIR="$(pwd)/.citest"
CERT_DIR="${CITEST_DIR}/certs"
# the compose network aliases the clients verify the service and Redis by,
# on top of localhost and the host name that gen_certs.sh always adds
TEST_CERTS_SAN="127.0.0.1,api.local.trustyca.io,redis.local.trustyca.io"

compose() {
    docker compose -f docker-compose.tester.yml -p "$PROJECT" "$@"
}

# ---------------------------------------------------------------------------
# certificates
#
# The stack has a PKI of its own, issued on every run under the checked-in
# dev root: the developer's ~/.trustyca/certs is never read or rewritten, so
# the dev DB keeps the platform issuer its key was registered with. The
# files are made world readable, since the service runs as nonroot and Redis
# as its own user; they are throw-away test certificates.
# ---------------------------------------------------------------------------
gen_certs() {
    # hsm-tool is installed by `make tools`
    export PATH="${PROJ_ROOT}/bin:${PATH}"
    if ! command -v hsm-tool >/dev/null 2>&1; then
        echo "*** hsm-tool not found: run 'make tools'" >&2
        exit 1
    fi

    rm -rf "$CITEST_DIR"
    mkdir -p "$CERT_DIR" "${CITEST_DIR}/root"
    tar -xzf "${PROJ_ROOT}/etc/dev/certs/root/trustyca_root.key.tar.gz" -C "${CITEST_DIR}/root"
    cp "${PROJ_ROOT}/etc/dev/certs/root/trustyca_root.pem" "${CITEST_DIR}/root/"
    cp "${PROJ_ROOT}/etc/dev/certs/root/trustyca_root.pem" "${CERT_DIR}/"

    "${PROJ_ROOT}/.project/gen_certs.sh" \
        --hsm-config inmem \
        --ca-config "${PROJ_ROOT}/etc/dev/certs/ca-config.bootstrap.yaml" \
        --output-dir "$CERT_DIR" \
        --csr-dir "${PROJ_ROOT}/etc/dev/certs/csr_profile" \
        --csr-prefix trustyca_ \
        --out-prefix trustyca_ \
        --key-label citest_ \
        --san "$TEST_CERTS_SAN" \
        --root-ca "${CITEST_DIR}/root/trustyca_root.pem" \
        --root-ca-key "${CITEST_DIR}/root/trustyca_root.key" \
        --ca1 --ca2 --bundle --server --peer --client --admin --ra --aia \
        >"${CITEST_DIR}/gen_certs.log" 2>&1 || {
        echo "*** gen_certs.sh failed:" >&2
        cat "${CITEST_DIR}/gen_certs.log" >&2
        exit 1
    }
    rm -rf "${CITEST_DIR}/root"

    chmod 0755 "$CITEST_DIR" "$CERT_DIR"
    chmod 0644 "$CERT_DIR"/*
    echo "*** issued $(ls "$CERT_DIR" | wc -l) certificate files in ${CERT_DIR}"
}

dump_logs() {
    echo "*** trustyca: service logs"
    compose logs --no-color --tail=400 trustyca || true
}

teardown() {
    if [[ -n "${ITEST_KEEP_UP:-}" ]]; then
        echo "*** ITEST_KEEP_UP set, leaving the '${PROJECT}' stack running"
        echo "*** tear it down with: docker compose -f $(pwd)/docker-compose.tester.yml -p ${PROJECT} down -v"
        return
    fi
    echo "*** trustyca: stopping the test environment"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}

echo "*** trustyca: integration tests"
echo "***   project: ${PROJECT}"
echo "***   service: ${ITEST_IMAGE}:${ITEST_IMAGE_TAG}"
echo "***   tester : ${ITEST_TESTER_IMAGE}:${ITEST_IMAGE_TAG}"

# a leftover stack from an aborted run would silently reuse its old database
compose down -v --remove-orphans >/dev/null 2>&1 || true

gen_certs

trap teardown EXIT

echo "*** trustyca: starting sql, redis and kms"
compose up -d --wait sql redis kms

echo "*** trustyca: creating the trustycadb database"
compose run --rm --no-deps sql-init >/dev/null

echo "*** trustyca: starting the service"
compose up -d trustyca

echo "*** trustyca: running the test suite"
set +e
compose run --rm --no-deps -T test-runner
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -ne 0 ]]; then
    dump_logs
fi

echo "*** trustyca: test exit code: ${EXIT_CODE}"
exit $EXIT_CODE
