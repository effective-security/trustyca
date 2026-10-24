#!/bin/bash
#
# Shared helpers for the integration tests. Sourced by run.sh before any
# test_*.sh, so every test has the same assertions and the same way of
# talking to the server.

TRUSTYCA_URL="${TRUSTYCA_URL:-https://api.local.trustyca.io:8880}"
TRUSTYCA_BACKEND_URL="${TRUSTYCA_BACKEND_URL:-https://api.local.trustyca.io:8881}"
TRUSTYCA_AIA_URL="${TRUSTYCA_AIA_URL:-http://api.local.trustyca.io:8888}"
TRUSTYCA_TRUSTED_CA="${TRUSTYCA_TRUSTED_CA:-/opt/trustyca/certs/trustyca_root.pem}"
TRUSTYCA_WORKDIR="${TRUSTYCA_WORKDIR:-/tmp/trustyca}"
# The CLI's default is 6s, and it is the gRPC dial timeout as well as the
# request timeout: a container that has just started can be slower.
TRUSTYCA_CLI_TIMEOUT="${TRUSTYCA_CLI_TIMEOUT:-30}"
# the console in cookie mode, an origin of the dev CORS configuration on a
# host under the cookie domain
CONSOLE_ORIGIN="${CONSOLE_ORIGIN:-https://app.local.trustyca.io:4200}"
# the landing page of the console, in auth.allowed_redirect_domains
CONSOLE_REDIRECT="${CONSOLE_ORIGIN}/auth/authenticated"
export TRUSTYCA_URL TRUSTYCA_BACKEND_URL TRUSTYCA_AIA_URL TRUSTYCA_TRUSTED_CA \
    TRUSTYCA_WORKDIR TRUSTYCA_CLI_TIMEOUT CONSOLE_ORIGIN CONSOLE_REDIRECT

# every user has its own token storage and cookie jar, see login() and
# browser_login()
TRUSTYCA_USERS_DIR="${TRUSTYCA_WORKDIR}/users"
mkdir -p "$TRUSTYCA_USERS_DIR"

FAILURES=0
CURRENT_TEST=""

log()  { echo "    $*"; }
info() { echo "*** $*"; }

fail() {
    echo "!!! FAIL ${CURRENT_TEST}: $*" >&2
    FAILURES=$((FAILURES + 1))
    return 1
}

assert_eq() {
    local expected="$1" actual="$2" what="${3:-value}"
    if [[ "$expected" != "$actual" ]]; then
        fail "${what}: expected '${expected}', got '${actual}'"
        return 1
    fi
    log "ok: ${what} == ${expected}"
}

assert_ne() {
    local unexpected="$1" actual="$2" what="${3:-value}"
    if [[ "$unexpected" == "$actual" ]]; then
        fail "${what}: expected anything but '${unexpected}'"
        return 1
    fi
    log "ok: ${what} != ${unexpected}"
}

assert_contains() {
    local haystack="$1" needle="$2" what="${3:-output}"
    if [[ "$haystack" != *"$needle"* ]]; then
        fail "${what}: '${needle}' not found in: ${haystack}"
        return 1
    fi
    log "ok: ${what} contains ${needle}"
}

assert_not_contains() {
    local haystack="$1" needle="$2" what="${3:-output}"
    if [[ "$haystack" == *"$needle"* ]]; then
        fail "${what}: '${needle}' found in: ${haystack}"
        return 1
    fi
    log "ok: ${what} does not contain ${needle}"
}

assert_not_empty() {
    local value="$1" what="${2:-value}"
    if [[ -z "$value" || "$value" == "null" ]]; then
        fail "${what}: is empty"
        return 1
    fi
    log "ok: ${what} is set"
}

assert_empty() {
    local value="$1" what="${2:-value}"
    if [[ -n "$value" && "$value" != "null" ]]; then
        fail "${what}: expected empty, got '${value}'"
        return 1
    fi
    log "ok: ${what} is empty"
}

# assert_fails runs a command that is expected to be rejected by the server.
assert_fails() {
    local what="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        fail "${what}: expected a failure, got: ${out}"
        return 1
    fi
    log "ok: ${what} was rejected"
}

# assert_fails_with <what> <needle> <command...> runs a command that is
# expected to be rejected by the server with the needle in its output.
assert_fails_with() {
    local what="$1" needle="$2"; shift 2
    local out
    if out=$("$@" 2>&1); then
        fail "${what}: expected a failure, got: ${out}"
        return 1
    fi
    if [[ "$out" != *"$needle"* ]]; then
        fail "${what}: rejected without '${needle}': ${out}"
        return 1
    fi
    log "ok: ${what} was rejected: ${needle}"
}

# ---------------------------------------------------------------------------
# CLI: bearer tokens
# ---------------------------------------------------------------------------

# trustyca_as <user> <args...> runs the trustyca CLI with that user's token
# storage.
trustyca_as() {
    local user="$1"; shift
    TRUSTYCA_STORAGE="${TRUSTYCA_USERS_DIR}/${user}" \
        trustyca -s "$TRUSTYCA_URL" -r "$TRUSTYCA_TRUSTED_CA" \
        --timeout "$TRUSTYCA_CLI_TIMEOUT" "$@"
}

# trustyca_anon <args...> runs the CLI with no credentials at all: an empty
# storage, and TRUSTYCA_AUTH_TOKEN cleared (the CLI prefers a non-empty
# value of it to the storage).
trustyca_anon() {
    TRUSTYCA_STORAGE="${TRUSTYCA_WORKDIR}/anon" TRUSTYCA_AUTH_TOKEN="" \
        trustyca -s "$TRUSTYCA_URL" -r "$TRUSTYCA_TRUSTED_CA" \
        --timeout "$TRUSTYCA_CLI_TIMEOUT" "$@"
}

# email_of <user> is the address the server records for the user: the local
# provider strips the "local+" prefix it was addressed with.
email_of() { echo "$1@trustyca.io"; }

# login <user> signs <user> in through the local identity provider as
# local+<user>@trustyca.io and stores the token under that user's storage.
#
# `trustyca auth login` runs the real OAuth code flow: it listens on a
# loopback port and opens a browser. tests/browser/xdg-open stands in for it
# and walks the redirect chain with curl, so the flow the CLI performs here
# is the one a person performs in a browser.
login() {
    local user="$1"
    local email="local+$(email_of "$user")"
    mkdir -p "${TRUSTYCA_USERS_DIR}/${user}"
    info "login ${email}"
    if ! TRUSTYCA_STORAGE="${TRUSTYCA_USERS_DIR}/${user}" TRUSTYCA_AUTH_TOKEN="" \
        timeout 60 trustyca -s "$TRUSTYCA_URL" -r "$TRUSTYCA_TRUSTED_CA" \
        --timeout "$TRUSTYCA_CLI_TIMEOUT" auth login "$email"; then
        fail "login ${email} failed, see $(xdg_open_log)"
        [[ -f "$(xdg_open_log)" ]] && tail -40 "$(xdg_open_log)" >&2
        return 1
    fi
}

xdg_open_log() { echo "${TRUSTYCA_WORKDIR}/xdg-open.log"; }

# trustycactl_as <user> <args...> runs the operator CLI on the backend
# listener with that user's token storage and DPoP keys, and no client
# certificate.
trustycactl_as() {
    local user="$1"; shift
    TRUSTYCA_STORAGE="${TRUSTYCA_USERS_DIR}/${user}" TRUSTYCA_AUTH_TOKEN="" \
        trustycactl -s "$TRUSTYCA_BACKEND_URL" -r "$TRUSTYCA_TRUSTED_CA" \
        --timeout "$TRUSTYCA_CLI_TIMEOUT" "$@"
}

# dpop_login <user> signs <user> in as login does, with a DPoP key of its
# storage: the token is bound to the key, as an operator's must be.
dpop_login() {
    local user="$1"
    local email="local+$(email_of "$user")"
    mkdir -p "${TRUSTYCA_USERS_DIR}/${user}"
    info "DPoP login ${email}"
    trustycactl_as "$user" dpop-key gen "$user" >/dev/null || {
        fail "dpop-key gen for ${user} failed"
        return 1
    }
    if ! TRUSTYCA_STORAGE="${TRUSTYCA_USERS_DIR}/${user}" TRUSTYCA_AUTH_TOKEN="" \
        timeout 60 trustyca -s "$TRUSTYCA_URL" -r "$TRUSTYCA_TRUSTED_CA" \
        --timeout "$TRUSTYCA_CLI_TIMEOUT" auth login "$email" --dpop-key default; then
        fail "DPoP login ${email} failed, see $(xdg_open_log)"
        [[ -f "$(xdg_open_log)" ]] && tail -40 "$(xdg_open_log)" >&2
        return 1
    fi
}

# org_of <user> prints the ID of the org selected in the user's token
org_of() {
    trustyca_as "$1" --o json org get | jq -r '.ID'
}

# ---------------------------------------------------------------------------
# Browser: the cookie session of the console
#
# A user's browser is a curl cookie jar. The console sends every call with
# the cookies (credentials: 'include'), from its own origin, and copies the
# CSRF cookie into the X-CSRF-Token header. The responses are kept in
# ${TRUSTYCA_WORKDIR}/http: RESP_HEADERS and RESP_BODY name the files of the
# last call, HTTP_STATUS is its status.
# ---------------------------------------------------------------------------

HTTP_DIR="${TRUSTYCA_WORKDIR}/http"
mkdir -p "$HTTP_DIR"
RESP_HEADERS="${HTTP_DIR}/headers"
RESP_BODY="${HTTP_DIR}/body"
HTTP_STATUS=""

curl_tls=(--silent --show-error --max-time 30 --cacert "$TRUSTYCA_TRUSTED_CA")

jar_of() { echo "${TRUSTYCA_USERS_DIR}/$1/cookies.jar"; }

# cookie_value <user> <name> prints the value of a cookie in the user's jar.
# HttpOnly cookies are stored with a #HttpOnly_ prefix on the domain.
cookie_value() {
    local jar
    jar="$(jar_of "$1")"
    [[ -f "$jar" ]] || return 0
    awk -F'\t' -v name="$2" 'NF >= 7 && $6 == name { print $7 }' "$jar" | tail -1
}

# header_of <name> prints the value of a header of the last response
header_of() {
    grep -i "^$1:" "$RESP_HEADERS" | tail -1 | cut -d: -f2- | sed -e 's/^ *//' -e 's/\r$//'
}

# set_cookie_of <name> prints the Set-Cookie header of the last response
# for the cookie
set_cookie_of() {
    grep -i "^set-cookie: *$1=" "$RESP_HEADERS" | tail -1 | sed -e 's/\r$//'
}

# browser_get <user> <url> requests the URL with the user's cookies and keeps
# the ones the response sets, without following a redirect
browser_get() {
    local jar
    jar="$(jar_of "$1")"
    mkdir -p "$(dirname "$jar")"
    HTTP_STATUS=$(curl "${curl_tls[@]}" -o "$RESP_BODY" -D "$RESP_HEADERS" \
        -w '%{http_code}' -b "$jar" -c "$jar" "$2") || HTTP_STATUS="000"
}

# browser_login <user> [remember_me] signs the user in as the console does in
# cookie mode: the browser follows authorize and the callback of the local
# provider on the API host, which sets the cookies, and stops at the redirect
# to the console. LOGIN_REDIRECT is that redirect, and CSRF_COOKIE the name
# of the CSRF cookie it names in its csrf parameter.
browser_login() {
    local user="$1" remember="${2:-false}"
    local email="local+$(email_of "$user")"
    rm -f "$(jar_of "$user")"
    info "browser login ${email} (remember_me=${remember})"

    local query
    query=$(jq -rn \
        --arg email "$email" \
        --arg redirect "$CONSOLE_REDIRECT" \
        --arg remember "$remember" \
        '{
            "client_id": "trustyca",
            "idpuser.email": $email,
            "redirect_uri": $redirect,
            "response_type": "cookie",
            "response_mode": "query",
            "scope": "openid email profile",
            "remember_me": $remember
        } | to_entries | map("\(.key)=\(.value | @uri)") | join("&")')

    LOGIN_REDIRECT=""
    browser_get "$user" "${TRUSTYCA_URL}/v1/auth/authorize?${query}"
    if [[ "$HTTP_STATUS" != "303" ]]; then
        fail "authorize for ${email}: HTTP ${HTTP_STATUS}: $(cat "$RESP_BODY")"
        return 1
    fi
    # the local provider answers on the callback of the API host
    local callback
    callback="$(header_of Location)"
    browser_get "$user" "$callback"
    if [[ "$HTTP_STATUS" != "303" ]]; then
        fail "callback for ${email}: HTTP ${HTTP_STATUS}: $(cat "$RESP_BODY")"
        return 1
    fi
    LOGIN_REDIRECT="$(header_of Location)"
    CSRF_COOKIE=$(sed -n 's/.*[?&]csrf=\([^&]*\).*/\1/p' <<<"$LOGIN_REDIRECT")
}

# console_rest <user> <method> <path> [json] calls a REST end-point the way
# the console does: from its origin, with the cookies and the CSRF header.
# NO_CSRF=1 leaves the header out, CSRF=<value> sends another value,
# ORIGIN=<origin> calls from another origin.
console_rest() {
    local user="$1" method="$2" path="$3" data="${4:-}"
    local jar csrf
    jar="$(jar_of "$user")"
    csrf="${CSRF-$(cookie_value "$user" "$CSRF_COOKIE")}"
    local args=(-X "$method" -H "Origin: ${ORIGIN:-$CONSOLE_ORIGIN}" -b "$jar" -c "$jar")
    [[ -z "${NO_CSRF:-}" ]] && args+=(-H "X-CSRF-Token: ${csrf}")
    [[ -n "$data" ]] && args+=(-H "Content-Type: application/json" --data "$data")
    HTTP_STATUS=$(curl "${curl_tls[@]}" -o "$RESP_BODY" -D "$RESP_HEADERS" \
        -w '%{http_code}' "${args[@]}" "${TRUSTYCA_URL}${path}") || HTTP_STATUS="000"
}

# console_grpcweb <user> <path> calls a gRPC method with an empty request
# message over gRPC-Web, the transport of the console, with the cookies and
# the CSRF header (NO_CSRF, CSRF and ORIGIN as for console_rest;
# COOKIES=<header> sends that Cookie header instead of the jar).
# GRPC_STATUS is the gRPC status code of the call.
console_grpcweb() {
    local user="$1" path="$2"
    local jar csrf
    jar="$(jar_of "$user")"
    csrf="${CSRF-$(cookie_value "$user" "$CSRF_COOKIE")}"
    local args=(
        -H "Origin: ${ORIGIN:-$CONSOLE_ORIGIN}"
        -H "Content-Type: application/grpc-web+proto"
        -H "Accept: application/grpc-web+proto"
        -H "X-Grpc-Web: 1"
        -H "X-User-Agent: grpc-web-javascript/0.1"
    )
    if [[ -n "${COOKIES:-}" ]]; then
        args+=(-H "Cookie: ${COOKIES}")
    else
        args+=(-b "$jar" -c "$jar")
    fi
    [[ -z "${NO_CSRF:-}" ]] && args+=(-H "X-CSRF-Token: ${csrf}")
    # one uncompressed frame with an empty message
    HTTP_STATUS=$(printf '\x00\x00\x00\x00\x00' | curl "${curl_tls[@]}" \
        -o "$RESP_BODY" -D "$RESP_HEADERS" -w '%{http_code}' \
        "${args[@]}" --data-binary @- "${TRUSTYCA_URL}${path}") || HTTP_STATUS="000"
    # the status is in the trailer frame of the body, or in the headers of a
    # response without a message
    GRPC_STATUS=$(cat "$RESP_HEADERS" "$RESP_BODY" | LC_ALL=C grep -aioE 'grpc-status: *[0-9]+' |
        head -1 | grep -oE '[0-9]+$')
}

# body_has <text> succeeds when the last response body has the text, binary
# protobuf included
body_has() {
    LC_ALL=C grep -aqF "$1" "$RESP_BODY"
}
