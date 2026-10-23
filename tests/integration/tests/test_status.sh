# Status endpoints and the unauthenticated surface of the listeners.
# Sourced by run.sh; helpers come from lib.sh.

curl_pub=(curl --silent --show-error --fail --max-time 10 --cacert "$TRUSTYCA_TRUSTED_CA")

info "status endpoints of the wfe are served over TLS the dev root CA signs"
for path in /v1/status/server /v1/status/version /v1/status/node; do
    if "${curl_pub[@]}" -o /dev/null "${TRUSTYCA_URL}${path}"; then
        log "ok: GET ${path}"
    else
        fail "GET ${path} failed"
    fi
done

info "version reports the build the image was made from"
version=$("${curl_pub[@]}" -H 'Accept: application/json' "${TRUSTYCA_URL}/v1/status/version" | jq -r '.Build // empty')
assert_not_empty "$version" "server version"

info "the backend listener answers a probe without a client certificate"
if "${curl_pub[@]}" -o /dev/null "${TRUSTYCA_BACKEND_URL}/v1/status/server"; then
    log "ok: backend /v1/status/server"
else
    fail "backend /v1/status/server failed"
fi

info "the aia listener serves plain HTTP"
if curl --silent --show-error --fail --max-time 10 -o /dev/null "${TRUSTYCA_AIA_URL}/v1/status/server"; then
    log "ok: aia /v1/status/server"
else
    fail "aia /v1/status/server failed"
fi

info "an unauthenticated caller is a guest"
caller=$("${curl_pub[@]}" "${TRUSTYCA_URL}/v1/auth/caller")
assert_eq "guest" "$(jq -r '.Role' <<<"$caller")" "unauthenticated caller role"

info "the local identity provider is offered for a local+ address"
providers=$("${curl_pub[@]}" -H 'Content-Type: application/json' \
    -d "{\"Email\":\"local+$(email_of user1)\"}" "${TRUSTYCA_URL}/v1/auth/providers")
assert_eq '["local"]' "$(jq -c '.ProviderNames' <<<"$providers")" "providers for local+user1"
assert_eq "https://api.local.trustyca.io:8880/v1/auth/authorize" "$(jq -r '.AuthURL' <<<"$providers")" "auth URL"

info "the CLI reaches the server too"
out=$(trustyca_anon version 2>&1) || fail "trustyca version failed: ${out}"
assert_contains "$out" "$version" "trustyca version output"
