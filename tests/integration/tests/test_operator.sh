# The operator drives the CA with trustycactl on the backend listener. Its
# identity is a DPoP token of the wfe whose email the backend lists under
# trustyca-admin (operator@trustyca.io, trustyca-config.citest.yaml): no
# client certificate is the operator, and neither is a bearer token or the
# DPoP token of another user. Every request names its org, whichever org
# the login selected. Uses USER1_ORG and the bearer login of user1 from
# test_auth.sh.

dpop_login operator || return 1

info "the operator reads the platform"
roots=$(trustycactl_as operator --o json ca root list 2>&1) || fail "ca root list failed: ${roots}"
assert_not_empty "$(jq -r '.Roots[0].ID // empty' <<<"$roots")" "a platform anchor"
issuers=$(trustycactl_as operator --o json ca issuer list --platform 2>&1) ||
    fail "ca issuer list --platform failed: ${issuers}"
assert_not_empty "$(jq -r '.Issuers[0].ID // empty' <<<"$issuers")" "a platform issuer"

info "the operator names the org, not the org of its login"
assert_ne "$USER1_ORG" "$(trustyca_as operator --o json org get | jq -r '.ID')" "the org of the operator's login"
roots=$(trustycactl_as operator --o json ca root list --org "$USER1_ORG" 2>&1) ||
    fail "ca root list --org failed: ${roots}"
assert_eq "0" "$(jq -r '.Roots // [] | length' <<<"$roots")" "anchors of user1's org"

info "no other identity is the operator"
dpop_login user3 || return 1
# the backend maps another DPoP token to the default role, a bearer token to
# no identity, and the client certificate to its service role
assert_fails_with "the DPoP token of a user" "user role not allowed" \
    trustycactl_as user3 ca root list
assert_fails_with "a bearer token" "guest role not allowed" \
    trustycactl_as user1 ca root list
assert_fails_with "a client certificate" "trustyca-client role not allowed" \
    env TRUSTYCA_STORAGE="${TRUSTYCA_USERS_DIR}/user1" TRUSTYCA_AUTH_TOKEN="" \
    trustycactl -s "$TRUSTYCA_BACKEND_URL" -r "$TRUSTYCA_TRUSTED_CA" \
    -c "${TRUSTYCA_TRUSTED_CA%/*}/trustyca_client.pem" -k "${TRUSTYCA_TRUSTED_CA%/*}/trustyca_client.key" \
    --timeout "$TRUSTYCA_CLI_TIMEOUT" ca root list
