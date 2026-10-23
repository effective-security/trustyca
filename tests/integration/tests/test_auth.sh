# Users sign in with the CLI through the local identity provider: the bearer
# session. `auth login local+<user>@trustyca.io` runs the full OAuth code
# flow against the server; tests/browser/xdg-open stands in for the browser.
# Each user keeps its own token storage, so later tests can act as any of
# them.

TEST_USERS=(user1 user2)

for user in "${TEST_USERS[@]}"; do
    login "$user" || continue

    caller=$(trustyca_as "$user" --o json caller 2>&1) || {
        fail "caller for ${user} failed: ${caller}"
        continue
    }
    email=$(jq -r '.Claims[] | select(.Key=="email") | .Value' <<<"$caller")
    assert_eq "$(email_of "$user")" "$email" "${user} token email"
    assert_not_empty "$(jq -r '.Subject' <<<"$caller")" "${user} subject"
done

info "the first login creates the default org, owned by the user"
org=$(trustyca_as user1 --o json org get 2>&1) || fail "org get failed: ${org}"
assert_eq "Default" "$(jq -r '.Name' <<<"$org")" "user1 org name"
USER1_ORG=$(jq -r '.ID' <<<"$org")
assert_not_empty "$USER1_ORG" "user1 org"

info "the user token carries the identity the server recorded"
token=$(trustyca_as user2 --o json auth usertoken 2>&1) || fail "auth usertoken failed: ${token}"
assert_not_empty "$(jq -r '.Token.AccessToken // empty' <<<"$token")" "user2 access token"
assert_eq "$(email_of user2)" "$(jq -r '.UserInfo.Email' <<<"$token")" "user2 user info email"
assert_eq "Owner" "$(jq -r '.UserInfo.OrgRole' <<<"$token")" "user2 org role"

info "signing in twice keeps the same user and org"
before=$(trustyca_as user1 --o json caller | jq -r '.Subject')
login user1
after=$(trustyca_as user1 --o json caller | jq -r '.Subject')
assert_eq "$before" "$after" "user1 subject across logins"
assert_eq "$USER1_ORG" "$(org_of user1)" "user1 org across logins"

info "a bearer session switches the org with the token in the response"
second=$(trustyca_as user1 --o json org create "Second" 2>&1) || fail "org create failed: ${second}"
USER1_SECOND_ORG=$(jq -r '.ID' <<<"$second")
switched=$(trustyca_as user1 --o json auth org "$USER1_SECOND_ORG" 2>&1) || fail "auth org failed: ${switched}"
assert_not_empty "$(jq -r '.Token.AccessToken // empty' <<<"$switched")" "token of the org switch"
assert_eq "$USER1_SECOND_ORG" "$(org_of user1)" "user1 org after the switch"
trustyca_as user1 auth org "$USER1_ORG" >/dev/null || fail "user1 switching back failed"
assert_eq "$USER1_ORG" "$(org_of user1)" "user1 org after switching back"

info "an org without a grant is refused"
assert_fails_with "user2 selects user1's org" "no access to the requested organization" \
    trustyca_as user2 auth org "$USER1_ORG"

info "sign-out revokes the token"
out=$(trustyca_as user2 auth revoke 2>&1) || fail "auth revoke failed: ${out}"
assert_contains "$out" "token revoked" "auth revoke output"
# porto reports a token it refuses as an invalid identity
assert_fails_with "a revoked token" "unauthorized: invalid identity" trustyca_as user2 org get
# later tests act as user2 again
login user2

info "a caller without a token is refused"
# the CLI does not call without a token
assert_fails_with "org get without a login" "unable to load auth token" trustyca_anon org get
# and the server refuses a guest
out=$(curl "${curl_tls[@]}" -X POST -H 'Content-Type: application/json' -d '{}' \
    -w '\n%{http_code}' "${TRUSTYCA_URL}/pb.Orgs/GetOrg")
assert_eq "401" "$(tail -1 <<<"$out")" "GetOrg of a guest: status"
assert_contains "$out" "guest role not allowed" "GetOrg of a guest"
