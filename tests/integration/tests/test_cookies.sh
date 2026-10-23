# The cookie session of the console (the Web UI in cookie mode): CORS from
# the console origin, the login with response_type=cookie, the auth cookie
# with the CSRF double submit over gRPC-Web and REST, the org switch that
# replaces the cookies, and the sign-out.
#
# The browser is a curl cookie jar talking to api.local.trustyca.io, a host
# under the cookie domain of the dev configuration (.local.trustyca.io); the
# console is CONSOLE_ORIGIN, an origin of its CORS configuration. See the
# browser helpers of lib.sh.

WEB_USER=webuser
# lower-case and sorted, as a browser sends them (the Fetch standard): the
# CORS handler accepts no other list
PREFLIGHT_HEADERS="content-type,grpc-timeout,x-csrf-token,x-grpc-web,x-user-agent"
FOREIGN_ORIGIN="https://evil.example.com"

# preflight <origin> sends the CORS preflight of a gRPC-Web call
preflight() {
    HTTP_STATUS=$(curl "${curl_tls[@]}" -o "$RESP_BODY" -D "$RESP_HEADERS" -w '%{http_code}' \
        -X OPTIONS \
        -H "Origin: $1" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: ${PREFLIGHT_HEADERS}" \
        "${TRUSTYCA_URL}/pb.Orgs/GetUserOrgs") || HTTP_STATUS="000"
}

info "CORS: the console may send a gRPC-Web call with credentials"
preflight "$CONSOLE_ORIGIN"
assert_eq "204" "$HTTP_STATUS" "preflight status"
assert_eq "$CONSOLE_ORIGIN" "$(header_of Access-Control-Allow-Origin)" "preflight allowed origin"
assert_eq "true" "$(header_of Access-Control-Allow-Credentials)" "preflight credentials"
allowed=$(header_of Access-Control-Allow-Headers | tr '[:upper:]' '[:lower:]')
for h in ${PREFLIGHT_HEADERS//,/ }; do
    assert_contains "$allowed" "$h" "preflight allowed headers"
done

info "CORS: another origin is not allowed"
preflight "$FOREIGN_ORIGIN"
assert_empty "$(header_of Access-Control-Allow-Origin)" "preflight allowed origin for ${FOREIGN_ORIGIN}"
assert_empty "$(header_of Access-Control-Allow-Credentials)" "preflight credentials for ${FOREIGN_ORIGIN}"

info "login: the callback sets the cookies on the cookie domain and lands on the console"
browser_login "$WEB_USER" true
assert_contains "$LOGIN_REDIRECT" "${CONSOLE_REDIRECT}?" "landing page"
assert_contains "$LOGIN_REDIRECT" "cookie_set=true" "landing page"
assert_contains "$LOGIN_REDIRECT" "expires_in=" "landing page"
assert_not_empty "$CSRF_COOKIE" "CSRF cookie name in the landing page"
# the console never sees the token: it is in the HttpOnly cookie only
assert_not_contains "$LOGIN_REDIRECT" "token=" "landing page"
assert_not_contains "$LOGIN_REDIRECT" "code=" "landing page"

# the auth cookie is the HttpOnly one of the jar
AUTH_COOKIE=$(awk -F'\t' '$1 ~ /^#HttpOnly_/ { print $6 }' "$(jar_of "$WEB_USER")" | head -1)
assert_not_empty "$AUTH_COOKIE" "auth cookie in the jar"
assert_not_empty "$(cookie_value "$WEB_USER" "$AUTH_COOKIE")" "auth cookie value"
assert_ne "$CSRF_COOKIE" "$AUTH_COOKIE" "CSRF and auth cookies"
CSRF_VALUE=$(cookie_value "$WEB_USER" "$CSRF_COOKIE")
assert_not_empty "$CSRF_VALUE" "CSRF cookie value"

auth_set=$(set_cookie_of "$AUTH_COOKIE")
for attr in HttpOnly Secure SameSite=None Domain=local.trustyca.io Path=/ Max-Age=; do
    assert_contains "$auth_set" "$attr" "auth Set-Cookie"
done
csrf_set=$(set_cookie_of "$CSRF_COOKIE")
for attr in Secure SameSite=None Domain=local.trustyca.io Path=/ Max-Age=; do
    assert_contains "$csrf_set" "$attr" "CSRF Set-Cookie"
done
# a script of the console reads it
assert_not_contains "$csrf_set" "HttpOnly" "CSRF Set-Cookie"

info "gRPC-Web: the cookie and the CSRF header authenticate the console"
console_grpcweb "$WEB_USER" /pb.Auth/GetUserToken
assert_eq "200" "$HTTP_STATUS" "GetUserToken HTTP status"
assert_eq "0" "$GRPC_STATUS" "GetUserToken gRPC status"
assert_eq "$CONSOLE_ORIGIN" "$(header_of Access-Control-Allow-Origin)" "gRPC-Web allowed origin"
assert_eq "true" "$(header_of Access-Control-Allow-Credentials)" "gRPC-Web credentials"
assert_contains "$(header_of Access-Control-Expose-Headers | tr '[:upper:]' '[:lower:]')" "grpc-status" \
    "gRPC-Web exposed headers"
if body_has "$(email_of "$WEB_USER")"; then
    log "ok: the user token names $(email_of "$WEB_USER")"
else
    fail "GetUserToken does not name $(email_of "$WEB_USER")"
fi
# a JWT starts with the base64 of '{"'
if body_has "eyJ"; then
    fail "GetUserToken of a cookie session returned the token"
else
    log "ok: the response of a cookie session has no token"
fi

info "gRPC-Web: a tenant call with the cookie and the CSRF header"
console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "0" "$GRPC_STATUS" "GetOrg gRPC status"
body_has "Default" && log "ok: the default org of the login" || fail "GetOrg does not return the default org"

info "gRPC-Web: without the CSRF header the cookie is ignored and the caller is a guest"
NO_CSRF=1 console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "16" "$GRPC_STATUS" "GetOrg without the CSRF header: Unauthenticated"
CSRF=not-the-cookie console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "16" "$GRPC_STATUS" "GetOrg with another CSRF value: Unauthenticated"

info "gRPC-Web: another origin is refused before the call"
ORIGIN="$FOREIGN_ORIGIN" console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "403" "$HTTP_STATUS" "gRPC-Web from ${FOREIGN_ORIGIN}"
assert_empty "$(header_of Access-Control-Allow-Origin)" "gRPC-Web allowed origin for ${FOREIGN_ORIGIN}"

info "REST: a GET needs the cookie only"
NO_CSRF=1 console_rest "$WEB_USER" GET /v1/auth/usertoken
assert_eq "200" "$HTTP_STATUS" "usertoken status"
assert_eq "$(email_of "$WEB_USER")" "$(jq -r '.UserInfo.Email' "$RESP_BODY")" "usertoken email"
assert_empty "$(jq -r '.Token.AccessToken // empty' "$RESP_BODY")" "usertoken token of a cookie session"
assert_eq "Owner" "$(jq -r '.UserInfo.OrgRole' "$RESP_BODY")" "usertoken org role"
WEB_FIRST_ORG=$(jq -r '.UserInfo.OrgID' "$RESP_BODY")
assert_not_empty "$WEB_FIRST_ORG" "org of the login"

info "REST: a POST needs the CSRF header"
NO_CSRF=1 console_rest "$WEB_USER" POST /pb.Orgs/GetUserOrgs '{}'
assert_eq "401" "$HTTP_STATUS" "GetUserOrgs without the CSRF header"
console_rest "$WEB_USER" POST /pb.Orgs/GetUserOrgs '{}'
assert_eq "200" "$HTTP_STATUS" "GetUserOrgs status"
assert_eq "$CONSOLE_ORIGIN" "$(header_of Access-Control-Allow-Origin)" "REST allowed origin"
assert_eq "true" "$(header_of Access-Control-Allow-Credentials)" "REST credentials"
assert_eq "$WEB_FIRST_ORG" "$(jq -r '.Orgs[].OrgID' "$RESP_BODY")" "the orgs of the user"

info "org switch: the console creates a second org"
console_rest "$WEB_USER" POST /pb.Orgs/RegisterOrg '{"Name":"Web Second"}'
assert_eq "200" "$HTTP_STATUS" "RegisterOrg status"
WEB_SECOND_ORG=$(jq -r '.ID' "$RESP_BODY")
assert_not_empty "$WEB_SECOND_ORG" "second org"

info "org switch: Auth.SelectOrg cannot set a cookie, so it returns no token and keeps the cookies"
console_rest "$WEB_USER" POST /pb.Auth/SelectOrg "{\"OrgID\":\"${WEB_SECOND_ORG}\"}"
assert_eq "200" "$HTTP_STATUS" "SelectOrg status"
assert_eq "$WEB_SECOND_ORG" "$(jq -r '.UserInfo.OrgID' "$RESP_BODY")" "SelectOrg org"
assert_empty "$(jq -r '.Token.AccessToken // empty' "$RESP_BODY")" "SelectOrg token of a cookie session"
assert_empty "$(set_cookie_of "$AUTH_COOKIE")" "SelectOrg Set-Cookie"
NO_CSRF=1 console_rest "$WEB_USER" GET /v1/auth/usertoken
assert_eq "$WEB_FIRST_ORG" "$(jq -r '.UserInfo.OrgID' "$RESP_BODY")" "org of the session after SelectOrg"

info "org switch: POST /v1/auth/org replaces the cookies"
old_auth=$(cookie_value "$WEB_USER" "$AUTH_COOKIE")
old_csrf=$(cookie_value "$WEB_USER" "$CSRF_COOKIE")
console_rest "$WEB_USER" POST /v1/auth/org "{\"OrgID\":\"${WEB_SECOND_ORG}\",\"RememberMe\":true}"
assert_eq "200" "$HTTP_STATUS" "auth org status"
assert_eq "$CONSOLE_ORIGIN" "$(header_of Access-Control-Allow-Origin)" "auth org allowed origin"
assert_eq "true" "$(header_of Access-Control-Allow-Credentials)" "auth org credentials"
assert_eq "$WEB_SECOND_ORG" "$(jq -r '.UserInfo.OrgID' "$RESP_BODY")" "auth org org"
assert_eq "Owner" "$(jq -r '.UserInfo.OrgRole' "$RESP_BODY")" "auth org role"
assert_empty "$(jq -r '.Token.AccessToken // empty' "$RESP_BODY")" "auth org token of a cookie session"
for attr in HttpOnly Secure SameSite=None Domain=local.trustyca.io Max-Age=; do
    assert_contains "$(set_cookie_of "$AUTH_COOKIE")" "$attr" "auth org auth Set-Cookie"
done
assert_contains "$(set_cookie_of "$CSRF_COOKIE")" "Domain=local.trustyca.io" "auth org CSRF Set-Cookie"
assert_ne "$old_auth" "$(cookie_value "$WEB_USER" "$AUTH_COOKIE")" "auth cookie after the org switch"
assert_ne "$old_csrf" "$(cookie_value "$WEB_USER" "$CSRF_COOKIE")" "CSRF cookie after the org switch"

NO_CSRF=1 console_rest "$WEB_USER" GET /v1/auth/usertoken
assert_eq "$WEB_SECOND_ORG" "$(jq -r '.UserInfo.OrgID' "$RESP_BODY")" "org of the session after the switch"
console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "0" "$GRPC_STATUS" "GetOrg after the switch"
body_has "Web Second" && log "ok: GetOrg returns the second org" || fail "GetOrg does not return the second org"

info "org switch: the CSRF value of the previous cookie no longer matches"
CSRF="$old_csrf" console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "16" "$GRPC_STATUS" "GetOrg with the previous CSRF value: Unauthenticated"

info "sign-out: a GET never revokes"
console_rest "$WEB_USER" GET /pb.Auth/RevokeToken
assert_eq "405" "$HTTP_STATUS" "GET RevokeToken"
NO_CSRF=1 console_rest "$WEB_USER" GET /v1/auth/usertoken
assert_eq "$(email_of "$WEB_USER")" "$(jq -r '.UserInfo.Email' "$RESP_BODY")" "session after GET RevokeToken"

info "sign-out: DELETE /pb.Auth/RevokeToken revokes the token and removes the cookies"
signed_out_auth=$(cookie_value "$WEB_USER" "$AUTH_COOKIE")
signed_out_csrf=$(cookie_value "$WEB_USER" "$CSRF_COOKIE")
console_rest "$WEB_USER" DELETE /pb.Auth/RevokeToken
assert_eq "204" "$HTTP_STATUS" "RevokeToken status"
assert_contains "$(set_cookie_of "$AUTH_COOKIE")" "Max-Age=0" "RevokeToken auth Set-Cookie"
assert_contains "$(set_cookie_of "$CSRF_COOKIE")" "Max-Age=0" "RevokeToken CSRF Set-Cookie"
assert_empty "$(cookie_value "$WEB_USER" "$AUTH_COOKIE")" "auth cookie after the sign-out"

info "sign-out: a copy of the revoked cookie is a guest"
COOKIES="${AUTH_COOKIE}=${signed_out_auth}; ${CSRF_COOKIE}=${signed_out_csrf}" CSRF="$signed_out_csrf" \
    console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "16" "$GRPC_STATUS" "GetOrg with the revoked cookie: Unauthenticated"

info "login without remember_me: the cookies end with the browser session"
browser_login "$WEB_USER" false
auth_set=$(set_cookie_of "$AUTH_COOKIE")
assert_not_empty "$auth_set" "auth Set-Cookie"
assert_not_contains "$auth_set" "Max-Age=" "auth Set-Cookie of a browser session"
assert_not_contains "$auth_set" "Expires=" "auth Set-Cookie of a browser session"
console_grpcweb "$WEB_USER" /pb.Orgs/GetOrg
assert_eq "0" "$GRPC_STATUS" "GetOrg of the new session"

info "removecookie clears the cookies"
console_rest "$WEB_USER" DELETE /v1/auth/removecookie
assert_eq "204" "$HTTP_STATUS" "removecookie status"
assert_empty "$(cookie_value "$WEB_USER" "$AUTH_COOKIE")" "auth cookie after removecookie"
