# Trusty CA Implementation Plan

Execution plan for [DESIGN.md](design/DESIGN.md). Phases are ordered by dependency;
each phase ends with a green `make build test lint`. A finished phase keeps a
one-line summary here: its steps, decisions and tests are in the git history
of this file (`git log -p -- Documentation/PLAN.md`) and in the
[codemap](codemap.md).

## Completed phases

| Phase | Delivered |
| ----- | --------- |
| 0     | Design artifacts: DESIGN.md, this plan, the tables of `sql/trustycadb/migrations/1_tables.up.sql` with nullable `(org_id, project_id)` tenancy, the protos with `(es.api.allowed_roles)` and `(es.api.scopes)` |
| 1     | Orgs, projects, memberships, invites, API keys and the authorization layer (`internal/authctx`: roles, grants, scopes, the Authorizer, CheckAccess), DESIGN.md section 3 |
| 2     | The CA tables in `internal/db` and the CA core library (`internal/ca`: keys, issuer creation, the platform bootstrap) |
| 2a    | Multi-tenant issuer resolution: the issuer registry keyed by row ID with scoped label resolution and its caches (DESIGN.md section 5.1), with the warm and cold resolution benchmark |
| 3     | The CA gRPC service: issuers, profiles, roots, signing, certificates, revocation and the current CRL, the `trustyca-ra` and `trustyca-aia` identities |
| 4     | The revocation pipeline: CRL publishing (`internal/ca.CrlPublisher`, `PublishCrls`, the `crl_renewal` task) and the `cert_status` task (expiry and retention) |
| 5     | The CIS service (`server/service/cis`): the read-only JSON and gRPC API of authenticated callers |
| 6     | Operator tooling: the `ca` commands of `trustycactl`, `ca org bootstrap`, the `privpb.Admin` support lists, the CIS commands of `trustyca` |
| 7     | Hardening: the metrics of DESIGN.md section 11, deny by default on the backend listener, the load test of the CA tables (`tests/load`, Documentation/perf/load-certificates.md) |
| 8     | The AIA listener (`server/service/aia`): the issuer certificate, CRL and OCSP routes of the issued certificates over plain HTTP, the OCSP response cache |
| 9     | The signing plane (steps 1 to 3, 5 and 6): named service clients, `privpb.Backend` on the backend listener with every CA method and an explicit `OrgID`, `pb.CA` on the wfe as a proxy that takes the org of the token (DESIGN.md sections 2.1 and 2.2); step 4 is open below |
| 10    | Web UI sessions: the cookie session of the console, the `local` identity provider, token revocation and the container integration tests (section below) |

## Phase 10: Web UI sessions (done)

The console (`trustyca-ui`) calls the `wfe` over gRPC-Web in bearer mode or
in cookie mode (its DESIGN.md section 4.2). The cookie mode, its CORS, the
`local` provider of the tests and the integration suite were compared with
cynos, whose console runs the same porto stack, and brought in line.

1. Cookie session: `POST /v1/auth/org` (`AuthOrgHandler`, the BE-2 item of
   the console plan) runs the org switch of `Auth.SelectOrg` and writes the
   new token into the auth cookie with a new CSRF cookie; `SelectOrg` (gRPC)
   keeps returning no token to a cookie session. `GET /pb.Auth/RevokeToken`
   went: a GET passes porto without the CSRF check, so any page could sign
   a cookie session out; the sign-out is `DELETE /pb.Auth/RevokeToken`,
   which removes the cookies first.
2. Token revocation: the JWT parser of the container has porto's
   revocation over the cache (Redis), as cynos does. Before it every
   `RevokeToken` answered Unimplemented, so a signed-out token stayed valid
   until it expired. A guest is refused (`no token to revoke`).
3. The `local` identity provider: offered only by `service.environment:
   local` in `service.cluster: local` (`config.Service.IsLocal`, the dev
   configuration; every other environment fails closed). `local+<user>@<domain>`
   signs in as `<user>@<domain>` without an invitation, and the authorize
   end-point sends the browser to the callback of its own host, so the
   cookies are set for the host the console logs in on.
4. Configuration: the wfe CORS admits the console in cookie mode
   (`https://app.local.trustyca.io:4200`, under the cookie domain
   `.local.trustyca.io`); the server certificate of `make gen_test_certs`
   names `api.local.trustyca.io` (`TEST_CERTS_SAN`); the `"*"` exposed
   header went (a credentialed response never honors it).
5. The `trustyca` CLI sends the stored token over gRPC to every server, not
   only to the hosts of its config file, as its HTTP client does.
6. `tests/integration` and `make docker-citest`, also in CI: the service
   image in a compose stack with its own PKI, PostgreSQL, Redis and the KMS
   emulator; the CLI signs users in through the `local` provider
   (`test_auth.sh`), and curl plays the browser and the console in cookie
   mode (`test_cookies.sh`: CORS, the cookies, the CSRF double submit over
   gRPC-Web and REST, the org switch, the sign-out). The binaries link the
   PKCS#11 provider with cgo, so `make docker-build` compiles them in the
   golang image of the Debian release the images run on.

## Open work

1. Two apps in one stack (phase 9 step 4): a web pod (wfe and aia
   listeners, the `ca` and `aia` clients pointing at the other) and a
   signing pod (backend), where a tenant token signs, revokes and publishes
   through the wfe and the AIA answers OCSP through its client. The stack of
   `tests/integration` can run the service image twice with
   `--backend-listen-url none` and `--wfe-listen-url none`; the CA flows of
   the console (onboarding with `trustycactl ca org bootstrap`, signing and
   revoking through `pb.CA` with a cookie session) belong in it.
2. A failed login after the callback has decoded the state answers JSON on
   the API host; answer it on the client's redirect URI with
   `error`/`error_description`, which the console and the CLI listener
   expect.
3. Profile invalidation broadcast to every backend instance (Redis pub/sub
   or PostgreSQL NOTIFY); until then a profile change reaches a remote
   backend after `ca.issuer_cache_ttl` (ROADMAP RM-007). A token revocation
   reaches the other instances within porto's snapshot of the revoked IDs
   (5 minutes) for the same reason.
4. Least privilege of the signing plane: a data protection key for issuer
   keys that the web pods do not hold, DB roles per pod role, name
   constraints on tenant issuing CAs, a method allowlist per service role
   in `authctx` (ROADMAP RM-008).
5. `ca` registers no JSON route on the wfe (`httppb.GetCAHTTPHandler` with
   the access check), as `cis` does; the console speaks gRPC-Web and does
   not need it.

## Verification checklist per phase

- `make proto` (when protos change), `go generate ./...`, `make build`,
  `make test`, `make lint`, `make docker-citest` (when the server, the CLI
  or the configuration of the wfe change).
- Schema changes: `make drop-sql start-sql gen-sql-schema docs` and commit the
  regenerated `internal/db/model`, `internal/db/schema`, `internal/db/README.md`
  and `Documentation/api/internal_db_*.md`.

## NOTES

- do not create new SQL migrations until explicitly asked, the service is in development and not deployed.
  We continue using `sql/trustycadb/migrations/1_tables.up.sql` and if needed can drop and re-create the schema on migration changes.
