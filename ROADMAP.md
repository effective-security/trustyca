# Roadmap

Active planned work. Order is suggested, not a delivery commitment. Current runtime navigation
is in [Documentation/codemap.md](Documentation/codemap.md); defects are in
the local, gitignored `FINDINGS.md`, whose IDs are not cited here.

## Implemented baseline

[PLAN.md](Documentation/PLAN.md) phase 1: login, orgs, projects, memberships,
invites, API keys and the authorization layer; phase 2 and 2a: the CA
tables, the CA core library (`internal/ca`: tenant-scoped issuer registry,
keys, platform bootstrap) and the issuer, profile, root and signing methods
of the CA service; phase 3: the certificate, revocation and current CRL
methods of the CA service, the `trustyca-ra` and `trustyca-aia` roles of
the backend listener and the CA client; phase 4: CRL publishing
(`internal/ca.CrlPublisher`, `PublishCrls`, the `crl_renewal` task) and the
`cert_status` task (expiry and retention); phase 5: the CIS service
(`server/service/cis`: the JSON and gRPC API for authenticated callers);
phase 6: the operator tooling (`trustycactl ca ...` and `ca org bootstrap`,
the `privpb.Admin` support lists across orgs, the CIS commands of
`trustyca`); phase 7: the hardening; phase 8: the AIA service
(`server/service/aia`: the public AIA, CRL and OCSP routes and the OCSP
response cache on a plain HTTP listener).

## Active work

| ID     | Status      | Work                               | Ownership / contract                                                                                                                                                         |
| ------ | ----------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RM-001 | Open        | Public precondition error contract | server/service/orgs answers HTTP 409 `conflict` / gRPC FailedPrecondition (preconditionFailed); map FailedPrecondition to 409 in porto so Go gRPC clients agree (they see 400 `bad_request`; only the CA service of the wfe restores 409 for what a remote backend returns, `ca.forwardedError`), then pin it |
| RM-002 | Open        | Issuer renewal under one label     | `UNIQUE NULLS NOT DISTINCT (org_id, project_id, label)` on `issuer` holds in every status, so a renewed issuer cannot take the label of the archived one and `internal/ca.Bootstrap` refuses a rotated key; replace it with a unique index on Active (and Pending) issuers, or rename archived issuers, with a migration and a bootstrap that archives in place (DESIGN.md §5.4) |
| RM-003 | Open        | OCSP issuer lookup by IKID         | `pb.OCSPRequest` carries the DER request only; the CA finds an issuer that is not in memory by a SHA-1 key hash through the `skid` index, so a SHA-256 CertID, an imported issuer whose SKID is not the SHA-1 of its key, and a lookup by name hash miss a cold issuer. Add an optional `IKID` that the AIA routes `/v1/ocspi/{ikid}` pass on, so every hash algorithm resolves without a scan (DESIGN.md §8) |
| RM-005 | Open        | Deny by default on the wfe listener | The index page of the UI is served at `/`, so `/` stays under `authz.allow_any` of the wfe and every path without a rule is open to every identity at the authz layer; the services rely on the access check of each method. Serve the UI pages under a listed prefix, or add an exact-match rule to porto's authz, then remove `/` from `allow_any` as the backend listener does |
| RM-006 | In progress | Signing plane split (PLAN.md phase 9) | `pb.CA` on the `wfe` for the tenants (the org of the token, no `OrgID` in the requests) forwards every call to `privpb.Backend` on the backend listener, the API of the service identities with an explicit `OrgID`, with named service clients per pod role (DESIGN.md §2.1, §2.2). Open: a two-app integration test through the wfe with a tenant token. The console calls every service over gRPC-Web (trustyca-ui DESIGN.md section 2.1), so the JSON route of `pb.CA` on the wfe is not needed for the Web UI and stays optional |
| RM-007 | Open        | Profile invalidation across instances | The issuer registry of a backend instance learns of a profile changed elsewhere after `ca.issuer_cache_ttl`; broadcast the invalidation to every backend instance (Redis pub/sub or PostgreSQL NOTIFY) (DESIGN.md §2.1, §5.1) |
| RM-008 | Open        | Least privilege of the signing plane | A data protection key for issuer keys that the web pods do not hold (today one provider wraps the token signing key and the software issuer keys), DB roles per pod role, name constraints on tenant issuing CAs, and a method allowlist per `trustyca-*` role in `authctx` instead of the prefix that trusts every service role for every reachable method (DESIGN.md §2.1) |
| RM-009 | Open        | Cursor-only pagination | Every `List` request carries `Limit`, `Offset` and `Cursor`, and `NextPage` answers with the offset or the cursor, so each list has two SQL variants and two code paths, a client must know which one to continue with, and `Offset` is documented as capped at 10000 while a keyset page costs the same at any depth and neither skips nor repeats a row when rows are inserted meanwhile (`internal/db/pgsql/query/cursor.go`: an id, `(created_at, id)` or `(name, id)` key, the `xdb.Cursor` token). Switch the contract to the cursor alone: drop `Offset` from the requests and from `NextPage` (reserve the fields), make an empty `Cursor` the first page (keep accepting `initial`), give `ListAPIKeysRequest` `Limit` and `Cursor` (the service lists one page of 500 keys and the response reports a next page the request cannot ask for); then drop `Offset` from the query requests, `setPage`, `listRows`, the `--offset` flags and the offset line of `printNextPage`, and move the Web UI and the Go clients to the token. A cursor is a transient token, but the removal is a breaking change of the JSON and gRPC list contracts: ship it with a version note |

## Completion policy

Move completed features into their owning docs and update the codemap in
the same change. Contract changes include proto/SQL generation and
compatibility notes; shared-state changes require race and multi-process
checks. Never infer completion from a historical milestone's recorded test
or benchmark result.

## Security

- DPoP replay protection is missing. porto's server-side DPoP check passes
  an empty config: no replay cache, no proof-to-token hash (`ath`), no
  trusted URL; this is an upstream porto item. It applies to the `backend`
  listener as well, where the operators authenticate with DPoP. The trustyca login endpoint has
  no replay cache either: the only one xpki ships is in-memory and rejects
  every proof once full, and login needs no authentication, so anyone could
  fill it and block DPoP logins. A Redis-backed cache is the right shape.
- gRPC DPoP proofs are checked against the incoming `:authority`; forwarded
  host headers are not used. Before prod, run one `--dpop-key` login plus a
  gRPC command against dev (wfe.dev.trustyca.io) to confirm the ingress passes
  `:authority` through unchanged.

- No server-side bound on a request (porto). The gRPC and gRPC-Web calls of
  a listener run as long as the client's `grpc-timeout` allows, and without
  one until the client goes away: porto's `timeout.request` is the drain
  timeout of a stopping listener (its config comment calls it the timeout
  for client requests to finish), and the listener `timeouts` are read
  deadlines only. The console sends 60 s on the key operations, so nothing
  blocks it (trustyca-ui BE-7), but an API client can hold a signing or key
  generation handler indefinitely. Upstream porto item: a configurable
  maximum deadline per listener (applied when the client sends none or a
  longer one) and a config name or comment that says what `timeout.request`
  is; then set the maximum on the `wfe` and `backend` listeners above the
  longest key operation.

## Lint

- Tighten the golangci-lint configuration.
- Report uses of deprecated APIs (staticcheck SA1019) in lint and CI.
