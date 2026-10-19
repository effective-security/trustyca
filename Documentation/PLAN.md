# Trusty CA Implementation Plan

Execution plan for [DESIGN.md](design/DESIGN.md). Phases are ordered by dependency;
each phase ends with a green `make build test lint`.

## Phase 0: design artifacts (done)

- `Documentation/design/DESIGN.md`, this plan.
- `sql/trustycadb/migrations/1_tables.up.sql` and `1_tables.down.sql`: `project`,
  `issuer`, `root_certificate`, `certificate_profile`, `certificate`, `revoked`,
  `crl`; nullable `(org_id, project_id)` tenancy with `UNIQUE NULLS NOT DISTINCT`
  and composite FKs `(org_id, project_id) -> project (org_id, id)` on
  `membership` and `invite`. Verified with up and down runs on a scratch DB.
- Protos: `pkix.proto`, `ca.proto`, `cis.proto`, `orgs.proto`, `types.proto`,
  `auth.proto`. Tenant requests carry no `OrgID`; methods declare the minimum
  roles with `(es.api.allowed_roles)` and, where `APIKey` is allowed, the
  scopes with `(es.api.scopes)`. Generated with `make proto`, mocks with
  `go generate`.

## Phase 1: org, project, membership and authorization layer (done)

Implements the spec end to end; see DESIGN.md section 3.

- `internal/authctx`: role hierarchy (`CanAssumeRoles`, `CanAssumeRole`),
  `Grants` with additive resolution per scope (`Roles`, `HighestRole`), derived
  org Viewer, grantability rules, scopes (`HasScopes`, `IsKnownScope`),
  `Authorizer` (cached grants and projects, `CheckRole`), `CheckAccess` driven
  by `allowed_roles` and `scopes`, API key path, token context with `org`,
  `org_role`, `org_role_source`, `scope`, `project` claims, `ProjectRequester`,
  `GetAllowedMethods`, `GetCallerScope`. The DB layer has no dependency on
  authorization code.
- DB layer: project CRUD, scope-aware membership and invite queries with
  `IS NULL`/`IS NOT NULL` predicates, `expires_at` on invites,
  `GetUserMemberships`, `GetUserOrgs` deduplicated, `TryCreateEvent` on the
  interface, `apikey` CRUD (`RegisterAPIKey`, `GetAPIKey`, `ListAPIKeys` with
  project, key, scopes and status filters, `UseAPIKey`, `DeleteAPIKey`).
- Auth service: `SelectOrg`, initial org selection at login, default org and
  project creation, `UserInfo` with org fields, `AuthenticateAPIKey`,
  `GetAllowedMethods`, `GetCallerScope`, user lifecycle events (sign-up,
  sign-in, sign-out, accepted invites, API key sign-in).
- `internal/events`: the event builder every service emits audit events
  with (DESIGN.md section 11).
- Orgs service: token-scoped org RPCs, `GetUserOrgs`, `GetUserMemberships`,
  project RPCs with grant-filtered `ListProjects`, member RPCs with
  grantability checks and last-Owner protection, `CreateAPIKey`,
  `ListAPIKeys`, `DeleteAPIKey`, audit events.
- CLI: `auth org|allowed|scope`, `org list|access|get|update|delete`,
  `member ...` for org-wide grants, `project ...`, `project member ...`,
  `api-key create|list|delete`.
- Tests: `internal/authctx` (hierarchy, grants, scopes, authorizer,
  `CheckAccess` for users, API keys, scoped tokens and service roles,
  `GetAllowedMethods`, `GetCallerScope`), query builders, DB integration
  (`Test_ProjectMembership`, `Test_APIKey`, `Test_EventWithoutMetadata`),
  service tests with a fake authorizer including API keys and the exact
  event of each mutation, auth event integration tests, CLI with golden
  output.

Acceptance criteria from the spec covered by tests: 1, 2, 3, 4, 5, 6, 7, 8, 9,
11, 12, 13, 14. Criterion 10 (revocation bound) is the 3 minute cache TTL
plus invalidation after every membership mutation.

Follow-ups in this area:

1. Most recently used org at login; today the first accessible org is selected.
2. `privpb.Admin` support views across orgs (`ListProjects`, `ListMemberships`).
3. Cookie refresh on `SelectOrg` for browser sessions (`RememberMe`).
4. API key rotation and a client helper that signs requests with the key
   (HMAC over method and timestamp) for `AuthenticateAPIKey`.
5. Done in phase 2: `issuer.config` and `certificate_profile.config` map to
   `model.JSON` (`internal/db/model/json.go`) in `typesmap.yaml`, because
   `xdb.Metadata` is `map[string]string` and cannot hold the nested
   `pb.IssuerConfig`/`pb.CertProfile`.
6. Regeneration note: `make drop-sql start-sql gen-sql-schema docs` emits the two
   `*.gen.go` files without imports; run `goimports -w` on them afterwards.

## Phase 2: CA core library (`internal/ca`, done)

1. `internal/db` (done): `CaReadonlyDb` and `CaDb` interfaces and `pgsql`
   implementations in lifecycle order (Register/Upsert, Get, List, Delete) for
   issuers, roots, profiles, certificates, revoked, CRLs. Requests use
   `QueryParams()` structs; lists order by `id DESC` and paginate by offset or
   with a cursor on `id` (`query.Cursor`, `query.ParseCursor`).
   - `RegisterCertificate` with an event, `RevokeCertificate` and
     `PublishCrl` are single transactions; `PublishCrl` only accepts a CRL
     whose IKID is the issuer's SKID and whose number is greater than the
     issuer's (`ErrStaleCrlNumber`), and a revoked certificate fails with
     `ErrAlreadyRevoked`.
   - `ListCertificates` supports `ProjectID`, `IKID`, `SKID`, `Profile`,
     `Status`, `ExpiringBefore`; `ListRevoked` supports `IKID` and `ValidAfter`
     for CRL generation.
   - Migration `2_revoked_view` adds `vw_revoked_certificate` (revocation
     joined with its certificate) for `ListRevokedCertificates`; the
     `model.RevokedCertificate` row is generated from it. Migration
     `3_revoked_index` adds the unique `(ikid, serial_number)` index of
     `revoked` for `GetRevoked` by issuer and serial (OCSP).
   - Tenancy fails closed: a list names `OrgID`, `Platform` (`org_id IS
NULL`) or `AllOrgs` (`ErrOrgScopeRequired` otherwise), and every
     mutation of a row names its exact org, so another org's row is not
     found; `FindIssuer`/`FindProfile` take an exact scope and the label,
     the resolution `(org, project, label) -> (org, 0, label)` belongs to
     `internal/ca`.
   - Tests: query SQL goldens, model conversions, and DB integration tests
     with real certificates from `tests/testutils.NewTestCA`
     (`Test_Issuer`, `Test_Issuer_Activate`, `Test_Root`, `Test_Profile`,
     `Test_Certificate`, `Test_Crl`).
2. `internal/ca/keys.go` (done): `Keys` over the `crypto_provider`
   registry (`cryptoprov.Load`, provided by `appcontainer`) and the
   `dataprotection.Provider`; `KeySpec` defaults and limits; key labels
   `trustyca/{org}/{project}/{label}`; `KeyRef` with the key URI of a
   provider key or the wrapped PEM of a software key; `Signer` loads either;
   `ImportKey`, `Destroy`, `SubjectKeyID`.
3. `internal/ca/profile.go`, `config.go` (done): `ProfileFromPb` with
   `authority.CertProfile.Validate`, `ProfileToPb`, `ExtensionsFromPb`,
   `IssuerConfigFromPb` (the AIA section is always present, so the CRL and
   OCSP timings fall back to the authority defaults), `IssuerConfigToPb`.
4. `internal/ca/registry.go`, `bootstrap.go` (done): the `Registry` of
   phase 2a resolves `(org, project, label) -> (org, 0, label)` for profiles
   and issuers, builds `authority.Issuer` from a row with
   `authority.CreateIssuer` and the signer of `Keys`, and caches it by row
   ID with a TTL. `Bootstrap` mirrors an `authority.Config` into platform
   rows. The decisions the loader needed: a registered issuer with the same
   SKID only has its settings refreshed in place (`UpdateIssuer` with the
   config, never `crl_number`); a certificate for a new key is an error,
   because the label is unique per scope in every status (ROADMAP.md);
   `RegisterIssuer(Type=Root)` registers the `root_certificate` row after
   the issuer, not in one transaction, and the service logs a failure since
   `RegisterRoot` is idempotent.
5. `internal/ca/issuer.go` (done for issuers): `NewRootIssuer`,
   `NewSignedIssuer`, `NewPendingIssuer` (DESIGN.md section 5.2),
   `ImportIssuer`, `ActivatedIssuer`. `SignCertificate` and `SignOCSP` stay
   in the service on top of `Registry.Resolve` and `IssuerByKeyHash`;
   `Revoke` and `BuildCRL` are phase 4.
6. Tests (done): `internal/ca` over a map-backed fake DB and the `inmem`
   provider, with the fixtures created through the package itself; profile
   conversion tables; parent authorization and scope shadowing of the
   registry; concurrency under the race detector.

## Phase 2a: multi-tenant issuer resolution (done)

Replaces the single bootstrap `*authority.Authority` the CA service signed
with, which collided on issuer labels across orgs and loaded every issuer at
startup. The decision is recorded in DESIGN.md section 5.1: an issuer
registry keyed by row ID with scoped resolution, not an `Authority` per org,
because labels are unique per `(org, project)` and project profiles shadow
org profiles.

1. `internal/ca.Registry`: `Resolve` (profile of the scope, the issuer it
   binds to or the requested one for `*` profiles, Active only, profile
   registered on the issuer under a versioned name), `FindProfile`,
   `FindIssuer`, `Issuer`, `IssuerBySKID`, `IssuerByKeyHash`,
   `IssuerByNameHash`, `InvalidateIssuer`, `InvalidateProfile`. Caches are
   `hashicorp/golang-lru/v2/expirable` with `ca.issuer_cache_ttl` and
   `ca.issuer_cache_size`; one build per issuer under a striped lock.
2. `server/appcontainer.provideCA` provides `*ca.Registry` and runs
   `Registry.Bootstrap` on `ca.bootstrap_config` (the `authority` config key
   became the `ca` section): a `disabled` issuer is archived and enabled
   again by the configuration, the anchor of a root issuer is registered on
   every start, and every enabled issuer is loaded, so a platform issuer
   that does not load fails the start.
3. `server/service/ca`: `SignCertificate` resolves through the registry
   (profile not found, issuer not found, label required, mismatch, not
   allowed, not active are mapped to the API codes), `SignOCSP` through
   `IssuerByKeyHash` and `IssuerByNameHash`; `RegisterIssuer`,
   `ImportIssuer`, `ActivateIssuer`, `UpdateIssuer`, `GetIssuer`,
   `ListIssuers`, `RegisterProfile`, `GetProfile`, `ListProfiles`,
   `DeleteProfile`, `RegisterRoot`, `ListRoots` are implemented, with audit
   events and registry invalidation after every mutation. A row resolved by
   ID or IKID is authorized against its own project (`rowAccess`), a list
   without a project is limited to the projects of a member with project
   grants only (`listProjects`, `ProjectIDs` of the list queries), and the
   parent of a new issuer must be visible from the new issuer's scope
   (DESIGN.md section 6).
4. Benchmarks (`internal/ca/bench_test.go`, `server/service/ca/bench_test.go`;
   `go test -bench . -benchmem`), measured on 2026-10-18 on a 16-thread
   desktop with the `inmem` provider, an in-memory fake DB and mocked
   registration; the figures are a guide to the shape of the cost, not a
   target:

   | Benchmark                                                   | ns/op   | allocs/op |
   | ----------------------------------------------------------- | ------- | --------- |
   | `Registry.Resolve`, warm                                    | 294     | 3         |
   | `Registry.Resolve`, warm, rotating over 16 orgs             | 310     | 3         |
   | `Registry.Resolve`, cold (lookups, key load, construction)  | 206,145 | 466       |
   | `Registry.Resolve` + `Issuer.Sign`                          | 193,959 | 431       |
   | option A: `Authority.GetIssuerByProfile` + `Issuer.Sign`    | 191,999 | 428       |
   | option A: `Authority.GetIssuerByProfile` alone              | 8       | 0         |
   | `Service.SignCertificate`, warm                             | 211,389 | 539       |
   | `Service.SignOCSP`, warm                                    | 53,531  | 283       |

   The warm resolution adds about 0.3 µs to a signature of about 190 µs
   (a KMS signature adds a network round trip of milliseconds), so the
   registry costs nothing measurable on the hot path compared with the
   single authority. A cold issuer pays its DB lookups (two to four
   queries) and about 0.2 ms of construction once per TTL and instance.

Follow-ups:

1. Issuer renewal under one label (ROADMAP.md).
2. `OCSPRequest.IKID` from the CIS route (ROADMAP.md); until then an issuer
   that is not in memory is found by a SHA-1 key hash only.
3. `pb.Issuer.Profiles` is not populated; `GetIssuer` could list the
   profiles bound to the issuer.
4. Negative resolutions are not cached: an unknown profile costs DB lookups
   on every request.
5. Tenants list only the trust anchors of their org; platform anchors are
   served by CIS.
6. `UpdateIssuer`, `ActivateIssuer` and `DeleteProfile` carry no
   `ProjectID`, so a project Admin cannot manage the rows of its project
   through them (ROADMAP.md).

## Phase 3: CA gRPC service

The issuer, profile, root and signing methods are done in phase 2a
(`server/service/ca/issuer.go`, `profile.go`, `root.go`, `signer.go`,
`tenant.go`): the org comes from the token or, for a `trustyca-*` service
caller, from the request and is verified through `db.OrgsDb`; the project
is verified with the authorizer; the certificate and its
`CertificateIssued` event are one transaction; OCSP answers good, revoked
(reason and time from `GetRevoked`) or unknown. The service tests build the
CA through `internal/ca` with the `inmem` provider over a mock DB whose
reads serve in-memory rows (`service_test.go`).

1. `server/service/ca`: implement the remaining `pb.CAServer` methods on top
   of `internal/ca` and `db.CaDb`: `GetCertificate`, `ListCertificates`,
   `UpdateCertificateLabel`, `RevokeCertificate`, `ListRevokedCertificates`
   (`cert.go`), `GetCRL` and `PublishCrls` (`crl.go`, with phase 4).
2. `authctx.CheckAccess` already enforces `allowed_roles` for user tokens and
   the `ca:*`/`certs:*` scopes for API keys, and passes `trustyca-*` service
   roles through; `tenantOrg` and `tenantProject` verify that an explicit
   `OrgID` from a service caller is an active org and that `ProjectID`
   belongs to it (done).
3. Config: the `ca` section (`bootstrap_config`, `issuer_cache_ttl`,
   `issuer_cache_size`) and the `backend` listener with `ca` are done; add
   the `trustyca-ra` and `trustyca-cis` TLS roles and
   `authz.allow: /pb.CA:trustyca-ra,trustyca-admin`.
4. Client: `api/client` factory method for `pb.CAClient`; `api/pb/pb.go` already has
   mockgen directives for `ca` and `cis`.
5. Tests: gRPC end-to-end sign, get, list, revoke, CRL with the bootstrap
   `trusty.svc` issuer through `tests/mockappcontainer`.

## Phase 4: revocation pipeline

1. `PublishCrls` implementation and `server/tasks/crlrenewal` task; CRL number
   increments in the same transaction as the `crl` upsert (`db.PublishCrl`).
   The due issuers are `ListIssuers` (Active, then Archived, with `AllOrgs`)
   minus `ListCrls` with `ExpiringBefore`: add a joined `ListIssuersDueForCrl`
   or a status set filter if that is too many queries.
2. `SignOCSP` with delegated responder support and `unknown` for foreign serials.
3. `server/tasks/certstatus`: mark `Expired`, apply retention
   (`ca.retention.expired_after`, default 0 = keep forever). Needs a bulk
   `UPDATE certificate SET status = Expired WHERE status = Active AND
not_after < ?` paged by id, and a bulk delete; the DB layer has neither.
4. Tests: CRL contents after revoke, CRL number monotonicity, OCSP good/revoked/unknown.

## Phase 5: CIS service

1. `server/service/cis`: implement `pb.CISServer` (JSON) using `db.CaReadonlyDb`;
   register binary routes `/v1/cert/{ikid}`, `/v1/crl/{ikid}`, `/v1/ocsp...`.
2. OCSP handler: GET (base64 path) and POST, forward to `CA.SignOCSP` through the
   backend client, LRU cache keyed by request hash with expiry at `NextUpdate`,
   `Cache-Control` headers.
3. Config: add `cis` to the `wfe` listener (or a dedicated `cis` listener),
   `allow_any` and `skip_auth` entries; update `etc/dev/ca-config.dev.yaml` AIA
   templates to `/v1/cert`, `/v1/crl`, `/v1/ocsp`.
4. Tests: HTTP tests for each media type, OCSP round trip via `golang.org/x/crypto/ocsp`,
   `openssl verify -crl_check` in the docker CI test.

## Phase 6: operator tooling

1. `internal/ctl/admin`: `ca issuer list|get|register|import|activate|archive`,
   `ca profile list|register --file profile.yaml|delete`, `ca crl publish`,
   `ca cert list|get|revoke`, `ca root register|list`; `privpb/protos/admin.proto`
   gains cross-org `ListIssuers` and `ListCertificates` for support staff.
2. `trustyca` CLI: read-only `project` and `cert` commands for org users where useful.
3. Onboarding command: `ca org bootstrap --org <id> --templates <dir>` copies
   template profiles into an org and registers its first issuing CA under the
   platform intermediate.
4. Docs: `Documentation/cli/*.md` regenerated with `make docs`; README section on
   CA and CIS configuration.

## Phase 7: hardening

1. Metrics from DESIGN.md section 13 in `internal/metricskey`.
2. Load test `SignCertificate` and `ListCertificates` with 10M synthetic rows;
   confirm index usage with `EXPLAIN (ANALYZE, BUFFERS)`; decide on partitioning.
3. Security review: key material never logged, `key_protected` only for `inmem`
   in non-prod, mTLS role tests for every `/pb.CA` method.
4. Optional: CRL and certificate publishing to S3/GCS, idempotency keys,
   certificate hold removal.

## Verification checklist per phase

- `make proto` (when protos change), `go generate ./...`, `make build`,
  `make test`, `make lint`.
- Schema changes: `make drop-sql start-sql gen-sql-schema docs` and commit the
  regenerated `internal/db/model`, `internal/db/schema`, `internal/db/README.md`
  and `Documentation/api/internal_db_*.md`.

## NOTES

- do not create new SQL migrations until explicitly asked, the service is in development and not deployed.
  We continue using `sql/trustycadb/migrations/1_tables.up.sql` and if needed can drop and re-create the schema on migration changes.
