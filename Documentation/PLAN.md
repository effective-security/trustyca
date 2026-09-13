# Trusty CA Implementation Plan

Execution plan for [DESIGN.md](DESIGN.md). Phases are ordered by dependency;
each phase ends with a green `make build test lint`.

## Phase 0: design artifacts (done)

- `Documentation/DESIGN.md`, this plan, and the membership baseline
  `Documentation/membership-authorization-spec.md`.
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
  `GetAllowedMethods`, `GetCallerScope`.
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
  (`Test_ProjectMembership`, `Test_APIKey`), service tests with a fake
  authorizer including API keys, CLI with golden output.

Acceptance criteria from the spec covered by tests: 1, 2, 3, 4, 5, 6, 7, 8, 9,
11, 12, 13, 14. Criterion 10 (revocation bound) is the 3 minute cache TTL
plus invalidation after every membership mutation.

Follow-ups in this area:

1. Most recently used org at login; today the first accessible org is selected.
2. `privpb.Admin` support views across orgs (`ListProjects`, `ListMemberships`).
3. Cookie refresh on `SelectOrg` for browser sessions (`RememberMe`).
4. API key rotation and a client helper that signs requests with the key
   (HMAC over method and timestamp) for `AuthenticateAPIKey`.
5. Type mapping for `issuer.config` and `certificate_profile.config`: a new
   `model.JSON` type (`json.RawMessage` with `Scan`/`Value`), because
   `xdb.Metadata` is `map[string]string` and cannot hold the nested
   `pb.IssuerConfig`/`pb.CertProfile`. Add it to `typesmap.yaml` before Phase 2.
6. Regeneration note: `make drop-sql start-sql gen-sql-schema docs` emits the two
   `*.gen.go` files without imports; run `goimports -w` on them afterwards.

## Phase 2: CA core library (`internal/ca`)

1. `internal/db`: new `CaReadonlyDb` and `CaDb` interfaces and `pgsql` implementations
   in lifecycle order (Register/Upsert, Get, List, Delete) for issuers, roots,
   profiles, certificates, revoked, CRLs. Requests use `QueryParams()` structs;
   lists are paginated with cursor on `id`.
   - `RevokeCertificate` and `PublishCrl` are single transactions.
   - `ListCertificates` supports `ProjectID`, `IKID`, `Profile`, `Status`, `ExpiringBefore`.
2. `internal/ca/keys`: crypto provider registry built from `config.CA.Crypto`
   using `cryptoprov.Load`; key label scheme `trustyca/{org}/{project}/{label}`;
   software keys wrapped with `dataprotection.Provider`.
3. `internal/ca/profiles`: conversion `pb.CertProfile <-> authority.CertProfile`,
   validation via `authority.CertProfile.Validate`, resolution
   `(org, project, label) -> (org, 0, label)`.
4. `internal/ca/issuers`: build `authority.Issuer` from an `issuer` row
   (`authority.CreateIssuer` with a `crypto.Signer` from the provider), TTL cache
   keyed by issuer ID, invalidation on update; bootstrap loader that mirrors
   `authority.Config` issuers and profiles into `org_id = 0` rows at startup.
5. `internal/ca/signer`: `SignCertificate` flow from DESIGN.md section 7,
   `RegisterIssuer` shapes from section 5.2 (root, parent-signed, pending),
   `ImportIssuer`, `ActivateIssuer`, `Revoke`, `BuildCRL`, `SignOCSP`.
6. Unit tests with the `inmem` provider and `xpki/testca`; table-driven tests for
   profile resolution and parent-issuer authorization.

## Phase 3: CA gRPC service

1. `server/service/ca`: implement `pb.CAServer` on top of `internal/ca`; wire
   `db.CaDb` and the key registry through `appcontainer` providers.
2. `authctx.CheckAccess` already enforces `allowed_roles` for user tokens and
   the `ca:*`/`certs:*` scopes for API keys, and passes `trustyca-*` service
   roles through; the CA service must additionally verify that an explicit `OrgID` from a service
   caller is a valid org and that `ProjectID` belongs to it.
3. Config: `ca` section in `internal/config/config.go` and `etc/dev/trustyca-config.yaml`;
   add `ca` to the `backend` listener, `trustyca-ra` and `trustyca-cis` TLS roles,
   `authz.allow: /pb.CA:trustyca-ra,trustyca-admin`.
4. Client: `api/client` factory method for `pb.CAClient`; `api/pb/pb.go` already has
   mockgen directives for `ca` and `cis`.
5. Tests: service tests with `tests/mockappcontainer`, gRPC end-to-end sign, get,
   list, revoke, CRL with the bootstrap L2 issuer.

## Phase 4: revocation pipeline

1. `PublishCrls` implementation and `server/tasks/crlrenewal` task; CRL number
   increments in the same transaction as the `crl` upsert.
2. `SignOCSP` with delegated responder support and `unknown` for foreign serials.
3. `server/tasks/certstatus`: mark `Expired`, apply retention
   (`ca.retention.expired_after`, default 0 = keep forever).
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
  regenerated `internal/db/model`, `internal/db/schema`, `internal/db/README.md`,
  `Documentation/db/*.md`.
