---
name: code-review
description: >-
  Review pull requests and diffs in this Go, SQL, and protobuf repository
  against AGENTS.md. Use for Copilot code review, PR comments, and when
  asked to review trustyca changes.
---

# Trustyca code review

Review this PR as a senior reviewer of trustyca: a public, multi-tenant
Certification Authority in Go with protobuf APIs, PostgreSQL, OAuth/DPoP
login, org/project/membership authorization, API keys, crypto providers
(KMS, PKCS#11, inmem), CRL/OCSP, scheduled tasks and CLI/CTL.

## How to review

1. Read root `AGENTS.md`, then the relevant concept/package section in
   `Documentation/codemap.md`. Check the local `FINDINGS.md`, when present,
   for existing defects and `ROADMAP.md` for deferred work; do not present an
   existing defect as new unless the diff changes its impact.
2. Prefer codebase-memory-mcp symbol/caller/snippet tools with
   `project="trustyca"` (`MCP.md`); fall back to scoped `rg` for literals,
   configs or graph gaps. Open the owning source and tests before expanding
   scope.
3. Classify the diff: Go, SQL/migration, proto/API, generated artifacts,
   authorization/tenancy, auth service (OAuth, DPoP, cookies, API keys),
   CA/PKI (issuers, keys, profiles, signing), revocation/CRL/OCSP, scheduled
   tasks, tests, CLI/CTL. Apply the matching checklist and the contributor
   rules.
4. Use `Documentation/design/DESIGN.md` for the accepted contracts and
   `Documentation/PLAN.md` for what each phase delivers. The CA and CIS
   services are stubs until their phases land; review an implementation
   against DESIGN.md, not against the stub.
5. Skip reading generated `Documentation/api/` and `Documentation/cli/`;
   check source/generation paths and diff consistency instead.
6. Comment only on verified issues affected by this diff. Prefer fewer,
   higher-signal comments and state verification limits.

## Comment style

- One issue per comment, tied to a specific line or hunk.
- Say why it matters here. Do not give generic advice.
- When a style-guide rule applies, cite the section
  (for example `AGENTS.md → Errors`).
- Suggest a concrete fix. Do not rewrite large files.
- Do not nitpick names that already match the surrounding package.
- The repository is public: describe a security defect precisely enough to
  fix, without an exploit recipe, and never quote a secret from the diff.

## Severity

- **Blocker**: correctness, data loss, authz bypass or cross-tenant access,
  private key or token exposure, wrong certificate/CRL/OCSP content, broken
  revocation, ignored errors, proto/SQL contract break, generated files out
  of sync.
- **Should fix**: style-guide violations that will ship (error wrapping,
  pagination, log keys, weak tests, N+1 queries).
- **Nit**: optional clarity. Use sparingly.

## Do not comment on

- gofmt, import order, or other findings `make lint` already enforces.
- Hand edits inside generated files unless the change is the generator.
- Restating the PR description.
- Style that already matches the surrounding package.

## Generated and paired artifacts

Flag source changes whose outputs were not updated:

| Source                                         | Also required                                                         |
| ---------------------------------------------- | --------------------------------------------------------------------- |
| Proto under `api/pb/protos` or `privpb/protos` | Regenerated Go/HTTP/proxy/method info (`make proto`)                  |
| DB, client or service interfaces               | Regenerated mocks (`make generate`); `mocks/` is gitignored           |
| SQL migrations                                 | Matching `*.down.sql`, plus schema/model/docs (`make gen-sql-schema`) |
| CLI output captured by a suite                 | Reviewed `testdata/prints_<suite test>.txt` (`TRUSTYCA_UPDATE_GOLDEN=1`) |

If `.github/CODEOWNERS` assigns reviewers for a touched path, preserve that
review boundary while still reviewing its code. Do not infer additional
approval requirements from this skill.

## Checklists by change type

### Go

- Create and wrap errors with `github.com/cockroachdb/errors`.
- Wrap external errors with `errors.WithMessage` (static) or `errors.Wrapf`
  (dynamic values).
- Do not ignore errors from DB, crypto providers, cloud SDKs,
  serialization, filesystem, or generated helpers.
- Preserve sentinel errors so callers can use `errors.Is`.
- Map not-found to the response's not-found path. Do not collapse it into
  a generic "failed to get ..." error.
- A refusal the org's state causes uses `preconditionFailed` (409 /
  FailedPrecondition), returned unwrapped; `NewGrpcFromCtx` with
  `codes.FailedPrecondition` becomes an HTTP 500 with the pinned porto.
- Keep error strings accurate after refactors. No stale component names.
- Sanitize user-facing errors. Put diagnostics in server logs.

### SQL and DB

- Every `*.up.sql` has a matching `*.down.sql`. An empty down file is OK
  only when the up migration is intentionally irreversible and that is
  documented.
- New tables make tenancy explicit with nullable `(org_id, project_id)`,
  composite project foreign keys and `UNIQUE NULLS NOT DISTINCT` where
  platform and tenant rows share a key; usually include
  `created_at`/`updated_at`, and add indexes for real filter paths.
- `List` methods are paginated. Single-object or bounded reads are `Get...`.
  An offset must not advance over a set the caller shrinks.
- Prefer request structs with `QueryParams()` over long positional argument
  lists.
- Reads go on the read-only DB interface; mutations on the write interface.
  The DB layer does not import authorization code.
- A multi-row write runs every statement on the transaction provider that
  `BeginTx` returned.
- No N+1 queries. Do not load full rows only to compute a count.

### Protobuf and API

- Reuse existing `pb` messages and enums. A new denormalized message needs
  a comment for the source of truth.
- Public messages, fields, and enum values have comments that describe
  product semantics.
- Tenant methods declare `(es.api.allowed_roles)`, and `(es.api.scopes)`
  when API keys may call them; tenant requests carry no `OrgID`.
- Use the repo enum wrapper style (`repeated xxxType.Enum`).
- `List...Request` / `List...Response` include pagination fields.
- CLI command annotations stay aligned with the existing CLI hierarchy.
- For parsing Enums use .Parse method on enum, for example: `req.Type = pb.EventType_Unknown.Parse(a.Type)`

### Logging

- Use structured `xlog` with `logger.ContextKV` when a context exists.
- Log keys are `snake_case` and stable (`org`, `project`, `reason`, `err`).
- Keep the value type of a given key stable.
- No per-row `INFO` logs in loops.
- No tokens, API key secrets, private keys, PINs or CSRF values in logs.

### Authorization and tenancy

- The org comes from the token; an explicit `OrgID` is accepted only from a
  `trustyca-*` service role, and the service verifies the project belongs
  to that org.
- Project checks go through `authctx.Authorizer`; a foreign or inactive
  project is not found, not forbidden.
- Membership and project mutations invalidate the authorizer cache after
  commit. Grantability follows `CanGrantOrgRole` / `CanGrantProjectRole`;
  the last org-wide Owner cannot be removed or demoted.
- API keys are checked against scopes, only on methods whose allowed roles
  include APIKey; a project-scoped key stays in its project.
- privpb.Admin stays limited to `trustyca-*` service roles; do not open a
  new path in `authz.allow_any` or `identity_map.skip_auth` without a reason
  in the PR.

### Auth service, cookies and CLI login

- Tokens and API key secrets never go in a URL query string, a log or a
  plain-text page; the CLI `--no-browser` flow uses the fragment response
  mode and the `/authenticated` page.
- Auth cookies stay HttpOnly, Secure, SameSite=None with the configured
  domain; revocation clears them. A new token for a cookie session must
  update the cookie or say why not.
- OAuth state stays protected by dataprotection; DPoP proofs are verified
  for the request they sign. API key HMACs use constant-time comparison and
  a bounded timestamp window.
- The CLI login listener uses its own mux, shuts down and waits for Serve.

### CA, keys and signing

- Keys stay in their crypto provider; software keys are stored only wrapped
  by `dataprotection.Provider`; `inmem` is for tests. Key labels follow
  `trustyca/{org}/{project}/{label}`; renewal uses a new key (new SKID).
- Profile and issuer resolution follow DESIGN.md §6: tenant rows before
  platform rows, platform profiles never visible to tenants, `"*"` issuer
  labels require an allowed profile.
- Request `NotAfter` only shortens the profile expiry; extensions outside
  `allowed_extensions` are refused unless the issuer omits them. Serial
  numbers come from `xpki/authority`.
- The certificate insert and its issue event are one transaction.

### Revocation, CRL and OCSP

- Revocation inserts `revoked` and updates the certificate status in one
  transaction; the CRL number increments with the CRL upsert and never
  goes back.
- CRL entries exclude expired certificates; OCSP answers `unknown` for a
  serial the issuer did not sign.
- CIS is public and read-only, holds no issuer keys, forwards OCSP signing
  to the CA and caches no longer than `NextUpdate`.

### Scheduled tasks

- Task names and configuration match `server/tasks.Factories`; an unknown
  task name fails startup.
- Work is idempotent across pods; bound batches/deadlines and keep per-row
  failure handling. Page by the last ID seen when the task changes the
  filtered set.

### Tests

- Use `assert` and `require`.
- Assert the real `err` and distinguish missing keys from empty values.
- Reuse generated gomock interfaces under `mocks/` and regenerate when
  interfaces change. Match meaningful request fields, not only `gomock.Any()`
  or call order.
- Fixtures must match their comments. Cleanup runs before resources close.
- Parallel tests must have independent state; CLI parsing writes globals,
  so CLI suites are not parallel; auth service tests that change BaseURL or
  providers are not parallel; parallel tests must not share an `xdb.ID`.
  Golden output changes only with `TRUSTYCA_UPDATE_GOLDEN=1`.
- Shared-state changes need a test that actually races and
  `make test RACE=true`. Docker-backed checks require the configured local
  stack; do not recreate a non-disposable database to review code.
- Run checks appropriate to the diff. `make lint` runs fmt and
  golangci-lint; `make vulns` is separate. CI `build.yml` runs `make test` /
  `make covtest`; it does not establish lint, race or container
  integration success.

### Documentation

- Every new package includes a handwritten `doc.go`; document exported
  symbols and non-obvious usage.
- Update codemap ownership, entry points, dependencies, invariants and test
  layout in the same change, including a stub replaced by an
  implementation.
- Current API samples must agree with source. DESIGN.md is the accepted
  design; PLAN.md phase status changes with the code.
- Newly discovered unfixed defects go to the local `FINDINGS.md`; committed
  code and docs do not cite finding IDs. Publicly tracked work goes to
  ROADMAP.md without exploit details.
- Generated docs come from source comments/protos and `make docs`; avoid
  asking for hand edits or accepting obsolete hand-maintained API copies.

## Review output

For each finding report:

- severity (`Blocker` / `Should fix` / `Nit`)
- file and location
- what is wrong
- a concrete fix

If the diff is clean against `AGENTS.md` and these checklists, say so.
Do not invent nits.
