# RULES OF CONDUCT

This module (`github.com/effective-security/trustyca`) is a multi-tenant
Certification Authority service: the access layer (login, orgs, projects,
memberships, API keys) and the CA (`pb.CA`) and certificate information
(`pb.CIS`) services built on it. The repository is public.

Package boundaries and direct internal imports are listed in
[`Documentation/codemap.md`](Documentation/codemap.md).

## NAVIGATION

1. Read the matching concept row in
   [`Documentation/codemap.md`](Documentation/codemap.md), then that package's
   entry points, invariants and test notes. Read only the relevant sections.
2. Prefer codebase-memory-mcp for code discovery when available, with
   `project="trustyca"` ([`MCP.md`](MCP.md)): `search_graph` for symbols,
   `trace_path` for callers/callees, `get_code_snippet` for source,
   `query_graph` for complex relationships, and `get_architecture` for an
   overview. Check the index status and coverage, and paginate narrow
   queries; do not reindex unless asked.
3. Read the owning source and its tests before expanding scope. Fall back to
   `rg` for literals, documentation/configuration, graph coverage gaps, or a
   concept absent from the map; scope searches to the owning package first.
   Add any missing ownership or invariant to the codemap in the same change.
4. Read `FINDINGS.md`, when you have it, before changing surprising
   behavior: it is the local list of known defects and is gitignored, so it
   may be absent. [`ROADMAP.md`](ROADMAP.md) owns active planned work.
   [`Documentation/design/DESIGN.md`](Documentation/design/DESIGN.md) is the
   accepted design and [`Documentation/PLAN.md`](Documentation/PLAN.md) its
   implementation phases; the CA and CIS services are still stubs.
5. Skip `Documentation/api/` and `Documentation/cli/`: `make docs` generates
   them. Edit source comments/protos and regenerate instead.
6. Preserve existing staged and unstaged work. Documentation-only work must
   not recreate databases, regenerate artifacts or rewrite fixtures merely
   to inspect them. Choose checks that exercise the changed behavior.

## CODING GUIDELINES

### Style

- Target Go 1.27 (`go.mod`). Use the standard library where it now covers a
  helper: `slices.Contains`, `cmp.Or`, `maps.Copy`, `strings.SplitSeq`,
  `min`/`max`, range-over-int, `math/rand/v2` and `crypto/rand`. Prefer the
  stdlib `slices` over `github.com/effective-security/x/slices`. Do not add
  calls to functions marked `Deprecated` in the stdlib, in
  `github.com/effective-security/x`, `xpki`, `porto`, or in third-party
  modules; `.golangci.yml` still excludes SA1019, so check by hand
  (ROADMAP.md → Lint).
- Do not use long one-liners for map or struct population; split
  key-value pairs on new lines for readability.
- Do not use many hardcoded strings or integers; define `const` at the
  top of the file or in the package. Header and metadata names live in
  `porto/xhttp/header`, REST paths and OAuth values in `api/pb/rest.go`;
  reuse them.
- Memoize into variables; do not call functions with the same parameters
  more than once.
- Use `any`, not `interface{}`.
- Search the existing `pb`, `model`, request, query and CLI vocabulary
  before adding names. Avoid prefixes and suffixes the containing type
  already supplies; keep CLI flag names short.

### SQL and Database Code

#### Migrations

- Every `*.up.sql` migration that changes schema needs a matching `*.down.sql`
  rollback.
- Empty down migrations are acceptable only when the up migration is
  intentionally irreversible and that reason is documented.
- Do not duplicate a schema change in both a historical base migration and a new
  forward migration unless that is intentional and fresh DB creation has been
  verified.
- Keep primary key column order consistent across migration SQL, generated
  schema comments, and generated docs.

#### Tables

- New tables make tenancy explicit: nullable `(org_id, project_id)` with
  composite foreign keys to `project (org_id, id)` and `UNIQUE NULLS NOT
  DISTINCT` where a platform row (`org_id IS NULL`) and tenant rows share a
  key (DESIGN.md §4).
- New tables should normally include `created_at` and `updated_at`. If rows are
  immutable or the table is truly global and tiny, document that.
- Add useful unique constraints and indexes for expected query paths, not just a
  primary key. Certificate and revocation tables grow without bound: design
  indexes around the real filters (`org_id`, `project_id`, `ikid`, `status`,
  `not_after`) and check them with `EXPLAIN` before adding a list query.
- Name denormalized fields after their real meaning: IKID, SKID, serial
  number, issuer label and profile label are distinct identifiers.
- Put DB code in the package/file that owns the domain concept, not just where
  the first caller happens to live.

#### DB APIs and Queries

- Prefer request structs with `QueryParams()` over functions that take many
  positional arguments, and follow the existing request/query patterns.
- `List` DB methods should be paginated and return a result with a next offset
  or equivalent pagination state. Do not advance an offset over a filtered set
  the caller is shrinking (status updates, deletes): page by the last ID seen.
- If a method returns a single object or intentionally bounded unpaginated data,
  name it `Get...`, not `List...`.
- Put read methods on the `...ReadonlyDb` interface and mutations on the
  write-capable interface. The DB layer stays plain CRUD: it never imports
  `internal/authctx`.
- A method that writes more than one row opens a transaction with `BeginTx`
  and runs every statement on the provider it returns, not on the receiver.
- Keep model, schema, query, and service naming aligned with the SQL table and
  relationship direction.
- Group related provider methods in a lifecycle order that is easy to review:
  `Register`/`Upsert`, `Get`, `List`, `Delete`.
- No N+1 queries in services or tasks. Use count-specific or ID-specific
  queries when callers only need counts or identifiers; deduplicate IDs before
  DB calls.

### Protobuf and API Contracts

- Prefer existing `pb` messages and enums over duplicate DTOs. If a new
  denormalized message is necessary, document the source of truth and why an
  existing message is not enough.
- Public proto messages, fields, and enum values need comments that describe
  product semantics.
- Every tenant method declares its minimum roles with `(es.api.allowed_roles)`
  and, when API keys may call it, the required `(es.api.scopes)`;
  `authctx.CheckAccess` enforces both from the generated method info.
  Tenant requests carry no `OrgID`: the server takes the org from the token.
- Use the enum wrapper style already used in this repo, such as
  `repeated xxxType.Enum`, instead of raw numeric or ad hoc enum fields.
- `List...Request` and `List...Response` must include pagination fields. If the
  API returns a single object or bounded unpaginated data, name it `Get...`.
- Keep JSON names clean and stable. Avoid temporary review terms and redundant
  prefixes/suffixes unless they are part of the product contract.
- Keep CLI command annotations and public RPC naming aligned with existing CLI
  hierarchy.
- For parsing Enums use .Parse method on enum, for example: `if req.Type = pb.EventType_Unknown.Parse(a.Type); req.Type == pb.EventType_Unknown { return errors.Errorf("invalid event type: %s", a.Type) }`

### Authorization, tokens and CA keys

- The org comes from the token (`authctx.FromContext(ctx).OrgID()`); only
  `trustyca-*` service roles (RA, CIS, jobs over mTLS) pass tenant scope
  explicitly, and the service must still verify that the project belongs to
  that org. A project of another org or an inactive project is reported as
  not found, so existence does not leak.
- Permissions are resolved from DB grants by the shared `authctx.Authorizer`;
  token role claims are informational. Every membership or project mutation
  calls `InvalidateUser` / `InvalidateProject` after it commits.
- An org always keeps an org-wide Owner; only an Owner grants Owner.
- Private keys never leave their crypto provider and are never logged; a
  software key is stored only wrapped by `dataprotection.Provider`, and the
  `inmem` provider is for tests. Key labels follow
  `trustyca/{org}/{project}/{label}`. Serial numbers come from
  `xpki/authority`, never from a counter.
- State changes that must agree are one transaction: a certificate insert and
  its issue event, a revocation and the certificate status, a CRL upsert and
  the issuer's CRL number (which only grows).
- CIS is public and read-only, holds no issuer keys and forwards OCSP signing
  to the CA.

### Logging

- Use the repo's structured `xlog` style with package-level loggers and
  `logger.ContextKV` when a context is available.
- Use snake_case log keys, for example `project_id`, not camelCase names such as
  `ProjectID`.
- Keep log keys stable inside a package or task. Do not switch between keys such
  as `reason` and `message` for the same concept.
- Keep structured log value types stable for a given key. Do not emit an `xdb.ID`
  in one path and a numeric ID in another path under the same key.
- Prefer existing keys such as `reason`, `status`, `task`, `org`, `project`,
  `action` and `err`.
- Avoid per-row `INFO` logs in loops. Resolve shared values once outside loops
  and use `DEBUG` for repetitive trace details.
- Never log access tokens, API key secrets, private keys, PINs or CSRF
  values; log key IDs, IKIDs and serial numbers instead.

### Errors

- Use `github.com/cockroachdb/errors` for all error creation and wrapping.
- Wrap external errors (filesystem, YAML/JSON, network, Redis, gRPC, KMS/HSM,
  AWS SDK) using either:
  - `errors.WithMessage(err, "unable to read file")` for static context.
  - `errors.Wrapf(err, "failed to resolve file %s", path)` when context
    includes dynamic values.
- Errors originated from internal sentinel types must also be wrapped so
  the stack is preserved. For `var ErrNotFound = errors.New("not found")`
  do not simply `return ErrNotFound`.
- Compare errors with `errors.Is` / `errors.As`, never `==` or a type
  assertion. Errors returned to HTTP or gRPC callers go through
  `porto/xhttp/httperror` so status codes and codes stay consistent.
- A refusal the caller can fix by changing the org's state (deleted org,
  last Owner) is `preconditionFailed` (HTTP 409 `conflict`, gRPC
  FailedPrecondition). Do not build it with `NewGrpcFromCtx(ctx,
  codes.FailedPrecondition, ...)`: the pinned porto maps that to HTTP 500 and
  hides the message. Return it unwrapped.
- Map not-found cases explicitly when the response type already supports a
  not-found path. Do not collapse expected not-found errors into generic
  "failed to get ..." responses.
- Keep user-facing errors sanitized, but specific enough to be useful. Put
  internal diagnostics in server-side logs.
- Never ignore errors from serialization, filesystem, or network calls in
  library paths that already return `error`. Helpers that intentionally
  swallow errors must keep that behavior documented in
  `Documentation/codemap.md`.
- Keep error strings accurate after refactors. Do not leave stale package
  or function names in runtime errors.
- Library code does not panic on bad input or bad configuration; it
  returns an error. The only intentional panics are `Must*` constructors,
  `init()`-time table construction and service factories given a nil server.
- Every outgoing HTTP call takes a `context.Context` and a client with a
  timeout (`http.NewRequestWithContext`; no bare `http.Get`).
- Credentials: bearer tokens, cookies, API key secrets, private keys and
  PINs are never logged in full and never put in a URL query string; token
  files are written with mode `0600`; random values come from
  `crypto/rand`; use constant-time comparison for secrets and HMACs.
- Headers that carry caller identity (`X-Forwarded-For`, `X-Real-Ip`,
  `X-Forwarded-Proto`, `Authorization`, DPoP) are untrusted input. Do not
  widen what the servers accept from them without a `ROADMAP.md` entry.

### Tests

- Build tests using `assert` and `require` from
  `github.com/stretchr/testify`; suites use `testify/suite`.
- Assert exact behavior, including key absence versus empty values and
  the real `err` from the call being tested.
- Do not assert on source line numbers or on exact compressed bytes; both
  change with unrelated edits or Go releases.
- Prefer table tests for conversion and formatting helpers.
- Use `package foo_test` for black-box tests and `package foo` only when a
  test needs unexported seams.
- External fixtures come from `etc/dev/` and `tests/testutils`. PostgreSQL,
  Redis, LocalStack and KMS are started by `make start-localstack`; generate
  the certificates with `make folders gen_test_certs` first. Initialize only
  a disposable local database with `make drop-sql start-sql`. `make test`
  does not start dependencies, and `-short` does not bypass every package
  setup. Tests load `etc/dev/trustyca-config.unittest.yaml` through
  `testutils.LoadConfig("UNIT_TEST")`.
- Cover shared state with a test that actually races, and run
  `make test RACE=true` before proposing a change to shared state
  (authorizer caches, schema metadata, port allocation, CLI globals,
  issuer caches).
- This module uses gomock-generated interfaces under `mocks/`, which is
  gitignored: run `make generate` on a fresh checkout. Reuse the existing
  mocks or exercise components directly; interface changes require
  `make generate`. Match meaningful request fields, not only `gomock.Any()`.
- Add `t.Parallel()` only for tests with independent state. Suites that
  parse CLI configuration mutate process-wide formatting, so they are never
  parallel. Their captured output is compared with the suite's golden file,
  `testdata/prints_<suite test>.txt`; rewrite it only on purpose, with
  `TRUSTYCA_UPDATE_GOLDEN=1 go test ./api/cli/command`, and review the diff.
  The auth service tests share one server: a test that changes its BaseURL
  or providers is not parallel. Never share an `xdb.ID` between parallel
  tests: its string cache is not synchronized.
- Avoid `time.Sleep`, use `require.Eventually` where appropriate.

### Tools

- `make tools` : install lint, coverage, docs, PKI, schema, migrate and mock
  tools listed in `Makefile` (govulncheck is installed separately)
- `make generate version` : regenerate the gitignored mocks and
  `api/version/current.go`
- `make fmt` : apply go fmt with the project rewrites
- `make build` : build `trustyca`, `trustycactl` and `trustycasvc`
- `make test` : test entire project (requires the configured local stack)
- `make testshort` : tests with `-test.short`
- `make lint` : gofmt, golangci-lint
- `make vulns` : govulncheck (install it separately)
- `make covtest` : coverage run and console report
- `make covtest coverage` : coverage run and HTML report
- `make docs` : regenerate API and CLI references under `Documentation/api/`
  and `Documentation/cli/`; run `make build` first
- `make all` : clean, tools, generate, certificates, local stack, recreated
  SQL database, build, dry-run and test (see `Makefile`)

If the proto changes and needs to be updated `make proto` for types and `make proto generate` for services.

If the SQL schema changes and needs to be updated, drop and recreate:

```sh
make drop-sql start-sql
make gen-sql-schema
```

CI (`.github/workflows/build.yml`) builds and prepares the local stack, runs
`make test` on pushes and `make covtest` on PRs, and publishes a coverage
status against `MIN_TESTCOV`, which the workflow does not set yet. CI does
not run `make lint`, the race detector or `make docker-citest`; run lint and
race locally. Pushes to `main` that change `.VERSION` create a tag
`<.VERSION>.<commit count>`.

### Documentation

- Every new package, including commands and generated support packages,
  has a handwritten `doc.go` with a package/command comment and, where the
  package has a non-obvious entry point, a short usage example. Most
  existing packages do not have one yet: add it when you change the package.
- Document all exported types, functions, interfaces, and interface
  methods. Say what a symbol is _for_, not just what it is named.
- Keep samples in `doc.go`, the root `README.md` and handwritten
  `Documentation/` accurate against the current API. A wrong sample is
  worse than no sample; compile a changed sample before committing it.
- When you add a package, add `doc.go` and a section plus concept-index
  rows in `Documentation/codemap.md`.
- When you find a defect you are not fixing in the same change, add it to
  your local `FINDINGS.md` with the next free ID. It is not committed, so
  committed code, comments and docs never cite a finding ID: state the
  constraint itself in the comment. Larger API or contract changes, and
  defects that need public tracking, go to `ROADMAP.md`; do not publish an
  exploitable security detail there.

#### Keep `Documentation/codemap.md` current

Update the codemap in the **same change** when you add functionality or
make a major change, including:

- New, removed, or renamed package, subpackage, or file that owns a
  concept.
- New, moved, or renamed exported entry-point type, func, or interface.
- Changed invariants: panic vs error, process-global state (loggers,
  registries, caches, default clients), locking, config file format, header
  or metadata names, supported auth methods, roles and scopes, key handling,
  goroutine/callback rules, or internal imports between packages.
- A stub replaced by an implementation (CA, CIS, tasks).
- Changed test layout or fixture conventions.

The map must stay the navigation index: concept → file → entry points →
invariants. If you had to grep to find something that belongs there, add
the row.

## REPOSITORY MAP

Start here instead of grepping the tree.

- **[`Documentation/codemap.md`](Documentation/codemap.md)** — concept
  index, per-package files and entry points, invariants, internal
  dependencies, test layout, build and CI.
- **[`README.md`](README.md)** — build targets, local setup and client
  configuration.
- **[`Documentation/design/DESIGN.md`](Documentation/design/DESIGN.md)** —
  accepted design: tenancy and authorization, domain model, issuers, keys,
  profiles, signing, revocation, CRL/OCSP and APIs.
- **[`Documentation/PLAN.md`](Documentation/PLAN.md)** — implementation
  phases of the design and their status.
- **[`ROADMAP.md`](ROADMAP.md)** — larger planned work.
- **`FINDINGS.md`** — local, gitignored list of known defects. Read it
  before "fixing" surprising behavior: it may already be recorded, with the
  compatibility decision still open.
- **[`MCP.md`](MCP.md)** — codebase-memory-mcp project selection and usage.
- Package `doc.go`, where a package has one.
