# Coding Guidelines

This guide covers conventions for Go, SQL, protobuf, DB, background workflow,
and test changes in this repo. It is intended for human contributors and AI
agents writing or reviewing code.

The rules below focus on review expectations that are not reliably enforced by
formatters or linters: error behavior, nil safety, generated artifacts, DB/API
shape, naming, logging, SQS/job lifecycle, test assertions, compile readiness,
and performance.

---

## 1. Working in This Repo

- Keep generated output in sync with its source. Do not hand-edit generated
  files unless the generator itself is being changed.
- SQL schema or migration changes must include regenerated schema/model/docs
  output when those artifacts are affected.
- Do not commit placeholder prose, pseudo-code, scratch comments, invalid Go, or
  local debug text.
- After non-trivial Go edits, run at least the package compile/test command that
  proves the touched package still builds.

---

## 2. Go Code

### Errors

- Use `github.com/cockroachdb/errors` for all error creation and wrapping.
- Wrap all external errors (from DB calls, cloud SDKs, queue operations,
  serialization, filesystem, generated helpers, etc.) using either:
  - `errors.WithMessage(err, "failed to initialize mcp client")`, for static context strings.
  - `errors.Wrapf(err, "invalid %s for asset %s", LabelOpenPorts, resourceID)`, when context includes dynamic values.
- Never ignore errors from serialization, DB calls, queue operations, cloud SDK
  calls, generated helpers, or filesystem operations.
- Preserve sentinel errors used by callers. For example, invalid SQS payloads
  should still be detectable with `errors.Is(err, awsprov.ErrInvalidSQSMessage)`.
- Wrap errors with context that identifies the failed operation without losing
  the original cause.
- Keep error strings accurate after refactors. Do not leave stale component
  names, old interface names, or copy-pasted action names in runtime errors.
- Map not-found cases explicitly when the response type already supports a
  not-found path. Do not collapse expected not-found errors into generic
  "failed to get ..." responses.
- Keep user-facing and LLM/tool-facing errors sanitized, but specific enough to
  be useful. Put internal diagnostics in server-side logs.

### Naming

- Search existing `pb`, `model`, request, query, and CLI vocabulary before
  adding new names.
- Use the American spelling `analyzer` consistently. Do not mix it with
  `analyser`.
- Avoid redundant prefixes and suffixes when the containing type already
  supplies context.
- Prefer clear zero enum names such as `Undefined` when that is the local
  convention.
- Keep CLI names short and consistent. Avoid unnecessary `ID` suffixes in CLI
  field names when the help text already says the value is an ID.

---

## 3. SQL and Database Code

### Migrations

- Every `*.up.sql` migration that changes schema needs a matching `*.down.sql`
  rollback.
- Empty down migrations are acceptable only when the up migration is
  intentionally irreversible and that reason is documented.
- Do not duplicate a schema change in both a historical base migration and a new
  forward migration unless that is intentional and fresh DB creation has been
  verified.
- Keep primary key column order consistent across migration SQL, generated
  schema comments, and generated docs.

### Tables

- New tables should make lifecycle ownership explicit. Add `project_id`,
  or another owner column when needed for cleanup, tenancy, or query scoping.
- New tables should normally include `created_at` and `updated_at`. If rows are
  immutable or the table is truly global and tiny, document that.
- Add useful unique constraints and indexes for expected query paths, not just a
  primary key.
- Design indexes around actual filters. If query paths filter by
  `(project_id, key_id)`, keep both columns available to the query builder.
- Name denormalized fields after their real meaning. Distinguish asset ID,
  resource ID, display name, and generic target.
- Choose column sizes that fit real identifiers and targets, including cloud
  resource IDs and non-asset targets.
- Put DB code in the package/file that owns the domain concept, not just where
  the first caller happens to live.

### DB APIs and Queries

- Prefer request structs with `QueryParams()` over functions that take many
  positional arguments.
- Follow existing request/query patterns.
- `List` DB methods should be paginated and return a result with a next offset
  or equivalent pagination state.
- If a method returns a single object or intentionally bounded unpaginated data,
  name it `Get...`, not `List...`.
- Put read methods on the relevant `ReadOnlyDb` interface. Put mutation methods
  on the write-capable interface.
- Keep model, schema, query, and service naming aligned with the SQL table and
  relationship direction.
- Group related provider methods in a lifecycle order that is easy to review:
  `Register`/`Upsert`, `Get`, `List`, `Delete`.
- Avoid unnecessary prefixes on query helpers when the package/function context
  already makes the purpose clear.
- Use count-specific or ID-specific queries when callers only need counts or
  identifiers.

---

## 4. Protobuf and API Contracts

- Prefer existing `pb` messages and enums over duplicate DTOs.
- If a new denormalized message is necessary, document the source of truth and
  why an existing message is not enough.
- Public proto messages, fields, and enum values need comments that describe
  product semantics.
- Use the enum wrapper style already used in this repo, such as
  `repeated xxxType.Enum`, instead of raw numeric or ad hoc enum fields.
- `List...Request` and `List...Response` must include pagination fields. If the
  API returns a single object or bounded unpaginated data, name it `Get...`.
- Keep JSON names clean and stable. Avoid temporary review terms and redundant
  prefixes/suffixes unless they are part of the product contract.
- Keep CLI command annotations and public RPC naming aligned with existing CLI
  hierarchy.
- For parsing Enums use .Parse method on enum, for example: `if req.Type = pb.EventType_Unknown.Parse(a.Type); req.Type == pb.EventType_Unknown { return errors.Errorf("invalid event type: %s", a.Type) }`

---

## 5. Logging

- Use the repo's structured `xlog` style with package-level loggers and
  `logger.ContextKV` when a context is available.
- Use snake_case log keys, for example `project_id`, not camelCase names such as
  `ProjectID`.
- Keep log keys stable inside a package or task. Do not switch between keys such
  as `reason` and `message` for the same concept.
- Keep structured log value types stable for a given key. Do not emit an `xdb.ID`
  in one path and a numeric ID in another path under the same key.
- Prefer existing keys such as `reason`, `status`, `task`, `project_id`, and `err`.
- Avoid per-row `INFO` logs in loops. Resolve shared values once outside loops
  and use `DEBUG` for repetitive trace details.
- Log enough correlated IDs to connect worker IDs, job IDs, queue messages, and
  S3/cache paths when they differ.

---

## 6. Batch Jobs, SQS, and RunContext

- Preserve lifecycle semantics: failures, cancellations, invalid messages, and
  skipped work must not be turned into successful jobs by `RunContext.Finish`.
- Be explicit about SQS ownership and retry behavior: operate on the queue the
  task consumed from and preserve sentinel errors such as
  `awsprov.ErrInvalidSQSMessage`.
- Keep scheduling order deliberate when one task materializes data consumed by
  another.
- Check feature settings before enqueueing work that would immediately no-op,
  and keep code behavior aligned with task comments.

---

## 7. Tests

- Build tests using `assert` and `require` pattern.
- Assert exact behavior, including key absence versus empty values and the real
  `err` from the call being tested.
- Keep test setup and cleanup trustworthy: fixtures should match their comments,
  cleanup should run before resources close, and tests should actually execute
  in CI.
- Match mocks on meaningful request fields such as S3 bucket/key/prefix or queue
  URL instead of relying on indistinguishable `gomock.Any()` call order.

---

## 8. Performance and Scalability

- Avoid N+1 DB queries in services, migrations, and background workflows.
- Prefer bulk queries or count-specific queries when processing many rows.
- Do not load full rows only to compute a count.
- Deduplicate IDs before DB, graph, or service calls.
- Avoid extra GraphDB round-trips inside loops when the data can be projected in
  one traversal.
- Do not add cache layers unless they reduce real repeated work. A cache that is
  fully repopulated from DB every run may be redundant.
- Keep hot-path query complexity under control. If a query is growing
  hard-to-review joins or aggregations, consider a purpose-built summary table
  or precomputed result.
- Sort response slices and SQL aggregates when stable output matters.

## 9. Tools

- `make proto` : compile updated proto files
- `make generate` : generate mocks on updated interfaces
- `male -j build` : build all executables
- `make test` : test entire project
- `make lint` : final check

If the SQL schema changes and needs to be updated, drop and recreate:

```sh
make drop-sql start-sql
make gen-sql-schema
```
