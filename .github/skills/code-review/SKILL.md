---
name: code-review
description: >-
  Review pull requests and diffs in this Go, SQL, and protobuf repository
  against STYLEGUIDE.md. Use for Copilot code review, PR comments, and when
  asked to review cynos changes.
---

# Cynos code review

Review this PR as a senior reviewer of cynos: a Go service with protobuf APIs,
PostgreSQL, Stripe billing, SQS workers, and CLI/CTL.

## How to review

1. Classify the diff: Go, SQL/migration, proto/API, generated artifacts,
   SQS/jobs, billing/payments, tests, CLI/CTL.
2. Apply the matching checklist below plus `STYLEGUIDE.md`.
3. Comment only on issues that are real in this diff.
4. Prefer fewer, higher-signal comments.

## Comment style

- One issue per comment, tied to a specific line or hunk.
- Say why it matters here. Do not give generic advice.
- When a style-guide rule applies, cite the section
  (for example `STYLEGUIDE §2 Errors`).
- Suggest a concrete fix. Do not rewrite large files.
- Do not nitpick names that already match the surrounding package.

## Severity

- **Blocker**: correctness, data loss, authz bypass, money/billing bugs,
  broken job lifecycle, ignored errors, proto/SQL contract break, generated
  files out of sync.
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
| Proto under `api/pb/protos` or `privpb/protos` | Regenerated Go/HTTP/mocks (`make proto`)                              |
| DB or service interfaces                       | Regenerated mocks (`make generate`)                                   |
| SQL migrations                                 | Matching `*.down.sql`, plus schema/model/docs (`make gen-sql-schema`) |

`CODEOWNERS` requires human review for proto, SQL, `internal/db`, and
`internal/config`. Still review those files; do not skip them.

## Checklists by change type

### Go

- Create and wrap errors with `github.com/cockroachdb/errors`.
- Wrap external errors with `errors.WithMessage` (static) or `errors.Wrapf`
  (dynamic values).
- Do not ignore errors from DB, cloud SDKs, queues, serialization,
  filesystem, or generated helpers.
- Preserve sentinel errors so callers can use `errors.Is`.
- Map not-found to the response's not-found path. Do not collapse it into
  a generic "failed to get ..." error.
- Keep error strings accurate after refactors. No stale component names.
- Sanitize user-facing and LLM/tool-facing errors. Put diagnostics in
  server logs.

### SQL and DB

- Every `*.up.sql` has a matching `*.down.sql`. An empty down file is OK
  only when the up migration is intentionally irreversible and that is
  documented.
- New tables make ownership explicit (`project_id` or billing-account
  scope), usually include `created_at`/`updated_at`, and add indexes for
  real filter paths.
- `List` methods are paginated. Single-object or bounded reads are `Get...`.
- Prefer request structs with `QueryParams()` over long positional argument
  lists.
- Reads go on the read-only DB interface; mutations on the write interface.
- No N+1 queries. Do not load full rows only to compute a count.

### Protobuf and API

- Reuse existing `pb` messages and enums. A new denormalized message needs
  a comment for the source of truth.
- Public messages, fields, and enum values have comments that describe
  product semantics.
- Use the repo enum wrapper style (`repeated xxxType.Enum`).
- `List...Request` / `List...Response` include pagination fields.
- CLI command annotations stay aligned with the existing CLI hierarchy.
- For parsing Enums use .Parse method on enum, for example: `req.Type = pb.EventType_Unknown.Parse(a.Type)`

### Logging

- Use structured `xlog` with `logger.ContextKV` when a context exists.
- Log keys are `snake_case` and stable (`project_id`, `reason`, `err`).
- Keep the value type of a given key stable.
- No per-row `INFO` logs in loops.

### SQS and jobs

- Failures, cancellations, invalid messages, and skipped work must not be
  finished as success by `RunContext.Finish`.
- Preserve `awsprov.ErrInvalidSQSMessage`.
- Check feature settings before enqueueing work that would immediately
  no-op.

### Billing and payments

- A project is bound to a billing account before quote or order creation.
- Quote and order totals are computed on the server from `Amount` and the
  product's prices (`up_to` metadata). Do not reintroduce a client
  `PriceID` or a request `BillingAddress` on `PaymentOrderRequest`.
- Tax and address come from the Stripe Customer on the billing account.
- A membership row is either project-scoped or billing-account-scoped,
  never both.
- `pb.Role_Billing` is 4; Admin and Owner imply Billing. Do not reuse role
  integers incorrectly.
- A personal account (empty name) cannot invite members until it is named
  and the Stripe Customer has a billing address.

### Tests

- Use `assert` and `require`.
- Assert the real `err` and distinguish missing keys from empty values.
- Match mocks on meaningful fields (bucket, key, queue URL), not only
  `gomock.Any()` call order.
- Fixtures must match their comments. Cleanup runs before resources close.

## Review output

For each finding report:

- severity (`Blocker` / `Should fix` / `Nit`)
- file and location
- what is wrong
- a concrete fix

If the diff is clean against `STYLEGUIDE.md` and these checklists, say so.
Do not invent nits.
