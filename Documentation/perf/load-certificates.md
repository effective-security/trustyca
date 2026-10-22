# Load test: the certificate tables at 10M rows

The run of `tests/load` that PLAN.md phase 7 asked for: 10M synthetic
certificates with their revocations in a disposable database, every query
of the CA explained at that volume, and the insert of SignCertificate.
Rerun it with:

    go run ./tests/load -rows 10000000 -batch 50000 -load -explain -sign 2000 -out load.md
    go run ./tests/load -drop

## Setup

- PostgreSQL 15.7 in the dev container (`docker-compose.trustyca.yml`):
  `shared_buffers` 128MB, `work_mem` 4MB, the defaults of the image. The
  numbers are of that container, not of a tuned production instance; the
  plans are what matters.
- Rows: 10,000,000 certificates, one of every 100 revoked (100,000
  revocation rows), 200 orgs, 5 projects per org, a fifth of the rows
  org-wide, 2 issuers per org, a fifth of the rows in one big org
  (2,000,000 rows), every key with three certificates, validity 180 days
  issued within the last year (about half expired and still Active, the
  worst case of the status task), one 900-byte PEM per row.
- Queries: the ones `internal/db/pgsql/query` builds, with the arguments
  the services pass; `provider` is the wall time of the provider call, the
  plan is `EXPLAIN (ANALYZE, BUFFERS)` of the same statement.

## Results

Load: 10M certificates and 100k revocations in 13m11s (12.6k rows/s at the
end, index maintenance bound); the table is 13 GB, each list index 0.3 to
1.3 GB (sizes below).

### Lists (`ListCertificates`, 100 rows a page)

`before` is the shipped schema of phase 6, `after` the schema of this
change: `(org_id, id DESC)` added and `(ikid, id DESC)` replaced by
`(org_id, ikid, id DESC)`. Times are the execution time of the plan; the
provider call adds about 0.5 ms of connection, decoding and result
building.

| List                                        | before                                            | after                                     |
| ------------------------------------------- | ------------------------------------------------- | ----------------------------------------- |
| big org (2M rows), first page               | 0.04 ms, pkey backward scan, 24 pages             | same                                      |
| big org, cursor page                        | 0.04 ms                                           | same                                      |
| big org, offset 10,000                      | 11 ms, 7,226 pages (offset pagination is linear)  | same                                      |
| big org, project                            | 0.05 ms, `(org_id, project_id, id)`               | same                                      |
| big org, visible projects / profile / scope | 0.03 to 0.05 ms                                   | same                                      |
| big org, status Revoked (1% of rows)        | 14 ms, 9,213 pages (status is not indexed)        | same                                      |
| big org, expiring within 30 days            | 0.75 ms, 549 pages                                | 0.42 ms                                   |
| big org, by issuer                          | 0.8 ms, pkey backward scan with filter, 599 pages | 0.05 ms, `(org_id, ikid, id)`, 81 pages   |
| small org (40k rows), first page            | 4.4 ms, pkey backward scan, 4,507 pages           | 0.05 ms, `(org_id, id)`, 102 pages        |
| small org, by issuer                        | 64 ms, bitmap of two indexes, sort, 20,447 pages  | 0.06 ms, 105 pages                        |
| tiny org (10 rows), first page              | 3,869 ms, pkey backward scan, 1.7M pages read     | 0.01 ms, 5 pages                          |
| tiny org, by issuer                         | 2.1 ms                                            | 0.01 ms                                   |
| small org, by an issuer of another org      | not measured                                      | 0.02 ms, 4 pages: nothing to scan         |
| support: every org, by issuer, no org       | 64 ms                                             | 8.8 ms, pkey backward scan; see below     |
| CIS: newest certificate of a key            | 0.03 ms, `(skid)` and a sort of 3 rows            | same                                      |

The tiny org is the case that matters: without an index that the org
leads, the planner found no better plan than walking the primary key
backwards until it had 100 rows of the org, which for a tenant with fewer
rows than that is the whole table, on every page of every list. The
composite `(org_id, ikid, id DESC)` fixes the list by issuer the same way
and makes a list by the key identifier of another org's issuer return
nothing without a scan, which the tenant path (the IKID is public through
the CIS) must not pay for. The support list across orgs by IKID resolves
the org of the issuer first (`server/service/admin`), so it takes the
org-led index too; the 8.8 ms above is the raw statement without that
resolution, which is what the list of a deleted issuer's certificates
costs. Extended statistics on `(org_id, ikid)` were tried and made the
planner pick the old `(ikid, id)` index for the tenant list, but did nothing
for a foreign IKID; the composite index covers both.

### Lookups

| Lookup                                   | Plan                                          | Time     |
| ---------------------------------------- | --------------------------------------------- | -------- |
| by issuer and serial (OCSP)              | `unique_certificate_ikid_serial`, 5 pages     | 0.014 ms |
| by thumbprint                            | `unique_certificate_sha256`, 5 pages          | 0.013 ms |
| revocation by issuer and serial (OCSP)   | `idx_revoked_ikid_serial`, 3 pages            | 0.010 ms |

### CRL entries (`ListRevoked` by issuer, valid now, pages of 1,000)

The big issuer (10k revocations, half of them of valid certificates):
4,907 entries in 5 pages in 24 ms; the first page walks the primary key of
`revoked` backwards with the issuer filter (532 pages). A small issuer
(92 entries): a bitmap scan of `(ikid, not_after)`, 0.14 ms. An index
`(ikid, id DESC)` on `revoked` was tried and never chosen; the table is a
hundredth of `certificate`, and the task reads every page of an issuer
anyway.

### Certificate status task

| Batch of 1,000                                   | Time   | Pages dirtied |
| ------------------------------------------------ | ------ | ------------- |
| expire (status Active, not_after < now, by id)   | 93 ms  | about 6,100   |
| delete (retention, not_after < cutoff, by id)    | 8 ms   | 1             |

The expiry update rewrites a wide row (the PEM) and every index entry of it,
because a full page leaves no room for a heap-only update. A fillfactor of
90 on a 1M-row load cut the batch from 46 to 36 ms (dirtied pages 5,760 to
4,015) and no more: the free tenth of a page is smaller than a row, so most
updates still move. A fillfactor low enough for heap-only updates would
cost a quarter of the table in free space for a task that runs in the
background in batches; the default stays. With about half the rows expired
at once, the full pass is 5,000 batches, about eight minutes, in the hourly
task.

### Insert (`RegisterCertificate` with its event, one connection)

| inserts | total   | rate  | p50    | p95     | p99     | max     |
| ------- | ------- | ----- | ------ | ------- | ------- | ------- |
| 2,000   | 2.113 s | 946/s | 848 µs | 1.21 ms | 1.45 ms | 2.80 ms |

At 10M rows the insert of a certificate and its event costs about 0.85 ms
on one connection; the ECDSA signature in front of it is about 0.2 ms
(`server/service/ca` bench_test.go).

### Sizes

| relation                               | size    |
| -------------------------------------- | ------- |
| certificate                            | 13 GB   |
| certificate_pkey                       | 215 MB  |
| idx_certificate_org_id_desc            | 301 MB  |
| idx_certificate_org_project_id_desc    | 692 MB  |
| idx_certificate_org_ikid_id_desc       | 825 MB  |
| idx_certificate_org_project_notafter   | 506 MB  |
| idx_certificate_notafter               | 275 MB  |
| idx_certificate_skid                   | 400 MB  |
| unique_certificate_ikid_serial         | 1313 MB |
| unique_certificate_sha256              | 1191 MB |
| revoked, with its four indexes         | 46 MB   |

## Decisions

- Two indexes added to `sql/trustycadb/migrations/1_tables.up.sql`:
  `idx_certificate_org_id_desc (org_id, id DESC)`, and
  `idx_certificate_org_ikid_id_desc (org_id, ikid, id DESC)` in place of
  `idx_certificate_ikid_id_desc (ikid, id DESC)`. The dev database is
  recreated (`make drop-sql start-sql`) to pick them up; the generated
  schema and model carry them.
- The support list by issuer without an org resolves the org of the issuer
  before the query.
- No partitioning: every tenant path is bounded by the rows of the tenant,
  and the only table-wide reads were planner choices the indexes removed.
  `PARTITION BY HASH (org_id)` stays an open item for a tenant beyond
  roughly 100M rows (DESIGN.md section 4.5).
- The fillfactor of `certificate` stays at the default.
- Offset pagination costs the offset; clients page by cursor.
