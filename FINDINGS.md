# Findings

Active defects and verification gaps. Use stable IDs in reviews; IDs are
never reused. Update or remove an item in the same change that resolves it.
Larger contract or architecture work belongs in [ROADMAP.md](ROADMAP.md).

This file is gitignored (the repository is public): committed code and docs
do not cite these IDs.

Open = actionable work; Needs Decision = a compatibility or operational
choice. Source symbols are stable references; line numbers are omitted.

## Index

| ID    | Package / location                                                                                                                | Title                                                                               | Type        | Severity | Status         |
| ----- | --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ----------- | -------- | -------------- |
| F-011 | internal/ca: Registry.FindProfile, FindIssuer                                                                                     | Failed resolutions are not cached, so an unknown label costs DB lookups per request | performance | LOW      | Needs Decision |
| F-012 | server/service/backend: GetIssuer, model.Issuer.Pb                                                                                | `pb.Issuer.Profiles` is never populated                                             | api         | LOW      | Needs Decision |
| F-013 | internal/ca: Keys.Destroy; server/service/backend: UpdateIssuer                                                                   | Destroying an issuer whose provider key cannot be removed only logs                 | correctness | LOW      | Needs Decision |
| F-031 | etc/dev/trustyca-config.yaml: backend identity_map.tls                                                                            | The `trustyca-client` role of the backend has no rule                               | config      | LOW      | Needs Decision |
| F-032 | internal/db/pgsql: ListMemberships; server/service/orgs: GetMembers, findMember, checkLastOwner; internal/authctx: getMemberships | The membership reads are capped at the default page (500 rows) without a next page  | correctness | LOW      | Accepted       |
| F-033 | xdb schema/postgres.go: postgresQueryIndexes; internal/db/schema/schema.gen.go, internal/db/README.md                             | The index column order of the generated schema comments is not stable               | tooling     | LOW      | Open           |

## Details

### F-011: Negative resolutions are not cached

`Registry.FindProfile` and `FindIssuer` cache only the rows they find. A
client that repeats a request for an unknown profile, or for a label that
only exists in the org scope from a project (first probe misses), costs the
DB one or two lookups per request. The authorizer does not cache negative
results either; a short negative TTL with invalidation on `RegisterProfile`
and `RegisterIssuer` is the fix if it shows up.

### F-012: `pb.Issuer.Profiles` is empty

`model.Issuer.Pb` does not fill `Profiles`, the list of profile labels the
issuer serves (the profiles bound to its label plus the `*` profiles in its
`AllowedProfiles`); `internal/db/model` issuer_test asserts it is empty
("profiles are resolved by the service"), but no service resolves them.
`GetIssuer` could compute it with `ListProfiles` by issuer label in the
issuer's scope. Decide what the scope is first: a profile resolves in the
project, then the org, and so does its issuer label, so an org-wide issuer
also serves the project profiles bound to its label in every project
without an issuer of that label, and an org-wide profile requested in a
project with its own issuer of the label resolves to that project issuer.
"The labels of the Active profiles that a request in the issuer's own
scope resolves to it" is computable with one bounded list; the labels
across the projects of the org are not.

### F-013: A key that cannot be destroyed is only logged

`UpdateIssuer(Status=Destroyed)` updates the row first, which clears
`key_protected`, then calls `Keys.Destroy`; for a provider that does not
implement `cryptoprov.KeyManager`, or when the provider call fails, the key
stays in the provider and the service logs an error and returns the
Destroyed issuer. Decide whether the status change should fail instead, or
the task that reconciles provider keys should own the retry.

### F-031: The trustyca-client role of the backend has no rule

The backend listener maps `spiffe://trustyca/client` to `trustyca-client`
(`identity_map.tls.roles`), but no `authz` rule of any listener admits
the role, so the certificate reaches only the public status routes, as a
guest would. `make gen_test_certs --client` generates `trustyca_client`,
which the unit tests use as a client certificate that is no operator or
service of the CA. Remove the mapping, or name what the identity is for
and give it its rule.

DECISION: remove `trustyca-client`, we should only have real roles matching the pods:
cis/aia, ca, peer

### F-032: Membership reads are capped at the default page

`ListMemberships` runs its query through `xdb.ExecuteQuery` with the page
of the request, `xdb.DefaultPageSize` (500 rows) when the callers pass no
limit, and returns a slice without a next page. `GetMembers`, `findMember`,
`checkLastOwner` and the authorizer's `getMemberships` read a whole scope
from it: an org with more than 500 grants, or a user with more than 500
grants, silently loses the rest. A member beyond the cap is not found, an
Owner beyond it is not counted, and the cached grants of a user omit it
(fails closed: fewer permissions). The order is deterministic
(`email ASC, id ASC`), so the dropped rows are the last by email.
Options: page `GetMembers` (`MembersResponse` has no `NextPage`), or
let the callers that need every row (the authorizer, `checkLastOwner`) loop
over the pages in the DB layer.

Decision: accepted as is. Support users are no longer members of every org,
so a user or an org with more than 500 grants is not expected; `GetMembers`
and `ListAPIKeys` keep one page of `xdb.DefaultPageSize` rows.

### F-033: Generated index column order is not stable

`xdbcli schema generate` lists the columns of an index with
`array_agg(a.attname)` over a join on `a.attnum = ANY(ix.indkey)` and no
ordering (xdb `schema/postgres.go`, `postgresQueryIndexes`), so every
`make gen-sql-schema` may reorder the columns in the comments of
`schema.gen.go` and `model.gen.go`, in `internal/db/README.md` and in
`Documentation/api/internal_db_schema.md`. The run that added
`idx_org_name_id` flipped `idx_certificate_org_id_desc` to `[id,org_id]`
and lists the new index as `[id,name]`, although the migration defines
`(name, id)`. Only comments and docs are affected: the `Indexes` name lists
are sorted and the queries do not read the column order. Fix in xdb:
`array_agg(a.attname ORDER BY array_position(ix.indkey::int2[], a.attnum))`,
release, reinstall `xdbcli` and regenerate; the migration SQL is the
reference until then.

NOTE: xdb is updated to generate deterministic order.

### F-034: Certificate and key verification drops the delegated OCSP profile, so an ML-DSA issuer with an OCSP URL cannot be imported, activated or bootstrapped

FIXED: `setVerifiedCertificate` clears the OCSP URL with the profile for the
verification-only build; `CheckOCSPSigner` refuses the settings at
registration, import, activation and update (`ErrOCSPSignerRequired`).

`internal/ca/issuer.go` `setVerifiedCertificate` clears
`acfg.AIA.DelegatedOCSPProfile` before `createIssuer`, because the registry
resolves the responder profile later. Since xpki v1.1, `authority.CreateIssuer`
refuses a post-quantum signer whose `aia.ocsp_url` is set and whose
`aia.delegated_ocsp_profile` is empty ("an ML-DSA key cannot sign OCSP
responses"). So `ImportIssuer`, `ActivatedIssuer` and the bootstrap of an
ML-DSA CA fail whenever `OcspURL` is set, even when the row's config names a
valid delegated profile. Classical keys are not affected.
Options: clear `OcspURL` too for the verification-only build (the chain is
what is verified there), or resolve the profile as `Registry.build` does.
Add a registration-time check for `RegisterIssuer` (root or signed): an
ML-DSA `KeySpec` with `OcspURL` and no `DelegatedOcspProfile` is only
rejected when the registry first builds the issuer, after the row exists.

### F-035: `pb.CertProfile` has no `AllowedKeyAlgorithms`, so the xpki key policy of a profile is silently dropped

FIXED: field 26 of `pb.CertProfile`, carried by `pbconv`.

`authority.CertProfile.AllowedKeyAlgorithms` (`allowed_key_algorithms`:
rsa, ecdsa, ed25519, ml-dsa; xpki v1.1) is not in `pb.CertProfile`, and
`internal/ca/pbconv` `ProfileToPb`/`ProfileFromPb` do not carry it. A
ca-config or `trustycactl ca profile register --file` profile that sets it
is stored without it, and the issuer signs any key algorithm the profile
meant to exclude. Add the field to `pkix.proto`, both conversions and their
round-trip tests (`pbconv/profile_test.go`), then `make proto docs`.

### F-036: Authority errors name the registry's internal profile name

`Registry.Resolve` registers a profile in the `authority.Issuer` under an
internal name (`<profile id>@<stamp>`, `addProfile`), and the authority
puts that name in its errors ("public key algorithm ECDSA is not allowed by
profile 1006@1794204553931"). `SignCertificate` now replaces it with the
label of the request before answering; the issuer creation errors
(`NewSignedIssuer` through `issuerError`) still carry it. ROADMAP RM-010.

### F-037: ListLogins is the last list with an offset

`ListLogins(ctx, limit, offset)` still runs `xdb.ExecuteQueryWithPagination`
over `query.ListAllColumns`, after RM-009 moved every list request to the
cursor. No service calls it, only `TestLoginUser`, whose comment says it
fails beyond 500 rows. Options: delete the method and `ListAllColumns`, or give
it a request with a `Cursor` by id when something needs the logins.

FIXED: both deleted.

### F-038: A CA that signs OCSP itself has no digital signature usage

`CheckOCSPSigner` lets a classical issuer with an `OcspURL` and no
`DelegatedOcspProfile` sign OCSP responses with the CA key, while the CA
profiles (`tenant_ca`, `ROOT`, `L1_CA`, `L2_CA`) set `cert sign` and `crl sign`
only. RFC 5280 4.2.1.3 asks for `digitalSignature` on a key that verifies other
signatures than certificates and CRLs: `TestPostQuantum_Hierarchy` issues such
a CA (`EC_UNDER_PQ`), with key usage 96. Options: require a delegated responder
for every issuer, which also keeps the CA key off the online OCSP path but
changes `CheckOCSPSigner` and the imports that rely on it, or a CA profile with
`digital signature` for the issuers that sign OCSP.

FIXED: `CheckOCSPSigner` requires the delegated responder for every issuer, and
`SignOCSP` answers an issuer without one as not found.
