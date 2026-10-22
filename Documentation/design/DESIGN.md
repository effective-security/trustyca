# Trusty CA Design

Status: accepted design for v1. Companion documents:
[PLAN.md](../PLAN.md) (execution plan) and
[codemap.md](../codemap.md) (where the code lives).

## 1. Scope

Trusty CA is a multi-tenant Certification Authority used as a backend by other
products. Three services are built from this repo:

| Service             | Transport     | Exposure                                        | Purpose                                                              |
| ------------------- | ------------- | ----------------------------------------------- | -------------------------------------------------------------------- |
| CA (`pb.CA`)        | gRPC only     | backend network only                            | issuers, profiles, signing, revocation, CRL/OCSP signing             |
| CIS (`pb.CIS`)      | gRPC and REST | HTTPS, authenticated callers of the `wfe`       | roots, issuer chains, certificate information and status, CRLs       |
| AIA (binary routes) | REST only     | internet facing, plain HTTP, no authentication  | issuer certificates (AIA), CRL Distribution Points, OCSP responder   |

Out of scope for this repo: Registration Authority (RA) and Validation Authority
(VA). The RA is the only trusted caller of the CA. It authenticates end users,
maps its own tenancy onto CA tenancy, enforces product policy, and calls
`pb.CA` over mTLS.

The access layer (login, users, orgs, projects, memberships, invites, events,
`pb.Auth` and `pb.Orgs`) is part of this repo and is the foundation the CA
features build on. Its model is described in section 3.

## 2. Architecture

```
                 internet                         backend network
   ┌──────────┐   HTTPS    ┌──────────────┐  gRPC/mTLS  ┌──────────────┐
   │ Clients  │──────────▶ │   RA / VA    │───────────▶ │  CA service  │
   └──────────┘            │ (other repo) │             │  pb.CA       │
                           └──────────────┘             └──────┬───────┘
   ┌──────────┐   HTTP     ┌──────────────┐  gRPC/mTLS         │
   │ TLS      │──────────▶ │ AIA service  │──SignOCSP──────────┘
   │ verifiers│  CRL/OCSP  │ REST         │                    │
   └──────────┘            └──────┬───────┘                    │
   ┌──────────┐   HTTPS    ┌──────┴───────┐                    │
   │ Users,   │──────────▶ │ CIS service  │                    │
   │ CLI      │  token     │ pb.CIS (wfe) │                    │
   └──────────┘            └──────┬───────┘                    │
                                  │ read-only                  │ read/write
                                  ▼                            ▼
                           ┌─────────────────────────────────────────┐
                           │ PostgreSQL trustycadb (schema trustyca) │
                           └─────────────────────────────────────────┘
                                                               │
                                                               ▼
                                         ┌─────────────────────────────────┐
                                         │ crypto providers: AWS KMS, GCP  │
                                         │ KMS, PKCS#11, inmem (dev)       │
                                         └─────────────────────────────────┘
```

The three services are `gserver` services in this binary (`server/service/ca`,
`server/service/cis`, `server/service/aia`) and are enabled per listener in
`etc/dev/trustyca-config.yaml`:

- `backend` listener: `status`, `admin`, `ca`. mTLS with client cert auth.
- `wfe` listener: `status`, `auth`, `orgs`, `ui`, `cis`. HTTPS; the CIS is
  read-only and admits any authenticated caller.
- `aia` listener: `status`, `aia`. Plain HTTP on its own port (8888 in the
  dev configuration), no TLS and no identity mapping: the AIA, CRL and OCSP
  URLs embedded in the certificates are fetched by verifiers that have not
  validated anything yet, so they cannot depend on the TLS listener or on
  its authorization, and the listener serves nothing else.

Signing is done in process with `xpki/authority`. Private keys live in a
`cryptoprov` provider and never leave it. Tasks (`server/tasks`) run CRL
renewal and certificate status maintenance on a schedule.

## 3. Tenancy, membership and authorization

### 3.1 Terminology and decision

An **Organization** is the tenant and administrative boundary. A **Project**
owns a collection of resources governed by a common access policy. Every
resource that is not org-wide belongs to exactly one project, and every
project belongs to exactly one org. A _Team_ (a group of users receiving
grants) is not modeled in v1.

Every tenant table carries two columns:

| Column       | Meaning                                                                            |
| ------------ | ---------------------------------------------------------------------------------- |
| `org_id`     | tenant. `NULL` is the platform scope, used only by the CA's own bootstrap issuers. |
| `project_id` | `NULL` means org scope; otherwise the owning project.                              |

`NULL` is the scope marker because `xdb.ID` maps a zero ID to SQL `NULL` in
both directions, so Go code never special-cases a sentinel. Unique keys that
include tenancy columns are declared `UNIQUE NULLS NOT DISTINCT` (PostgreSQL
15+) so a label is unique within its scope. `membership` and `invite` carry a
composite foreign key `(org_id, project_id) REFERENCES project (org_id, id)`,
which guarantees at the database level that a project grant always points at
a project of the same org. CA data-plane tables have no FK to `org` or
`project`: certificates, revocations and issuers are audit records and must
survive tenant deactivation (orgs and projects are soft-deleted via `status`).

Why two levels and not one: a single `org_id` forces the RA to flatten
Org+Project into one CA org, which loses shared issuers across projects,
per-project grants, quotas and audit, and makes adding the column later an
expensive online migration on the `certificate` table. Why not deeper: the
enterprise hierarchies we target (org → team/account/namespace) are two
levels; unbounded depth complicates every query.

### 3.2 Roles and the role hierarchy

A membership is an explicit grant `(org_id, project_id nullable, user_id, role)`.
Roles are `Viewer`, `User`, `Support`, `Billing`, `Security`, `Admin`, `Owner`
for people and `APIKey` for machine identities. Roles are never compared
numerically. Each method declares the **minimum roles** that may call it with
`(es.api.allowed_roles)`, and a caller passes when one of its roles at the
request scope can assume one of them. The hierarchy is
`authctx.CanAssumeRoles`:

| Caller role | May assume                                             |
| ----------- | ------------------------------------------------------ |
| Owner       | Owner, Admin, Security, Support, Billing, User, Viewer |
| Admin       | Admin, Security, Support, Billing, User, Viewer        |
| Security    | Security, User, Viewer                                 |
| Support     | Support, User, Viewer                                  |
| Billing     | Billing, User, Viewer                                  |
| User        | User, Viewer                                           |
| Viewer      | Viewer                                                 |
| APIKey      | APIKey                                                 |

With `allowed_roles = "User,APIKey"` a Viewer is denied, a Security member is
allowed because Security may assume User, and an API key is allowed subject to
its scopes (section 3.5). `APIKey` is never assumed by a person's role, so a
method that lists `APIKey` opts in to machine access explicitly.

Roles at a scope are the union of the caller's grants that apply there
(`Grants.Roles`):

- org scope (no `ProjectID` in the request): the org-wide grant, or the derived
  Viewer of section 3.3;
- project scope: the org-wide grant plus the explicit grant in that project.

`Grants.HighestRole(projectID, allowedRoles)` returns the caller's role that
satisfies the method, or `None`. Grants are additive and independent: a project
grant never reduces the org-wide role, removing one grant never touches the
other, and a project Admin never becomes an org Admin because project roles
are not consulted at org scope. `Owner` and `Billing` cannot be granted per
project (`authctx.ProjectRoles`).

Examples from the spec, as implemented in `authctx.Grants`:

| User | Org grant | Project 201 grant | Effective                                                   |
| ---- | --------- | ----------------- | ----------------------------------------------------------- |
| 300  | User      | Admin             | 201: Admin; other projects: User; org scope: User           |
| 301  | none      | Admin             | 201: Admin; other projects: none; org scope: derived Viewer |
| 302  | Admin     | Viewer            | 201 keeps Admin from the org-wide grant                     |
| 303  | Viewer    | none              | Viewer in every current and future project                  |

### 3.3 Derived org Viewer

A user with project grants and no org-wide grant is classified as a derived
org Viewer. It is computed, never stored: `Grants.ResolvedOrgRole()` returns
`Viewer` with `RoleSource_Project`, and `Grants.Roles(0)` contains only
`Viewer`. That allows the org to appear in the selector, be selected, its
summary read and its projects listed; `ListProjects` returns only the granted
projects (`Grants.CanListAllProjects` is false without an org-wide role).
Unlike an explicit org Viewer, the derived Viewer is not inherited by other
projects. When the last project grant is removed the derived access
disappears within the cache bound.

### 3.4 Tokens and org selection

Login (`/v1/auth/callback`) issues a token for the first accessible org, or
for a default org created for a user without any grant when
`orgs.default_org_name` is configured (with a default project when
`orgs.default_project_name` is set). `Auth.SelectOrg(OrgID)` verifies an active
org-wide or project grant and issues a new token; it is the only tenant
request that carries `OrgID`.

Token claims:

| Claim             | Meaning                                                                                         |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `sub`             | user ID, or the API key ID                                                                      |
| `org`             | selected org (the identity mapper's tenant claim)                                               |
| `org_role`        | resolved role for display: the explicit org-wide role, `Viewer` when derived, `APIKey` for keys |
| `org_role_source` | `direct` or `project`                                                                           |
| `scope`           | scopes granted to an API key or a scoped user token; absent on regular user tokens              |
| `project`         | the project an API key is restricted to; absent for org-wide keys                               |

The token carries neither all memberships nor project roles; discovery is an
API responsibility (`Orgs.GetUserOrgs`, `Orgs.GetUserMemberships`,
`Auth.GetCallerScope`). Authorization never trusts `org_role` for people:
roles are always resolved from the grants in the database. For API keys
`org_role`, `scope` and `project` are authoritative because the key has no
membership rows.

### 3.5 Runtime authorization

Two method options drive `authctx.CheckAccess`, which runs in the gRPC
interceptor and the REST handlers:

| Option                   | Applies to                                       | Meaning                                                         |
| ------------------------ | ------------------------------------------------ | --------------------------------------------------------------- |
| `(es.api.allowed_roles)` | every caller                                     | minimum roles at the request scope, judged with `CanAssumeRole` |
| `(es.api.scopes)`        | `APIKey` callers and tokens with a `scope` claim | scopes the token must hold, all of them                         |

Methods without `allowed_roles` need an authenticated caller only. Scopes are
declared only on methods that list `APIKey`; `CreateAPIKey`, for example, has
`allowed_roles = "Admin"` and no scopes because keys cannot mint keys. The
scopes are `org:read`, `project:read`, `ca:read`, `ca:write`, `certs:read`,
`certs:issue`, `certs:revoke`; a key may hold `<area>:*` or `*`
(`authctx.HasScope`). A key created without scopes gets `org:read`,
`project:read`, `ca:read`.

`CheckAccess` proceeds as follows:

1. `privpb` and `pb.Status` are restricted to `trustyca-*` service roles as
   before, and `/pb.Auth/*` (login, `SelectOrg`, `RevokeToken`, discovery) is
   gated by the server's identity configuration, not by roles.
2. Service identities (`trustyca-ra`, `trustyca-aia`, ...) bypass grants: they
   pass tenant scope explicitly and authorized the end user themselves. On
   the backend listener they come from mTLS: the backend interceptor builds
   the caller context from the context the WFE forwards
   (`x-trustyca-context`) when there is one, otherwise from the identity the
   listener authenticated.
3. The org comes from the token; an explicit `OrgID` in a request must match
   it. `ProjectID` (the `ProjectRequester` interface) selects project scope,
   and the project must belong to the org and be active.
4. User tokens: `Authorizer.CheckRole(org, project, user, allowedRoles...)`
   loads the caller's grants (cached per user for 3 minutes, invalidated after
   every membership mutation) and requires `HighestRole` at the request scope
   to be a role. A token with a `scope` claim must additionally hold the
   method's scopes.
5. API keys: the method must list `APIKey`, a project scoped key may act only
   in its project (a request without `ProjectID` defaults to it), and the key
   must hold every scope of the method. A row resolved by the service (a
   certificate by ID, for example) is authorized against its own project: a
   project scoped key reads an org-wide row as the derived org Viewer and may
   not change it.

The service layer adds the checks the interceptor cannot express: resource
ownership (a project resolved by alias is authorized after resolution with
`CheckRole(..., Viewer)`), collection filtering (`ListProjects` returns granted
projects unless the caller has an org-wide role), and grantability
(section 3.6). Cross-org project IDs, inactive projects and unknown projects
are all reported as not found so existence is not leaked.

`Auth.GetAllowedMethods` lists the methods the caller may call at org scope,
grouped by service; `Auth.GetCallerScope` returns the resolved org role,
explicit project roles, token scopes and, per method, the required roles and
scopes with the verdict at org scope. Both are read-only views of the same
rules and back the CLI commands `auth allowed` and `auth scope`.

### 3.6 Membership administration

- `AddMember` creates an org-wide or project grant, or an invite at the same
  scope when the user does not exist yet. The caller must be allowed to grant
  the role at that scope (`Grants.CanGrantOrgRole`, `CanGrantProjectRole`): an
  Owner may grant anything org-wide; an org Admin grants any org role except
  Owner; an Admin at the project, inherited or explicit, grants project roles.
- `ChangeMemberRole` and `DeleteMember` act on the grant at the requested scope
  only and require the caller to be allowed to grant both the current and the
  new role there. The last org Owner cannot be removed or demoted.
- Invites carry `expires_at` (14 days by default); expired invites are skipped
  at login and rejected on acceptance. Acceptance creates the explicit grant at
  the invite's scope and deletes the invite. No synthetic org grant is created.
- Every mutation invalidates the affected user's cached grants and records an
  `event` row (`OrgMemberAdded`, `ProjectMemberRoleChanged`, ...).

### 3.7 RA mapping

| RA concept                                  | CA concept                                                                 |
| ------------------------------------------- | -------------------------------------------------------------------------- |
| tenant / enterprise                         | `org`                                                                      |
| team, cloud account, namespace, environment | `project` (alias is client chosen, e.g. the account ID)                    |
| end-user identity and product roles         | RA responsibility; the CA sees `OrgID`, `ProjectID` and the RA's mTLS role |

### 3.8 API keys

An API key is a machine identity owned by an org, optionally restricted to one
project. It has no user and no membership rows; its access is the `APIKey`
role plus the scopes stored with it.

- Table `apikey`: `(org_id, project_id nullable, key, secret, label, scopes[],
status, expires_at, used_at, used_count)`, composite FK
  `(org_id, project_id) -> project (org_id, id)` and an index on
  `(org_id, project_id)`. The DB layer is plain CRUD (`RegisterAPIKey`,
  `GetAPIKey`, `ListAPIKeys`, `UseAPIKey`, `DeleteAPIKey`).
- `Orgs.CreateAPIKey` (`allowed_roles = "Admin"`) validates the label, scopes
  (`authctx.IsKnownScope`), project and expiry (90 days by default), stores the
  secret protected with the server's data protection key and returns the clear
  secret once. The public key is `sk_<OrgID>_<protectedKeyID>`.
  `ListAPIKeys` never returns secrets; `DeleteAPIKey` removes the key.
  `CreateAPIKey` and `DeleteAPIKey` record `APIKeyCreated` and
  `APIKeyDeleted` events.
- `Auth.AuthenticateAPIKey` accepts the key and an HMAC-SHA256 signature of
  the method and timestamp under the secret, checks expiry and status, bumps
  usage and issues a one hour token with `org`, `org_role = APIKey`, `scope`
  and `project` claims (`APIKeyLogin` event). From there the key is an
  ordinary bearer token and section 3.5 applies.
- CLI: `api-key create|list|delete`.

## 4. Domain model

Schema: `sql/trustycadb/migrations/1_tables.up.sql`. IDs are flake IDs from
`xdb.IDGenerator`. All timestamps are `TIMESTAMP(3) WITH TIME ZONE`.

### 4.1 Access layer

| Table                | Purpose                                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `org`                | tenant; soft-deleted via `status`                                                                        |
| `project`            | `(org_id, alias)` unique, `(org_id, id)` unique for composite FKs; soft-deleted via `status`             |
| `membership`         | grant `(org_id, project_id NULL, user_id, role)`, `UNIQUE NULLS NOT DISTINCT`, composite FK to `project` |
| `invite`             | `(org_id, project_id NULL, email, role, expires_at)`, same keys as membership                            |
| `vw_membership_info` | membership joined with org, project and user names for listing                                           |
| `event`              | audit trail with nullable `org_id` and `project_id`                                                      |

### 4.2 `issuer`

One row per CA certificate that the service can sign with, or is about to be
able to sign with.

| Column group   | Columns                                                                                               | Notes                                                                                                  |
| -------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| tenancy        | `org_id, project_id, label`                                                                           | `UNIQUE NULLS NOT DISTINCT (org_id, project_id, label)`                                                |
| classification | `type` (`pb.AuthorityType`), `status` (`pb.IssuerStatus`), `parent_id`                                | `parent_id` points at the signing issuer inside this CA, `NULL` for roots and externally signed        |
| certificate    | `skid, ikid, serial_number, subject, issuer, sha256, not_before, not_after, pem, chain_pem, root_pem` | `UNIQUE (skid)`: one key, one active certificate; renewal means key rotation                           |
| pending        | `csr_pem`                                                                                             | set while `status = Pending`                                                                           |
| key            | `key_provider, key_id, key_protected`                                                                 | provider manufacturer and key ID; `key_protected` is dataprotection-wrapped PEM for software keys only |
| runtime        | `config` JSONB (`pb.IssuerConfig`), `crl_number`                                                      | AIA/CDP/OCSP URL templates, CRL and OCSP timings, allowed profiles                                     |

Lifecycle: `Pending -> Active -> Archived -> Destroyed`. Archived issuers do
not sign new certificates but keep producing CRLs and OCSP. Destroyed issuers
had their key removed from the provider; the last CRL stays published until
`next_update`.

### 4.3 `root_certificate`

Trust anchors published by CIS: `org_id, skid, subject, sha256, trust, pem, validity`.
Roots created by `RegisterIssuer(Type=Root)` are inserted automatically;
external anchors are added with `RegisterRoot`.

### 4.4 `certificate_profile`

`org_id, project_id, label, issuer_label, status, config JSONB, timestamps`,
`UNIQUE NULLS NOT DISTINCT (org_id, project_id, label)`. `config` is
`pb.CertProfile`, which has the same shape as the YAML `profiles:` entries in
`etc/dev/ca-config.*.yaml`, so a YAML profile can be imported without
translation. Validation reuses `xpki/authority.CertProfile.Validate`.

### 4.5 `certificate`

Immutable issuance record plus mutable `label`, `metadata`, `locations`,
`status` (`pb.CertificateStatus`). Indexes:

| Index                             | Query                                                                 |
| --------------------------------- | --------------------------------------------------------------------- |
| `UNIQUE (ikid, serial_number)`    | OCSP, CRL, `GetCertificate(IssuerSerial)`                             |
| `UNIQUE (sha256)`                 | dedupe, lookup by thumbprint                                          |
| `(org_id, id DESC)`               | `ListCertificates` of an org, newest first, keyset cursor on `id`     |
| `(org_id, project_id, id DESC)`   | `ListCertificates` of a project                                       |
| `(org_id, project_id, not_after)` | expiring certificates per tenant                                      |
| `(not_after)`                     | the `cert_status` task: expiry and retention, all orgs                |
| `(org_id, ikid, id DESC)`         | list per issuer; the org leads, since an issuer belongs to one org    |
| `(skid)`                          | lookup by subject key                                                 |

Every tenant path is bounded by the rows of the tenant through these
indexes, and the lists page by keyset cursor. The 10M-row load test
([perf/load-certificates.md](../perf/load-certificates.md)) confirmed the
plans and added the two org-led list indexes: without them the planner
walked the primary key backwards for the rows of a small org (the whole
table) and mis-planned the list by issuer. Partitioning is not needed at
this volume: a path to `PARTITION BY HASH (org_id)` exists because every
unique key can carry `org_id`, and stays an open item for a tenant beyond
roughly 100M rows. A retention task removes certificates expired for longer
than a configurable period; CRLs only need revoked and unexpired entries.

### 4.6 `revoked`

`certificate_id (FK, cascade), ikid, serial_number, not_after, revoked_at, reason, reason_text`
with `UNIQUE (certificate_id)`. `ikid`, `serial_number`, `not_after` are
denormalized so a CRL is produced with one index range scan on
`(ikid, not_after)` with `not_after > now()`. Revocation also sets
`certificate.status = Revoked` in the same transaction.

### 4.7 `crl`

Current CRL per issuer, `UNIQUE (ikid)`, replaced on every publish together
with `issuer.crl_number = crl_number + 1` in one transaction. `locations`
records where the CRL was uploaded when external publishing is enabled.

## 5. Issuers and key management

### 5.1 Two sources of issuers

1. **Bootstrap (platform) issuers** come from `etc/dev/ca-config.local.yaml`
   style files (`ca.bootstrap_config`) loaded with `authority.LoadConfig`.
   They are the service's own Root, L1 and L2 CAs and are created offline
   with `hsm-tool`. On startup `internal/ca.Bootstrap` mirrors them into
   `issuer` rows with `org_id IS NULL`, so that platform issuers sign tenant
   CA certificates and the CIS and AIA serve their chains and CRLs through the same
   tables; the root bundle becomes `root_certificate` rows and the profiles
   `certificate_profile` rows with `org_id IS NULL`. The key file of an
   issuer is either a key URI, stored as the key reference, or key material,
   stored wrapped (section 5.3); both are checked against the certificate.
   The bootstrap is idempotent: a registered issuer with the same key only
   has its runtime settings refreshed, and a certificate for a new key is an
   error until the old issuer is archived under another label (section 5.4).
   A `disabled` issuer is archived, so that it stops signing on every
   instance, and becomes Active again when the configuration enables it; a
   destroyed one is an error. The anchor of a root issuer is registered
   again on every start, since it is a separate row. After the rows, every
   enabled issuer is loaded with its key and delegated OCSP profile, and
   one that does not load fails the start rather than the first request.
   The URL templates of file issuers use `:ISSUER_ID`, because the config
   loader expands `${...}` as environment variables.
2. **Tenant issuers** are created through `pb.CA` and live only in the DB.
   The first issuing CA of an org is signed by a platform intermediate that
   allows a CA profile: in `etc/dev/ca-config.local.yaml` the L1 CA
   `trusty.l1` (path length 1) lists `tenant_ca` in its `allowed_profiles`,
   while the L2 `trusty.svc` has path length zero and signs no CA.
   `trustycactl ca org bootstrap` registers it and copies the template
   profiles (section 6).

The CA does not keep one `authority.Authority`: that registry is keyed by
label, and the labels of different orgs, and of different projects of one
org, collide. The issuer registry of `internal/ca` resolves the issuer and
the profile of every request in the scope of the request (section 6) and
keeps the built `authority.Issuer` per issuer row ID, which is unique across
orgs, in a cache bounded by size and by `ca.issuer_cache_ttl`; the
resolutions of a scope and label are cached under the requested scope. A
mutation made through the service invalidates its entries at once; one made
by another instance is visible after the TTL. Profiles are registered on the
issuer under a versioned name (the profile row ID and its `updated_at`), so
one issuer serves the profiles of several scopes with equal labels, and a
replaced profile is picked up without rebuilding the issuer.

#### Decision: an issuer registry, not an authority per org

The single `authority.Authority` of the stand-alone CA was kept as long as
the service had no tenants. Two multi-tenant shapes were weighed:

| Option                                                                                     | Pros                                                       | Cons                                                                                                                                                          |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A: one `Authority`, issuers registered as `{org}_{label}`, every issuer loaded at startup | lookups are a map read; issuers are warm                    | startup loads and holds every tenant key; one typo in the prefix crosses a tenant boundary; no project scope; a broken tenant issuer fails the start          |
| B: an `Authority` per org, created on demand and kept in an LRU                            | explicit boundaries; only the orgs in use are in memory     | still keyed by label, so project-scoped issuers and profiles of one org collide; cannot apply project shadowing; cold orgs pay a full load                    |

The registry is option B at the granularity the data model has: the cache
key is the issuer row, the resolution follows the `(org, project, label)`
scopes of the DB, and the `authority.Issuer` is the signing object only.
The measurements of PLAN.md (phase 2a) show the warm resolution costs
about 0.3 µs against a software ECDSA P-256 signature of about 190 µs, and a
cold issuer costs the DB lookups plus about 0.2 ms of construction once per
TTL.

### 5.2 Creating a tenant issuer

| Shape                | Request                                                             | Result                                                                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Self-signed root     | `Type = Root`, no `ParentID`, `Profile` = a CA profile with `is_ca` | `Active`, root inserted in `root_certificate`                                                                                                                                                     |
| Signed inside the CA | `ParentID` set, `Type != Root`                                      | parent must be an Active issuer visible from the scope of the new issuer (org-wide, or of the same project), or a platform issuer whose `config.allowed_profiles` contains `Profile`; the CA profile is resolved in the scope of the parent (section 6). The chain of the parent must leave room for a subordinate CA with the profile's `max_path_len` (RFC 5280 pathLenConstraint): an issuing CA with path length zero signs no subordinate. A `Root` with a `ParentID` is refused: only a self-signed certificate is a trust anchor. This is how SHAKEN delegated CAs are issued per org from the platform `DELEGATED_L1_CA`. |
| Externally signed    | no `ParentID`, `Type != Root`                                       | key generated, `Pending` with `Csr` and the key identifier of the key as `skid`; `ActivateIssuer` uploads the certificate and chain, which must be for that key and verify to the given root                                                     |

`ImportIssuer` covers bring-your-own-CA: certificate plus either a provider
key URI (`pkcs11:` form, as the providers export it) or a PEM key that is
stored wrapped by the `dataprotection.Provider`; the key must match the
certificate and the chain must verify to the given or the self-signed root.

The `chain_pem` of an issuer holds the CA certificates between the issuer
and its root, never the root itself; `root_pem` holds the root, and a
self-signed issuer is its own root. Stored PEM has no trailing newline.

### 5.3 Keys

- Default `KeySpec` is ECDSA P-256. RSA 2048 to 4096 and P-384 are accepted.
- The key provider is chosen per issuer (`KeyProvider`, a `manufacturer` or
  `manufacturer/model` of `crypto_provider`); empty is the default provider.
  Production defaults to a KMS provider; `inmem` is for tests and
  development only: `ca.allow_software_keys` admits the keys that no
  provider holds (the `inmem` keys, the PEM keys of `ImportIssuer`, the
  bootstrap key files), off by default and refused outright when
  `service.environment` is `prod`; the wrapped keys of existing rows still
  load.
- A key a provider holds is referenced by its key URI in `key_id`, with the
  manufacturer in `key_provider`, and never leaves the provider. A software
  key (generated by `inmem`, or given as PEM to `ImportIssuer` or in a
  bootstrap key file) is wrapped by the `dataprotection.Provider` into
  `key_protected`, with `key_provider = inmem` and the key label in
  `key_id`.
- Key labels in the provider are `trustyca/{org_id}/{project_id}/{label}`.
- The key identifier of a key is the SHA-1 of its public key bits (RFC 5280
  method 1): the SKID the CA puts in the certificates it issues, the IKID of
  the certificates the key signs, and the issuer key hash of their OCSP
  requests.
- `Destroyed` calls `KeyManager.DestroyKeyPairOnSlot` where the provider
  manages keys and clears `key_protected`; a provider key that cannot be
  destroyed is logged for the operator.

### 5.4 Renewal

Renewing an issuer means registering a new issuer with a new key (new SKID)
and archiving the old one. Reusing a key would give two certificates the same
SKID and make `/v1/crl/{ikid}` ambiguous, so `UNIQUE (skid)` forbids it.
The label is unique per scope in every lifecycle status today, so the old
issuer must be archived under another label before the new one takes the
label; a unique index on Active issuers only is planned (ROADMAP.md).

## 6. Profiles

Profiles are per `(org, project)`. `issuer_label` binds a profile to an issuer
of the same org; `"*"` means any issuer whose `config.allowed_profiles` lists
the profile, which is how one `ocsp` profile serves many issuers.

Resolution at `SignCertificate(OrgID, ProjectID, Profile, IssuerLabel)`:

1. profile: `(org, project, Profile)` then `(org, NULL, Profile)`; not found is `NotFound`.
2. issuer label: `profile.issuer_label` unless it is `"*"`, in which case
   `IssuerLabel` from the request is required and must be in the issuer's
   `allowed_profiles`. If both are set they must match.
3. issuer: `(org, project, label)` then `(org, NULL, label)`, `status = Active`.
4. the caller's role at the project scope (`User` or an API key with
   `certs:issue`), when the caller is not the RA.

An inactive profile is not found and does not fall back to the org scope.
Platform profiles are never visible to tenants; the platform scope resolves
only for the parent of a tenant issuer. Tenant onboarding copies a set of
template profiles into the org (`trustycactl ca org bootstrap --org <id>
--parent <platform issuer> --templates <dir>`: one YAML profile per file,
named after its label; a template without `issuer_label` binds to the new
issuing CA, one bound to `*` is listed in the allowed profiles of the
issuer), which keeps tenant configuration explicit and auditable.

The registry caches a resolution under the scope and label of the request,
for `ca.issuer_cache_ttl`, and only resolutions that succeed; a request for
an unknown profile queries the DB every time.

Reads and mutations by ID follow the same visibility. The interceptor
authorizes the scope a request names, but `GetIssuer`, `GetProfile`,
`UpdateIssuer`, `ActivateIssuer` and `DeleteProfile` resolve a row whose
project the request did not name, so the service authorizes the row's
project again with the method's roles: an org-wide row is visible to every
member of the org and to every API key of the org; a project row to the
members with a grant in that project (an org-wide role is inherited) and to
the API keys restricted to it. A row of a project the caller cannot read is
not found, a row it can read but not change is forbidden. A list without a
project returns the org-wide rows and the rows of the caller's projects for
a member with project grants only (section 3.3); an org-wide role lists
every project. The parent of a new issuer must be visible from the scope of
the new issuer: platform, org-wide or the same project.

## 7. Signing flow

```
RA ──SignCertificate──▶ CA service
  1. authz: mTLS role trustyca-ra (or a User token / API key with certs:issue); OrgID required
  2. validate ProjectID belongs to OrgID (cached)
  3. resolve profile and issuer (section 6)
  4. build csr.SignRequest: CSR bytes (PEM/DER), SAN, Subject, NotBefore/NotAfter,
     Extensions; profile limits win over request values
  5. authority.Issuer.Sign -> x509.Certificate
  6. INSERT certificate (status Active) + INSERT event CertificateIssued  [tx]
  7. return pb.Certificate with Pem and IssuersPem
```

`NotAfter` in the request may only shorten the profile expiry. Extensions not
in `allowed_extensions` fail the request unless the issuer has
`omit_disabled_extensions`. Serial numbers are 20 random bytes (the RFC 5280
maximum) generated by `xpki/authority`.

## 8. Revocation, CRL and OCSP

- `RevokeCertificate` inserts `revoked` and updates `certificate.status` in one
  transaction, then emits `CertificateRevoked`. `CertificateHold` is
  accepted; `RemoveFromCRL` is refused, since it releases a certificate from
  hold (RFC 5280 section 5.3.1) instead of revoking it, and hold removal is a
  follow-up.
- `PublishCrls` builds a CRL per Active or Archived issuer whose current CRL is
  missing or within `crl_renewal` of `next_update` (or `Force`). CRL number is
  `issuer.crl_number + 1`, stored with the CRL in one transaction, so that of
  two instances publishing at once the second keeps the first's CRL. Entries
  come from `revoked WHERE ikid = ? AND not_after > now()`, with their reason
  codes; the validity is `crl_expiry`, capped at the issuer's expiry. The
  scheduled task `crl_renewal` calls the same code path
  (`internal/ca.CrlPublisher`), which reads the current CRLs of a page of
  issuers in one query and loads an issuer's key only when it signs; a
  revocation does not publish a CRL by itself.
- The `cert_status` task marks expired Active certificates `Expired`, keeping
  a revocation that commits while the statement waits for the row, and, with
  `ca.retention.expired_after`, deletes certificates (and their revocations)
  that expired longer ago than that, in batches.
- `SignOCSP` resolves the issuer by the issuer key hash of the request: the
  issuers in memory match any hash algorithm, and a SHA-1 hash is looked up
  through the `skid` index, since it is the key identifier of a CA
  certificate this CA issued (section 5.3). It then looks up
  `(ikid, serial_number)` and answers `good`, `revoked` or `unknown` with
  `ocsp_expiry` validity. The AIA route carries the IKID and will pass it on
  (ROADMAP.md), which makes the lookup exact for every hash. When `delegated_ocsp_profile` is set the
  issuer signs with a delegated responder certificate created lazily with
  `authority.Issuer.CreateDelegatedOCSPSigner`.
- Neither the CIS nor the AIA holds issuer keys. The OCSP handler of the
  AIA forwards DER requests to `CA.SignOCSP` over the backend gRPC client,
  created on the first request with the `aia.client_tls` identity, and
  caches the signed responses by request hash until their `NextUpdate`, so
  a revocation reaches a cached `good` answer when it expires
  (`ocsp_expiry`). A failure of the CA is an OCSP error response
  (malformedRequest, unauthorized for an issuer the CA does not serve,
  tryLater when the CA cannot be reached, internalError) and is not cached.

## 9. APIs

### 9.1 Orgs (`api/pb/protos/orgs.proto`)

Tenant requests carry no `OrgID`; the server takes the org from the token.

| Group     | RPCs                                                                                                                                         | allowed_roles (scopes)                                                  |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Org       | `RegisterOrg`, `GetOrg`, `UpdateOrg`, `DeleteOrg`                                                                                            | none; `Viewer,APIKey` (`org:read`); `Admin`; `Owner`                    |
| Discovery | `GetUserOrgs` (each accessible org once with the resolved role), `GetUserMemberships` (resolved access and explicit grants in the token org) | none; `Viewer`                                                          |
| Members   | `GetMembers`; `AddMember`, `ChangeMemberRole`, `DeleteMember`, `DeleteInvite`                                                                | `Support,Security`; `Admin`, judged at org scope or at `ProjectID`      |
| Projects  | `RegisterProject`, `UpdateProject`, `DeleteProject`; `GetProject`; `ListProjects`                                                            | `Admin`; `Viewer,APIKey` (`project:read`); `Viewer,APIKey` (`org:read`) |
| API keys  | `CreateAPIKey`, `ListAPIKeys`, `DeleteAPIKey`                                                                                                | `Admin`                                                                 |

`Auth.SelectOrg(OrgID)` switches the org and returns the new token. The CLI
maps these to `auth org`, `auth allowed`, `auth scope`, `org ...`,
`member ...` (org-wide grants), `project ...` / `project member ...` and
`api-key ...`. Its read-only `cert get|status`, `issuer get`, `crl get` and
`root list` commands read the CIS (section 9.3) with the token of the login.

### 9.2 CA (`api/pb/protos/ca.proto`)

| Group             | RPCs                                                                                                                              |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Issuers           | `RegisterIssuer`, `ImportIssuer`, `ActivateIssuer`, `GetIssuer`, `ListIssuers`, `UpdateIssuer`                                    |
| Roots             | `RegisterRoot`, `ListRoots`                                                                                                       |
| Profiles          | `RegisterProfile` (upsert by label), `GetProfile`, `ListProfiles`, `DeleteProfile`                                                |
| Certificates      | `SignCertificate`, `GetCertificate`, `ListCertificates`, `UpdateCertificateLabel`, `RevokeCertificate`, `ListRevokedCertificates` |
| Revocation status | `GetCRL`, `PublishCrls`, `SignOCSP`                                                                                               |

The CA is a backend API: requests carry `OrgID` and optional `ProjectID`
explicitly because the RA calls it with a service identity. Methods declare
`allowed_roles` (`Admin` for issuer, root and profile administration,
`User,APIKey` for signing, `Viewer,APIKey` for reads, `Security` for
revocation, `Admin,Security,APIKey` for CRL publishing, where a project Admin
and an API key restricted to a project name their `ProjectID`) and the
matching `ca:*`/`certs:*` scopes so the
same `CheckAccess` applies when a user token or an API key reaches the CA
directly. Conventions: string IDs, enum wrappers,
`Limit/Offset/Cursor` plus `NextPage` on every `List`, no HTTP annotations.

The operator drives the CA with `trustycactl ca issuer|profile|root|cert|crl
...` and `ca org bootstrap` over the backend listener, with the
`trustyca-admin` client certificate, naming the org of every request;
`privpb.Admin.ListIssuers` and `ListCertificates` are the support lists
across orgs (`ca issuer list` and `ca cert list` without `--org`).

### 9.3 CIS (`api/pb/protos/cis.proto`)

JSON endpoints follow the repo convention `POST /pb.CIS/{Method}`: `GetRoots`,
`GetIssuer`, `GetCertificate`, `GetCertificateStatus`, `GetCRL`; the same
methods are served over gRPC. The CIS is the `cis` service of the `wfe`
listener and admits any authenticated caller (`authz.allow_any_role`): the
methods declare no roles, since the views carry no tenancy, and the
listener refuses a guest. It exposes no tenant listing: every lookup needs
an IKID, serial, SKID, SHA-256 or ID, and `GetRoots` lists the anchors of
the platform or of one org. The public views carry no tenancy and no
client-owned fields: a certificate is returned without its org, project,
profile, label and metadata, a CRL without its org. `GetIssuer` returns the
AIA, CRL and OCSP URLs of the issuer with the key identifier in place of
the placeholder of the template.

### 9.4 AIA (`server/service/aia`)

The binary endpoints the issued certificates reference are hand-registered
in `aia.Service.RegisterRoute` and served by the `aia` listener over plain
HTTP to any caller; the service has no gRPC API:

| Route                                                                                                                     | Media type                  | Source                         |
| ------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------ |
| `GET /v1/cert/{ikid}`                                                                                                     | `application/pkix-cert`     | `issuer.pem` (AIA caIssuers)   |
| `GET /v1/crl/{ikid}`                                                                                                      | `application/pkix-crl`      | `crl.pem` decoded to DER (CDP) |
| `GET /v1/ocspi/{ikid}/{base64-request}`, `POST /v1/ocspi/{ikid}`, `GET /v1/ocsp/{base64-request}`, `POST /v1/ocsp`       | `application/ocsp-response` | `CA.SignOCSP`                  |

Issuer `IssuerConfig` URL templates use `${ISSUER_ID}` (or `:ISSUER_ID` in a
ca-config file) which is replaced by the issuer SKID; they name the public
URL of the `aia` listener. The responses set `Cache-Control`, `Expires` and
`Last-Modified` from `next_update` and `this_update` (an issuer certificate
is cached for a day) with an `ETag`, so that public caches and verifiers
revalidate instead of downloading. A path the listener does not list is
refused: the AIA serves nothing but these routes and the status routes.

## 10. Configuration

```yaml
orgs:
  default_org_name: Default # org created for a user without grants; empty disables
  default_project_name: Default # project created in the default org; empty disables
crypto_provider:
  default: ${TRUSTYCA_CONFIG_DIR}/kms/aws-dev-kms.yaml # the default key provider
  providers: [] # more providers, selected by KeyProvider
ca:
  bootstrap_config: ${TRUSTYCA_CONFIG_DIR}/ca-config.local.yaml # platform issuers and profiles
  issuer_cache_ttl: 5m # staleness bound of the cached issuers and profiles
  issuer_cache_size: 1000 # issuers kept in memory
  retention:
    expired_after: 0 # delete certificates this long after their expiry; 0 keeps them
  allow_software_keys: true # keys stored wrapped by the data protection provider; dev only, refused in prod
  # planned: crl_publish_locations
aia: # the CIS needs no configuration
  client_tls: # the identity the AIA presents to the CA backend (spiffe://trustyca/aia)
    cert: ${HOME}/.trustyca/certs/trustyca_aia.pem
    key: ${HOME}/.trustyca/certs/trustyca_aia.key
    trusted_ca: ${HOME}/.trustyca/certs/trustyca_root.pem
  ocsp_cache_size: 10000 # OCSP responses kept in memory until their NextUpdate
tasks:
  - name: crl_renewal # the due CRLs of every issuer (section 8)
    schedule: "every 10 minutes"
  - name: cert_status # expired certificates and ca.retention
    schedule: "every 1 hour"
```

Backend listener: `trustyca-ra` and `trustyca-aia` TLS roles
(`identity_map.tls.enabled: true`), `authz.allow:
/pb.CA:trustyca-ra,trustyca-admin` and `/pb.CA/SignOCSP` for `trustyca-aia`
as well, the only method the AIA calls; it lists no root path under
`authz.allow_any`, so a path without a rule is refused to every identity
(the status routes are listed). The `wfe` listener keeps `/` public for the
index page of the UI, which opens every path without a rule at this layer:
its services rely on the access check of each method; `/pb.CIS` is listed
under `authz.allow_any_role`, so the CIS admits any authenticated caller
and refuses a guest, and no CIS path is under `identity_map.skip_auth`.
The `aia` listener is plain HTTP without an identity map (every caller is
a guest) and lists only the AIA and status routes under `authz.allow_any`,
so every other path is refused. The AIA forwards OCSP to
`client.server_url.backend` with the certificate of `aia.client_tls`;
`make gen_test_certs` generates it (`trustyca_aia`) with the RA one
(`trustyca_ra`).

## 11. Audit and observability

Every mutating RPC writes an `event` row with `org_id`, `project_id`, `type`,
`ref_id` pointing at the org, project, user, invite, API key, issuer,
profile, certificate or CRL, `email` of the actor and `source` = the emitting
service (`auth`, `orgs`). Services build events with `internal/events` and
emit them after the action succeeds; the row is written in the background
and a failed write is logged, not returned to the caller. `DeleteInvite` has
no event type and records nothing.

The auth service records the user lifecycle: `UserSignup` on a new user's
first login, `OrgMemberAccepted`/`ProjectMemberAccepted` for the invites it
accepts, `OrgCreated`/`ProjectCreated` for the default org and project,
`UserSignedIn` when a login issues a token or `SelectOrg` switches the org,
`UserSignedOut` when a user revokes the token (`TokenRevoked` for an API key
token) and `APIKeyLogin` when an API key gets a token. `UserDisabled`,
`UserEnabled`, `OrganizationDisabled` and `OrganizationEnabled` wait for the
admin APIs that disable users and orgs. The CA service records the issuer,
profile, root, certificate and revocation events, and `CrlPublished` for
every CRL it publishes; the `crl_renewal` task records `CrlPublished` with
the task name as the source and no actor.
Metrics follow `internal/metricskey`: `ca_cert_issued{ca,profile,org}` and
`ca_fail_sign_cert{ca,profile,org}`, the `ca_sign_latency{ca,profile}`
sample of a signing (the signature and the insert of the certificate with
its event), `ca_cert_revoked{ikid}`, `ca_crl_published{ca}` and
`ca_fail_publish_crl{ca}`, `ca_ocsp_signed{ikid,status}`,
`aia_cache_hit{type}` and `aia_cache_miss{type}`, the `aia_download_*`
counters of the AIA routes, `perf_db_query{method}` and `perf_task_run{task}`.

## 12. Open items

- Most recently used org on login (the first accessible org is selected today).
- Teams as grant recipients, on top of the project grants.
- API key rotation (a second secret with an overlap window) and scoped user
  tokens minted from the UI.
- Per-key rate limits and last-used reporting in `ListAPIKeys`.
- `privpb.Admin` support views across orgs: `ListMemberships` (`ListProjects`,
  `ListIssuers` and `ListCertificates` exist).
- Certificate hold removal and CRL delta support.
- Declarative partitioning of `certificate`/`revoked` once a tenant exceeds
  roughly 100M rows.
- Publishing CRLs and certificates to object storage and CDN.
- Idempotency keys on `SignCertificate` for RA retries.
- Issuer renewal under one label: a unique index on Active issuers per
  scope, or a rename of the archived issuer.
- `OCSPRequest.IKID` from the AIA route, so that an issuer is found for any
  hash algorithm without being in memory.
