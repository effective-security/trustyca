# Trusty CA Design

Status: accepted design for v1. Companion documents:
[PLAN.md](PLAN.md) (execution plan) and
[membership-authorization-spec.md](membership-authorization-spec.md)
(the membership and authorization baseline this design implements).

## 1. Scope

Trusty CA is a multi-tenant Certification Authority used as a backend by other
products. Two services are built from this repo:

| Service                        | Transport | Exposure               | Purpose                                                                         |
| ------------------------------ | --------- | ---------------------- | ------------------------------------------------------------------------------- |
| CA (`pb.CA`)                   | gRPC only | backend network only   | issuers, profiles, signing, revocation, CRL/OCSP signing                        |
| CIS (`pb.CIS` + binary routes) | REST      | may be internet facing | roots, issuer chains, certificate info, CRL Distribution Points, OCSP responder |

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
   ┌──────────┐   HTTPS    ┌──────────────┐  gRPC/mTLS         │
   │ TLS      │──────────▶ │ CIS service  │──SignOCSP──────────┘
   │ verifiers│  CRL/OCSP  │ REST         │                    │
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

Both services are `gserver` services in this binary (`server/service/ca`,
`server/service/cis`) and are enabled per listener in `etc/dev/trustyca-config.yaml`:

- `backend` listener: `status`, `admin`, `ca`. mTLS with client cert auth.
- `wfe` listener (or a dedicated `cis` listener): `status`, `auth`, `orgs`, `ui`, `cis`.
  CIS routes are anonymous and read-only.

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
2. Service identities (`trustyca-ra`, `trustyca-cis`, ...) bypass grants: they
   pass tenant scope explicitly and authorized the end user themselves.
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
   must hold every scope of the method.

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
  `ListAPIKeys` never returns secrets; `DeleteAPIKey` removes the key. All
  three record `APIKeyCreated`/`APIKeyDeleted` events.
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

| Index                             | Query                                                  |
| --------------------------------- | ------------------------------------------------------ |
| `UNIQUE (ikid, serial_number)`    | OCSP, CRL, `GetCertificate(IssuerSerial)`              |
| `UNIQUE (sha256)`                 | dedupe, lookup by thumbprint                           |
| `(org_id, project_id, id DESC)`   | `ListCertificates` newest first, keyset cursor on `id` |
| `(org_id, project_id, not_after)` | expiring certificates, retention                       |
| `(ikid, id DESC)`                 | list per issuer                                        |
| `(skid)`                          | lookup by subject key                                  |

Volume is handled by these indexes and by keyset pagination; a path to
`PARTITION BY HASH (org_id)` exists because every unique key can carry
`org_id` (an issuer belongs to exactly one org). Not done in v1. A retention
task removes certificates expired for longer than a configurable period; CRLs
only need revoked and unexpired entries.

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

1. **Bootstrap (platform) issuers** come from `etc/dev/ca-config.bootstrap.yaml`
   style files loaded with `authority.LoadConfig`. They are the service's own
   Root, L1 and L2 CAs and are created offline with `hsm-tool`. On startup they
   are mirrored into `issuer` rows with `org_id IS NULL` so that CIS can serve
   their CRLs and chains through the same tables. Their profiles are loaded as
   `certificate_profile` rows with `org_id IS NULL`.
2. **Tenant issuers** are created through `pb.CA` and live only in the DB.

The CA keeps an in-memory `authority.Authority` per issuer, built lazily from
the DB row and the crypto provider, and invalidated on `UpdateIssuer` or when
the row's `updated_at` changes.

### 5.2 Creating a tenant issuer

| Shape                | Request                                                             | Result                                                                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Self-signed root     | `Type = Root`, no `ParentID`, `Profile` = a CA profile with `is_ca` | `Active`, root inserted in `root_certificate`                                                                                                                                                     |
| Signed inside the CA | `ParentID` set                                                      | parent must be in the same org, or a platform issuer whose `config.allowed_profiles` contains `Profile`. This is how SHAKEN delegated CAs are issued per org from the platform `DELEGATED_L1_CA`. |
| Externally signed    | no `ParentID`, `Type != Root`                                       | key generated, `Pending` with `Csr`; `ActivateIssuer` uploads the certificate and chain                                                                                                           |

`ImportIssuer` covers bring-your-own-CA: certificate plus either a provider
key URI (`awskms://`, `gcpkms://`, `pkcs11:`) or a PEM key that is stored
wrapped by the `dataprotection.Provider`.

### 5.3 Keys

- Default `KeySpec` is ECDSA P-256. RSA 2048 to 4096 and P-384 are accepted.
- The key provider is chosen per issuer (`KeyProvider`) with a server default
  configured under a new `ca.crypto` config section. Production defaults to a
  KMS provider; `inmem` is for tests only and stores the wrapped key in
  `key_protected`.
- Key labels in the provider are `trustyca/{org_id}/{project_id}/{label}`.
- `Destroyed` calls `KeyManager.DestroyKeyPairOnSlot` where supported and
  clears `key_protected`.

### 5.4 Renewal

Renewing an issuer means registering a new issuer with a new key (new SKID)
and archiving the old one. Reusing a key would give two certificates the same
SKID and make `/v1/crl/{ikid}` ambiguous, so `UNIQUE (skid)` forbids it.

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

Platform profiles are never visible to tenants. Tenant onboarding copies a set
of template profiles into the org (a CTL command), which keeps tenant
configuration explicit and auditable.

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
  transaction, then emits `CertificateRevoked`. `CertificateHold` and
  `RemoveFromCRL` are accepted but hold removal is a follow-up.
- `PublishCrls` builds a CRL per Active or Archived issuer whose current CRL is
  missing or within `crl_renewal` of `next_update` (or `Force`). CRL number is
  `issuer.crl_number + 1`. Entries come from `revoked WHERE ikid = ? AND not_after > now()`.
  The scheduled task `crl_renewal` calls the same code path.
- `SignOCSP` resolves the issuer by IKID or by issuer key hash from the
  request, looks up `(ikid, serial_number)` and answers `good`, `revoked` or
  `unknown` with `ocsp_expiry` validity. When `delegated_ocsp_profile` is set the
  issuer signs with a delegated responder certificate created lazily with
  `authority.Issuer.CreateDelegatedOCSPSigner`.
- CIS never holds issuer keys. Its OCSP handler forwards DER requests to
  `CA.SignOCSP` over the backend gRPC client and caches responses by request
  hash until `NextUpdate`.

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
`api-key ...`.

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
revocation and CRL publishing) and the matching `ca:*`/`certs:*` scopes so the
same `CheckAccess` applies when a user token or an API key reaches the CA
directly. Conventions: string IDs, enum wrappers,
`Limit/Offset/Cursor` plus `NextPage` on every `List`, no HTTP annotations.

### 9.3 CIS (`api/pb/protos/cis.proto`)

JSON endpoints follow the repo convention `POST /pb.CIS/{Method}`: `GetRoots`,
`GetIssuer`, `GetCertificate`, `GetCertificateStatus`, `GetCRL`. Binary
endpoints are hand-registered in `cis.Service.RegisterRoute`:

| Route                                                                           | Media type                  | Source                         |
| ------------------------------------------------------------------------------- | --------------------------- | ------------------------------ |
| `GET /v1/cert/{ikid}`                                                           | `application/pkix-cert`     | `issuer.pem` (AIA caIssuers)   |
| `GET /v1/crl/{ikid}`                                                            | `application/pkix-crl`      | `crl.pem` decoded to DER (CDP) |
| `GET /v1/ocsp/{ikid}/{base64-request}`, `POST /v1/ocsp/{ikid}`, `POST /v1/ocsp` | `application/ocsp-response` | `CA.SignOCSP`                  |

Issuer `IssuerConfig` URL templates use `${ISSUER_ID}` which is replaced by the
issuer SKID. CIS responses set `Cache-Control` from `next_update` and expose no
tenant listing: every lookup needs an IKID, serial, SKID, SHA-256 or ID.

## 10. Configuration

```yaml
orgs:
  default_org_name: Default # org created for a user without grants; empty disables
  default_project_name: Default # project created in the default org; empty disables
ca:
  bootstrap_config: ${TRUSTYCA_CONFIG_DIR}/ca-config.bootstrap.yaml
  crypto:
    default: ${TRUSTYCA_CONFIG_DIR}/kms-provider.yaml
    providers: []
  default_key_spec: { algo: ECDSA, size: 256 }
  cis_url: https://cis.dev.trustyca.io
  crl_publish_locations: []
  issuer_cache_ttl: 5m
tasks:
  - name: crl_renewal
    schedule: "every 10 minutes"
  - name: cert_status
    schedule: "every 1 hour"
```

Backend listener: `trustyca-ra` and `trustyca-cis` TLS roles,
`authz.allow: /pb.CA:trustyca-ra,trustyca-admin`. CIS routes are listed under
`authz.allow_any` and `identity_map.skip_auth`.

## 11. Audit and observability

Every mutating RPC writes an `event` row with `org_id`, `project_id`, `type`,
`ref_id` pointing at the org, project, user, invite, issuer, profile,
certificate or CRL, `email` of the actor and `source` = the request target.
Metrics follow `internal/metricskey`: `ca_sign_total{profile,org}`,
`ca_sign_latency`, `ca_revoke_total`, `crl_publish_total`,
`ocsp_sign_total{status}`, `cis_cache_hit_total`.

## 12. Open items

- Most recently used org on login (the first accessible org is selected today).
- Teams as grant recipients, on top of the project grants.
- API key rotation (a second secret with an overlap window) and scoped user
  tokens minted from the UI.
- Per-key rate limits and last-used reporting in `ListAPIKeys`.
- `privpb.Admin` support views across orgs (`ListProjects`, `ListMemberships`).
- Certificate hold removal and CRL delta support.
- Declarative partitioning of `certificate`/`revoked` once a tenant exceeds
  roughly 100M rows.
- Publishing CRLs and certificates to object storage and CDN.
- Idempotency keys on `SignCertificate` for RA retries.
