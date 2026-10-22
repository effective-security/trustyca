# Roadmap

Active planned work. Order is suggested, not a delivery commitment. Current runtime navigation
is in [Documentation/codemap.md](Documentation/codemap.md); defects are in
the local, gitignored `FINDINGS.md`, whose IDs are not cited here.

## Implemented baseline

[PLAN.md](Documentation/PLAN.md) phase 1: login, orgs, projects, memberships,
invites, API keys and the authorization layer; phase 2 and 2a: the CA
tables, the CA core library (`internal/ca`: tenant-scoped issuer registry,
keys, platform bootstrap) and the issuer, profile, root and signing methods
of the CA service; phase 3: the certificate, revocation and current CRL
methods of the CA service, the `trustyca-ra` and `trustyca-cis` roles of
the backend listener and the CA client. CRL publishing (`PublishCrls`
answers Unimplemented) and the CIS service are stubs; their phases (4 to 7)
are planned in PLAN.md.

## Active work

| ID     | Work                               | Ownership / contract                                                                                                                                                         |
| ------ | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RM-001 | Public precondition error contract | server/service/orgs answers HTTP 409 `conflict` / gRPC FailedPrecondition (preconditionFailed); map FailedPrecondition to 409 in porto so Go gRPC clients agree, then pin it |
| RM-002 | Issuer renewal under one label     | `UNIQUE NULLS NOT DISTINCT (org_id, project_id, label)` on `issuer` holds in every status, so a renewed issuer cannot take the label of the archived one and `internal/ca.Bootstrap` refuses a rotated key; replace it with a unique index on Active (and Pending) issuers, or rename archived issuers, with a migration and a bootstrap that archives in place (DESIGN.md §5.4) |
| RM-003 | OCSP issuer lookup by IKID         | `pb.OCSPRequest` carries the DER request only; the CA finds an issuer that is not in memory by a SHA-1 key hash through the `skid` index. Add an optional `IKID` that the CIS route `/v1/ocsp/{ikid}` passes on, so every hash algorithm resolves without a scan (DESIGN.md §8) |
| RM-004 | Project-scoped issuer and profile mutations | `UpdateIssuerRequest`, `ActivateIssuerRequest` and `DeleteProfileRequest` carry no `ProjectID`, so the interceptor authorizes them at org scope and a project Admin cannot archive, activate or delete the rows of its own project. Add `ProjectID` to the three requests, as `UpdateCertificateLabelRequest` and `RevokeCertificateRequest` have it (the row must belong to the named project); the service already authorizes the resolved row against its project (`rowAccess`, DESIGN.md §6) |

## Completion policy

Move completed features into their owning docs and update the codemap in
the same change. Contract changes include proto/SQL generation and
compatibility notes; shared-state changes require race and multi-process
checks. Never infer completion from a historical milestone's recorded test
or benchmark result.

## Security

- DPoP replay protection is missing. porto's server-side DPoP check passes
  an empty config: no replay cache, no proof-to-token hash (`ath`), no
  trusted URL; this is an upstream porto item. The trustyca login endpoint has
  no replay cache either: the only one xpki ships is in-memory and rejects
  every proof once full, and login needs no authentication, so anyone could
  fill it and block DPoP logins. A Redis-backed cache is the right shape.
- gRPC DPoP proofs are checked against the incoming `:authority`; forwarded
  host headers are not used. Before prod, run one `--dpop-key` login plus a
  gRPC command against dev (wfe.dev.trustyca.io) to confirm the ingress passes
  `:authority` through unchanged.

## Lint

- Tighten the golangci-lint configuration.
- Report uses of deprecated APIs (staticcheck SA1019) in lint and CI.
