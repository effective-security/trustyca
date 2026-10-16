# Roadmap

Active planned work. Order is suggested, not a delivery commitment. Current runtime navigation
is in [Documentation/codemap.md](Documentation/codemap.md); defects are in
the local, gitignored `FINDINGS.md`, whose IDs are not cited here.

## Implemented baseline

[PLAN.md](Documentation/PLAN.md) phase 1: login, orgs, projects, memberships,
invites, API keys and the authorization layer. The CA and CIS services are
stubs; their phases (2 to 7) are planned in PLAN.md.

## Active work

| ID     | Work                               | Ownership / contract                                                                                                                                                         |
| ------ | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RM-001 | Public precondition error contract | server/service/orgs answers HTTP 409 `conflict` / gRPC FailedPrecondition (preconditionFailed); map FailedPrecondition to 409 in porto so Go gRPC clients agree, then pin it |

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
