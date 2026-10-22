# trustyca

Lightweight Certification Authority

## Requirements

1. GoLang

Install manually or using VS Code extension for `Golang Tools`:

2. Postgresql Client and pg_restore 15.7+

Install posgresql client & restore, for data import locally. Needed for pg_restore to run.

## go mod

To replace a package with the latest commit:

```
go list -m -json <repo>@<commit> | jq -r .Version
```

## Build

- `make all` initializes all dependencies, builds and tests.
- `make proto` generates gRPC protobuf.
- `make build` build the executable
- `make gen_test_certs` generate test certificates
- `make test` run the tests
- `make testshort` runs the tests skipping the end-to-end tests and the code coverage reporting
- `make covtest` runs the tests with end-to-end and the code coverage reporting
- `make coverage` view the code coverage results from the last make test run.
- `make generate` runs go generate to update any code gen'd files (query_console.go in our case)
- `make fmt` runs go fmt on the project.
- `make lint` runs the go linter on the project.

run `make all` once, then run `make build` or `make test` as needed.

First run:

    make all

Subsequent builds:

    make build

Tests:

    make test

Optionally run golang race detector with test targets by setting RACE flag:

    make test RACE=true

Review coverage report:

    make coverage

## Generate protobuf

    make proto

## Integration test

    make docker docker-citest

## Certificate Information Service

The `cis` service of the `wfe` listener is the read-only view of the CA for
authenticated users: a JSON and gRPC API (`POST /pb.CIS/GetRoots`,
`GetIssuer`, `GetCertificate`, `GetCertificateStatus`, `GetCRL`) that
serves the trust anchors, issuer chains, certificate information and status
and CRLs of every org without their tenancy. The listener admits any
authenticated caller to `/pb.CIS` and refuses a guest. The service holds no
keys and needs no configuration.

    curl -sk https://localhost:8880/pb.CIS/GetIssuer -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"IKID\":\"$IKID\"}"

The `trustyca` CLI reads it with the token of the login:

    bin/trustyca -s https://localhost:8880 auth login
    bin/trustyca -s https://localhost:8880 issuer get $IKID
    bin/trustyca -s https://localhost:8880 cert status --ikid $IKID --serial $SERIAL
    bin/trustyca -s https://localhost:8880 root list

## Authority Information Access

The `aia` service serves the URLs embedded in the issued certificates on
its own plain HTTP listener (`http://localhost:8888` in the dev
configuration), without TLS or authentication, as a TLS verifier fetches
them: the issuer certificate (AIA caIssuers, `GET /v1/cert/{ikid}`), the
CRL (CRL Distribution Point, `GET /v1/crl/{ikid}`) and the OCSP responder
(`/v1/ocsp`, `/v1/ocspi/{ikid}`). The listener serves nothing else. The
service holds no keys: OCSP requests are forwarded to `CA.SignOCSP` on the
backend listener with the certificate of the `aia` section
(`make gen_test_certs` creates `trustyca_aia`), and the signed responses
are cached until their next update.

    # the issuer certificate and the CRL of an issuer, by its key identifier
    curl -s http://localhost:8888/v1/cert/$IKID -o issuer.der
    curl -s http://localhost:8888/v1/crl/$IKID -o issuer.crl
    # the status of a certificate
    openssl ocsp -issuer issuer.pem -cert leaf.pem -url http://localhost:8888/v1/ocsp -resp_text

The URL templates of an issuer (`aia.issuer_url`, `crl_url`, `ocsp_url` of
a ca-config file, `Config` of `RegisterIssuer`) name the AIA routes with
`:ISSUER_ID` or `${ISSUER_ID}` for the key identifier, as in
`etc/dev/ca-config.local.yaml`.

## Certification Authority

The `ca` service of the `backend` listener is the CA: the issuers,
profiles, trust anchors, certificates, revocations and CRLs of every org.
It is not exposed to the internet: the Registration Authority calls it with
the `trustyca-ra` identity and the operator with `trustyca-admin`, both TLS
client certificates mapped by `identity_map.tls` of the listener
(`make gen_test_certs` creates `trustyca_ra` and `trustyca_admin`). The `ca`
section of the configuration names the ca-config of the platform issuers
(`bootstrap_config`), mirrored into the CA tables at startup: in
`etc/dev/ca-config.local.yaml` the L1 CA `trusty.l1` signs the issuing CAs
of the orgs with the `tenant_ca` profile, and the L2 CA `trusty.svc` the
platform's own certificates.

`trustycactl ca ...` operates the CA with the admin certificate; every
request names the org:

    alias trustycactl='bin/trustycactl -s https://localhost:8881 -c ~/.trustyca/certs/trustyca_admin.pem -k ~/.trustyca/certs/trustyca_admin.key -r ~/.trustyca/certs/trustyca_root.pem'
    # the platform issuers and anchors, the certificates of every org
    trustycactl ca issuer list --platform
    trustycactl ca root list
    trustycactl ca cert list --limit 20
    # onboard an org: its issuing CA under the platform intermediate, and the template profiles
    trustycactl ca org bootstrap --org $ORG --parent trusty.l1 --templates etc/dev/profiles \
        --cn "Example Issuing CA" --ocsp-profile ocsp \
        --crl-url 'http://localhost:8888/v1/crl/${ISSUER_ID}' \
        --ocsp-url 'http://localhost:8888/v1/ocspi/${ISSUER_ID}' \
        --aia-url 'http://localhost:8888/v1/cert/${ISSUER_ID}'
    # the CA of the org
    trustycactl ca issuer list --org $ORG
    trustycactl ca profile register --org $ORG --file etc/dev/profiles/server.yaml --issuer issuing
    trustycactl ca cert revoke --org $ORG $CERT_ID --reason KeyCompromise
    trustycactl ca crl publish --org $ORG --force

A profile file has the shape of a `profiles` entry of a ca-config file, one
profile per file named after its label (`etc/dev/profiles`); a template
without `issuer_label` binds to the issuing CA the onboarding registers.
`trustycactl --help` lists the commands; the reference is
[Documentation/cli/trustycactl.md](Documentation/cli/trustycactl.md).

Issuer keys live in the crypto providers of `crypto_provider`. The dev
configuration sets `ca.allow_software_keys: true` for the platform key files
and the `inmem` provider, whose keys are stored wrapped by the data
protection provider; a `service.environment: prod` instance refuses to
start with it.

### Load test

`tests/load` fills a disposable database with synthetic certificates and
reports the plans and timings of the CA queries at that volume:

    go run ./tests/load -rows 10000000 -load -explain -sign 2000 -out load.md
    go run ./tests/load -drop

The last run is in
[Documentation/perf/load-certificates.md](Documentation/perf/load-certificates.md).

## Debug

Add the launch configuration to .vscode/launch.json:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Server",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "host": "127.0.0.1",
      "program": "${workspaceRoot}/cmd/trustycasvc",
      "env": {
        "TRUSTYCA_DP_SEED": "testseed"
      },
      "args": [
        "--log-pretty",
        "--cfg",
        "${workspaceRoot}/etc/dev/trustyca-config.yaml"
      ],
      "showLog": false
    }
  ]
}
```

## Troubleshooting

### Data protection seed

Every process that uses the dev database (the server, `make test`, the
container tests) must share one `TRUSTYCA_DP_SEED`: the platform issuer the
start bootstraps from `ca.bootstrap_config` keeps its software key wrapped
under the seed of the process that registered it. The Makefile exports
`testseed` unless the environment sets a seed, and the tests use the
environment's seed in the same way, so a seed exported by your shell profile
is used by `make`, by the tests and by a server started from that shell or
the IDE. A start that fails with

    failed to bootstrap CA: issuer "trusty.svc": unable to unprotect key of issuer ...: check that the data protection seed (TRUSTYCA_DP_SEED) is the one the key was wrapped under

ran with a different seed than the process that registered the platform
issuer: start with that seed, or recreate the disposable dev database with
`make drop-sql start-sql` so that the next start registers the platform
issuer again from the configuration. Never delete a tenant or imported
issuer for this error: the wrapped key in its row is the only copy.

If your build fails with the error `fatal: could not read Username for 'https://github.com': terminal prompts disabled` you likely need to adjust your gitconfig.  
This error occurs when the repo has been cloned via SSH but `go get` clones repositories over HTTPS by default.

You can check how the repo was cloned by running `git config remote.origin.url`. If it starts with `git@` you will need to adjust your gitconfig.  
Open `$HOME/.gitconfig` and add the below section. If you do not have an existing `.gitconfig` you'll need to create it.

```
[url "ssh://git@github.com/"]
    insteadOf = https://github.com/
```

After making the change rerun the build.

### Client config

    cat ~/.config/trustyca/config.yaml

```yaml
---
clients:
  local_wfe:
    host: https://localhost:8880
    tls:
      trusted_ca: ~/.trustyca/certs/trustyca_root.pem
    request:
      retry_limit: 3
      timeout: 6s
    storage_folder: ~/.trustyca
  remote_wfe_dev:
    host: https://wfe.dev.trustyca.io
    request:
      retry_limit: 3
      timeout: 6s
    storage_folder: ~/.trustyca
  remote_wfe_prod:
    host: https://wfe.prod.trustyca.io
    request:
      retry_limit: 3
      timeout: 6s
    storage_folder: ~/.trustyca
```
