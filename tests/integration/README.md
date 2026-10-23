# Integration tests

Black-box tests that run the service in a container, against a real
PostgreSQL, Redis and KMS emulator, and drive it through the shipped
`trustyca` CLI and through `curl` playing the browser and the Web UI. The
same command runs locally and in GitHub CI:

```bash
make docker-citest
```

It builds both images (`make docker docker-tester`) and runs `setup.sh`. It
needs Docker with compose v2, `hsm-tool` (`make tools`) and the Go module
cache of a `make build`: `make docker-build` compiles the binaries in a
`golang` container from that cache, offline.

## Layout

| path                        | what it is                                                                     |
| --------------------------- | ------------------------------------------------------------------------------ |
| `docker-compose.tester.yml` | the stack: `sql`, `sql-init`, `redis`, `kms`, `trustyca`, `test-runner`        |
| `setup.sh`                  | issues the PKI, brings the stack up, runs the suite, tears it down             |
| `tests/run.sh`              | the driver: runs each `test_*.sh` and prints a summary                         |
| `tests/lib.sh`              | assertions, the CLI helpers (`login`, `trustyca_as`) and the browser helpers   |
| `tests/browser/xdg-open`    | headless stand-in for the browser `trustyca auth login` opens                  |
| `tests/if-trustyca-ready.sh`| waits for the service before the suite starts                                  |
| `tests/test_*.sh`           | the tests themselves                                                           |

| test              | what it covers                                                                                           |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| `test_status.sh`  | the status routes of the three listeners, a guest caller, the `local` provider of a `local+` address      |
| `test_auth.sh`    | the bearer session of the CLI: login, the default org, the org switch, sign-out with token revocation    |
| `test_cookies.sh` | the cookie session of the console: CORS, the cookies of the login, CSRF over gRPC-Web and REST, the org switch that replaces the cookies (`POST /v1/auth/org`), sign-out |

Two images are built from the repository `Dockerfile`, both on Debian trixie,
since the binaries link the PKCS#11 provider with cgo:

- `effective-security/trustyca`: the service, distroless with glibc.
- `effective-security/trustyca-tester`: the runner, the CLIs plus bash, curl
  and jq.

## How a login works

The suite signs users in the way a person does, through the OAuth flow,
rather than minting tokens behind the server's back.

The `local` provider is offered only by an instance with
`service.environment: local` in cluster `local` (`config.Service.IsLocal`),
which the dev configuration is. It needs no external IdP: the authorize
end-point sends the caller to the callback on the host it was called on, and
the `local+` prefix is stripped, so `local+user1@trustyca.io` signs in as
`user1@trustyca.io`. Any other environment refuses the provider.

- The CLI (bearer session): `trustyca auth login local+user1@trustyca.io`
  starts the code flow, listens on `http://localhost:38987/login` and
  launches a browser. In the container `tests/browser/xdg-open` is that
  browser: it follows the redirects with curl and posts the `form_post`
  page of the callback to the CLI listener, which exchanges the one-time
  code for a token. Each user has its own token storage under
  `/tmp/trustyca/users/<user>`, which lets one test act as several people.
- The console (cookie session): `browser_login` requests
  `/v1/auth/authorize` with `response_type=cookie` and follows the callback
  with a cookie jar per user, and stops at the redirect to the console
  (`CONSOLE_ORIGIN`, `https://app.local.trustyca.io:4200`). The console
  helpers send every call from that origin with the cookies and the
  `X-CSRF-Token` header, over gRPC-Web (a framed empty message) or REST.

## Certificates and names

`setup.sh` issues a PKI of its own on every run, under the checked-in dev
root, into `tests/integration/.citest/certs` (gitignored): the developer's
`~/.trustyca/certs` is never read or rewritten, and the CA keys of the dev DB
platform issuers stay as they are. The files are world readable: the service
runs as `nonroot` and Redis as its own user.

The compose network addresses the service as `api.local.trustyca.io` and
Redis as `redis.local.trustyca.io`, and both names are in the server and
peer certificates (`--san` of `.project/gen_certs.sh`), so every client
verifies the server certificate. `api.local.trustyca.io` is a host under the
cookie domain of the dev configuration (`.local.trustyca.io`), so the
cookies are accepted by the cookie jar exactly as by a browser.

## Configuration

The service loads `etc/dev/trustyca-config.yaml` with
`etc/dev/trustyca-config.citest.yaml` merged on top. The override only carries
what differs inside the container: the compose network names, the database
of `TRUSTYCA_SQL_CONN`, the KMS emulator (`etc/dev/kms/aws-dev-kms.citest.yaml`),
no tasks and no metrics. The TLS paths of the base file resolve because the
container sets `HOME=/home/nonroot` and mounts the stack's PKI on
`/home/nonroot/.trustyca/certs`; the CORS, cookie and authz settings are the
dev ones, which is what the cookie test checks.
`internal/config` TestLoadCitestOverride loads the override with the base.

## Running and debugging

```bash
# keep the stack up after the run
ITEST_KEEP_UP=1 make docker-citest

# re-run part of the suite against a stack that is still up. Name every file
# the ones you care about depend on: they share one shell.
docker compose -f tests/integration/docker-compose.tester.yml -p trustyca-ci \
    run --rm --no-deps test-runner \
    /opt/trustyca/tests/run.sh test_status.sh test_cookies.sh

# service logs
docker compose -f tests/integration/docker-compose.tester.yml -p trustyca-ci logs trustyca
```

The test scripts are bind-mounted, so editing a `test_*.sh` and re-running the
command above needs no rebuild. Changing Go code does: `make docker docker-tester`.

While the stack is up the service is also published on the host, on ports
that deliberately differ from the dev ones so a dev server can run beside it:
`https://localhost:18880` (wfe), `:18881` (backend), `http://localhost:18888`
(aia).

## Adding a test

Drop a `test_<area>.sh` in `tests/` and add it to the `SUITE` list in
`run.sh`. Files are sourced, in order, into one shell, so a test can use what
an earlier one exported: `test_auth.sh` leaves `user1` and `user2` signed in.
Use `fail`, `assert_eq`, `assert_ne`, `assert_contains`, `assert_empty`,
`assert_not_empty` and `assert_fails` from `lib.sh` and let the file run to
the end: the driver counts assertions, it does not stop at the first one.
