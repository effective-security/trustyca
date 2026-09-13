# trustyca

LLM Semantic Router

## Requirements

1. GoLang

Install manually or using VS Code extension for `Golang Tools`:

2. Postgresql Client and pg_restore 15.7+

Install posgresql client & restore, for data import locally. Needed for pg_restore to run.

3. Obtain credential for cyres_primary from AWS Console (should have access to AWS Dev) & export the same before run.

```sh
go install golang.org/x/tools/cmd/stringer@latest
go install golang.org/x/tools/cmd/gorename@latest
go install golang.org/x/tools/cmd/godoc@latest
go install golang.org/x/tools/cmd/guru@latest
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/go-delve/delve/cmd/dlv@latest
go install golang.org/x/tools/gopls@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

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
      "env": {},
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
      trusted_ca: ~/.trustyca/certs/trusty_root_ca.pem
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

## Stripe

- https://stripe.com/docs/stripe-cli
- https://stripe.com/docs/payments/payment-intents/verifying-status

To install the Stripe CLI on Linux without a package manager:

- Download the latest linux tar.gz file from https://github.com/stripe/stripe-cli/releases/latest
- Unzip the file: tar -xvf stripe_X.X.X_linux_x86_64.tar.gz
- Move ./stripe to your execution path.

Login

stripe login --api-key $TRUSTYCA_STRIPE_API_KEY
stripe listen --skip-verify --forward-to https://localhost:8880/v1/webhooks/stripe
export TRUSTYCA_STRIPE_WEBHOOK_SECRET=c1..aw
