include .project/gomod-project.mk

SHA := $(shell git rev-parse HEAD)

# the data protection seed of every process that uses the dev database: the
# environment's seed when it sets one (the server started from a shell or the
# IDE inherits it), testseed otherwise (CI). A platform issuer key wrapped
# under another seed fails the start: see README.md, Troubleshooting.
ifeq ($(strip $(TRUSTYCA_DP_SEED)),)
TRUSTYCA_DP_SEED := testseed
endif
export TRUSTYCA_DP_SEED
export TRUSTYCA_GITHUB_CLIENT_ID=testclientid
export TRUSTYCA_GITHUB_CLIENT_SECRET=testclientsecret
export TRUSTYCA_GOOGLE_CLIENT_ID=testclientid
export TRUSTYCA_GOOGLE_CLIENT_SECRET=testclientsecret

# Container images built by `make docker` / `make docker-tester` and consumed
# by tests/integration/docker-compose.tester.yml.
ITEST_IMAGE ?= effective-security/trustyca
ITEST_TESTER_IMAGE ?= effective-security/trustyca-tester
ITEST_IMAGE_TAG ?= main
export ITEST_IMAGE
export ITEST_TESTER_IMAGE
export ITEST_IMAGE_TAG
# the binaries link the PKCS#11 provider with cgo: docker-build builds them in
# the golang image of the Go version of go.mod, on the Debian release of the
# images of the Dockerfile, so that they find the glibc they were built with
DOCKER_GO_IMAGE ?= golang:$(shell sed -n 's/^go //p' go.mod)-trixie

export COVERAGE_EXCLUSIONS="tests|third_party|api/pb/|main\.go|clisuite|testsuite\.go|mocks\.go|\.pb\.go|\.gen\.go"
export TRUSTYCA_DIR=${PROJ_ROOT}
BUILD_FLAGS=

.PHONY: *

.SILENT:

default: help

all: clean folders tools generate version change_log gen_test_certs start-localstack drop-sql start-sql build dry-run test

recover: clean folders tools generate version gen_test_certs start-localstack drop-sql start-sql build dry-run

#
# clean produced files
#
clean:
	echo "Running clean ${PROJ_DATA_DIR}"
	rm -rf \
		${PROJ_DATA_DIR} \
		./bin \
		./.gopath \
		${COVPATH} \

tools:
	echo "*** installing tools"
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
	go install github.com/effective-security/golangci-linters/cmd/custom-linters@v0.1.11
	go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest
	go install github.com/effective-security/cov-report/cmd/cov-report@latest
	go install github.com/effective-security/xpki/cmd/hsm-tool@latest
	go install github.com/effective-security/xpki/cmd/xpki-tool@latest
	go install github.com/effective-security/xdb/cmd/xdbcli@latest
	go install github.com/itchyny/gojq/cmd/gojq@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install go.uber.org/mock/mockgen@latest

folders:
	echo "*** creating folders ${PROJ_DATA_DIR}/certs ${PROJ_DATA_DIR}/logs"
	mkdir -p ${PROJ_DATA_DIR}/certs \
		${PROJ_DATA_DIR}/logs
	chmod -R 0700 ${PROJ_DATA_DIR}

version:
	echo "*** building version $(GIT_VERSION)"
	gofmt -r '"GIT_VERSION" -> "$(GIT_VERSION)"' api/version/current.template > api/version/current.go

build_client:
	echo "*** Building client"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/trustyca ./cmd/trustyca

build_svc:
	echo "*** Building service"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/trustycasvc ./cmd/trustycasvc

build_trustycactl:
	echo "*** Building trustycactl"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/trustycactl ./cmd/trustycactl

build: build_svc build_trustycactl build_client

dry-run:
	echo "*** starting dry-run"
	${PROJ_ROOT}/bin/trustycasvc --dry-run 2>/dev/null
	echo "*** dry-run completed"

change_log:
	echo "Recent changes" > ./change_log.txt
	echo "Build Version: $(GIT_VERSION)" >> ./change_log.txt
	echo "Commit: $(GIT_HASH)" >> ./change_log.txt
	echo "==================================" >> ./change_log.txt
	git log -n 20 --pretty=oneline --abbrev-commit >> ./change_log.txt

commit_version:
	echo "*** committing version"
	git add .; git commit -m "Updated version"

trusty_root:
	echo "*** extracting trusty root CA"
	mkdir -p ${PROJ_DATA_DIR}/certs
	tar -xzvf $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.key.tar.gz -C $(PROJ_ROOT)/etc/dev/certs/root/
	cp $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.pem ${PROJ_DATA_DIR}/certs/trustyca_root.pem

gen_test_root:
	echo "*** generating test root CA"
	mkdir -p ${PROJ_DATA_DIR}/certs
	$(PROJ_ROOT)/.project/gen_certs.sh \
		--hsm-config inmem \
		--ca-config $(PROJ_ROOT)/etc/dev/certs/ca-config.bootstrap.yaml \
		--output-dir $(PROJ_ROOT)/etc/dev/certs/root \
		--csr-dir $(PROJ_ROOT)/etc/dev/certs/csr_profile \
		--csr-prefix trustyca_ \
		--out-prefix trustyca_ \
		--key-label test_root_ \
		--root-ca $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.pem \
		--root-ca-key $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.key \
		--root
	cd $(PROJ_ROOT)/etc/dev/certs/root && tar -cvzf trustyca_root.key.tar.gz trustyca_root.key

# TEST_CERTS_SAN is added to the server and peer certificates on top of
# localhost and the host name (gen_certs.sh --san replaces the san list of
# the CSR profiles): api.local.trustyca.io is the wfe under the dev cookie
# domain, the API host of the console in cookie mode (README.md, Web UI
# sessions). The integration test stack issues its own (tests/integration).
TEST_CERTS_SAN ?= 127.0.0.1,api.local.trustyca.io

gen_test_certs: trusty_root
	echo "*** Running gen_test_certs"
	echo "*** generating test CAs"
	$(PROJ_ROOT)/.project/gen_certs.sh \
		--hsm-config inmem \
		--ca-config $(PROJ_ROOT)/etc/dev/certs/ca-config.bootstrap.yaml \
		--output-dir ${PROJ_DATA_DIR}/certs \
		--csr-dir $(PROJ_ROOT)/etc/dev/certs/csr_profile \
		--csr-prefix trustyca_ \
		--out-prefix trustyca_ \
		--key-label test_ \
		--san $(TEST_CERTS_SAN) \
		--root-ca $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.pem \
		--root-ca-key $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.key \
		--ca1 --ca2  --bundle --server --peer --client --ra --aia --force

start-localstack:
	echo "*** starting localstack"
	# we need re-create ${PROJ_DATA_DIR}redis folder with certs
	rm -rf ${PROJ_DATA_DIR}/redis
	mkdir -p ${PROJ_DATA_DIR}/redis
	cp $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.pem ${PROJ_DATA_DIR}/certs/trustyca_peer.* ${PROJ_DATA_DIR}/redis
	chmod 644 ${PROJ_DATA_DIR}/redis/*
	#
	PROJ_DATA_DIR=$(PROJ_DATA_DIR) docker compose -f docker-compose.trustyca.yml -p trustyca up -d --force-recreate --remove-orphans
	# allow to start SQL
	sleep 3
	#
	aws configure set aws_access_key_id "dummy" --profile localstack
	aws configure set aws_secret_access_key "dummy" --profile localstack
	aws configure set region "us-west-2" --profile localstack
	aws configure set output "table" --profile localstack

create-kms-key:
	@echo "Checking for existing alias 'alias/trustyca-dp'..."
	ALIAS_INFO=$$(aws --endpoint-url=http://localhost:54566 kms list-aliases --profile localstack --output json | gojq -r '.Aliases[] | select(.AliasName=="alias/trustyca-dp")'); \
	if [ -n "$$ALIAS_INFO" ]; then \
		KEY_ID=$$(echo "$$ALIAS_INFO" | gojq -r '.TargetKeyId'); \
		echo "Alias 'alias/trustyca-dp' already exists. Using KeyId: $$KEY_ID"; \
	else \
		KEY_ID=$$(aws --endpoint-url=http://localhost:54566 kms create-key --description "trustyca-dp" --profile localstack --output json | gojq -r '.KeyMetadata.KeyId'); \
		aws --endpoint-url=http://localhost:54566 kms create-alias --alias-name alias/trustyca-dp --target-key-id $$KEY_ID --profile localstack --output table | cat; \
		echo "Created new KMS key and alias. KeyId: $$KEY_ID"; \
	fi

start-sql:
	echo "*** creating SQL tables "
	$(PROJ_ROOT)/sql/trustycadb/wait_sql.sh localhost 55432 postgres postgres
	docker exec -e 'PGPASSWORD=postgres' trustyca-sql-1 psql -h localhost -p 55432 -U postgres -a -f /trustyca_sql/trustycadb/create_local_db.sql
	docker exec -e 'PGPASSWORD=postgres' trustyca-sql-1 psql -h localhost -p 55432 -U postgres -lqt
	# escape password for postgres
	echo "postgres://trustyca:trustyca%3Flocal%23%26@localhost:55432?sslmode=disable&dbname=trustycadb" > etc/dev/sql-conn-trustycadb.txt

drop-sql:
	echo "*** dropping SQL tables "
	$(PROJ_ROOT)/sql/trustycadb/wait_sql.sh localhost 55432 postgres postgres
	docker exec -e 'PGPASSWORD=postgres' trustyca-sql-1 psql -h localhost -p 55432 -U postgres -a -f /trustyca_sql/trustycadb/drop_local_db.sql
	docker exec -e 'PGPASSWORD=postgres' trustyca-sql-1 psql -h localhost -p 55432 -U postgres -lqt

gen-sql-schema: #dry-run
	echo "*** generating SQL schema"
	echo "\`\`\`" > internal/db/README.md && \
	bin/xdbcli --sql-source=file://etc/dev/sql-conn-trustycadb.txt \
		schema columns --dependencies --schema trustyca --db trustycadb >> internal/db/README.md && \
	echo "\`\`\`" >> internal/db/README.md
	#rm -f ./internal/db/model/*.gen.go ./internal/db/schema/*.gen.go
	bin/xdbcli --sql-source=file://etc/dev/sql-conn-trustycadb.txt \
		schema generate --db trustycadb \
		--schema trustyca \
		--types-def internal/db/schema/typesmap.yaml \
		--imports github.com/effective-security/trustyca/api/pb \
		--dependencies \
		--out-model internal/db/model \
		--out-schema internal/db/schema \
		--view vw_membership_info \
		--view vw_revoked_certificate
	#goimports -w ./internal/db/model/*.gen.go ./internal/db/schema/*.gen.go

# docker-build builds the linux binaries of the images into bin/linux with
# the host's module cache, read-only and offline, so the container needs no
# network and no credentials: run `make build` (or `go mod download`) first.
docker-build:
	echo "*** building the linux binaries of the images in $(DOCKER_GO_IMAGE)"
	mkdir -p $(PROJ_ROOT)/bin/linux $(PROJ_ROOT)/.tmp/docker-gocache
	docker run --rm \
		--user $$(id -u):$$(id -g) \
		-v $(PROJ_ROOT):/src \
		-v $$(go env GOMODCACHE):/go/pkg/mod:ro \
		-e HOME=/tmp \
		-e GOCACHE=/src/.tmp/docker-gocache \
		-e GOMODCACHE=/go/pkg/mod \
		-e GOPROXY=off \
		-e GOFLAGS="-mod=readonly -buildvcs=false" \
		-e GOTOOLCHAIN=local \
		-w /src \
		$(DOCKER_GO_IMAGE) \
		sh -c 'for cmd in trustycasvc trustyca trustycactl; do go build ${BUILD_FLAGS} -o bin/linux/$$cmd ./cmd/$$cmd || exit 1; done'

docker: change_log docker-build
	echo "*** building $(ITEST_IMAGE):$(ITEST_IMAGE_TAG)"
	docker build -f Dockerfile --target runtime -t $(ITEST_IMAGE):$(ITEST_IMAGE_TAG) .

docker-tester: docker-build
	echo "*** building $(ITEST_TESTER_IMAGE):$(ITEST_IMAGE_TAG)"
	docker build -f Dockerfile --target tester -t $(ITEST_TESTER_IMAGE):$(ITEST_IMAGE_TAG) .

docker-push: docker
	[ ! -z ${DOCKER_PASSWORD} ] && echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin || echo "skipping docker login"
	docker push $(ITEST_IMAGE):$(ITEST_IMAGE_TAG)
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effective-security/trustyca:${DOCKER_NUMBER} || echo "skipping docker version, pushing latest only"

# docker-citest builds both images and runs the integration suite of
# tests/integration in its own compose stack, with its own throw-away PKI
# (tests/integration/README.md); it never touches ~/.trustyca or the dev DB
docker-citest: docker docker-tester
	cd ./tests/integration && ./setup.sh

proto: proto-pub proto-priv
	echo "*** built protos"

proto-pub:
	echo "*** building public proto in $(PROJ_ROOT)/api/pb"
	mkdir -p ./api/pb/mockpb ./api/pb/openapi ./api/pb/proxypb
	docker run --rm \
	    --user $(UID):$(GID) \
		-v $(PROJ_ROOT)/api/pb:/dirs \
		-v $(PROJ_ROOT)/api/pb/third_party:/third_party \
		--name protoc-gen-go \
		effectivesecurity/protoc-gen-go:sha-0841a17 \
		--i "-I /third_party" \
		--dirs /dirs/protos \
		--golang ./.. \
		--enum pb ./.. \
		--http pb ./.. \
		--json ./.. \
		--mock ./.. \
		--proxy ./.. \
		--methods ./.. \
		--oapi output_mode=source_relative,naming=proto:./../openapi
	goimports -l -w ./api/pb
	gofmt -s -l -w -r 'interface{} -> any' ./api/pb
	# remove empty generated openapi files without any service
	rm -rf ./api/pb/openapi/types.openapi.yaml

proto-priv:
	echo "*** building private proto in $(PROJ_ROOT)/privpb"
	mkdir -p ./privpb/mockpb
	docker run --rm \
		--user $(UID):$(GID) \
		-v $(PROJ_ROOT)/privpb:/dirs \
		-v $(PROJ_ROOT)/api/pb/protos:/trustyca \
		-v $(PROJ_ROOT)/api/pb/third_party:/third_party \
		--name protoc-gen-go \
		effectivesecurity/protoc-gen-go:sha-0841a17 \
		--i "-I /trustyca -I /third_party" \
		--dirs /dirs/protos \
		--golang ./.. \
		--json ./.. \
		--enum privpb ./.. \
		--mock ./.. \
		--http privpb ./.. \
		--methods ./.. \
		--proxy ./..
	rm -rf ./privpb/modelpb
	goimports -l -w ./privpb
	gofmt -s -l -w -r 'interface{} -> any' ./privpb

docs:
	echo "*** generating Docs"
	rm -rf Documentation/api
	mkdir -p Documentation/api
	for pkg in $$(go list ./... | grep -v '/cmd/' | grep -v '/tests/' | grep -v '/mocks/' | grep -v '/pb/' | grep -v '/privpb/'| grep -v 'api/cli/' | grep -v 'internal/ctl/'| grep -v 'server/tasks'); do \
		out=Documentation/api/$$(echo $$pkg | sed 's#${REPO_NAME}/##; s#/#_#g').md; \
		gomarkdoc --output $$out --repository.default-branch main $$pkg || exit 1; \
	done
	echo "API reference written to Documentation/api"
	echo "\`\`\`bash" > ./Documentation/cli/trustyca.md
	bin/trustyca --help >> ./Documentation/cli/trustyca.md
	echo "\`\`\`" >> ./Documentation/cli/trustyca.md
	echo "\`\`\`bash" > ./Documentation/cli/trustycactl.md
	bin/trustycactl --help >> ./Documentation/cli/trustycactl.md
	echo "\`\`\`" >> ./Documentation/cli/trustycactl.md
	echo "CLI reference written to Documentation/cli"