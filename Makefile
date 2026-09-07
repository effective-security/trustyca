include .project/gomod-project.mk

SHA := $(shell git rev-parse HEAD)

export TRUSTYCA_DP_SEED=testseed
export TRUSTYCA_GITHUB_CLIENT_ID=testclientid
export TRUSTYCA_GITHUB_CLIENT_SECRET=testclientsecret
export TRUSTYCA_GOOGLE_CLIENT_ID=testclientid
export TRUSTYCA_GOOGLE_CLIENT_SECRET=testclientsecret
#export TRUSTYCA_STRIPE_API_KEY=sk_test_teststripeapikey
#export TRUSTYCA_STRIPE_WEBHOOK_SECRET=teststripewebhooksecret

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
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
	go install github.com/effective-security/golangci-linters/cmd/custom-linters@v0.1.10
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
	echo "*** generating trusty root CA"
	mkdir -p ${PROJ_DATA_DIR}/certs
	tar -xzvf $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.key.tar.gz -C $(PROJ_ROOT)/etc/dev/certs/root/
	cp $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem ${PROJ_DATA_DIR}/certs/trusty_root_ca.pem

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
		--root-ca $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem \
		--root-ca-key $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.key \
		--ca1 --ca2  --bundle --server --peer --client --force

start-localstack:
	echo "*** starting localstack"
	# we need re-create ${PROJ_DATA_DIR}redis folder with certs
	rm -rf ${PROJ_DATA_DIR}/redis
	mkdir -p ${PROJ_DATA_DIR}/redis
	cp $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem ${PROJ_DATA_DIR}/certs/trustyca_peer.* ${PROJ_DATA_DIR}/redis
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
		--view vw_membership_info
	#goimports -w ./internal/db/model/*.gen.go ./internal/db/schema/*.gen.go

docker: change_log
	docker build --no-cache -f Dockerfile -t effective-security/trustyca:main .

docker-push: docker
	[ ! -z ${DOCKER_PASSWORD} ] && echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin || echo "skipping docker login"
	docker push effective-security/trustyca:main
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effective-security/trustyca:${DOCKER_NUMBER} || echo "skipping docker version, pushing latest only"

docker-citest:
	cd ./scripts/integration && ./setup.sh

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
		effectivesecurity/protoc-gen-go:sha-3d7439c \
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
		effectivesecurity/protoc-gen-go:sha-3d7439c \
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
	# generate the docs using specific packages
	gomarkdoc ./internal/db/model > ./Documentation/db/trustyca-model.md
	gomarkdoc ./internal/db/schema > ./Documentation/db/trustyca-schema.md
	gomarkdoc ./api/client > ./Documentation/api/client.md
	bin/trustyca --help > ./Documentation/cli/trustyca.md
	bin/trustycactl --help > ./Documentation/cli/trustycactl.md