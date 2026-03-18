PROVIDER_DIR := $(PWD)
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=keyfactor.com
GOFMT_FILES  := $$(find $(PROVIDER_DIR) -name '*.go' |grep -v vendor)
NAMESPACE=keyfactor
WEBSITE_REPO=https://github.com/Keyfactor/terraform-provider-keyfactor
NAME=keyfactor
VERSION=2.2.0
BINARY=terraform-provider-${NAME}
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
BASEDIR := ${HOME}/.terraform.d/plugins
INSTALLDIR := ${BASEDIR}/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

default: build

build: fmtcheck
	go mod tidy
	go install

tfdocs:
	tfplugindocs generate
	terraform fmt -recursive ./examples/

release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	mv ./bin/${BINARY}_${VERSION}_darwin_amd64 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_darwin_amd64.zip ./bin/terraform-provider-keyfactor
	GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386
	mv ./bin/${BINARY}_${VERSION}_freebsd_386 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_freebsd_386.zip ./bin/terraform-provider-keyfactor
	GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64
	mv ./bin/${BINARY}_${VERSION}_freebsd_amd64 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_freebsd_amd64.zip ./bin/terraform-provider-keyfactor
	GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm
	mv ./bin/${BINARY}_${VERSION}_freebsd_arm ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_freebsd_arm.zip ./bin/terraform-provider-keyfactor
	GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386
	mv ./bin/${BINARY}_${VERSION}_linux_386 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_linux_386.zip ./bin/terraform-provider-keyfactor
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64
	mv ./bin/${BINARY}_${VERSION}_linux_amd64 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_linux_amd64.zip ./bin/terraform-provider-keyfactor
	GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm
	mv ./bin/${BINARY}_${VERSION}_linux_arm ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_linux_arm.zip ./bin/terraform-provider-keyfactor
	GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386
	mv ./bin/${BINARY}_${VERSION}_openbsd_386 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_openbsd_386.zip ./bin/terraform-provider-keyfactor
	GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64
	mv ./bin/${BINARY}_${VERSION}_openbsd_amd64 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_openbsd_amd64.zip ./bin/terraform-provider-keyfactor
	GOOS=solaris GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_solaris_amd64
	mv ./bin/${BINARY}_${VERSION}_solaris_amd64 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_solaris_amd64.zip ./bin/terraform-provider-keyfactor
	GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386
	mv ./bin/${BINARY}_${VERSION}_windows_386 ./bin/terraform-provider-keyfactor.exe
	zip -j ./bin/${BINARY}_${VERSION}_windows_386.zip ./bin/terraform-provider-keyfactor.exe
	GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64
	mv ./bin/${BINARY}_${VERSION}_windows_amd64 ./bin/terraform-provider-keyfactor.exe
	zip -j ./bin/${BINARY}_${VERSION}_windows_amd64.zip ./bin/terraform-provider-keyfactor.exe
install:
	go build -o ${BINARY}
	mkdir -p ${INSTALLDIR}
	cp ${BINARY} ${INSTALLDIR}/${BINARY}

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

testunit:
	go test ./keyfactor/ -run "TestUnit" -v $(TESTARGS) -timeout 30m

testunit-record:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnit" -v -count=1 $(TESTARGS) -timeout 30m

# Record a single unit test cassette. Usage: make testunit-record-one TEST_NAME=TestUnitFoo
testunit-record-one:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testunit-record-one TEST_NAME=TestUnitFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 30m

testunit-record-csr:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_CSR" -v -count=1 -timeout 30m

testunit-record-application:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorApplication" -v -count=1 -timeout 30m

testunit-record-pam-provider:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorPAMProvider[^T]" -v -count=1 -timeout 30m

testunit-record-pam-provider-type:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorPAMProviderType" -v -count=1 -timeout 30m

# Run unit tests and display only failures (quiet mode)
testunit-check:
	go test ./keyfactor/ -run "TestUnit" -count=1 $(TESTARGS) -timeout 30m

KEYFACTOR_ENV_FILE ?= ~/.env_ses2541
KEYFACTOR_K8S_CREDENTIALS_FILE ?= $(HOME)/GolandProjects/terraform-keyfactor-provider-testing/examples/certs/deployment/k8s-creds.json

testint:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 go test ./keyfactor/ -run "TestInt" -v $(TESTARGS) -timeout 120m

testint-check:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 go test ./keyfactor/ -run "TestInt" -v -count=1 -timeout 120m

testint-run:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testint-run TEST_NAME=TestIntFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 120m

testint-debug:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testint-debug TEST_NAME=TestIntFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_LOG=DEBUG TF_ACC=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 120m 2>&1 | tee /tmp/tf-debug.log

# Run a single integration test with TF debug logging. Usage: make testint-debug-run TEST_NAME=TestIntFoo
testint-debug-run:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testint-debug-run TEST_NAME=TestIntFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_LOG=DEBUG TF_ACC=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 120m 2>&1 | tee /tmp/tf-debug.log

# Run all PAM integration tests
testint-pam:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestInt.*PAM" -v -count=1 -timeout 120m

# Run all Certificate Authority integration tests
testint-ca:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestInt.*CertificateAuthority" -v -count=1 -timeout 120m

# Run all Certificate Template integration tests
testint-template:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestInt.*CertificateTemplate" -v -count=1 -timeout 120m

# Run all tests (unit + int + acc). Requires lab connection.
testall:
	$(MAKE) testunit
	$(MAKE) testint-check

# Lint the provider code
lint:
	@which golangci-lint > /dev/null 2>&1 || (echo "golangci-lint not found, install from https://golangci-lint.run/usage/install/"; exit 1)
	golangci-lint run ./...

# Format Go files and check for issues
check: fmt vet

vet:
	go vet ./...

fmtcheck:
	@./scripts/gofmtcheck.sh

fmt:
	gofmt -w $(GOFMT_FILES)
	terraform fmt -recursive ./examples/

debug: install
	@./scripts/gofmtcheck.sh

setversion:
	sed -i '' -e 's/VERSION = ".*"/VERSION = "$(VERSION)"/' keyfactor/version.go
	@sed -i '' -e 's/TAG_VERSION=v*.*/TAG_VERSION=v$(VERSION)/' tag.sh

tidy:
	go mod tidy

vendor:
	rm -rf vendor
	go mod vendor

vendor-dev:
	go mod tidy
	./vendor_dev.sh

tag:
	git tag -d v$(VERSION) || true
	git push origin v$(VERSION) || true
	git tag v$(VERSION) || true
	git push origin v$(VERSION) || true

showlines:
	@if [ -z "$(FILE)" ] || [ -z "$(FROM)" ] || [ -z "$(TO)" ]; then \
		echo "Usage: make showlines FILE=<path> FROM=<line> TO=<line>"; \
		exit 1; \
	fi
	@sed -n '$(FROM),$(TO)p' $(FILE) | cat -v

# ---------------------------------------------------------------------------
# Applications API debugging targets (uses KEYFACTOR_ENV_FILE credentials)
# Usage examples:
#   make api-list-applications
#   make api-get-application APP_ID=9
#   make api-create-application APP_NAME=my-app
#   make api-update-application APP_ID=9 APP_NAME=my-app APP_INTERVAL=30
#   make api-delete-application APP_ID=9
#   make api-options-application
# ---------------------------------------------------------------------------
APP_ID ?= 1
APP_NAME ?= test-application
APP_INTERVAL ?= 60
APP_DAILY_TIME ?=
APP_OVERWRITE ?= false

# Internal helper: get OAuth token from env file
define get_token
	. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token')
endef

api-list-applications:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-get-application:
	@if [ -z "$(APP_ID)" ]; then echo "Usage: make api-get-application APP_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications/$(APP_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-create-application:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"Name\":\"$(APP_NAME)\",\"OverwriteSchedules\":$(APP_OVERWRITE),\"Schedule\":{\"Interval\":{\"Minutes\":$(APP_INTERVAL)}}}" | jq .

api-update-application:
	@if [ -z "$(APP_ID)" ]; then echo "Usage: make api-update-application APP_ID=<id> [APP_NAME=...] [APP_INTERVAL=...]"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X PUT \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"Id\":$(APP_ID),\"Name\":\"$(APP_NAME)\",\"OverwriteSchedules\":$(APP_OVERWRITE),\"Schedule\":{\"Interval\":{\"Minutes\":$(APP_INTERVAL)}}}" | jq .

api-delete-application:
	@if [ -z "$(APP_ID)" ]; then echo "Usage: make api-delete-application APP_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X DELETE \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications/$(APP_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN"

api-options-application:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	echo "--- OPTIONS /Applications ---" && \
	curl -sk -i -X OPTIONS "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" 2>&1 | grep -i "^allow:" && \
	echo "--- OPTIONS /Applications/$(APP_ID) ---" && \
	curl -sk -i -X OPTIONS "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Applications/$(APP_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" 2>&1 | grep -i "^allow:"

# ---------------------------------------------------------------------------
# Certificate Authority API debugging targets (uses KEYFACTOR_ENV_FILE credentials)
# Usage examples:
#   make api-list-cas
#   make api-get-ca CA_ID=1
# ---------------------------------------------------------------------------
CA_ID ?= 1

api-list-cas:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateAuthority" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-get-ca:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make api-get-ca CA_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateAuthority/$(CA_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-list-cas-short:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateAuthority" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '[.[] | {Id, LogicalName, HostName, CAType, Standalone, Remote}]'

# ---------------------------------------------------------------------------
# PAM Providers API debugging targets (uses KEYFACTOR_ENV_FILE credentials)
# Usage examples:
#   make api-list-pam-providers
#   make api-get-pam-provider PAM_ID=1
#   make api-list-pam-provider-types
#   make api-get-pam-provider-type PAM_TYPE_ID=c09bbfa5-a081-4194-9dd2-31f3cc3fabcc
#   make api-delete-pam-provider PAM_ID=1
#   make api-delete-pam-provider-type PAM_TYPE_ID=<guid>
# ---------------------------------------------------------------------------
PAM_ID ?= 1
PAM_TYPE_ID ?=
PAM_NAME ?= test-pam-provider
PAM_TYPE_GUID ?=

api-list-pam-providers:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/PamProviders" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-get-pam-provider:
	@if [ -z "$(PAM_ID)" ]; then echo "Usage: make api-get-pam-provider PAM_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/PamProviders/$(PAM_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-delete-pam-provider:
	@if [ -z "$(PAM_ID)" ]; then echo "Usage: make api-delete-pam-provider PAM_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X DELETE \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/PamProviders/$(PAM_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN"

api-list-pam-provider-types:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/PamProviders/Types" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-get-pam-provider-type:
	@if [ -z "$(PAM_TYPE_ID)" ]; then echo "Usage: make api-get-pam-provider-type PAM_TYPE_ID=<guid>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/PamProviders/Types/$(PAM_TYPE_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-delete-pam-provider-type:
	@if [ -z "$(PAM_TYPE_ID)" ]; then echo "Usage: make api-delete-pam-provider-type PAM_TYPE_ID=<guid>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X DELETE \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/PamProviders/Types/$(PAM_TYPE_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN"

TEMPLATE_ID ?= 1

api-list-templates:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Templates" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-get-template:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Templates/$(TEMPLATE_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

# Certificate API targets
#   make api-list-certs                         — list 5 most recent certs
#   make api-get-cert CERT_ID=123               — get certificate context by ID
#   make api-download-cert CERT_ID=123          — download cert as P7B
#   make api-recover-cert CERT_ID=123           — recover cert+key as STORE format
#   make api-recover-cert-pfx CERT_ID=123       — recover cert+key as PFX
#   make api-recover-cert-pem CERT_ID=123       — recover cert+key as PEM
CERT_ID ?=
CERT_PASSWORD ?= Tftest123456

CERT_QUERY ?=

api-list-certs:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	QUERY="pq.returnLimit=10&pq.sortAscending=0&pq.includeParameters=IncludeHasPrivateKey"; \
	if [ -n "$(CERT_QUERY)" ]; then QUERY="$$QUERY&pq.queryString=$(CERT_QUERY)"; fi; \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates?$$QUERY" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '[.[] | {Id, IssuedCN, Thumbprint, HasPrivateKey}]'

api-get-cert:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-get-cert CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/$(CERT_ID)?IncludeHasPrivateKey=true&IncludeMetadata=true" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-download-cert:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-download-cert CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/Download" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "x-certificateformat: P7B" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"CertID\": $(CERT_ID), \"IncludeChain\": true}" | head -200

api-recover-cert:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-recover-cert CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/Recover" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d '{"CertID": $(CERT_ID), "Password": "$(CERT_PASSWORD)", "IncludeChain": true}' | head -200

api-recover-cert-pfx:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-recover-cert-pfx CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/Recover" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d '{"CertID": $(CERT_ID), "Password": "$(CERT_PASSWORD)", "IncludeChain": true, "CertFormat": "PFX"}' | head -200

api-recover-cert-pem:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-recover-cert-pem CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/Recover" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d '{"CertID": $(CERT_ID), "Password": "$(CERT_PASSWORD)", "IncludeChain": true, "CertFormat": "PEM"}' | head -200

.PHONY: build release install test testacc testunit testunit-record testunit-record-one testunit-record-csr testunit-check testint testint-check testint-run testint-debug testint-debug-run testint-pam testint-ca testint-template testall lint check vet fmtcheck fmt tag setversion vendor vendor-dev showlines api-list-applications api-list-cas api-get-ca api-list-cas-short api-get-application api-create-application api-update-application api-delete-application api-options-application api-list-pam-providers api-get-pam-provider api-delete-pam-provider api-list-pam-provider-types api-get-pam-provider-type api-delete-pam-provider-type api-list-templates api-get-template api-list-certs api-get-cert api-download-cert api-recover-cert api-recover-cert-pfx api-recover-cert-pem