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
	$(eval SCREENSHOTS_TMP := $(shell mktemp -d))
	@if [ -d docs/screenshots ]; then cp -r docs/screenshots "$(SCREENSHOTS_TMP)/"; fi
	tfplugindocs generate
	terraform fmt -recursive ./examples/
	@if [ -d "$(SCREENSHOTS_TMP)/screenshots" ]; then cp -r "$(SCREENSHOTS_TMP)/screenshots" docs/; fi
	@rm -rf "$(SCREENSHOTS_TMP)"

## release-harness: Run the full terraform/ release-test harness against the
##   registry provider (keyfactor-pub/keyfactor). See terraform/GNUmakefile.
release-harness:
	$(MAKE) -C $(PROVIDER_DIR)/terraform harness-registry

## release-harness-dev: Run the full terraform/ release-test harness against
##   a locally-built dev provider binary. See terraform/GNUmakefile.
release-harness-dev:
	$(MAKE) -C $(PROVIDER_DIR)/terraform harness-dev

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
	go install
	mkdir -p ${INSTALLDIR}
	cp $(shell go env GOPATH)/bin/${BINARY} ${INSTALLDIR}/${BINARY}

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
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 KEYFACTOR_CLIENT_TIMEOUT=300 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 60m

testunit-record-csr:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_CSR" -v -count=1 -timeout 30m

testunit-record-cert-import:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_(PFX|CSR)_Import|TestUnitKeyfactorCertificateResource_PFX_PrivateKeyRead" -v -count=1 -timeout 30m

testunit-record-keytypes:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 KEYFACTOR_CLIENT_TIMEOUT=300 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_(PFX|CSR)_KeyTypes" -v -count=1 -timeout 60m

testunit-record-keytypes-pfx:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 KEYFACTOR_CLIENT_TIMEOUT=300 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_PFX_KeyTypes" -v -count=1 -timeout 60m

testunit-record-keytypes-csr:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_CSR_KeyTypes" -v -count=1 -timeout 30m

testunit-record-application:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorApplication" -v -count=1 -timeout 30m

testunit-record-application-schedules:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorApplicationResource(ScheduleTypes|Monthly|ExactlyOnce)" -v -count=1 -timeout 30m

testunit-record-pam-provider:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorPAMProvider[^T]" -v -count=1 -timeout 30m

testunit-record-pam-provider-type:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorPAMProviderType" -v -count=1 -timeout 30m

testunit-record-security-identity:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorIdentity" -v -count=1 -timeout 30m

testunit-record-security-role:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorSecurityRole" -v -count=1 -timeout 30m

testunit-record-cert-store-type:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateStoreType[^s]" -v -count=1 -timeout 30m

testunit-record-cert-store-types:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateStoreTypes" -v -count=1 -timeout 30m

testunit-record-agent-ds:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorAgentDataSource" -v -count=1 -timeout 30m

testunit-record-permission-set:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorPermissionSetDataSource" -v -count=1 -timeout 30m

testunit-record-oauth-claim:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuth(ClaimResource$$|SecurityClaimDataSource)" -v -count=1 -timeout 30m

testunit-record-oauth-role:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuthRoleResource$$" -v -count=1 -timeout 30m

testunit-record-oauth-role-ds:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuthSecurityRoleDataSource" -v -count=1 -timeout 30m

testunit-record-oauth-role-claim-assoc:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuthSecurityRoleClaimAssociation" -v -count=1 -timeout 30m

# Enrollment patterns require Command v25+; this target also sets TF_ACC=1 for API discovery
testunit-record-enrollment-pattern:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 TF_ACC=1 go test ./keyfactor/ -run "TestUnitKeyfactorEnrollmentPatternDataSource" -v -count=1 -timeout 30m

testunit-record-cert-authority:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateAuthority" -v -count=1 -timeout 30m

testunit-record-cert-template:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateTemplate" -v -count=1 -timeout 30m

testunit-record-cert-deploy:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateDeployResource$$" -v -count=1 -timeout 30m

testunit-record-cert-deploy-no-inv:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateDeployResource_NoInvSchedule" -v -count=1 -timeout 30m

testunit-record-template-role-binding:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorTemplateRoleBindingResource" -v -count=1 -timeout 30m

testunit-record-template-role-binding-import:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorTemplateRoleBindingResource_Import" -v -count=1 -timeout 30m

testunit-record-cert-store-import:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateStoreResource_Import" -v -count=1 -timeout 30m

# Record only the containers/<id>/stores/<guid> import cassette. Requires a
# container/application to exist in the lab so a store can be created inside it.
testunit-record-cert-store-import-container:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateStoreResource_Import_ContainersPath" -v -count=1 -timeout 30m

testunit-record-oauth-role-import:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuthRoleResource_Import" -v -count=1 -timeout 30m

# Nil-Id error path cassettes are hand-crafted (not recorded), but targets kept for consistency
testunit-record-oauth-role-nil:
	@echo "Cassette oauth_security_role_resource_nil_id_create is hand-crafted — no recording needed"
	@echo "Cassette oauth_security_role_resource_nil_id_import is hand-crafted — no recording needed"

testunit-record-oauth-claim-nil:
	@echo "Cassette oauth_security_claim_resource_nil_id_create is hand-crafted — no recording needed"

testunit-record-oauth-role-claim-assoc-import:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource_Import" -v -count=1 -timeout 30m

testunit-record-oauth-role-claim-assoc-multi:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorOAuthSecurityRoleClaimAssociation_MultiClaim" -v -count=1 -timeout 30m

testunit-record-cert-store-ds-guid:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateStoreDataSourceByGUID" -v -count=1 -timeout 30m

testunit-record-cert-full-subject:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_FullSubject" -v -count=1 -timeout 30m

testunit-record-cert-dns-sans:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_DNS_SANs" -v -count=1 -timeout 30m

testunit-record-cert-ip-sans:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_IP_SANs" -v -count=1 -timeout 30m

testunit-record-cert-uri-sans:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_URI_SANs" -v -count=1 -timeout 30m

testunit-record-cert-mixed-sans:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_MixedSANs" -v -count=1 -timeout 30m

testunit-record-cert-pfx-metadata:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_PFX_Metadata" -v -count=1 -timeout 30m

testunit-record-cert-csr-metadata:
	. $(KEYFACTOR_ENV_FILE) && RECORD_CASSETTES=1 go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_CSR_Metadata" -v -count=1 -timeout 30m

testunit-record-cert-no-ca:
	$(MAKE) testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateResource_PFX_NoCA
	$(MAKE) testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateResource_CSR_NoCA

## testunit-record-cert-friendly-collection: Record the VCR cassette for the
## "inconsistent result after apply" regression test (collection_id, friendly_name,
## use_cn_as_friendly_name preserved across Read).
testunit-record-cert-friendly-collection:
	$(MAKE) testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateResource_PFX_FriendlyNameAndCollectionPreserved

## testunit-repro-friendly-collection-bug: Reproduce the original v2.8.0 regression
## by checking out the exact buggy commit (b132d59) for resource_keyfactor_certificate.go,
## running the regression test (which is expected to FAIL on the buggy code), and then
## restoring the fix from HEAD. Use this to confirm the test actually catches the
## regression it documents. b132d59 is the precise commit that introduced the bug
## (more accurate than the v2.8.0 tag, which contains unrelated changes).
testunit-repro-friendly-collection-bug:
	@echo "==> Reproducing v2.8.0 regression: checking out b132d59 keyfactor/resource_keyfactor_certificate.go (buggy)"
	git checkout b132d59 -- keyfactor/resource_keyfactor_certificate.go
	@echo "==> Running TestUnitKeyfactorCertificateResource_PFX_FriendlyNameAndCollectionPreserved (expected to FAIL on buggy code)"
	-go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_PFX_FriendlyNameAndCollectionPreserved" -v -count=1 -timeout 5m
	@echo "==> Restoring fixed resource_keyfactor_certificate.go from HEAD"
	git checkout HEAD -- keyfactor/resource_keyfactor_certificate.go
	@echo "==> Re-running test on fixed code (expected to PASS)"
	go test ./keyfactor/ -run "TestUnitKeyfactorCertificateResource_PFX_FriendlyNameAndCollectionPreserved" -v -count=1 -timeout 5m

# Re-record ALL unit test cassettes (requires lab connection and Command v25+ for enrollment-pattern).
# This is the primary target to run when the Command API changes break existing cassettes.
testunit-record-all:
	$(MAKE) testunit-record-csr
	$(MAKE) testunit-record-application
	$(MAKE) testunit-record-pam-provider
	$(MAKE) testunit-record-pam-provider-type
	$(MAKE) testunit-record-security-identity
	$(MAKE) testunit-record-security-role
	$(MAKE) testunit-record-cert-store-type
	$(MAKE) testunit-record-cert-store-types
	$(MAKE) testunit-record-cert-store-ds-guid
	$(MAKE) testunit-record-agent-ds
	$(MAKE) testunit-record-permission-set
	$(MAKE) testunit-record-oauth-claim
	$(MAKE) testunit-record-oauth-role
	$(MAKE) testunit-record-oauth-role-ds
	$(MAKE) testunit-record-oauth-role-claim-assoc
	$(MAKE) testunit-record-enrollment-pattern
	$(MAKE) testunit-record-application-schedules
	$(MAKE) testunit-record-cert-authority
	$(MAKE) testunit-record-cert-template
	$(MAKE) testunit-record-cert-deploy
	$(MAKE) testunit-record-cert-deploy-no-inv
	$(MAKE) testunit-record-template-role-binding
	$(MAKE) testunit-record-template-role-binding-import
	$(MAKE) testunit-record-cert-store-import
	$(MAKE) testunit-record-oauth-role-import
	$(MAKE) testunit-record-oauth-role-claim-assoc-import
	$(MAKE) testunit-record-oauth-role-claim-assoc-multi
	$(MAKE) testunit-record-cert-full-subject
	$(MAKE) testunit-record-cert-dns-sans
	$(MAKE) testunit-record-cert-ip-sans
	$(MAKE) testunit-record-cert-uri-sans
	$(MAKE) testunit-record-cert-mixed-sans
	$(MAKE) testunit-record-cert-pfx-metadata
	$(MAKE) testunit-record-cert-csr-metadata
	$(MAKE) testunit-record-cert-no-ca
	$(MAKE) testunit-record-cert-friendly-collection

# Run unit tests and display only failures (quiet mode)
testunit-check:
	go test ./keyfactor/ -run "TestUnit" -count=1 $(TESTARGS) -timeout 30m

# Run all CA-related unit tests: VCR import test + nil-safe regression test
testunit-ca:
	go test ./keyfactor/ -run "TestUnitKeyfactorCertificateAuthority|TestUnitCertificateAuthorityResponseToState" -v -count=1 -timeout 30m

KEYFACTOR_ENV_FILE ?= ~/.env_ses2541
KEYFACTOR_K8S_CREDENTIALS_FILE ?= $(HOME)/GolandProjects/terraform-keyfactor-provider-testing/examples/certs/deployment/k8s-creds.json

# Integration test timeout; override with `make testint-check INT_TIMEOUT=180m`.
# The full suite runs ~117m and occasionally exceeds the 120m default.
INT_TIMEOUT ?= 120m

testint:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 go test ./keyfactor/ -run "TestInt" -v $(TESTARGS) -timeout $(INT_TIMEOUT)

testint-check:
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 go test ./keyfactor/ -run "TestInt" -v -count=1 -timeout $(INT_TIMEOUT)

testint-run:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testint-run TEST_NAME=TestIntFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout $(INT_TIMEOUT)

testint-debug:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testint-debug TEST_NAME=TestIntFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_LOG=DEBUG TF_ACC=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 120m 2>&1 | tee /tmp/tf-debug.log

# Run a single integration test with TF debug logging. Usage: make testint-debug-run TEST_NAME=TestIntFoo
testint-debug-run:
	@if [ -z "$(TEST_NAME)" ]; then echo "Usage: make testint-debug-run TEST_NAME=TestIntFoo"; exit 1; fi
	. $(KEYFACTOR_ENV_FILE) && KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_LOG=DEBUG TF_ACC=1 go test ./keyfactor/ -run "$(TEST_NAME)" -v -count=1 -timeout 120m 2>&1 | tee /tmp/tf-debug.log

# Run the basic certificate deploy integration test (no-schedule path).
# Completes quickly without an orchestrator — stores created without inventory_schedule
# skip the validateDeployment polling loop.
# Requires: KEYFACTOR_K8S_CREDENTIALS_FILE set to a kubeconfig JSON file path.
testint-deploy:
	set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
	KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 \
	go test ./keyfactor/ -run "^TestIntKeyfactorCertificateDeployResource$$" -v -count=1 -timeout 5m

# Run the certificate deploy integration test that requires an inventory schedule.
# Fails (not skips) after 10 minutes if the orchestrator never completes inventory.
# Requires: KEYFACTOR_K8S_CREDENTIALS_FILE set to a kubeconfig JSON file path.
testint-deploy-inventory:
	set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
	KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 \
	go test ./keyfactor/ -run "TestIntKeyfactorCertificateDeployResource_WithInventory" -v -count=1 -timeout 10m

# Run the both-paths certificate deploy integration test (no-schedule then with-schedule).
# Step 1 completes quickly (no polling). Step 2 requires orchestrator inventory.
# Fails (not skips) after 10 minutes if the orchestrator never completes.
# Requires: KEYFACTOR_K8S_CREDENTIALS_FILE set to a kubeconfig JSON file path.
testint-deploy-both-paths:
	set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
	KEYFACTOR_K8S_CREDENTIALS_FILE=$(KEYFACTOR_K8S_CREDENTIALS_FILE) TF_ACC=1 \
	go test ./keyfactor/ -run "TestIntKeyfactorCertificateDeployResource_BothPaths" -v -count=1 -timeout 12m

# Run all PAM integration tests
testint-pam:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestInt.*PAM" -v -count=1 -timeout 120m

# Run all Certificate Authority integration tests
testint-ca:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestInt.*CertificateAuthority" -v -count=1 -timeout 120m

# Run all Certificate Template integration tests
testint-template:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestInt.*CertificateTemplate" -v -count=1 -timeout 120m

# Run PFX key type integration tests (RSA-2048/4096, ECC P-256/P-384/P-521)
testint-keytypes-pfx:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestIntKeyfactorCertificateResource_PFX_KeyTypes" -v -count=1 -timeout 120m

# Run CSR key type integration tests (RSA, ECC P-256/P-384/P-521, Ed25519)
testint-keytypes-csr:
	. $(KEYFACTOR_ENV_FILE) && TF_ACC=1 go test ./keyfactor/ -run "TestIntKeyfactorCertificateResource_CSR_KeyTypes" -v -count=1 -timeout 120m

# Run only the OAuth access_token-only auth integration test. The test will
# auto-fetch a token from KEYFACTOR_AUTH_CLIENT_ID/SECRET/TOKEN_URL when
# KEYFACTOR_AUTH_ACCESS_TOKEN is not pre-set.
testint-oauth-access-token:
	set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
	TF_ACC=1 KEYFACTOR_API_PATH=Keyfactor/API \
	go test -mod=mod -v -timeout 5m -run "TestIntOAuthAccessTokenAuth" ./keyfactor/

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
# Certificate Store raw API debugging targets
# Used to inspect raw server responses for fields like ContainerName/ApplicationName.
# Usage examples:
#   make api-create-store-raw AGENT_ID=<guid> STORE_TYPE_ID=104 CONTAINER_NAME=tf-int-app-test
#   make api-delete-store-raw STORE_ID=<guid>
# ---------------------------------------------------------------------------
AGENT_ID     ?=
CLIENT_MACHINE ?= tf-harness-debug
CONTAINER_NAME ?= tf-int-app-test

api-create-store-raw:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"ClientMachine\":\"$(CLIENT_MACHINE)\",\"Storepath\":\"default/curl-raw-test\",\"CertStoreType\":$(STORE_TYPE_ID),\"ContainerName\":\"$(CONTAINER_NAME)\",\"AgentId\":\"$(AGENT_ID)\",\"Properties\":\"{\\\"KubeSecretType\\\":\\\"tls\\\",\\\"ServerUseSsl\\\":\\\"true\\\"}\",\"ServerUsername\":\"kubeconfig\"}" | jq .

api-delete-store-raw:
	@if [ -z "$(STORE_ID)" ]; then echo "Usage: make api-delete-store-raw STORE_ID=<guid>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk -w "\nHTTP_STATUS: %{http_code}\n" -X DELETE \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores/$(STORE_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN"

# ---------------------------------------------------------------------------
# Certificate Store Type API debugging targets
# Usage examples:
#   make api-list-store-types
#   make api-get-store-type STORE_TYPE_ID=154
# ---------------------------------------------------------------------------
STORE_TYPE_ID ?= 154

api-list-store-types:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStoreTypes" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '[.[] | {StoreType, ShortName, Name}]'

api-get-store-type:
	@if [ -z "$(STORE_TYPE_ID)" ]; then echo "Usage: make api-get-store-type STORE_TYPE_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStoreTypes/$(STORE_TYPE_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '{ShortName, PasswordOptions, Properties: [.Properties[]? | {Name, Required, DefaultValue}], EntryParameters: [.EntryParameters[]? | {Name, Required, DefaultValue}]}'

# ---------------------------------------------------------------------------
# Certificate Authority API debugging targets (uses KEYFACTOR_ENV_FILE credentials)
# Usage examples:
api-list-agents:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Agents" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '[.[] | {AgentId, ClientMachine, Status, LastSeen, Capabilities}]'

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

## api-ca-gap-fields: Show the fields missing from the provider for the first CA (UseForEnrollment,
##   CertificateCleanupEnabled, DeleteWithArchivedKey, TimeAfterExpiration, TimeAfterExpirationUnits).
api-ca-gap-fields:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateAuthority/$${CA_ID:-1}" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '{UseForEnrollment, CertificateCleanupEnabled, DeleteWithArchivedKey, TimeAfterExpiration, TimeAfterExpirationUnits}'

# api-update-ca: PUT /CertificateAuthority?forceSave=true using the CA JSON snapshot
# piped via stdin.  Useful for verifying the correct PUT URL (no ID in path).
# Usage: make api-get-ca CA_ID=1 | make api-update-ca
#
# NOTE: the HTTP status is written to STDERR, not interleaved with the
# response body on stdout. A prior version used `curl -w "\nHTTP_STATUS:
# %{http_code}\n" | jq .`, which appends non-JSON trailing text to stdout --
# jq then tries to parse it as a second JSON document and fails with "parse
# error: Invalid numeric literal" and exit code 5, even when the PUT itself
# succeeded (confirmed 2026-08-08: this silently broke every caller that
# checks api-update-ca's exit code or pipes its output onward, e.g.
# ca_schedule_demo's step3/4/5-seed targets).
#
# TLS verification is controlled by KEYFACTOR_SKIP_VERIFY (set in
# KEYFACTOR_ENV_FILE): only "true" adds curl's -k; anything else leaves
# verification on. KEYFACTOR_CA_CERT may additionally point at a CA bundle
# to trust via --cacert. Client credentials and the resulting bearer token
# never appear on curl's command line (and so never in the process table any
# other local user on a shared machine could read via `ps`) -- they're
# written to a curl -K config file created with `mktemp` + `chmod 600` and
# removed immediately after use.
api-update-ca:
	@. $(KEYFACTOR_ENV_FILE) && \
	CURL_TLS=""; if [ "$$KEYFACTOR_SKIP_VERIFY" = "true" ]; then CURL_TLS="-k"; fi; \
	if [ -n "$$KEYFACTOR_CA_CERT" ]; then CURL_TLS="$$CURL_TLS --cacert $$KEYFACTOR_CA_CERT"; fi; \
	KFCFG=$$(mktemp); chmod 600 "$$KFCFG"; trap 'rm -f "$$KFCFG"' EXIT; \
	printf 'data = "grant_type=client_credentials&client_id=%s&client_secret=%s"\n' "$$KEYFACTOR_AUTH_CLIENT_ID" "$$KEYFACTOR_AUTH_CLIENT_SECRET" > "$$KFCFG"; \
	TOKEN=$$(curl -s $$CURL_TLS -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -K "$$KFCFG" | jq -r '.access_token'); \
	printf 'header = "Authorization: Bearer %s"\n' "$$TOKEN" > "$$KFCFG"; \
	BODY=$$(cat) && \
	RESPFILE=$$(mktemp) && \
	HTTP_STATUS=$$(curl -s $$CURL_TLS -o "$$RESPFILE" -w "%{http_code}" -X PUT \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-KeyfactorAPI}/CertificateAuthority?forceSave=true" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-K "$$KFCFG" \
		-d "$$BODY") && \
	echo "HTTP_STATUS: $$HTTP_STATUS" >&2 && \
	jq . "$$RESPFILE"; \
	RC=$$?; rm -f "$$RESPFILE" "$$KFCFG"; exit $$RC

## testint-ca-snapshot: Capture current CA state to /tmp/ca_snapshot_<CA_ID>.json.
##   Usage: make testint-ca-snapshot [CA_ID=1]
testint-ca-snapshot:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-KeyfactorAPI}/CertificateAuthority/$(CA_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq . | tee /tmp/ca_snapshot_$(CA_ID).json
	@echo "Snapshot saved to /tmp/ca_snapshot_$(CA_ID).json"

## testint-ca-diff: Run the CA update test and diff CA state before/after.
##   Usage: make testint-ca-diff [CA_ID=1]
##   Saves before snapshot to /tmp/ca_before_<CA_ID>.json, after to /tmp/ca_after_<CA_ID>.json.
testint-ca-diff:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-KeyfactorAPI}/CertificateAuthority/$(CA_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq . > /tmp/ca_before_$(CA_ID).json
	@echo "Before snapshot saved to /tmp/ca_before_$(CA_ID).json"
	$(MAKE) testint-run TEST_NAME=TestIntKeyfactorCertificateAuthorityResourceUpdate 2>&1 | tee /tmp/ca_test_output.txt; \
	. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-KeyfactorAPI}/CertificateAuthority/$(CA_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq . > /tmp/ca_after_$(CA_ID).json
	@echo "After snapshot saved to /tmp/ca_after_$(CA_ID).json"
	@echo "=== CA diff (before vs after) ==="
	@diff /tmp/ca_before_$(CA_ID).json /tmp/ca_after_$(CA_ID).json || true

## api-ca-schema-diff: Compare GET response fields vs PUT request fields from live Swagger.
##   Prints: fields only in GET (read-only), fields only in PUT (write-only), fields in both.
##   Useful for identifying provider gaps.
api-ca-schema-diff:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	JQ_FILTER=$$'(.components.schemas["Keyfactor.Web.KeyfactorApi.Models.CertificateAuthorities.CertificateAuthorityResponse"].properties | keys) as $$get | (.components.schemas["Keyfactor.Web.KeyfactorApi.Models.CertificateAuthorities.CertificateAuthorityRequest"].properties | keys) as $$put | {"GET_only_readonly": [$$get[] | select(. as $$k | $$put | index($$k) | not)], "PUT_only_writeonly": [$$put[] | select(. as $$k | $$get | index($$k) | not)], "in_both": [$$get[] | select(. as $$k | $$put | index($$k))]}' && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/swagger/v1/swagger.json" \
		-H "Authorization: Bearer $$TOKEN" | jq "$$JQ_FILTER"

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

# api-update-template: PUT /Templates with a raw JSON body (UpdateTemplateArg
#   shape) piped via stdin -- mirrors api-update-ca. Used to seed/restore a
#   template's state directly, bypassing Terraform (e.g. byte-for-byte
#   restoration of a shared lab template after a demo run touches it).
#
# See api-update-ca above for the TLS-verification (KEYFACTOR_SKIP_VERIFY/
# KEYFACTOR_CA_CERT) and secret-handling (curl -K config file, never argv)
# conventions this target follows.
api-update-template:
	@. $(KEYFACTOR_ENV_FILE) && \
	CURL_TLS=""; if [ "$$KEYFACTOR_SKIP_VERIFY" = "true" ]; then CURL_TLS="-k"; fi; \
	if [ -n "$$KEYFACTOR_CA_CERT" ]; then CURL_TLS="$$CURL_TLS --cacert $$KEYFACTOR_CA_CERT"; fi; \
	KFCFG=$$(mktemp); chmod 600 "$$KFCFG"; trap 'rm -f "$$KFCFG"' EXIT; \
	printf 'data = "grant_type=client_credentials&client_id=%s&client_secret=%s"\n' "$$KEYFACTOR_AUTH_CLIENT_ID" "$$KEYFACTOR_AUTH_CLIENT_SECRET" > "$$KFCFG"; \
	TOKEN=$$(curl -s $$CURL_TLS -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -K "$$KFCFG" | jq -r '.access_token'); \
	printf 'header = "Authorization: Bearer %s"\n' "$$TOKEN" > "$$KFCFG"; \
	BODY=$$(cat) && \
	RESPFILE=$$(mktemp) && \
	HTTP_STATUS=$$(curl -s $$CURL_TLS -o "$$RESPFILE" -w "%{http_code}" -X PUT \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Templates" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Content-Type: application/json" \
		-K "$$KFCFG" \
		-d "$$BODY") && \
	echo "HTTP_STATUS: $$HTTP_STATUS" >&2 && \
	jq . "$$RESPFILE"; \
	RC=$$?; rm -f "$$RESPFILE" "$$KFCFG"; exit $$RC

# Certificate API targets
#   make api-list-certs                              — list 5 most recent certs
#   make api-get-cert CERT_ID=123                    — get certificate context by ID
#   make api-download-cert CERT_ID=123               — download cert as P7B (base64 JSON)
#   make api-inspect-cert-download CERT_ID=123       — download P7B and hex-dump raw bytes (BER investigation)
#   make api-recover-cert CERT_ID=123                — recover cert+key as STORE format
#   make api-recover-cert-pfx CERT_ID=123            — recover cert+key as PFX (base64 JSON)
#   make api-inspect-cert-recover-pfx CERT_ID=123    — recover PFX and hex-dump raw PKCS#12 bytes
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

api-inspect-cert-download:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-inspect-cert-download CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	RESP=$$(curl -sk -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/Download" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "x-certificateformat: P7B" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"CertID\": $(CERT_ID), \"IncludeChain\": true}") && \
	B64=$$(echo "$$RESP" | jq -r '.Content // empty') && \
	if [ -z "$$B64" ] || [ "$$B64" = "null" ]; then echo "No Content field. Full response:"; echo "$$RESP" | jq .; exit 1; fi && \
	TMPF=$$(mktemp /tmp/cert-download-XXXXXX.bin) && \
	printf '%s' "$$B64" | tr -d '\n' | base64 -d > "$$TMPF" && \
	echo "=== P7B download for cert $(CERT_ID) ===" && \
	echo "Decoded: $$(wc -c < $$TMPF | tr -d ' ') bytes" && \
	echo "First 64 bytes:" && xxd -l 64 "$$TMPF" && \
	echo "Last 16 bytes:" && tail -c 16 "$$TMPF" | xxd && \
	rm -f "$$TMPF"

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

api-inspect-cert-recover-pfx:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-inspect-cert-recover-pfx CERT_ID=<id> [CERT_PASSWORD=Tftest123456]"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	RESP=$$(curl -sk -X POST \
		"https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/Recover" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "x-certificateformat: PFX" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"CertID\": $(CERT_ID), \"Password\": \"$(CERT_PASSWORD)\", \"IncludeChain\": true}") && \
	echo "=== JSON keys ===" && echo "$$RESP" | jq 'keys' && \
	B64=$$(echo "$$RESP" | jq -r '.PFX // .PKCS12Blob // .Content // empty') && \
	if [ -z "$$B64" ] || [ "$$B64" = "null" ]; then echo "No PFX blob found. Full response:"; echo "$$RESP" | jq .; exit 1; fi && \
	TMPF=$$(mktemp /tmp/cert-recover-XXXXXX.bin) && \
	printf '%s' "$$B64" | tr -d '\n' | base64 -d > "$$TMPF" && \
	OUTF=/tmp/cert-recover-$(CERT_ID).pfx && cp "$$TMPF" "$$OUTF" && rm -f "$$TMPF" && \
	echo "=== PKCS#12 recover for cert $(CERT_ID) ===" && \
	echo "Saved: $$OUTF" && \
	echo "Decoded: $$(wc -c < $$OUTF | tr -d ' ') bytes" && \
	echo "First 64 bytes:" && xxd -l 64 "$$OUTF" && \
	echo "Last 16 bytes:" && tail -c 16 "$$OUTF" | xxd && \
	echo "=== openssl pkcs12 parse ===" && \
	openssl pkcs12 -in "$$OUTF" -passin "pass:$(CERT_PASSWORD)" -noenc 2>&1 || true

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

# ---------------------------------------------------------------------------
# Enrollment pattern API targets
#   make api-list-enrollment-patterns             — list all enrollment patterns
#   make api-get-enrollment-pattern EP_ID=<id>   — get pattern details (KeyInfo, CAs, etc.)
# ---------------------------------------------------------------------------
EP_ID ?= 1

api-list-enrollment-patterns:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/EnrollmentPatterns" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

api-get-enrollment-pattern:
	@if [ -z "$(EP_ID)" ]; then echo "Usage: make api-get-enrollment-pattern EP_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/EnrollmentPatterns/$(EP_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

# ---------------------------------------------------------------------------
# PFX enrollment API targets — raw curl against POST /Enrollment/PFX
# Tests all supported key type + size combinations.
#
# RSA:
#   make api-enroll-pfx-rsa-2048  EP_ID=1   — RSA 2048
#   make api-enroll-pfx-rsa-3072  EP_ID=1   — RSA 3072
#   make api-enroll-pfx-rsa-4096  EP_ID=1   — RSA 4096
#   make api-enroll-pfx-rsa-8192  EP_ID=1   — RSA 8192
#
# ECC (KeyLength only — curve inferred from size):
#   make api-enroll-pfx-ecc-p256  EP_ID=1   — ECC P-256  (KeyLength=256)
#   make api-enroll-pfx-ecc-p384  EP_ID=1   — ECC P-384  (KeyLength=384)
#   make api-enroll-pfx-ecc-p521  EP_ID=1   — ECC P-521  (KeyLength=521)
#
# ECC (KeyLength + Curve OID both set):
#   make api-enroll-pfx-ecc-p256-both EP_ID=1
#   make api-enroll-pfx-ecc-p384-both EP_ID=1
#   make api-enroll-pfx-ecc-p521-both EP_ID=1
#
# ECC (debugging variants):
#   make api-enroll-pfx-ecc-curve EP_ID=1   — KeyType=ECC + Curve OID only (no KeyLength)
#   make api-enroll-pfx-ecc-nokey EP_ID=1   — Curve OID only, no KeyType
#
# Ed:
#   make api-enroll-pfx-ed25519   EP_ID=1
#   make api-enroll-pfx-ed448     EP_ID=1
#
# Verify issued cert:
#   make api-check-cert-key CERT_ID=<n>     — show KeyAlgorithm/KeySize/Curve
#
# Defaults: EP_ID=1  ENROLL_CA=Sub-CA  ENROLL_CN=tf-curl-debug-ecc.example.com
# Override: make api-enroll-pfx-ecc-p256 EP_ID=2 ENROLL_CA="MyCA" ENROLL_CN="test.example.com"
# ---------------------------------------------------------------------------
ENROLL_CA     ?= Sub-CA
ENROLL_CN     ?= tf-curl-debug-ecc.example.com
ENROLL_PW     ?= Tftest123456
P256_OID      := 1.2.840.10045.3.1.7
P384_OID      := 1.3.132.0.34
P521_OID      := 1.3.132.0.35

# Internal helper — token + curl enrollment + jq summary.
# Each target sets BODY shell var then calls this shared block.
# NOTE: GNU Make $(call) splits on commas so we avoid it; use explicit targets instead.
_ENROLL_HDR = -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 2" -H "x-certificateformat: PFX" -H "Content-Type: application/json"
_ENROLL_JQ  = jq '{disposition: .CertificateInformation.RequestDisposition, id: .CertificateInformation.KeyfactorId, msg: .CertificateInformation.DispositionMessage, err: .Message}'
_TOKEN_CMD  = curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" | jq -r '.access_token'

# --- RSA ---
api-enroll-pfx-rsa-2048:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"RSA\",\"KeyLength\":2048,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-rsa-3072:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"RSA\",\"KeyLength\":3072,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-rsa-4096:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"RSA\",\"KeyLength\":4096,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-rsa-8192:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"RSA\",\"KeyLength\":8192,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-rsa: api-enroll-pfx-rsa-2048

# --- ECC (KeyLength only — P-256/P-384/P-521 inferred from size) ---
api-enroll-pfx-ecc-p256:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"KeyLength\":256,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ecc-p384:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"KeyLength\":384,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ecc-p521:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"KeyLength\":521,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- ECC (KeyLength + Curve OID both set) ---
api-enroll-pfx-ecc-p256-both:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"KeyLength\":256,\"Curve\":\"$(P256_OID)\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ecc-p384-both:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"KeyLength\":384,\"Curve\":\"$(P384_OID)\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ecc-p521-both:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"KeyLength\":521,\"Curve\":\"$(P521_OID)\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- ECC (Curve OID only, no KeyLength — for comparison/debugging) ---
api-enroll-pfx-ecc-curve:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"ECC\",\"Curve\":\"$(P256_OID)\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ecc-keylen: api-enroll-pfx-ecc-p256

api-enroll-pfx-ecc-nokey:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"Curve\":\"$(P256_OID)\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Ed25519 / Ed448 (EnrollmentPatternId) ---
api-enroll-pfx-ed25519:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed25519\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed448:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed448\",\"KeyLength\":448,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Ed25519 / Ed448 (Template name — UI uses this form; compare against EnrollmentPatternId) ---
ENROLL_TEMPLATE ?= Server_tlsServerAuth-1y

api-enroll-pfx-ed25519-tmpl:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"Template\":\"$(ENROLL_TEMPLATE)\",\"KeyType\":\"Ed25519\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed448-tmpl:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"Template\":\"$(ENROLL_TEMPLATE)\",\"KeyType\":\"Ed448\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Ed25519 / Ed448 (Template + EnrollmentPatternId both set) ---
api-enroll-pfx-ed25519-both:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"Template\":\"$(ENROLL_TEMPLATE)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed25519\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed448-both:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"Template\":\"$(ENROLL_TEMPLATE)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed448\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Ed25519 / Ed448 as AlternativeKeyType (hybrid cert; primary=RSA 2048) ---
api-enroll-pfx-ed25519-altkey:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"RSA\",\"KeyLength\":2048,\"AlternativeKeyType\":\"Ed25519\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed448-altkey:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"RSA\",\"KeyLength\":2048,\"AlternativeKeyType\":\"Ed448\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Ed25519 / Ed448 with explicit KeyLength ---
api-enroll-pfx-ed25519-255:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed25519\",\"KeyLength\":255,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed25519-256:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed25519\",\"KeyLength\":256,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed448-448:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed448\",\"KeyLength\":448,\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Ed25519 / Ed448 with API version 1 (compare against version 2) ---
_ENROLL_HDR_V1 = -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -H "x-certificateformat: PFX" -H "Content-Type: application/json"

api-enroll-pfx-ed25519-v1:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed25519\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR_V1) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

api-enroll-pfx-ed448-v1:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	BODY="{\"Subject\":\"CN=$(ENROLL_CN)\",\"CertificateAuthority\":\"$(ENROLL_CA)\",\"EnrollmentPatternId\":$(EP_ID),\"KeyType\":\"Ed448\",\"Password\":\"$(ENROLL_PW)\",\"IncludeChain\":true,\"Timestamp\":\"$$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}" && \
	curl -sk -X POST "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Enrollment/PFX" $(_ENROLL_HDR_V1) -H "Authorization: Bearer $$TOKEN" -d "$$BODY" | $(_ENROLL_JQ)

# --- Check key type of any issued cert ---
api-check-cert-key:
	@if [ -z "$(CERT_ID)" ]; then echo "Usage: make api-check-cert-key CERT_ID=<id>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$($(_TOKEN_CMD)) && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Certificates/$(CERT_ID)?IncludeHasPrivateKey=true" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" \
		| jq '{Id, IssuedCN, KeyAlgorithm, KeySizeInBits, Curve}'

# Certificate store targets
#   make api-list-cert-stores                    — list certificate stores (up to 10)
#   make api-list-cert-stores STORE_QUERY=<q>    — list stores filtered by query (e.g. STORE_QUERY=K8SCert)
#   make api-get-cert-store STORE_ID=<guid>      — get a specific store by GUID
STORE_QUERY ?=
api-list-cert-stores:
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	QUERY="certificateStoreQuery.returnLimit=10"; \
	if [ -n "$(STORE_QUERY)" ]; then QUERY="$$QUERY&certificateStoreQuery.queryString=$(STORE_QUERY)"; fi; \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores?$$QUERY" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq '[.[] | {Id, ClientMachine, Storepath, CertStoreType, Properties}]'

api-get-cert-store:
	@if [ -z "$(STORE_ID)" ]; then echo "Usage: make api-get-cert-store STORE_ID=<guid>"; exit 1; fi
	@. $(KEYFACTOR_ENV_FILE) && TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
		| jq -r '.access_token') && \
	curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores/$(STORE_ID)" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "x-keyfactor-api-version: 1" \
		-H "Authorization: Bearer $$TOKEN" | jq .

.PHONY: release-harness release-harness-dev build release install test testacc testunit testunit-record testunit-record-one testunit-record-csr testunit-record-cert-import testunit-record-keytypes testunit-record-keytypes-pfx testunit-record-keytypes-csr testunit-record-application testunit-record-pam-provider testunit-record-pam-provider-type testunit-record-security-identity testunit-record-security-role testunit-record-cert-store-type testunit-record-cert-store-types testunit-record-cert-store-ds-guid testunit-record-agent-ds testunit-record-permission-set testunit-record-oauth-claim testunit-record-oauth-role testunit-record-oauth-role-ds testunit-record-oauth-role-claim-assoc testunit-record-enrollment-pattern testunit-record-application-schedules testunit-record-cert-authority testunit-record-cert-template testunit-record-cert-deploy testunit-record-template-role-binding testunit-record-template-role-binding-import testunit-record-cert-store-import testunit-record-oauth-role-import testunit-record-oauth-role-claim-assoc-import testunit-record-oauth-role-claim-assoc-multi testunit-record-oauth-role-nil testunit-record-oauth-claim-nil testunit-record-all testunit-check testunit-ca testint testint-check testint-run testint-debug testint-debug-run testint-pam testint-ca testint-template testint-keytypes-pfx testint-keytypes-csr testint-oauth-access-token testint-ca-snapshot testint-ca-diff testall lint check vet fmtcheck fmt tag setversion vendor vendor-dev showlines api-list-applications api-list-cas api-get-ca api-list-cas-short api-update-ca api-ca-schema-diff api-ca-gap-fields api-get-application api-create-application api-update-application api-delete-application api-options-application api-list-pam-providers api-get-pam-provider api-delete-pam-provider api-list-pam-provider-types api-get-pam-provider-type api-delete-pam-provider-type api-list-templates api-get-template api-update-template api-list-certs api-get-cert api-download-cert api-inspect-cert-download api-recover-cert api-recover-cert-pfx api-inspect-cert-recover-pfx api-recover-cert-pem api-list-enrollment-patterns api-get-enrollment-pattern api-enroll-pfx-rsa api-enroll-pfx-rsa-2048 api-enroll-pfx-rsa-3072 api-enroll-pfx-rsa-4096 api-enroll-pfx-rsa-8192 api-enroll-pfx-ecc-p256 api-enroll-pfx-ecc-p384 api-enroll-pfx-ecc-p521 api-enroll-pfx-ecc-p256-both api-enroll-pfx-ecc-p384-both api-enroll-pfx-ecc-p521-both api-enroll-pfx-ecc-curve api-enroll-pfx-ecc-keylen api-enroll-pfx-ecc-nokey api-enroll-pfx-ed25519 api-enroll-pfx-ed448 api-enroll-pfx-ed25519-tmpl api-enroll-pfx-ed448-tmpl api-enroll-pfx-ed25519-both api-enroll-pfx-ed448-both api-enroll-pfx-ed25519-altkey api-enroll-pfx-ed448-altkey api-enroll-pfx-ed25519-255 api-enroll-pfx-ed25519-256 api-enroll-pfx-ed448-448 api-enroll-pfx-ed25519-v1 api-enroll-pfx-ed448-v1 api-check-cert-key api-list-agents