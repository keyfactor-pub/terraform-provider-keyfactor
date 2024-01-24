PROVIDER_DIR := $(PWD)
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=keyfactor.com
GOFMT_FILES  := $$(find $(PROVIDER_DIR) -name '*.go' |grep -v vendor)
NAMESPACE=keyfactor
WEBSITE_REPO=https://github.com/Keyfactor/terraform-provider-keyfactor
NAME=keyfactor
BINARY=terraform-provider-${NAME}
VERSION=2.1.6-rc.5
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
BASEDIR := ~/.terraform.d/plugins
INSTALLDIR := ${BASEDIR}/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

default: build

build: fmtcheck
	go mod tidy
	go install

tfdocs:
	tfplugindocs generate
	terraform fmt -recursive ./examples/

macos_release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	mkdir -p ${HOME}/.terraform.d/plugins/keyfactor.com/keyfactor/keyfactor/${VERSION}/darwin_amd64
	cp ./bin/${BINARY}_${VERSION}_darwin_amd64 ${HOME}/.terraform.d/plugins/keyfactor.com/keyfactor/keyfactor/${VERSION}/darwin_amd64/${BINARY}
	mkdir -p ${HOME}/.terraform.d/plugins/keyfactor-pub/keyfactor/${VERSION}/darwin_amd64
	cp ./bin/${BINARY}_${VERSION}_darwin_amd64 ${HOME}/.terraform.d/plugins/keyfactor-pub/keyfactor/${VERSION}/darwin_amd64/${BINARY}
	mv ./bin/${BINARY}_${VERSION}_darwin_amd64 ./bin/terraform-provider-keyfactor
	zip -j ./bin/${BINARY}_${VERSION}_darwin_amd64.zip ./bin/terraform-provider-keyfactor
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
	rm -rf ${INSTALLDIR}
	mkdir -p ${INSTALLDIR}
	mv ${BINARY} ${INSTALLDIR}
	rm .terraform.lock.hcl || true
	terraform init -upgrade

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

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

vendor:
	go mod vendor

tag:
	git tag -d v$(VERSION) || true
	git push origin v$(VERSION) || true
	git tag v$(VERSION) || true
	git push origin v$(VERSION) || true

.PHONY: build release install test testacc fmtcheck fmt tag setversion vendor