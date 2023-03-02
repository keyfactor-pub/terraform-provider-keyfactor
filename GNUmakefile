PROVIDER_DIR := $(PWD)
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=keyfactor.com
GOFMT_FILES  := $$(find $(PROVIDER_DIR) -name '*.go' |grep -v vendor)
NAMESPACE=keyfactor
WEBSITE_REPO=https://github.com/Keyfactor/terraform-provider-keyfactor
NAME=keyfactor
BINARY=terraform-provider-${NAME}
VERSION=1.2.0
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
BASEDIR := ~/.terraform.d/plugins
INSTALLDIR := ${BASEDIR}/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

default: build

build: fmtcheck
	go install

tfdocs:
	tfplugindocs generate
	terraform fmt -recursive ./examples/

release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386
	GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64
	GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm
	GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64
	GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm
	GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386
	GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64
	GOOS=solaris GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_solaris_amd64
	GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386
	GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64

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

.PHONY: build release install test testacc fmtcheck fmt