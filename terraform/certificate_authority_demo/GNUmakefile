## certificate_authority_demo/GNUmakefile
##
## Import/read smoke test for keyfactor_certificate_authority, covering PR
## #179's enumPtrToTfInt64 refactor (enrollmentTypePtrToTfInt64,
## keyRetentionPtrToTfInt64, cleanupTimeUnitsPtrToTfInt64 now delegate to the
## shared generic helper). No behavior change was intended by that refactor.
##
## Deliberately IMPORT-ONLY: unlike this repo's other lab demos, this one
## never creates or destroys a CA connection -- there is exactly one real CA
## in this lab and fabricating a second risks confusing its PKI setup for no
## benefit (the refactor only touches Read()'s enum conversion, which import
## + a plan/refresh already exercises against the real, existing CA).
##
## Usage:
##   cd terraform/certificate_authority_demo
##   make build
##   make init
##   make lab-import-existing
##   make lab-drift-check

PROVIDER_ROOT  := $(abspath ../..)
PROVIDER_BIN   := $(HOME)/go/bin

TF            := TF_CLI_CONFIG_FILE=.terraformrc terraform
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

SHELL         := /bin/bash
LAB_ENV_FILE  ?= $(HOME)/.env_ses2541
LAB_TIMEOUT   ?= 600
CA_ID         ?= 1

LAB_ENV := set -a && source $(LAB_ENV_FILE) && set +a && \
           unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && \
           export KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT) &&

## build: Compile and install the provider binary to ~/go/bin
build:
	@echo "==> Building provider..."
	cd $(PROVIDER_ROOT) && go install .
	@echo "==> Provider installed to $(PROVIDER_BIN)/terraform-provider-keyfactor"

## init: Initialize the Terraform working directory
init:
	$(UNSET_BASIC) $(TF) init

## validate: Validate the Terraform configuration
validate:
	$(UNSET_BASIC) $(TF) validate

## import-existing: Import the real lab CA by ID
import-existing:
	$(UNSET_BASIC) $(TF) import keyfactor_certificate_authority.sub_ca $(CA_ID)

## drift-check: Plan after import — shows any real drift, or fields this demo's
##   minimal config doesn't fully match (Optional+Computed fields with
##   UseStateForUnknown should show no diff; only genuinely-mismatched
##   Optional fields not set in config would appear, which is expected/informative
##   here since this demo intentionally doesn't mirror every attribute)
drift-check:
	$(UNSET_BASIC) $(TF) plan

## show: Show the current state (enum fields of interest)
show:
	$(UNSET_BASIC) $(TF) output

## clean: Remove generated files (never touches the real CA)
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

## lab-import-existing: Import using lab credentials
lab-import-existing:
	$(LAB_ENV) $(MAKE) import-existing CA_ID=$(CA_ID)

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

.PHONY: build init validate import-existing drift-check show clean lab-import-existing lab-drift-check
