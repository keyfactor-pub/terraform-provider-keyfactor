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

PROVIDER_MODE ?= registry

ifeq ($(PROVIDER_MODE),dev)
TF            := TF_CLI_CONFIG_FILE=.terraformrc terraform
else
TF            := TF_CLI_CONFIG_FILE=$(PROVIDER_ROOT)/terraform/.terraformrc.registry terraform
endif
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

SHELL         := /bin/bash
KEYFACTOR_ENV_FILE ?= $(HOME)/.env_kfclab
LAB_TIMEOUT   ?= 600
CA_ID         ?= 2

LAB_ENV := set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
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

## plan: Alias for drift-check (this demo never plans a create -- see apply)
plan: drift-check

## apply: DISABLED -- this demo is import-only (see header). Refuses to run
##   so a stray `make apply` (e.g. from the top-level harness) can never
##   attempt to create a second connection to the lab's shared CA backend.
apply:
	@echo "SKIPPED: certificate_authority_demo is import-only (prevent_destroy); use 'make import-all' instead of 'make apply'."

## import-existing / import-all: Import the real lab CA by ID
import-existing:
	$(UNSET_BASIC) $(TF) import keyfactor_certificate_authority.openbao_pki $(CA_ID)

import-all: import-existing

## drift-check: Plan after import — shows any real drift, or fields this demo's
##   minimal config doesn't fully match (Optional+Computed fields with
##   UseStateForUnknown should show no diff; only genuinely-mismatched
##   Optional fields not set in config would appear, which is expected/informative
##   here since this demo intentionally doesn't mirror every attribute)
drift-check:
	$(UNSET_BASIC) $(TF) plan

## destroy: DISABLED -- lifecycle { prevent_destroy = true } on the resource
##   also blocks this at the Terraform Core level; this target exists only
##   so the canonical target name is present, and never touches the real CA.
destroy:
	@echo "SKIPPED: certificate_authority_demo never destroys the shared lab CA (prevent_destroy=true)."

## show: Show the current state (enum fields of interest)
show:
	$(UNSET_BASIC) $(TF) output

## clean: Remove generated files (never touches the real CA)
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

## lab-import-existing / lab-import-all: Import using lab credentials
lab-import-existing:
	$(LAB_ENV) $(MAKE) import-existing CA_ID=$(CA_ID)

lab-import-all: lab-import-existing

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

## lab-plan: Alias for lab-drift-check
lab-plan: lab-drift-check

## lab-apply / lab-destroy: DISABLED -- see apply/destroy above.
lab-apply:
	@echo "SKIPPED: certificate_authority_demo is import-only (prevent_destroy); use 'make lab-import-all' instead of 'make lab-apply'."

lab-destroy:
	@echo "SKIPPED: certificate_authority_demo never destroys the shared lab CA (prevent_destroy=true)."

## lifecycle: Full lifecycle for this demo: import-all -> drift-check (no apply/destroy -- see header)
lifecycle: lab-import-all lab-drift-check

.PHONY: build init validate plan apply import-existing import-all drift-check destroy show clean \
        lab-import-existing lab-import-all lab-plan lab-drift-check lab-apply lab-destroy lifecycle
