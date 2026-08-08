## certificate_template_demo/GNUmakefile
##
## Import + update demo for keyfactor_certificate_template. Templates cannot
## be created via the Command API -- this resource must be imported by
## integer ID before any update is possible.
##
## KNOWN LAB CONSTRAINT: some Command instances reject ANY template update
## with "'Policies' cannot be empty" (see main.tf header). `lab-update`
## reports this as a clear FAIL, not a harness crash -- that failure IS the
## point of this demo on labs with the gap.
##
## Usage:
##   cd terraform/certificate_template_demo
##   make build
##   make init
##   make lab-import-existing TEMPLATE_ID=6
##   make lab-update

PROVIDER_ROOT := $(abspath ../..)
PROVIDER_BIN  := $(HOME)/go/bin

PROVIDER_MODE ?= registry

ifeq ($(PROVIDER_MODE),dev)
TF          := TF_CLI_CONFIG_FILE=.terraformrc terraform
else
TF          := TF_CLI_CONFIG_FILE=$(PROVIDER_ROOT)/terraform/.terraformrc.registry terraform
endif
UNSET_BASIC := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

SHELL              := /bin/bash
KEYFACTOR_ENV_FILE ?= $(HOME)/.env_kfclab
LAB_TIMEOUT        ?= 600
TEMPLATE_ID        ?= 6

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

## plan: Show the execution plan (informational only until imported)
plan:
	$(UNSET_BASIC) $(TF) plan

## apply: DISABLED -- templates cannot be created via API; use import-existing.
apply:
	@echo "SKIPPED: certificate_template_demo cannot create templates (Command API limitation); use 'make import-all TEMPLATE_ID=<id>' instead."

## import-existing / import-all: Import the existing template by ID
import-existing:
	$(UNSET_BASIC) $(TF) import keyfactor_certificate_template.demo $(TEMPLATE_ID)

import-all: import-existing

## drift-check: Plan after import — real templates will likely show drift for
##   any field this demo doesn't declare; that's expected/informative (see
##   certificate_authority_demo's drift-check for the same pattern).
drift-check:
	$(UNSET_BASIC) $(TF) plan

## destroy: DISABLED -- this demo never deletes a real template.
destroy:
	@echo "SKIPPED: certificate_template_demo never destroys a real lab template."

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

## all: build, init, validate, import-all, drift-check
all: build init validate import-all drift-check

## lab-import-existing / lab-import-all / lab-drift-check:
lab-import-existing:
	$(LAB_ENV) $(MAKE) import-existing TEMPLATE_ID=$(TEMPLATE_ID)

lab-import-all: lab-import-existing

lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

lab-plan: lab-drift-check

lab-apply:
	@echo "SKIPPED: certificate_template_demo cannot create templates; use 'make lab-import-all' instead of 'make lab-apply'."

lab-destroy:
	@echo "SKIPPED: certificate_template_demo never destroys a real lab template."

## lab-update: Apply a safe friendly_name change to exercise Update().
##   Reports a clear PASS/FAIL -- a FAIL here on labs with the known
##   "'Policies' cannot be empty" gap is expected and IS the point of this
##   demo, not a harness crash.
lab-update:
	@echo "==> [1/3] import (if not already in state)..."
	@$(LAB_ENV) $(TF) state show keyfactor_certificate_template.demo >/dev/null 2>&1 || \
	  $(LAB_ENV) $(TF) import keyfactor_certificate_template.demo $(TEMPLATE_ID)
	@echo "==> [2/3] apply friendly_name change..."
	@$(LAB_ENV) TF_VAR_friendly_name_override="Terraform Harness Demo ($(TEMPLATE_ID))" \
	  $(TF) apply -auto-approve -no-color > /tmp/certificate_template_demo_update.txt 2>&1; \
	 APPLY_EXIT=$$?; \
	 cat /tmp/certificate_template_demo_update.txt; \
	 if [ $$APPLY_EXIT -eq 0 ]; then \
	   echo "PASS: template update succeeded."; \
	 else \
	   echo "FAIL: template update failed -- likely the known \"'Policies' cannot be empty\" lab/SDK gap (see main.tf header). This is a documented constraint, not a crash."; \
	   exit 1; \
	 fi
	@echo "==> [3/3] revert friendly_name..."
	$(LAB_ENV) $(TF) apply -auto-approve

## lifecycle: Full lifecycle for this demo: import-all -> lab-update -> drift-check
##   (no apply/destroy -- see header)
lifecycle: lab-import-all lab-update lab-drift-check

.PHONY: build init validate plan apply import-existing import-all drift-check destroy clean all \
        lab-import-existing lab-import-all lab-drift-check lab-plan lab-apply lab-destroy lab-update lifecycle
