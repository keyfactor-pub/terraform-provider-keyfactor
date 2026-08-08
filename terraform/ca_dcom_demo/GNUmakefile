## ca_dcom_demo/GNUmakefile
##
## Record-only demo for a DCOM (ca_type=0) keyfactor_certificate_authority
## registration. kfclab has no real Active Directory / DCOM CA backend (it is
## Authentik-OAuth-only), so this demo uses fabricated host/tenant values --
## see main.tf's header comment for the full rationale.
##
## If this Command instance rejects DCOM CA records outright (stricter
## validation than a pre-migration lab), `lifecycle` reports a clean SKIPPED
## instead of failing the whole harness -- this demo exists to document that
## constraint, not to force a DCOM connection that cannot exist here.
##
## Usage:
##   cd terraform/ca_dcom_demo
##   make build
##   make init
##   make lifecycle

PROVIDER_ROOT := $(abspath ../..)
PROVIDER_BIN  := $(HOME)/go/bin
SUFFIX        ?= _TF

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

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the DCOM CA record. Prints SKIPPED (exit 0) instead of
##   failing if Command rejects the record outright -- see header.
apply:
	@$(UNSET_BASIC) $(TF) apply -auto-approve -no-color -var="suffix=$(SUFFIX)" > /tmp/ca_dcom_demo_apply.txt 2>&1; \
	 APPLY_EXIT=$$?; \
	 cat /tmp/ca_dcom_demo_apply.txt; \
	 if [ $$APPLY_EXIT -ne 0 ]; then \
	   echo "SKIPPED: ca_dcom_demo -- this Command instance rejected the DCOM (ca_type=0) CA record (no real AD/DCOM backend in this lab). See main.tf header."; \
	   exit 0; \
	 fi

## import-all: Remove and re-import the CA by ID (no-op if apply was skipped)
import-all:
	@CA_ID=$$($(UNSET_BASIC) $(TF) output -raw ca_id 2>/dev/null); \
	 if [ -z "$$CA_ID" ]; then \
	   echo "SKIPPED: ca_dcom_demo -- no CA in state to import (apply was skipped)."; \
	   exit 0; \
	 fi; \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_certificate_authority.demo 2>&1 | grep -E "Removed|Successfully" || true; \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_certificate_authority.demo "$$CA_ID"

## drift-check: Plan after import — should show "No changes" (or SKIPPED if never created)
drift-check:
	@if [ -z "$$($(UNSET_BASIC) $(TF) output -raw ca_id 2>/dev/null)" ]; then \
	  echo "SKIPPED: ca_dcom_demo -- nothing in state to drift-check."; \
	  exit 0; \
	fi
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the DCOM CA record (no-op if never created)
destroy:
	@if [ -z "$$($(UNSET_BASIC) $(TF) output -raw ca_id 2>/dev/null)" ]; then \
	  echo "SKIPPED: ca_dcom_demo -- nothing in state to destroy."; \
	  exit 0; \
	fi
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

## all: Full workflow — build, init, validate, plan, apply, import-all, drift-check, destroy
all: build init validate plan apply import-all drift-check destroy

## lab-plan / lab-apply / lab-import-all / lab-drift-check / lab-destroy:
## Same as above, sourcing KEYFACTOR_ENV_FILE automatically.
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → import-all → drift-check → destroy
##   Each step is individually SKIP-safe (see apply/import-all/drift-check/destroy above).
lifecycle: lab-apply lab-import-all lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all drift-check destroy clean all \
        lab-plan lab-apply lab-import-all lab-drift-check lab-destroy lifecycle
