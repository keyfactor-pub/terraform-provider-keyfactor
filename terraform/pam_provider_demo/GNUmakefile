## pam_provider_demo/GNUmakefile
##
## Full-lifecycle demo for keyfactor_pam_provider against the lab's real
## Hashicorp-Vault PAM provider type:
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/pam_provider_demo
##   make build
##   make init
##   TF_VAR_vault_token=... make lifecycle

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

## validate: Validate the Terraform configuration (no credentials required)
validate:
	$(UNSET_BASIC) $(TF) validate

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the PAM provider
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove the managed resource from state then re-import by its real ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@PROVIDER_ID=$$($(UNSET_BASIC) $(TF) output -raw pam_provider_id 2>/dev/null) && \
	 echo "PAM Provider ID=$$PROVIDER_ID" && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_pam_provider.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_pam_provider.demo "$$PROVIDER_ID"

## reconcile: Apply after import to reconcile write-only secret param_values
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile — only the secret param_value should differ (write-only)
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the PAM provider
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

## all: Full workflow — build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
all: build init validate plan apply import-all reconcile drift-check destroy

## lab-plan / lab-apply / lab-import-all / lab-reconcile / lab-drift-check / lab-destroy:
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX)

lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → import-all → reconcile → drift-check → destroy
##   REQUIRES TF_VAR_vault_token to be set.
lifecycle:
	@if [ -z "$$TF_VAR_vault_token" ]; then \
	  echo "SKIPPED: pam_provider_demo requires TF_VAR_vault_token for the lab's Vault/OpenBao instance (no default -- see variables.tf)."; \
	else \
	  $(MAKE) lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy; \
	fi

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle
