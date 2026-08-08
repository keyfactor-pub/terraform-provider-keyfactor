## pam_provider_type_demo/GNUmakefile
##
## Full-lifecycle smoke test for keyfactor_pam_provider_type, covering PR
## #179's enumPtrToTfInt64 refactor (pamParameterDataTypePtrToTfInt64 now
## delegates to the shared generic helper instead of duplicating its body).
## No behavior change was intended by that refactor; this demo proves the
## real create/read/import round-trip for parameters[].data_type still works:
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/pam_provider_type_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make lifecycle           # run the full lab lifecycle
##   make SUFFIX=_MYORG lifecycle

PROVIDER_ROOT  := $(abspath ../..)
PROVIDER_BIN   := $(HOME)/go/bin
SUFFIX         ?= _TF

PROVIDER_MODE ?= registry

ifeq ($(PROVIDER_MODE),dev)
TF            := TF_CLI_CONFIG_FILE=.terraformrc terraform
else
TF            := TF_CLI_CONFIG_FILE=$(PROVIDER_ROOT)/terraform/.terraformrc.registry terraform
endif
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

# ---------------------------------------------------------------------------
# Lab environment helpers
# ---------------------------------------------------------------------------
SHELL         := /bin/bash
KEYFACTOR_ENV_FILE ?= $(HOME)/.env_kfclab
LAB_TIMEOUT   ?= 600

LAB_ENV := set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
           unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && \
           export KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT) &&

# ---------------------------------------------------------------------------
# Provider build
# ---------------------------------------------------------------------------

## build: Compile and install the provider binary to ~/go/bin
build:
	@echo "==> Building provider..."
	cd $(PROVIDER_ROOT) && go install .
	@echo "==> Provider installed to $(PROVIDER_BIN)/terraform-provider-keyfactor"

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## init: Initialize the Terraform working directory
init:
	$(UNSET_BASIC) $(TF) init

## validate: Validate the Terraform configuration
validate:
	$(UNSET_BASIC) $(TF) validate

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the PAM provider type resource
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove the managed resource from state then re-import by its real ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@echo "==> Extracting ID from state..."
	@PROVIDER_TYPE_ID=$$($(UNSET_BASIC) $(TF) output -raw pam_provider_type_id 2>/dev/null) && \
	 echo "PAM Provider Type ID=$$PROVIDER_TYPE_ID" && \
	 echo "==> Removing from state..." && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_pam_provider_type.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 echo "==> Re-importing by real ID..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_pam_provider_type.demo "$$PROVIDER_TYPE_ID"

## reconcile: Apply after import to reconcile fields not returned by the API
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed PAM provider type resource
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
all: build init validate plan apply import-all reconcile drift-check destroy

# ---------------------------------------------------------------------------
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

## lab-import-all: Import all resources using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

## lab-reconcile: Reconcile after import
lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX)

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

## lab-destroy: Destroy all managed resources using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle
