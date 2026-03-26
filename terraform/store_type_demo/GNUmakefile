## store_type_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of keyfactor_certificate_store_type resources:
##   build → init → validate → apply (data) → generate → plan → apply → import → destroy
##
## Usage:
##   cd terraform/store_type_demo
##   make build          # compile + install the provider locally
##   make init           # terraform init
##   make all            # run the full workflow
##   make SUFFIX=_MY_ORG generate  # regenerate with custom suffix

PROVIDER_ROOT := $(abspath ../..)
PROVIDER_BIN  := $(HOME)/go/bin
SUFFIX        ?= _TF

TF            := TF_CLI_CONFIG_FILE=.terraformrc terraform
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

# ---------------------------------------------------------------------------
# Lab environment helpers
# Source LAB_ENV_FILE for OAuth credentials.
# Override via: make LAB_ENV_FILE=~/.env_other lifecycle
# ---------------------------------------------------------------------------
SHELL         := /bin/bash
LAB_ENV_FILE  ?= $(HOME)/.env_ses2541
LAB_TIMEOUT   ?= 600

LAB_ENV := set -a && source $(LAB_ENV_FILE) && set +a && \
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

## apply-data: Apply only the data sources (discovers all store types, saves state)
apply-data:
	$(UNSET_BASIC) $(TF) apply -auto-approve -target=data.keyfactor_certificate_store_types.all

## generate: Generate store_types.tf from live state with SUFFIX appended to short_name/capability/name
generate: apply-data
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 gen_store_types.py --suffix "$(SUFFIX)" --state tf_state.json --out store_types.tf
	@echo "==> Generated store_types.tf ($(SUFFIX) suffix)"

## plan: Show the execution plan for all resources
plan:
	$(UNSET_BASIC) $(TF) plan

## apply: Create all store type resources (adds SUFFIX to short_name/name/capability)
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve

## import-all: Remove all managed resources from state then re-import by short_name
import-all:
	@echo "==> Exporting name/ID pairs from state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 _export_ids.py
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id sn; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_certificate_store_type.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by short_name..."
	@while IFS=' ' read -r name id sn; do \
	  result=$$($(UNSET_BASIC) $(TF) import "keyfactor_certificate_store_type.$$name" "$$sn" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name ($$sn)"; \
	  else \
	    echo "FAIL: $$name ($$sn)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt

## drift-check: Plan after import — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan

## destroy: Destroy all managed store type resources
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve

## clean: Remove generated files (state, generated tf, import pairs)
clean:
	rm -f tf_state.json store_types.tf _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, apply-data, generate, plan, apply, import-all, drift-check, destroy
all: build init validate generate plan apply import-all drift-check destroy

## demo-no-destroy: Run workflow without final destroy (leaves resources on server)
demo-no-destroy: build init validate generate plan apply import-all drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source LAB_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-generate: Discover store types and generate store_types.tf using lab credentials
lab-generate:
	$(LAB_ENV) $(MAKE) generate SUFFIX=$(SUFFIX)

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply

## lab-update: Re-apply to verify idempotency (store type fields are fully managed — re-apply = no-op)
## Also verifies zero drift immediately after apply.
lab-update:
	@echo "==> Verifying idempotent re-apply (in-place update with no config change)..."
	$(LAB_ENV) $(MAKE) apply
	$(LAB_ENV) $(MAKE) plan

## lab-import-all: Import all store types using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

## lab-destroy: Destroy all managed store types using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy

## lifecycle: Full lifecycle: generate → apply → update → import-all → drift-check → destroy
lifecycle: lab-generate lab-apply lab-update lab-import-all lab-drift-check lab-destroy

.PHONY: build init validate apply-data generate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-generate lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle
