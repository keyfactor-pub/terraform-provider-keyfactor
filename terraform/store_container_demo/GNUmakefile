## store_container_demo/GNUmakefile
##
## Validates that container_name (pre-v25 style) and application_name (v25+ alias)
## are interchangeable on keyfactor_certificate_store resources — both link the store
## to the same Keyfactor application/container without forcing resource replacement.
##
## Two K8STLSSecr stores are created and linked to a single keyfactor_application:
##   container_name_style  — uses container_name = application.name  (pre-v25)
##   application_name_style — uses application_name = application.name (v25+)
##
## Prerequisites — set these environment variables before running:
##   export KEYFACTOR_HOSTNAME=your-command-host.example.com
##   export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
##   export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
##   export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token
##   # Kubeconfig JSON for K8S orchestrator (path or content via TF var):
##   export TF_VAR_k8s_server_password_file=/path/to/sa-context.json
##
## Usage:
##   cd terraform/store_container_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make lifecycle          # full lifecycle: apply → update → import → drift-check → destroy

PROVIDER_ROOT := $(abspath ../..)
PROVIDER_BIN  := $(HOME)/go/bin

TF          := TF_CLI_CONFIG_FILE=.terraformrc terraform
UNSET_BASIC := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

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

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan

## apply: Create the application and both certificate stores
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve

## import-all: Remove both stores from state then re-import by store ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 _export_ids.py
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_certificate_store.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by store ID..."
	@while IFS=' ' read -r name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import "keyfactor_certificate_store.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$name (ID=$$id)"; \
	    echo "$$result" | tail -5; \
	  fi; \
	done < _import_pairs.txt

## drift-check: Plan after import — only write-only fields should appear as "to change"
drift-check:
	$(UNSET_BASIC) $(TF) plan

## destroy: Destroy both certificate stores and the application
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve

## clean: Remove generated files
clean:
	rm -f tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full lifecycle — build, init, validate, plan, apply, import-all, drift-check, destroy
all: build init validate plan apply import-all drift-check destroy

## demo-no-destroy: Run through drift-check but leave resources on server
demo-no-destroy: build init validate plan apply import-all drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source LAB_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials from LAB_ENV_FILE
lab-plan:
	$(LAB_ENV) $(MAKE) plan

## lab-apply: Apply using lab credentials from LAB_ENV_FILE
## Uses "Daily at 12:00:00" schedule to avoid "immediate" drift after apply.
lab-apply:
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) apply

## lab-update: Apply with updated inventory_schedule and create_if_missing to verify
## in-place update path (no resource replacement).
## Step 1: change schedule + disable create_if_missing.
## Step 2: revert — confirm no forced replacement occurs (validates backwards compat).
lab-update:
	@echo "==> Step 1: update inventory_schedule and create_if_missing (in-place update)..."
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 14:00:00" \
	           TF_VAR_create_if_missing=false \
	           $(MAKE) apply
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 14:00:00" \
	           TF_VAR_create_if_missing=false \
	           $(MAKE) plan
	@echo "==> Step 2: revert to default values — verify no forced replacement..."
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) apply
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) plan

## lab-import-all: Import all stores using lab credentials
lab-import-all:
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) import-all

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) drift-check

## lab-destroy: Destroy using lab credentials
lab-destroy:
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) destroy

## lifecycle: Full lifecycle: apply → update → import-all → apply (reconcile) → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-apply lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle
