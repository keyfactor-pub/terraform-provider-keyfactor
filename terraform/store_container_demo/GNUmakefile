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
## A THIRD store (repro175, see repro175.tf) reproduces GitHub issue #175:
## Update() silently clears a container assignment made out-of-band whenever
## config never declares application_name/container_name. Run `make
## repro175` for the standalone reproduction sequence (seed → unrelated
## update → verify); see repro175.tf's header comment for full detail.
##
## Prerequisites — set these environment variables before running:
##   export KEYFACTOR_HOSTNAME=your-command-host.example.com
##   export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
##   export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
##   export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token
##   # kfclab's K8S orchestrators use in-cluster pod-identity auth by default
##   # (no kubeconfig needed -- see stores.tf). Only set this for orchestrators
##   # without that RBAC binding:
##   export TF_VAR_k8s_server_password_file=/path/to/flat-kubeconfig.json
##
## Usage:
##   cd terraform/store_container_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make lifecycle          # full lifecycle: apply → update → import → drift-check → destroy
##   make repro175           # standalone issue #175 reproduction sequence

PROVIDER_ROOT := $(abspath ../..)
PROVIDER_BIN  := $(HOME)/go/bin

PROVIDER_MODE ?= registry

ifeq ($(PROVIDER_MODE),dev)
TF          := TF_CLI_CONFIG_FILE=.terraformrc terraform
else
TF          := TF_CLI_CONFIG_FILE=$(PROVIDER_ROOT)/terraform/.terraformrc.registry terraform
endif
UNSET_BASIC := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

# ---------------------------------------------------------------------------
# Lab environment helpers
# Source KEYFACTOR_ENV_FILE for OAuth credentials.
# Override via: make KEYFACTOR_ENV_FILE=~/.env_other lifecycle
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
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials from KEYFACTOR_ENV_FILE
lab-plan:
	$(LAB_ENV) $(MAKE) plan

## lab-apply: Apply using lab credentials from KEYFACTOR_ENV_FILE
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

# ---------------------------------------------------------------------------
# Issue #175 reproduction — see repro175.tf for the full writeup.
#
#   1. repro175-apply        -- create the repro store with NO container
#                                assignment declared in config
#   2. repro175-seed         -- out-of-band: PUT /CertificateStores/{id}
#                                directly assigns the store to
#                                keyfactor_application.demo's container ID,
#                                bypassing Terraform entirely
#   3. repro175-verify-apply -- apply an UNRELATED attribute change
#                                (repro175_inventory_schedule 13:00 -> 15:00).
#                                Pre-fix: Update() clears the assignment and
#                                Terraform fails with "Provider produced
#                                inconsistent result after apply:
#                                .container_id: was cty.NumberIntVal(N), but
#                                now cty.NumberIntVal(0)". Post-fix: apply
#                                succeeds AND the assignment survives.
#   4. repro175-verify-server -- direct API GET confirming ContainerId is
#                                still the real, non-zero value server-side.
# ---------------------------------------------------------------------------

## repro175-apply: Create the application + repro175 store (no container declared)
repro175-apply:
	$(LAB_ENV) $(TF) apply -auto-approve \
	  -target=keyfactor_application.demo \
	  -target=keyfactor_certificate_store.repro175 \
	  -var="repro175_inventory_schedule=Daily at 13:00:00"

## repro175-seed: Out-of-band PUT that assigns the repro175 store to the
##   application's container ID directly via the Command REST API.
repro175-seed:
	@$(LAB_ENV) \
	 STORE_ID=$$($(TF) output -raw repro175_store_id) && \
	 APP_ID=$$($(TF) output -raw application_id 2>/dev/null || $(TF) show -json | jq -r '.values.root_module.resources[] | select(.address=="keyfactor_application.demo") | .values.id') && \
	 echo "    store: $$STORE_ID  ->  container/application id: $$APP_ID" && \
	 TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
	   -d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
	   | jq -r '.access_token') && \
	 STORE_JSON=$$(curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores/$$STORE_ID" \
	   -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -H "Authorization: Bearer $$TOKEN") && \
	 UPDATED=$$(echo "$$STORE_JSON" | jq --argjson cid "$$APP_ID" '.ContainerId = $$cid') && \
	 HTTP_STATUS=$$(curl -sk -o /tmp/store_container_demo_repro175_seed.json -w "%{http_code}" -X PUT \
	   "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores" \
	   -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" \
	   -H "Content-Type: application/json" -H "Authorization: Bearer $$TOKEN" \
	   -d "$$UPDATED") && \
	 echo "    PUT /CertificateStores HTTP status: $$HTTP_STATUS" && \
	 cat /tmp/store_container_demo_repro175_seed.json && echo && \
	 if [ "$$HTTP_STATUS" -lt 200 ] || [ "$$HTTP_STATUS" -ge 300 ]; then \
	   echo "FAIL: out-of-band container assignment did not succeed (HTTP $$HTTP_STATUS)"; \
	   exit 1; \
	 fi
	@echo "==> Refreshing Terraform state to pick up the out-of-band assignment..."
	$(LAB_ENV) $(TF) apply -auto-approve -refresh-only \
	  -var="repro175_inventory_schedule=Daily at 13:00:00"

## repro175-verify-apply: Apply an unrelated attribute change (schedule only).
##   This is the actual regression proof: MUST succeed without an
##   inconsistent-result crash, and container_id MUST remain non-zero.
repro175-verify-apply:
	@echo "==> Applying unrelated attribute change (inventory_schedule 13:00 -> 15:00)..."
	@$(LAB_ENV) $(TF) apply -auto-approve -no-color \
	  -var="repro175_inventory_schedule=Daily at 15:00:00" > /tmp/store_container_demo_repro175_apply.txt 2>&1; \
	 APPLY_EXIT=$$?; \
	 cat /tmp/store_container_demo_repro175_apply.txt; \
	 if [ $$APPLY_EXIT -ne 0 ]; then \
	   echo "FAIL: apply failed (exit $$APPLY_EXIT) -- issue #175 inconsistent-result regression."; \
	   exit 1; \
	 fi
	@CID=$$($(LAB_ENV) $(TF) output -raw repro175_container_id 2>/dev/null); \
	 echo "    container_id in state after unrelated update: $$CID"; \
	 if [ -z "$$CID" ] || [ "$$CID" = "0" ]; then \
	   echo "FAIL: container_id was cleared by the unrelated update -- issue #175 reproduced."; \
	   exit 1; \
	 else \
	   echo "PASS: container_id survived the unrelated update (issue #175 fix confirmed)."; \
	 fi

## repro175-verify-server: Direct API GET confirming ContainerId server-side.
repro175-verify-server:
	@$(LAB_ENV) \
	 STORE_ID=$$($(TF) output -raw repro175_store_id) && \
	 TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
	   -d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
	   | jq -r '.access_token') && \
	 curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores/$$STORE_ID" \
	   -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -H "Authorization: Bearer $$TOKEN" \
	   | jq '{Id, ContainerId, ContainerName}'

## repro175: Full standalone reproduction sequence for issue #175.
repro175: repro175-apply repro175-seed repro175-verify-apply repro175-verify-server

.PHONY: build init validate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle \
        repro175-apply repro175-seed repro175-verify-apply repro175-verify-server repro175
