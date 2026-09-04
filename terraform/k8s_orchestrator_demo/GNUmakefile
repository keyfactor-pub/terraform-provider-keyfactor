## k8s_orchestrator_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of keyfactor_certificate_store resources
## for all K8S store types (K8STLSSecr, K8SSecret, K8SCert, K8SJKS,
## K8SPKCS12, K8SNS, K8SCluster) including buddy-pass (PasswordIsK8SSecret) variants.
##
## Prerequisites — set these environment variables before running:
##   export KEYFACTOR_HOSTNAME=your-command-host.example.com
##   export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
##   export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
##   export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token
##   # Kubeconfig JSON for K8S orchestrator (path or content via TF var):
##   export TF_VAR_k8s_server_password_file=/path/to/sa-context.json
##
## Optional TF variables (see variables.tf for full list):
##   TF_VAR_inventory_schedule  — default "immediate"; use "Daily at HH:MM:SS" for a
##                                persistent schedule and to avoid plan drift after apply.
##   TF_VAR_create_if_missing   — default true; set false to skip store creation jobs.
##   TF_VAR_namespace           — default "default"; Kubernetes namespace for store paths.
##
## Certificate deployment alias formats (k8s-orchestrator docs):
##   K8STLSSecr / K8SSecret  — no alias required; cert placed into the store's backing
##                              secret by store path.
##   K8SJKS                  — alias = "<field>.jks/<keystore-alias>"
##                              (default field name "jks"; set via CertificateDataFieldName)
##   K8SPKCS12               — alias = "<field>.p12/<keystore-alias>"
##                              (default field name ".p12"; override via CertificateDataFieldName)
##   K8SCert / K8SNS / K8SCluster — inventory/discovery only; Add not supported.
##
## NOTE — "immediate" schedule drift:
##   Command treats "immediate" as a one-shot trigger. After the inventory job runs
##   (or exhausts retries) Command removes the schedule, so subsequent plans show
##   inventory_schedule drifting from "immediate" to empty. This is expected.
##   Override with TF_VAR_inventory_schedule="Daily at 12:00:00" to avoid drift.
##
## Usage:
##   cd terraform/k8s_orchestrator_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make all                # full lifecycle: build → init → validate → plan → apply → import-all → drift-check → destroy
##   make lifecycle          # lab lifecycle (sources KEYFACTOR_ENV_FILE automatically)

LAB_CA        ?= OpenBao PKI
LAB_PATTERN   ?= Lab - AnyCA (lab-role)
LAB_ENV_EXTRA_EXPORTS = TF_VAR_certificate_authority="$(LAB_CA)" TF_VAR_certificate_enrollment_pattern="$(LAB_PATTERN)"

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan

## apply: Create all K8S certificate stores
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve

## import-all: Remove all stores from state then re-import by store ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 ../_export_ids.py keyfactor_certificate_store
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

## reconcile: Apply after import to reconcile fields not returned by the API.
## Should produce no further changes.
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve

## drift-check: Plan after import — should show "No changes" (server_password is write-only)
drift-check:
	$(UNSET_BASIC) $(TF) plan

## destroy: Destroy all managed K8S certificate stores
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

## lab-update: Apply with updated inventory_schedule to verify in-place update path.
## Also verifies full→minimal: re-applies with default schedule and create_if_missing to
## confirm fields are cleared/reset on the server correctly.
lab-update:
	@echo "==> Step 1: update inventory_schedule and create_if_missing (in-place update path)..."
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

## lab-reconcile: Reconcile after import (re-apply to settle fields not returned by the API)
lab-reconcile:
	$(LAB_ENV) TF_VAR_inventory_schedule="Daily at 12:00:00" \
	           TF_VAR_create_if_missing=true \
	           $(MAKE) reconcile

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

## lifecycle: Full lifecycle: apply → update → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle
