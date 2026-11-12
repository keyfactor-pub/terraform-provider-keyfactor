## k8s_orchestrator_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of keyfactor_certificate_store resources
## for all K8S store types (K8STLSSecr, K8SSecret, K8SCert, K8SJKS,
## K8SPKCS12, K8SNS, K8SCluster) including buddy-pass (PasswordIsK8SSecret) variants.
##
## Prerequisites: set these environment variables before running:
##   export KEYFACTOR_HOSTNAME=your-command-host.example.com
##   export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
##   export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
##   export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token
##   # Kubeconfig JSON for K8S orchestrator (path or content via TF var):
##   export TF_VAR_k8s_server_password_file=/path/to/sa-context.json
##
## Optional TF variables (see variables.tf for full list):
##   TF_VAR_inventory_schedule: default "immediate"; use "Daily at HH:MM:SS" for a
##                                persistent schedule and to avoid plan drift after apply.
##   TF_VAR_create_if_missing: default true; set false to skip store creation jobs.
##   TF_VAR_namespace: default "default"; Kubernetes namespace for store paths.
##
## Certificate deployment alias formats (k8s-orchestrator docs):
##   K8STLSSecr / K8SSecret: no alias required; cert placed into the store's backing
##                              secret by store path.
##   K8SJKS: alias = "<field>.jks/<keystore-alias>"
##                              (default field name "jks"; set via CertificateDataFieldName)
##   K8SPKCS12: alias = "<field>.p12/<keystore-alias>"
##                              (default field name ".p12"; override via CertificateDataFieldName)
##   K8SCert / K8SNS / K8SCluster: inventory/discovery only; Add not supported.
##
## NOTE: "immediate" schedule drift:
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

## drift-check: Plan after import (should show "No changes" (server_password is write-only)
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

## all: Full lifecycle: build, init, validate, plan, apply, import-all, drift-check, destroy
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
	@echo "==> Step 2: revert to default values; verify no forced replacement..."
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

# ---------------------------------------------------------------------------
# include_private_key / skip_removal / out-of-band-removal checks (OPT-IN)
#
# NOT part of `lifecycle`. These exercise keyfactor_certificate_deployment.opaque_secret
# (K8SSecret store) behaviours added in PR #228:
#   lab-ipk-check          include_private_key=false -> REPLACE; secret has only tls.crt;
#                          skip_removal=true blocks a replace at plan time; restore -> No changes
#   lab-ipk-oob-check      remove the cert from the store via the Command API, wait for
#                          Locations/inventory to drop it, expect "1 to add" + redeploy warning
#   lab-ipk-upgrade-check  create the deployment with a BASELINE provider (no include_private_key),
#                          then plan with the current provider: unset=no changes, true=in-place,
#                          false=replace. Needs BASE_PROVIDER_DIR (dir holding the baseline
#                          terraform-provider-keyfactor binary). Uses its own state in UPGRADE_DIR.
#
# Prerequisite for lab-ipk-check / lab-ipk-oob-check: `make lab-apply` has been run.
# All targets pass the lifecycle's TF_VAR_inventory_schedule/create_if_missing themselves.
# Primitives accept OPAQUE_IPK=<true|false> and OPAQUE_SKIP_REMOVAL=<true|false> (empty = unset).
# Logs: IPK_LOG_DIR (default ./.ipk-logs).
# ---------------------------------------------------------------------------

OPAQUE_IPK          ?=
OPAQUE_SKIP_REMOVAL ?=
IPK_LOG_DIR         ?= $(CURDIR)/.ipk-logs
IPK_OOB_MAX_WAIT    ?= 900
IPK_OOB_INTERVAL    ?= 20
BASE_PROVIDER_DIR   ?=
UPGRADE_DIR         ?= $(CURDIR)/.ipk-upgrade
KUBECONFIG_LAB      ?= $(HOME)/.kube/kfc-lab.yaml
K8S_NAMESPACE       ?= default
OPAQUE_SECRET_NAME  ?= tf-demo-opaque-secret
IPK_TARGET          := -target=keyfactor_certificate_deployment.opaque_secret

IPK_TFVARS = TF_VAR_inventory_schedule="Daily at 12:00:00" TF_VAR_create_if_missing=true \
             $(if $(OPAQUE_IPK),TF_VAR_opaque_include_private_key=$(OPAQUE_IPK)) \
             $(if $(OPAQUE_SKIP_REMOVAL),TF_VAR_opaque_skip_removal=$(OPAQUE_SKIP_REMOVAL))

UPG_TF_BASE = TF_CLI_CONFIG_FILE=$(UPGRADE_DIR)/.terraformrc.base terraform -chdir=$(UPGRADE_DIR)
UPG_TF_CUR  = TF_CLI_CONFIG_FILE=$(UPGRADE_DIR)/.terraformrc.cur terraform -chdir=$(UPGRADE_DIR)

# IPK_API_CALL: curl against the Command API; use after $(KF_CURL_AUTH) in the same recipe line.
IPK_API_CALL = curl -s $$CURL_TLS -K "$$KFCFG" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -H "Content-Type: application/json"
IPK_API_BASE = https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}
# IPK_FLAT: join a (no-color) terraform log into one line so grep survives diagnostic word-wrapping.
IPK_FLAT = tr '\n' ' ' | sed 's/│//g; s/  */ /g'

## lab-ipk-plan: Plan with OPAQUE_IPK / OPAQUE_SKIP_REMOVAL (no-color)
lab-ipk-plan:
	$(LAB_ENV) $(IPK_TFVARS) $(TF) plan -no-color

## lab-ipk-apply: Apply with OPAQUE_IPK / OPAQUE_SKIP_REMOVAL (no-color)
lab-ipk-apply:
	$(LAB_ENV) $(IPK_TFVARS) $(TF) apply -auto-approve -no-color

## lab-ipk-secret-keys: Print the data keys of the K8S secret backing the opaque_secret store
lab-ipk-secret-keys:
	@kubectl --kubeconfig $(KUBECONFIG_LAB) -n $(K8S_NAMESPACE) get secret $(OPAQUE_SECRET_NAME) -o json \
	  | jq -r '"secret $(OPAQUE_SECRET_NAME) type=" + .type + " data keys: " + (.data|keys|join(","))'

## lab-ipk-check: include_private_key replace + skip_removal plan-time guard + restore (needs lab-apply first)
lab-ipk-check:
	@mkdir -p $(IPK_LOG_DIR)
	@set -o pipefail; L=$(IPK_LOG_DIR); \
	echo "==> [1a] plan include_private_key=false: expect REPLACE of opaque_secret only"; \
	$(MAKE) --no-print-directory lab-ipk-plan OPAQUE_IPK=false 2>&1 | tee $$L/s1a-plan.log; \
	grep -q 'keyfactor_certificate_deployment.opaque_secret must be replaced' $$L/s1a-plan.log || { echo "ASSERT FAILED: opaque_secret not planned for replace"; exit 1; }; \
	grep -q 'Plan: 1 to add, 0 to change, 1 to destroy' $$L/s1a-plan.log || { echo "ASSERT FAILED: plan summary is not 1 add/0 change/1 destroy"; exit 1; }; \
	echo "==> [1b] apply include_private_key=false"; \
	$(MAKE) --no-print-directory lab-ipk-apply OPAQUE_IPK=false 2>&1 | tee $$L/s1b-apply.log; \
	echo "==> [1c] K8S secret contents (expect only tls.crt)"; \
	$(MAKE) --no-print-directory lab-ipk-secret-keys 2>&1 | tee $$L/s1c-secret-keys.log; \
	grep -q 'data keys: tls.crt$$' $$L/s1c-secret-keys.log || { echo "ASSERT FAILED: secret does not contain only tls.crt"; exit 1; }; \
	echo "==> [2a] apply skip_removal=true (include_private_key stays false): in-place update"; \
	$(MAKE) --no-print-directory lab-ipk-apply OPAQUE_IPK=false OPAQUE_SKIP_REMOVAL=true 2>&1 | tee $$L/s2a-apply.log; \
	echo "==> [2b] plan include_private_key unset + skip_removal=true: expect plan-time ERROR"; \
	if $(MAKE) --no-print-directory lab-ipk-plan OPAQUE_SKIP_REMOVAL=true 2>&1 | tee $$L/s2b-plan.log; then \
	  echo "ASSERT FAILED: plan unexpectedly succeeded"; exit 1; fi; \
	$(IPK_FLAT) < $$L/s2b-plan.log | grep -q 'Error:' || { echo "ASSERT FAILED: no Error: in plan output"; exit 1; }; \
	$(IPK_FLAT) < $$L/s2b-plan.log | grep -q 'skip_removal' || { echo "ASSERT FAILED: error does not mention skip_removal"; exit 1; }; \
	echo "==> [3a] apply skip_removal back to unset (include_private_key still false): in-place"; \
	$(MAKE) --no-print-directory lab-ipk-apply OPAQUE_IPK=false 2>&1 | tee $$L/s3a-apply.log; \
	echo "==> [3b] restore include_private_key to unset: expect REPLACE, apply"; \
	$(MAKE) --no-print-directory lab-ipk-plan 2>&1 | tee $$L/s3b-plan.log; \
	grep -q 'keyfactor_certificate_deployment.opaque_secret must be replaced' $$L/s3b-plan.log || { echo "ASSERT FAILED: restore not planned as replace"; exit 1; }; \
	$(MAKE) --no-print-directory lab-ipk-apply 2>&1 | tee $$L/s3b-apply.log; \
	$(MAKE) --no-print-directory lab-ipk-secret-keys 2>&1 | tee $$L/s3b-secret-keys.log; \
	echo "==> [3c] plan after restore: expect No changes"; \
	$(MAKE) --no-print-directory lab-ipk-plan 2>&1 | tee $$L/s3c-plan.log; \
	grep -q 'No changes' $$L/s3c-plan.log || { echo "ASSERT FAILED: plan after restore is not No changes"; exit 1; }; \
	echo "==> lab-ipk-check PASSED (logs in $$L)"

## lab-ipk-oob-remove: Remove the cert from the opaque_secret store via the Command API (Schedule.Immediate)
lab-ipk-oob-remove:
	@$(LAB_ENV) \
	 CERT_ID=$$($(TF) output -raw opaque_certificate_id) && \
	 STORE_ID=$$($(TF) output -json store_ids | jq -r .k8s_opaque_secret) && \
	 echo "    cert id $$CERT_ID, store id $$STORE_ID" && \
	 $(KF_CURL_AUTH) \
	 ALIAS=$$($(IPK_API_CALL) "$(IPK_API_BASE)/CertificateStores/$$STORE_ID/Inventory" | jq -r --argjson id "$$CERT_ID" '[.[]|select(any(.Certificates[]?; .Id==$$id))|.Name][0] // ""') && \
	 echo "    inventory alias: '$$ALIAS'" && \
	 BODY=$$(jq -nc --argjson c "$$CERT_ID" --arg s "$$STORE_ID" --arg a "$$ALIAS" '{CertificateId:$$c,Alias:"",CertificateStores:[{CertificateStoreId:$$s,Alias:$$a}],Schedule:{Immediate:true}}') && \
	 RESPFILE=$$(mktemp) && \
	 HTTP_STATUS=$$($(IPK_API_CALL) -o "$$RESPFILE" -w "%{http_code}" -X POST "$(IPK_API_BASE)/CertificateStores/Certificates/Remove" -d "$$BODY") && \
	 echo "    POST CertificateStores/Certificates/Remove HTTP status: $$HTTP_STATUS" && cat "$$RESPFILE" && echo && rm -f "$$RESPFILE" && \
	 if [ "$$HTTP_STATUS" -lt 200 ] || [ "$$HTTP_STATUS" -ge 300 ]; then echo "FAIL: out-of-band removal did not succeed"; exit 1; fi

## lab-ipk-oob-wait: Poll until the cert is gone from both its Locations and the store inventory
lab-ipk-oob-wait:
	@$(LAB_ENV) \
	 CERT_ID=$$($(TF) output -raw opaque_certificate_id) && \
	 STORE_ID=$$($(TF) output -json store_ids | jq -r .k8s_opaque_secret) && \
	 START=$$(date +%s); \
	 while :; do \
	   RES=$$( $(KF_CURL_AUTH) \
	     LOC=$$($(IPK_API_CALL) "$(IPK_API_BASE)/Certificates/$$CERT_ID?includeLocations=true" | jq --arg s "$$STORE_ID" '[.Locations[]?|select(.CertStoreId==$$s)]|length'); \
	     INV=$$($(IPK_API_CALL) "$(IPK_API_BASE)/CertificateStores/$$STORE_ID/Inventory" | jq --argjson id "$$CERT_ID" '[.[]|select(any(.Certificates[]?; .Id==$$id))]|length'); \
	     echo "$$LOC $$INV" ); \
	   LOC=$${RES% *}; INV=$${RES#* }; \
	   ELAPSED=$$(( $$(date +%s) - START )); \
	   echo "    t+$${ELAPSED}s: locations entries for store=$$LOC, inventory entries=$$INV"; \
	   if [ "$$LOC" = "0" ] && [ "$$INV" = "0" ]; then echo "    removed from Locations and inventory"; exit 0; fi; \
	   if [ $$ELAPSED -ge $(IPK_OOB_MAX_WAIT) ]; then echo "FAIL: still present after $(IPK_OOB_MAX_WAIT)s"; exit 1; fi; \
	   sleep $(IPK_OOB_INTERVAL); \
	 done

## lab-ipk-oob-check: out-of-band removal -> plan shows 1 to add + redeploy warning -> apply -> No changes (needs lab-apply first)
lab-ipk-oob-check:
	@mkdir -p $(IPK_LOG_DIR)
	@set -o pipefail; L=$(IPK_LOG_DIR); \
	echo "==> [4a] remove certificate from store out-of-band"; \
	$(MAKE) --no-print-directory lab-ipk-oob-remove 2>&1 | tee $$L/s4a-remove.log; \
	echo "==> [4b] wait for Locations/inventory to drop it"; \
	$(MAKE) --no-print-directory lab-ipk-oob-wait 2>&1 | tee $$L/s4b-wait.log; \
	echo "==> [4c] plan: expect 1 to add + 'no longer in store' warning"; \
	$(MAKE) --no-print-directory lab-ipk-plan 2>&1 | tee $$L/s4c-plan.log; \
	grep -q 'Plan: 1 to add, 0 to change, 0 to destroy' $$L/s4c-plan.log || { echo "ASSERT FAILED: plan summary is not 1 to add"; exit 1; }; \
	$(IPK_FLAT) < $$L/s4c-plan.log | grep -q 'no longer in store' || { echo "ASSERT FAILED: no 'no longer in store' warning"; exit 1; }; \
	$(IPK_FLAT) < $$L/s4c-plan.log | grep -q 'redeployed' || { echo "ASSERT FAILED: warning does not mention redeploy"; exit 1; }; \
	echo "==> [4d] apply (redeploy)"; \
	$(MAKE) --no-print-directory lab-ipk-apply 2>&1 | tee $$L/s4d-apply.log; \
	echo "==> [4e] plan: expect No changes"; \
	$(MAKE) --no-print-directory lab-ipk-plan 2>&1 | tee $$L/s4e-plan.log; \
	grep -q 'No changes' $$L/s4e-plan.log || { echo "ASSERT FAILED: plan after redeploy is not No changes"; exit 1; }; \
	echo "==> lab-ipk-oob-check PASSED (logs in $$L)"

## lab-ipk-upgrade-prepare: Copy the demo config to UPGRADE_DIR (include_private_key stripped) and init it.
## Requires BASE_PROVIDER_DIR (directory containing the baseline terraform-provider-keyfactor binary).
lab-ipk-upgrade-prepare:
	@test -x "$(BASE_PROVIDER_DIR)/terraform-provider-keyfactor" || { echo "BASE_PROVIDER_DIR must contain an executable terraform-provider-keyfactor (got '$(BASE_PROVIDER_DIR)')"; exit 1; }
	@! test -e $(UPGRADE_DIR)/terraform.tfstate || { echo "$(UPGRADE_DIR) already has state; run lab-ipk-upgrade-destroy first"; exit 1; }
	mkdir -p $(UPGRADE_DIR)/orig
	cp main.tf variables.tf stores.tf outputs.tf .terraform.lock.hcl $(UPGRADE_DIR)/
	cp deployments.tf $(UPGRADE_DIR)/orig/deployments.tf
	sed '/include_private_key/d' deployments.tf > $(UPGRADE_DIR)/deployments.tf
	printf 'provider_installation {\n  dev_overrides {\n    "keyfactor-pub/keyfactor" = "%s"\n  }\n  direct {}\n}\n' "$(abspath $(BASE_PROVIDER_DIR))" > $(UPGRADE_DIR)/.terraformrc.base
	printf 'provider_installation {\n  dev_overrides {\n    "keyfactor-pub/keyfactor" = "%s"\n  }\n  direct {}\n}\n' "$(PROVIDER_BIN)" > $(UPGRADE_DIR)/.terraformrc.cur
	$(LAB_ENV) $(UPG_TF_BASE) init -no-color

## lab-ipk-upgrade-baseline-apply: Create cert + store + opaque_secret deployment with the BASELINE provider
lab-ipk-upgrade-baseline-apply:
	$(LAB_ENV) $(IPK_TFVARS) $(UPG_TF_BASE) apply -auto-approve -no-color $(IPK_TARGET)

## lab-ipk-upgrade-use-current: Restore the full config (with include_private_key) in UPGRADE_DIR
lab-ipk-upgrade-use-current:
	cp $(UPGRADE_DIR)/orig/deployments.tf $(UPGRADE_DIR)/deployments.tf

## lab-ipk-upgrade-plan: Plan UPGRADE_DIR with the CURRENT provider (OPAQUE_IPK=true|false|unset)
lab-ipk-upgrade-plan:
	$(LAB_ENV) $(IPK_TFVARS) $(UPG_TF_CUR) plan -no-color $(IPK_TARGET)

## lab-ipk-upgrade-apply: Apply UPGRADE_DIR with the CURRENT provider
lab-ipk-upgrade-apply:
	$(LAB_ENV) $(IPK_TFVARS) $(UPG_TF_CUR) apply -auto-approve -no-color $(IPK_TARGET)

## lab-ipk-upgrade-destroy: Destroy everything in UPGRADE_DIR's state
lab-ipk-upgrade-destroy:
	$(LAB_ENV) $(IPK_TFVARS) $(UPG_TF_CUR) destroy -auto-approve -no-color

## lab-ipk-upgrade-check: baseline create -> current-provider plans (unset: no changes; true: in-place; false: replace)
lab-ipk-upgrade-check:
	@mkdir -p $(IPK_LOG_DIR)
	@set -o pipefail; L=$(IPK_LOG_DIR); \
	echo "==> [5a] prepare + create deployment with BASELINE provider"; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-prepare 2>&1 | tee $$L/s5a-prepare.log; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-baseline-apply 2>&1 | tee $$L/s5a-baseline-apply.log; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-use-current; \
	echo "==> [5b] CURRENT provider, attribute unset: expect No changes"; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-plan 2>&1 | tee $$L/s5b-plan.log; \
	grep -q 'No changes' $$L/s5b-plan.log || { echo "ASSERT FAILED: unset is not No changes"; exit 1; }; \
	echo "==> [5c] CURRENT provider, include_private_key=true: expect in-place update, no replace"; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-plan OPAQUE_IPK=true 2>&1 | tee $$L/s5c-plan.log; \
	grep -q 'Plan: 0 to add, 1 to change, 0 to destroy' $$L/s5c-plan.log || { echo "ASSERT FAILED: true is not a 1-change in-place update"; exit 1; }; \
	! grep -q 'must be replaced' $$L/s5c-plan.log || { echo "ASSERT FAILED: true planned a replace"; exit 1; }; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-apply OPAQUE_IPK=true 2>&1 | tee $$L/s5c-apply.log; \
	echo "==> [5d] CURRENT provider, include_private_key=false: expect REPLACE (plan only)"; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-plan OPAQUE_IPK=false 2>&1 | tee $$L/s5d-plan.log; \
	grep -q 'keyfactor_certificate_deployment.opaque_secret must be replaced' $$L/s5d-plan.log || { echo "ASSERT FAILED: false is not a replace"; exit 1; }; \
	echo "==> [5e] restore (attribute unset), plan"; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-apply 2>&1 | tee $$L/s5e-apply.log; \
	$(MAKE) --no-print-directory lab-ipk-upgrade-plan 2>&1 | tee $$L/s5e-plan.log; \
	echo "==> lab-ipk-upgrade-check done; run lab-ipk-upgrade-destroy to clean up (logs in $$L)"

## lifecycle: Full lifecycle: apply → update → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle \
        lab-ipk-plan lab-ipk-apply lab-ipk-secret-keys lab-ipk-check lab-ipk-oob-remove lab-ipk-oob-wait lab-ipk-oob-check \
        lab-ipk-upgrade-prepare lab-ipk-upgrade-baseline-apply lab-ipk-upgrade-use-current lab-ipk-upgrade-plan \
        lab-ipk-upgrade-apply lab-ipk-upgrade-destroy lab-ipk-upgrade-check
