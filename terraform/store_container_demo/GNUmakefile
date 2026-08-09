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

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

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

## lifecycle: Full lifecycle: apply → update → import-all → apply (reconcile) → drift-check
##   → repro175 (issue #175 OOB-container-clearing repro) → destroy.
##
##   repro175's own verify step is EXPECTED to FAIL on the currently released
##   provider (2.9.1) -- that failure is the genuine issue #175 reproduction
##   this demo exists to surface, not a harness defect. Its exit code is
##   captured (not chained with &&/||) so a real bug reproduction never skips
##   destroy and never gets confused with an actual harness-mechanics failure
##   in destroy itself. `make lifecycle` exits non-zero overall if #175
##   reproduces, after destroy has fully run -- read the printed summary to
##   tell a genuine harness regression (destroy failing) apart from the
##   expected #175 repro.
lifecycle:
	$(MAKE) lab-apply
	$(MAKE) lab-update
	$(MAKE) lab-import-all
	$(MAKE) lab-apply
	$(MAKE) lab-drift-check
	@HARNESS_FAIL=0; REPRO175_EXIT=0; \
	 if ! $(MAKE) repro175-apply; then echo "FAIL (harness): repro175-apply failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) repro175-seed; then echo "FAIL (harness): repro175-seed failed -- see above (this is the OOB setup step, not the bug check itself)."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) repro175-verify-apply; then REPRO175_EXIT=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ]; then $(MAKE) repro175-verify-server || true; fi; \
	 if ! $(MAKE) lab-destroy; then \
	   echo "FAIL (harness): lab-destroy failed after repro175 -- see above. Demo resources may be orphaned; check manually."; \
	   HARNESS_FAIL=1; \
	 fi; \
	 echo "=============================================================="; \
	 echo "store_container_demo summary:"; \
	 if [ $$HARNESS_FAIL -ne 0 ]; then \
	   echo "  HARNESS FAILURE occurred -- see FAIL (harness) lines above; this is a real regression, not a known-bug repro."; \
	 elif [ $$REPRO175_EXIT -ne 0 ]; then \
	   echo "  repro175 (issue #175 OOB-container-clearing check): KNOWN BUG #175 reproduced."; \
	 else \
	   echo "  repro175 (issue #175 OOB-container-clearing check): PASS (assignment survived)."; \
	 fi; \
	 echo "=============================================================="; \
	 if [ $$HARNESS_FAIL -ne 0 ] || [ $$REPRO175_EXIT -ne 0 ]; then exit 1; fi

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
##
## NOTE: GET /CertificateStores/{id} masks secret-typed custom properties
## (e.g. ServerUsername/ServerPassword on K8S store types) as an obfuscated
## placeholder object (Value: "********", SecretTypeGuid: ..., ...) --
## crucially, for THIS store type those live INSIDE the "Properties" field,
## which is itself a JSON-encoded STRING, not top-level keys. Blindly
## PUTting the placeholder back (whether top-level or still embedded in
## Properties) is rejected by Command with "0xA011000F: The 'Server
## Username' property with value '{...}' is invalid." (confirmed
## 2026-08-08, in both places) -- this is a harness/GET-PUT-asymmetry issue
## in this recipe, not part of the #175 repro itself, so strip those masked
## secret fields (top-level AND inside the parsed Properties string) before
## PUTting; omitting them lets Command preserve the existing values.
repro175-seed:
	@$(LAB_ENV) \
	 STORE_ID=$$($(TF) output -raw repro175_store_id) && \
	 APP_ID=$$($(TF) output -raw application_id 2>/dev/null || $(TF) show -json | jq -r '.values.root_module.resources[] | select(.address=="keyfactor_application.demo") | .values.id') && \
	 echo "    store: $$STORE_ID  ->  container/application id: $$APP_ID" && \
	 CURL_TLS=""; if [ "$$KEYFACTOR_SKIP_VERIFY" = "true" ]; then CURL_TLS="-k"; fi; \
	 if [ -n "$$KEYFACTOR_CA_CERT" ]; then CURL_TLS="$$CURL_TLS --cacert $$KEYFACTOR_CA_CERT"; fi; \
	 KFCFG=$$(mktemp); chmod 600 "$$KFCFG"; trap 'rm -f "$$KFCFG"' EXIT; \
	 printf 'data = "grant_type=client_credentials&client_id=%s&client_secret=%s"\n' "$$KEYFACTOR_AUTH_CLIENT_ID" "$$KEYFACTOR_AUTH_CLIENT_SECRET" > "$$KFCFG"; \
	 TOKEN=$$(curl -s $$CURL_TLS -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -K "$$KFCFG" | jq -r '.access_token'); \
	 printf 'header = "Authorization: Bearer %s"\n' "$$TOKEN" > "$$KFCFG"; \
	 STORE_JSON=$$(curl -s $$CURL_TLS "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores/$$STORE_ID" \
	   -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG") && \
	 UPDATED=$$(echo "$$STORE_JSON" | jq --argjson cid "$$APP_ID" '.ContainerId = $$cid | del(.ServerUsername) | del(.ServerPassword) | .Properties = ((.Properties | fromjson) | del(.ServerUsername) | del(.ServerPassword) | tojson)') && \
	 HTTP_STATUS=$$(curl -s $$CURL_TLS -o /tmp/store_container_demo_repro175_seed.json -w "%{http_code}" -X PUT \
	   "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores" \
	   -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" \
	   -H "Content-Type: application/json" -K "$$KFCFG" \
	   -d "$$UPDATED") && \
	 rm -f "$$KFCFG" && \
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
	   echo "FAIL (KNOWN BUG #175 reproduced): container_id was cleared by an unrelated update that never touched application_name/container_name. This is a genuine provider bug reproduction, not a harness failure."; \
	   exit 1; \
	 else \
	   echo "PASS: container_id survived the unrelated update (issue #175 fix confirmed)."; \
	 fi

## repro175-verify-server: Direct API GET confirming ContainerId server-side.
repro175-verify-server:
	@$(LAB_ENV) \
	 STORE_ID=$$($(TF) output -raw repro175_store_id) && \
	 CURL_TLS=""; if [ "$$KEYFACTOR_SKIP_VERIFY" = "true" ]; then CURL_TLS="-k"; fi; \
	 if [ -n "$$KEYFACTOR_CA_CERT" ]; then CURL_TLS="$$CURL_TLS --cacert $$KEYFACTOR_CA_CERT"; fi; \
	 KFCFG=$$(mktemp); chmod 600 "$$KFCFG"; trap 'rm -f "$$KFCFG"' EXIT; \
	 printf 'data = "grant_type=client_credentials&client_id=%s&client_secret=%s"\n' "$$KEYFACTOR_AUTH_CLIENT_ID" "$$KEYFACTOR_AUTH_CLIENT_SECRET" > "$$KFCFG"; \
	 TOKEN=$$(curl -s $$CURL_TLS -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -K "$$KFCFG" | jq -r '.access_token'); \
	 printf 'header = "Authorization: Bearer %s"\n' "$$TOKEN" > "$$KFCFG"; \
	 curl -s $$CURL_TLS "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/CertificateStores/$$STORE_ID" \
	   -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" \
	   | jq '{Id, ContainerId, ContainerName}'; \
	 rm -f "$$KFCFG"

## repro175: Full standalone reproduction sequence for issue #175.
repro175: repro175-apply repro175-seed repro175-verify-apply repro175-verify-server

.PHONY: build init validate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle \
        repro175-apply repro175-seed repro175-verify-apply repro175-verify-server repro175
