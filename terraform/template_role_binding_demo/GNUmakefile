## template_role_binding_demo/GNUmakefile
##
## Full-lifecycle smoke test for keyfactor_template_role_binding, covering
## PR #179's fix to Read()'s swallowed GetTemplates() API error:
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/template_role_binding_demo
##   make build
##   make init
##   make lifecycle
##   make SUFFIX=_MYORG lifecycle

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the role and template role binding
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove both managed resources from state then re-import by role name
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@echo "==> Extracting role name from state..."
	@ROLE_NAME=$$($(UNSET_BASIC) $(TF) output -raw role_name 2>/dev/null) && \
	 echo "Role Name=$$ROLE_NAME" && \
	 echo "==> Removing from state..." && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_template_role_binding.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_role.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 echo "==> Re-importing keyfactor_role by name..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_role.demo "$$ROLE_NAME" && \
	 echo "==> Re-importing keyfactor_template_role_binding by role name..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_template_role_binding.demo "$$ROLE_NAME"

## reconcile: Apply after import to reconcile fields not returned by the API
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile (should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed resources
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow: build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
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
##
##   KNOWN PROVIDER/SDK BUG: lab-apply is expected to FAIL here with "Error
##   updating template in Keyfactor: 'Policies' cannot be empty" -- Command
##   now requires a field on template update that keyfactor-go-client/v3's
##   UpdateTemplateArg request model does not send (same gap independently
##   noted in certificate_template_demo/main.tf). keyfactor_role.demo is
##   still created successfully before that failure, so every prerequisite
##   after lab-apply would normally be skipped by default GNU Make semantics
##   -- this target captures lab-apply's exit code instead so lab-destroy
##   ALWAYS runs and the role is never left orphaned on the lab.
lifecycle:
	@APPLY_EXIT=0; \
	 if ! $(MAKE) lab-apply SUFFIX=$(SUFFIX); then APPLY_EXIT=1; fi; \
	 if [ $$APPLY_EXIT -eq 0 ]; then \
	   $(MAKE) lab-import-all SUFFIX=$(SUFFIX) || exit 1; \
	   $(MAKE) lab-reconcile SUFFIX=$(SUFFIX) || exit 1; \
	   $(MAKE) lab-drift-check SUFFIX=$(SUFFIX) || exit 1; \
	 else \
	   echo "==> Skipping lab-import-all/lab-reconcile/lab-drift-check -- lab-apply failed (see summary below)."; \
	 fi; \
	 if ! $(MAKE) lab-destroy SUFFIX=$(SUFFIX); then \
	   echo "FAIL (harness): lab-destroy failed -- see above. keyfactor_role.demo (TemplateRoleBindingDemo$(SUFFIX)) may be orphaned; check manually."; \
	   exit 1; \
	 fi; \
	 echo "=============================================================="; \
	 echo "template_role_binding_demo summary:"; \
	 if [ $$APPLY_EXIT -ne 0 ]; then \
	   echo "  lab-apply: KNOWN PROVIDER/SDK BUG reproduced ('Policies' cannot be empty). See GNUmakefile lifecycle header."; \
	 else \
	   echo "  lab-apply: PASS (no 'Policies' error)."; \
	 fi; \
	 echo "=============================================================="; \
	 if [ $$APPLY_EXIT -ne 0 ]; then exit 1; fi

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle

# ---------------------------------------------------------------------------
# Opt-in PR #228 lab checks (NOT part of `lifecycle`; each is self-cleaning)
# ---------------------------------------------------------------------------
# Out-of-band template reads/writes use KF_CURL_AUTH (../kf-curl-auth.mk).
# TEMPLATE_SHORT_NAME must match the demo's template_short_name variable default.
# OOB_DIR holds the pre-change template snapshot (mode 700 dir, mode 600 files);
# override on the command line to keep evidence somewhere specific.
TEMPLATE_SHORT_NAME ?= AnyCA_lab-role
OOB_DIR             ?= /tmp/template_role_binding_demo.oob
TPL_URL              = https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Templates

## lab-oob-template-get: Print the demo template's role-binding-relevant fields (read-only)
lab-oob-template-get:
	@$(LAB_ENV) $(KF_CURL_AUTH) \
	 TPL=$$(curl -s $$CURL_TLS "$(TPL_URL)" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" \
	   | jq -c --arg n "$(TEMPLATE_SHORT_NAME)" '[.[] | select(.TemplateName==$$n or .CommonName==$$n)][0] | {Id,CommonName,TemplateName,UseAllowedRequesters,AllowedRequesters}') && \
	 echo "$$TPL"

## lab-role-replace: PR #228 check -- changing role_name to a different role forces replacement
##   (old role gone from the template, new role present); a case-only change is in-place.
##   Applies with a second role, switches binding to it, verifies via the API, then destroys.
lab-role-replace:
	@set -e; PLANLOG=$$(mktemp); trap 'rm -f "$$PLANLOG"' EXIT; \
	 V='-var=suffix=$(SUFFIX) -var=create_alt_role=true'; \
	 echo "==> [1/6] apply binding -> primary role"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) apply -auto-approve $$V -var=binding_role=primary; \
	 echo "==> [2/6] API: template state with role A bound"; \
	 $(MAKE) --no-print-directory lab-oob-template-get; \
	 echo "==> [3/6] plan binding_role=alt (expect replace)"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) plan -no-color $$V -var=binding_role=alt | tee "$$PLANLOG" >/dev/null; \
	 grep -nE 'forces replacement|must be replaced|Plan:' "$$PLANLOG"; \
	 echo "==> [4/6] apply binding_role=alt"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) apply -auto-approve $$V -var=binding_role=alt; \
	 echo "==> [5/6] API: template state after switch (role A must be gone, role B present)"; \
	 $(MAKE) --no-print-directory lab-oob-template-get; \
	 echo "==> [6/6] plan binding_role=alt + upper-case (expect in-place, NOT replace)"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) plan -no-color $$V -var=binding_role=alt -var=binding_role_upper=true | tee "$$PLANLOG" >/dev/null; \
	 grep -nE 'forces replacement|must be replaced|updated in-place|Plan:' "$$PLANLOG" || true; \
	 echo "==> cleanup: destroy"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) destroy -auto-approve $$V -var=binding_role=alt

# TPL_PUT_FILTER: jq projection of a GET /Templates/{id} body onto the fields PUT /Templates accepts --
# the same field set the provider's buildTemplateRoleBindingUpdateArg carries, so an out-of-band PUT
# changes only what the caller then overrides. TemplatePolicy mirrors the SDK struct: KeyInfo is dropped
# (Command rejects KeyInfo together with PrimaryKeyAlgorithms) and null/empty members are omitted, as omitempty does.
TPL_PUT_FILTER = {Id,CommonName,TemplateName,Oid,KeySize,KeyUsage,KeyType,ForestRoot,UseAllowedRequesters,AllowedRequesters,FriendlyName,AllowedEnrollmentTypes,KeyRetention,KeyRetentionDays,KeyArchival,EnrollmentFields,MetadataFields,TemplateRegexes,RFCEnforcement,RequiresApproval,TemplatePolicy:(.TemplatePolicy | del(.KeyInfo) | with_entries(select(.value != null)) | if (.AlternativeKeyAlgorithms==[]) then del(.AlternativeKeyAlgorithms) else . end)}

## lab-oob-template-put: PUT the JSON file PUT_FILE to /Templates; fails (and prints the response body) unless HTTP 2xx
lab-oob-template-put:
	@set -e; test -f "$(PUT_FILE)" || { echo "Usage: make lab-oob-template-put PUT_FILE=<json>"; exit 2; }; \
	 $(LAB_ENV) $(KF_CURL_AUTH) \
	 RESP=$$(mktemp); chmod 600 "$$RESP"; \
	 HS=$$(curl -s $$CURL_TLS -o "$$RESP" -w '%{http_code}' -X PUT "$(TPL_URL)" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -H "Content-Type: application/json" -K "$$KFCFG" -d @"$(PUT_FILE)"); \
	 echo "    PUT /Templates HTTP $$HS"; \
	 case "$$HS" in 2??) rm -f "$$RESP";; *) echo "    response:"; head -c 600 "$$RESP"; echo; rm -f "$$RESP"; exit 1;; esac

## lab-oob-useallowed-destroy: PR #228 check -- destroy of a binding whose role is listed on a template with
##   UseAllowedRequesters=false must send EXACTLY ONE template PUT and must NOT turn enforcement back on.
##   Steps: snapshot template; apply; PUT template with UseAllowedRequesters=false (role stays listed);
##   destroy with TF_LOG=DEBUG captured to $(OOB_DIR)/destroy.log (mode 600), counting PUTs; verify final state;
##   ALWAYS restore the snapshot's UseAllowedRequesters/AllowedRequesters at the end (even if a step failed).
lab-oob-useallowed-destroy:
	@set -e; umask 077; mkdir -p "$(OOB_DIR)"; chmod 700 "$(OOB_DIR)"; \
	 echo "==> [1/6] snapshot template"; \
	 $(LAB_ENV) $(KF_CURL_AUTH) \
	 TID=$$(curl -s $$CURL_TLS "$(TPL_URL)" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" \
	   | jq -r --arg n "$(TEMPLATE_SHORT_NAME)" '[.[] | select(.TemplateName==$$n or .CommonName==$$n)][0].Id'); \
	 echo "$$TID" > "$(OOB_DIR)/template_id"; \
	 curl -s $$CURL_TLS "$(TPL_URL)/$$TID" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" > "$(OOB_DIR)/template_before.json"; \
	 echo "    template id $$TID: UseAllowedRequesters=$$(jq .UseAllowedRequesters $(OOB_DIR)/template_before.json) AllowedRequesters=$$(jq -c .AllowedRequesters $(OOB_DIR)/template_before.json)"; \
	 RC=0; \
	 echo "==> [2/6] apply binding"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" || RC=$$?; \
	 if [ $$RC -eq 0 ]; then \
	   $(MAKE) --no-print-directory lab-oob-template-get; \
	   echo "==> [3/6] out-of-band: PUT template with UseAllowedRequesters=false (role stays listed)"; \
	   $(LAB_ENV) $(KF_CURL_AUTH) \
	   curl -s $$CURL_TLS "$(TPL_URL)/$$TID" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" \
	     | jq '$(TPL_PUT_FILTER) | .UseAllowedRequesters=false' > "$(OOB_DIR)/template_put.json"; \
	   $(MAKE) --no-print-directory lab-oob-template-put PUT_FILE="$(OOB_DIR)/template_put.json" || RC=$$?; \
	   $(MAKE) --no-print-directory lab-oob-template-get; \
	   if [ "$$($(MAKE) --no-print-directory lab-oob-template-get | jq .UseAllowedRequesters)" != "false" ]; then \
	     echo "SKIPPED: Command did not accept UseAllowedRequesters=false with the role still listed (it forces true while AllowedRequesters is non-empty / the template is linked to an enrollment pattern); the destroy below is therefore the ordinary enforced-template case, NOT the precondition under test."; \
	   fi; \
	 fi; \
	 echo "==> [4/6] destroy with TF_LOG=DEBUG -> $(OOB_DIR)/destroy.log"; \
	 rm -f "$(OOB_DIR)/destroy.log"; \
	 $(LAB_ENV) $(UNSET_BASIC) TF_LOG=DEBUG TF_LOG_PATH="$(OOB_DIR)/destroy.log" $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)" || RC=$$?; \
	 echo "    exit so far: $$RC"; \
	 echo "==> [5/6] final template state"; \
	 $(MAKE) --no-print-directory lab-oob-template-get; \
	 $(MAKE) --no-print-directory lab-oob-useallowed-count-puts; \
	 echo "==> [6/6] restore snapshot UseAllowedRequesters/AllowedRequesters"; \
	 $(MAKE) --no-print-directory lab-oob-useallowed-restore || RC=$$?; \
	 exit $$RC

## lab-oob-useallowed-count-puts: Count template PUTs recorded in $(OOB_DIR)/destroy.log (grep only; never prints the log)
lab-oob-useallowed-count-puts:
	@echo "    template PUT count in destroy log: $$(grep -c "Preparing a PUT request to path '[^']*/Templates'" "$(OOB_DIR)/destroy.log" || true)"

## lab-oob-useallowed-restore: Restore the template's UseAllowedRequesters/AllowedRequesters from template_before.json (idempotent)
lab-oob-useallowed-restore:
	@set -e; umask 077; $(LAB_ENV) $(KF_CURL_AUTH) \
	 TID=$$(cat "$(OOB_DIR)/template_id"); \
	 curl -s $$CURL_TLS "$(TPL_URL)/$$TID" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" > "$(OOB_DIR)/template_now.json"; \
	 jq --slurpfile b "$(OOB_DIR)/template_before.json" '$(TPL_PUT_FILTER) | .UseAllowedRequesters=$$b[0].UseAllowedRequesters | .AllowedRequesters=$$b[0].AllowedRequesters' "$(OOB_DIR)/template_now.json" > "$(OOB_DIR)/template_restore.json"; \
	 $(MAKE) --no-print-directory lab-oob-template-put PUT_FILE="$(OOB_DIR)/template_restore.json"; \
	 $(MAKE) --no-print-directory lab-oob-template-get; \
	 $(LAB_ENV) $(KF_CURL_AUTH) \
	 curl -s $$CURL_TLS "$(TPL_URL)/$$TID" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" > "$(OOB_DIR)/template_after.json"; \
	 if diff <(jq -S . "$(OOB_DIR)/template_before.json") <(jq -S . "$(OOB_DIR)/template_after.json") > "$(OOB_DIR)/template_diff.txt"; then \
	   echo "    full template GET after restore is IDENTICAL to the pre-check snapshot"; \
	 else echo "    WARNING: template differs from snapshot after restore: $$(wc -l < $(OOB_DIR)/template_diff.txt) diff lines in $(OOB_DIR)/template_diff.txt"; exit 1; fi

.PHONY: lab-oob-template-get lab-role-replace lab-oob-template-put lab-oob-useallowed-destroy lab-oob-useallowed-count-puts lab-oob-useallowed-restore

## lab-oob-template-list: List every template's short name, id, UseAllowedRequesters and AllowedRequesters (read-only)
lab-oob-template-list:
	@$(LAB_ENV) $(KF_CURL_AUTH) \
	 curl -s $$CURL_TLS "$(TPL_URL)" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" -K "$$KFCFG" \
	   | jq -c '.[] | {Id,CommonName,UseAllowedRequesters,AllowedRequesters}'

.PHONY: lab-oob-template-list
