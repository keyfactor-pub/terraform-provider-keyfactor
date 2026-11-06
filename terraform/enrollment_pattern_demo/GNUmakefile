## enrollment_pattern_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of the keyfactor_enrollment_pattern
## resource (plus its data source gap-fill):
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/enrollment_pattern_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make all                # run the full workflow
##   make SUFFIX=_MYORG all  # run with a custom name suffix

include ../demo-common.mk

# Default role name for the binding import. Override with ROLE=<name> on the
# command line (matches var.binding_role_name default).
ROLE ?= Administrator

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the enrollment pattern resource
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove the managed resources from state then re-import by ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 ../_export_ids.py keyfactor_enrollment_pattern
	@echo "==> Removing enrollment pattern from state..."
	@while IFS=' ' read -r name id; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_enrollment_pattern.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing enrollment pattern by numeric ID..."
	@while IFS=' ' read -r name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "keyfactor_enrollment_pattern.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$name (ID=$$id)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt
	@echo "==> Removing role binding from state..."
	$(UNSET_BASIC) $(TF) state rm "keyfactor_enrollment_pattern_role_binding.demo" 2>&1 | grep -E "Removed|no state" || true
	@echo "==> Re-importing role binding by composite key (patternName//roleName)..."
	@PATTERN_NAME="Demo Pattern$(SUFFIX)"; \
	 ROLE_NAME="$(ROLE)"; \
	 COMPOSITE_ID="$${PATTERN_NAME}//$${ROLE_NAME}"; \
	 result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "keyfactor_enrollment_pattern_role_binding.demo" "$${COMPOSITE_ID}" 2>&1); \
	 if echo "$$result" | grep -q "Import successful"; then \
	   echo "OK: role_binding.demo (ID=$${COMPOSITE_ID})"; \
	 else \
	   echo "FAIL: role_binding.demo (ID=$${COMPOSITE_ID})"; \
	   echo "$$result" | tail -3; \
	 fi

## reconcile: Apply after import to settle any remaining Computed-only
## fields. This step is typically a no-op ("No changes") immediately after
## import, since GetById populates all Computed fields on import itself.
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile (should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed enrollment pattern resource
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f .spare_role.txt .race_plan.txt tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow: build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
all: build init validate plan apply import-all reconcile drift-check destroy

## demo-no-destroy: Run workflow without final destroy (leaves resources on server)
demo-no-destroy: build init validate plan apply import-all reconcile drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

## lab-spare-role: Discover, via the Command API, a role that is neither the
## bootstrap role (InstanceAdmin) nor the default binding role (Administrator)
## and write its name to .spare_role.txt. lab-update binds it instead of the
## bootstrap role, and lab-ignore-changes-race uses it as the second binding.
## Nothing is hardcoded: any lab with a third role works.
lab-spare-role:
	@$(LAB_ENV) $(KF_CURL_AUTH) \
	 curl -s $$CURL_TLS -K "$$KFCFG" -H "x-keyfactor-requested-with: APIClient" \
	   "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Security/Roles" \
	   | jq -r --arg a "InstanceAdmin" --arg b "Administrator" '[.[].Name | select(. != $$a and . != $$b)][0] // empty' > .spare_role.txt; \
	 test -s .spare_role.txt || { echo "FAIL: no spare role found via the Command API"; exit 1; }; \
	 echo "    spare role: $$(cat .spare_role.txt)"

## lab-update: Apply with an updated description AND changed driver
## attributes (binding_role_name, certificate_authority_ids,
## policies.default_certificate_owner_role_id) to verify the in-place
## update path -- full-review Phase 1 required tests, item 3: this demo
## previously never touched these fields, which is why the mirror-pinning
## bugs (F2/F4) shipped undetected despite a green harness. Plan after each
## apply should show "No changes".
##
## Note: associated_role_name is intentionally NOT varied here -- the
## enrollment_pattern resource has lifecycle.ignore_changes =
## [associated_role_names], so changes to that variable have no effect
## after initial create. Changing binding_role_name exercises the
## role_binding resource's update path instead.
##
## The updated binding role is the discovered spare role, NOT the bootstrap
## role: the bootstrap role is the pattern's only role at this point, and
## destroying a binding for the last remaining role is rejected by Command
## ("Enrollment Pattern needs to have at least one associated role").
lab-update: lab-spare-role
	@echo "==> Step 1: update description + driver attributes (in-place update)..."
	$(LAB_ENV) TF_VAR_description_override="Updated by harness" \
	  TF_VAR_binding_role_name="$$(cat .spare_role.txt)" \
	  TF_VAR_owner_role_name="Administrator" \
	  TF_VAR_ca_name="OpenBao Root CA" \
	  $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) TF_VAR_description_override="Updated by harness" \
	  TF_VAR_binding_role_name="$$(cat .spare_role.txt)" \
	  TF_VAR_owner_role_name="Administrator" \
	  TF_VAR_ca_name="OpenBao Root CA" \
	  $(MAKE) plan SUFFIX=$(SUFFIX)
	@echo "==> Step 2: revert to defaults..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-import-all: Import all resources using lab credentials
## Pass ROLE=<role_name> to override the role name used for the composite binding key.
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX) ROLE=$(ROLE)

## lab-reconcile: Re-apply after import to settle any remaining Computed-only
## fields (see reconcile's comment above -- typically a no-op now)
lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX)

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

## lab-destroy: Destroy the managed enrollment pattern using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lab-ignore-changes-race: PR #219 finding #4 regression scenario. Pattern with
## lifecycle.ignore_changes = [associated_role_names] + two role bindings; in ONE
## apply destroy the second binding AND change the pattern description, then
## assert via the Command API that the removed role stays removed (the pattern's
## update PUT must send the server's current roles, not the refresh-time plan's)
## and that the other roles survive. Terraform does not order a binding destroy
## against the pattern's update, so this only exercises the stale-PUT window when
## the destroy happens to land first; the deterministic proof is the Go unit test
## TestUnitEnrollmentPatternUpdateIgnoreChangesDoesNotResurrectRemovedRole.
## The second role comes from lab-spare-role (API discovery; nothing hardcoded).
lab-ignore-changes-race: lab-spare-role
	@echo "==> [1/5] second binding role (discovered via API): $$(cat .spare_role.txt)"
	@echo "==> [2/5] apply with both bindings present..."
	@$(LAB_ENV) TF_VAR_second_binding_role_name="$$(cat .spare_role.txt)" $(MAKE) apply SUFFIX=$(SUFFIX)
	@echo "==> [3/5] one apply: destroy second binding + change pattern description..."
	@$(LAB_ENV) TF_VAR_description_override="ignore-changes race scenario" $(MAKE) apply SUFFIX=$(SUFFIX)
	@echo "==> [4/5] assert via API: removed role stays removed, other roles survive..."
	@$(LAB_ENV) \
	 PID=$$($(TF) output -raw pattern_id) && \
	 $(KF_CURL_AUTH) \
	 ROLES=$$(curl -s $$CURL_TLS -K "$$KFCFG" -H "x-keyfactor-requested-with: APIClient" -H "x-keyfactor-api-version: 1" \
	   "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/EnrollmentPatterns/$$PID" | jq -c '[.AssociatedRoles[].Name]') && \
	 echo "    pattern $$PID roles on server: $$ROLES" && \
	 RACE_ROLE=$$(cat .spare_role.txt) && \
	 echo "$$ROLES" | jq -e --arg r "$$RACE_ROLE" 'index($$r) == null' >/dev/null || { echo "FAIL: removed role '$$(cat .spare_role.txt)' was resurrected by the pattern update"; exit 1; }; \
	 echo "$$ROLES" | jq -e 'index("InstanceAdmin") != null and index("Administrator") != null' >/dev/null || { echo "FAIL: bootstrap/binding roles missing: $$ROLES"; exit 1; }; \
	 echo "    OK: removed role stayed removed; other roles intact"
	@echo "==> [5/5] plan (expect No changes), then revert description..."
	@$(LAB_ENV) TF_VAR_description_override="ignore-changes race scenario" $(TF) plan -var="suffix=$(SUFFIX)" -detailed-exitcode -no-color > .race_plan.txt 2>&1; \
	 PLAN_EXIT=$$?; \
	 if [ "$$PLAN_EXIT" -ne 0 ]; then echo "FAIL: plan after the race apply is not clean (exit $$PLAN_EXIT)"; grep -E "^Plan:|^  [~+-] " .race_plan.txt | head -20; rm -f .race_plan.txt; exit 1; fi; \
	 rm -f .race_plan.txt; echo "    OK: plan shows no changes"
	@$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	@rm -f .spare_role.txt

## lifecycle: Full lifecycle: apply → update → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-ignore-changes-race lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-ignore-changes-race lab-spare-role lab-destroy lifecycle
