## ca_schedule_demo/GNUmakefile
##
## keyfactor_certificate_authority CA schedule lifecycle validation, covering
## both the flat interval-minutes schedule fields (full_scan_interval_minutes,
## incremental_scan_interval_minutes, threshold_check_interval_minutes) and
## the Daily time-of-day variant restored by fix #193
## (full_scan_daily_time/incremental_scan_daily_time/threshold_check_daily_time)
## -- see main.tf's header for schema history. Step 4 exercises the Daily
## variant out-of-band (seeded via api-get-ca/api-update-ca, bypassing
## Terraform) and step6 exercises it declaratively (set directly via
## Terraform config); step5 exercises the still-open Weekly variant, which
## remains a known SDK-level gap (#185) unrelated to #193/#194.
##
## Creates a brand-new, deliberately unreachable CA (force_save=true) instead
## of touching any of the lab's real CA connections -- see main.tf header.
##
## Usage:
##   make build
##   make authcert       # generate throwaway authcert.pfx (gitignored, never committed)
##   make init
##   make step1-apply     # full_scan_interval_minutes=60, incremental=15
##   make step1-plan      # expect: No changes
##   make step2-apply     # change full_scan_interval_minutes=120 (in-place update)
##   make step2-plan      # expect: No changes
##   make step3-seed      # out-of-band: set threshold_check_interval_minutes (Interval) via api-update-ca
##   make step3-apply     # unrelated update (monitor_thresholds toggle only)
##   make step3-verify    # re-GET: threshold_check_interval_minutes must survive verbatim
##   make step4-seed-daily  # out-of-band: seed a Daily ThresholdCheck schedule
##   make step4-apply       # unrelated update (monitor_thresholds toggle back)
##   make step4-verify       # fix #193: Daily schedule must survive, not wipe to null
##   make step5-seed-weekly  # out-of-band: seed a Weekly ThresholdCheck schedule
##   make step5-verify       # KNOWN BUG #185: terraform plan is expected to crash (JSON unmarshal)
##   make step5-cleanup      # reset ThresholdCheck to null so terraform can read the CA again
##   make step6-apply-daily  # declare threshold_check_daily_time directly via Terraform config --
##                            # KNOWN GAP (confirmed 2026-08-08): expected to FAIL with "Provider
##                            # produced inconsistent result after apply" -- Command normalizes the
##                            # Daily schedule's date to "today" server-side; see main.tf's resource
##                            # block for the full writeup. This is a genuine, separate gap from the
##                            # OOB-preservation fix step4 exercises (which works correctly).
##   make step6-plan         # only reachable if step6-apply-daily unexpectedly succeeds
##   make step6-revert       # undeclare it again (back to the step1-5 shape); always run this
##                            # regardless of step6-apply-daily's outcome
##   make import-test     # import round-trip + drift-check
##   make destroy
##   make lifecycle        # runs all of the above in order; see the lifecycle target
##                          # itself for how step5's expected failure is handled

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

SHELL         := /bin/bash
KEYFACTOR_ENV_FILE ?= $(HOME)/.env_kfclab
LAB_TIMEOUT   ?= 600

LAB_ENV := set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
           unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && \
           export KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT) &&

## build: Compile and install the provider binary to ~/go/bin
build:
	@echo "==> Building provider..."
	cd $(PROVIDER_ROOT) && go install .
	@echo "==> Provider installed to $(PROVIDER_BIN)/terraform-provider-keyfactor"

## authcert: Generate a throwaway self-signed authcert.pfx (never committed --
##   see .gitignore). Only needed if this lab's Command instance rejects
##   HTTPS CA PUTs missing an Authentication Certificate (confirmed on a
##   prior lab; not yet re-confirmed against kfclab -- see main.tf header
##   and README.md "Known lab constraints").
authcert:
	@if [ -f authcert.pfx ]; then echo "authcert.pfx already exists; remove it first to regenerate."; exit 0; fi
	openssl req -x509 -newkey rsa:2048 -keyout /tmp/ca_schedule_demo_authcert_key.pem \
	  -out /tmp/ca_schedule_demo_authcert_cert.pem -days 1 -nodes \
	  -subj "/CN=tf-ca-schedule-demo-throwaway-authcert"
	openssl pkcs12 -export -out authcert.pfx \
	  -inkey /tmp/ca_schedule_demo_authcert_key.pem -in /tmp/ca_schedule_demo_authcert_cert.pem \
	  -passout pass:fakepassword
	@rm -f /tmp/ca_schedule_demo_authcert_key.pem /tmp/ca_schedule_demo_authcert_cert.pem
	@echo "==> Generated authcert.pfx (throwaway, password: fakepassword -- matches var.auth_certificate_password default)"

## init: Initialize the Terraform working directory (authcert.pfx must exist
##   first -- main.tf reads it unconditionally via filebase64(); run `make
##   authcert` once beforehand)
init: authcert
	$(LAB_ENV) $(TF) init

## validate: Validate the Terraform configuration
validate:
	$(LAB_ENV) $(TF) validate

# ---------------------------------------------------------------------------
# Step 1: Declare both schedule fields
# ---------------------------------------------------------------------------
step1-apply:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=60" -var="incremental_scan_interval_minutes=15"

step1-plan:
	$(LAB_ENV) $(TF) plan -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=60" -var="incremental_scan_interval_minutes=15"

# ---------------------------------------------------------------------------
# Step 2: In-place update of full_scan_interval_minutes
# ---------------------------------------------------------------------------
step2-apply:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15"

step2-plan:
	$(LAB_ENV) $(TF) plan -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15"

# ---------------------------------------------------------------------------
# Step 3: Out-of-band threshold_check_interval_minutes + unrelated update
# preservation (threshold_check_interval_minutes is never declared in
# main.tf, so it stays "undeclared/unmanaged")
# ---------------------------------------------------------------------------
## step3-seed: Out-of-band PUT that sets threshold_check_interval_minutes
##   directly via the API (bypassing Terraform). CA_ID must be set to the
##   demo CA's id (see `make show`).
# Out-of-band PUTs must re-supply AuthCertificate/AuthCertificatePassword --
# some Command instances reject any HTTPS CA PUT missing them (see main.tf),
# and GET never echoes back a reusable SecretValue, only metadata.
AUTHCERT_B64 := $(shell base64 -i $(CURDIR)/authcert.pfx | tr -d '\n')

step3-seed:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step3-seed CA_ID=<id>"; exit 1; fi
	$(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE) | \
	  jq --arg b64 "$(AUTHCERT_B64)" '.ThresholdCheck = {"Interval": {"Minutes": 30}, "Daily": null, "Weekly": null, "Monthly": null, "ExactlyOnce": null} | .AuthCertificate = {"SecretValue": $$b64} | .AuthCertificatePassword = {"SecretValue": "fakepassword"}' | \
	  $(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-update-ca KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE)

## step3-apply: Unrelated update (monitor_thresholds toggle only -- no
##   schedule attribute changes) to force resourceCertificateAuthority.Update() to run.
step3-apply:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=true"

## step3-verify: Re-GET the demo CA and print ThresholdCheck.Interval.Minutes --
##   must still be the value seeded by step3-seed, verbatim.
step3-verify:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step3-verify CA_ID=<id>"; exit 1; fi
	$(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE) | jq '.ThresholdCheck'

# ---------------------------------------------------------------------------
# Step 4: Daily-schedule wipe check (KNOWN PROVIDER BUG, confirmed 2026-08-07)
#
# Confirmed directly against Command 25.5 on kfclab: seed ThresholdCheck as
# a Daily schedule out-of-band, then run ANY unrelated terraform apply (here:
# monitor_thresholds toggle) -- the Daily schedule is WIPED to null
# server-side. Root cause: resourceCertificateAuthority's Read()
# (caResponseToState) only understands the Interval variant of
# KeyfactorCommonSchedulingKeyfactorSchedule; a Daily/Weekly/Monthly
# ThresholdCheck always reads back as threshold_check_interval_minutes=null
# in Terraform state regardless of the real server value. Because that field
# is Optional+Computed with UseStateForUnknown, the null flows straight into
# the next plan, so buildCARequest() omits ThresholdCheck from the PUT body
# entirely -- and Command's PUT /CertificateAuthority endpoint treats an
# omitted ThresholdCheck as "clear it" (full-object-replace semantics), not
# "leave unchanged". Net effect: an out-of-band Daily/Weekly/Monthly CA
# schedule is silently destroyed by the very next terraform apply, even one
# that never touches schedules at all.
# ---------------------------------------------------------------------------
## step4-seed-daily: Out-of-band PUT that sets ThresholdCheck to a Daily schedule.
step4-seed-daily:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step4-seed-daily CA_ID=<id>"; exit 1; fi
	$(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE) | \
	  jq --arg b64 "$(AUTHCERT_B64)" '.ThresholdCheck = {"Interval": null, "Daily": {"Time": "2026-01-01T02:30:00"}, "Weekly": null, "Monthly": null, "ExactlyOnce": null} | .AuthCertificate = {"SecretValue": $$b64} | .AuthCertificatePassword = {"SecretValue": "fakepassword"}' | \
	  $(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-update-ca KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE)

## step4-apply: Unrelated update (monitor_thresholds toggled back to false)
##   -- no schedule attribute changes -- this is what is expected to WIPE
##   the Daily schedule seeded by step4-seed-daily.
step4-apply:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=false"

## step4-verify: Re-GET the demo CA -- PASS if the Daily schedule survived
##   (no bug on this Command/provider version), or a clearly-labeled
##   KNOWN-BUG FAIL if it was wiped to null (the repro this step exists to
##   demonstrate). A FAIL here is a correct harness outcome, not a crash.
step4-verify:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step4-verify CA_ID=<id>"; exit 1; fi
	@$(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE) > /tmp/ca_schedule_demo_step4_verify.json
	@jq '.ThresholdCheck' /tmp/ca_schedule_demo_step4_verify.json
	@if jq -e '.ThresholdCheck.Daily != null' /tmp/ca_schedule_demo_step4_verify.json > /dev/null 2>&1; then \
	  echo "PASS: out-of-band Daily schedule survived an unrelated apply."; \
	else \
	  echo "FAIL (KNOWN PROVIDER BUG): out-of-band Daily ThresholdCheck schedule was wiped to null by an unrelated terraform apply (monitor_thresholds toggle). See GNUmakefile step4 header for root cause. This is a genuine provider bug reproduction, not a harness failure."; \
	  exit 1; \
	fi

# ---------------------------------------------------------------------------
# Step 5: Weekly-schedule deserialization failure (KNOWN BUG #185, confirmed
# 2026-08-07)
#
# Confirmed directly against Command 25.5 on kfclab: Command serializes
# ThresholdCheck.Weekly.Days as an array of day-name STRINGS (e.g.
# ["Monday","Wednesday","Friday"]), but keyfactor-go-client-sdk's generated
# SystemDayOfWeek.UnmarshalJSON only accepts a JSON number. Any CA carrying
# a Weekly schedule therefore makes EVERY terraform command that reads the
# CA (plan/apply/refresh/destroy) fail outright with a JSON unmarshal error
# -- this is the same ~80-enum int-only-unmarshal hazard tracked as
# keyfactor-go-client-sdk issue #185.
# ---------------------------------------------------------------------------
## step5-seed-weekly: Out-of-band PUT that sets ThresholdCheck to a Weekly schedule.
step5-seed-weekly:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step5-seed-weekly CA_ID=<id>"; exit 1; fi
	$(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE) | \
	  jq --arg b64 "$(AUTHCERT_B64)" '.ThresholdCheck = {"Interval": null, "Daily": null, "Weekly": {"Days": [1,3,5], "Time": "2026-01-01T03:00:00"}, "Monthly": null, "ExactlyOnce": null} | .AuthCertificate = {"SecretValue": $$b64} | .AuthCertificatePassword = {"SecretValue": "fakepassword"}' | \
	  $(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-update-ca KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE)

## step5-verify: Run `terraform plan` against the Weekly-seeded CA -- a
##   clearly-labeled KNOWN-BUG FAIL if it errors with the expected JSON
##   unmarshal message (the repro this step exists to demonstrate), a
##   distinct "harness/unexpected" FAIL if it errors any other way, or PASS
##   if the SDK has since been fixed to tolerate string day names.
step5-verify:
	@$(LAB_ENV) $(TF) plan -no-color -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=false" > /tmp/ca_schedule_demo_step5_plan.txt 2>&1; \
	 PLAN_EXIT=$$?; \
	 cat /tmp/ca_schedule_demo_step5_plan.txt; \
	 if [ $$PLAN_EXIT -ne 0 ] && grep -q "cannot unmarshal string into" /tmp/ca_schedule_demo_step5_plan.txt && grep -q "Weekly.Days" /tmp/ca_schedule_demo_step5_plan.txt; then \
	   echo "FAIL (KNOWN PROVIDER BUG #185): terraform plan crashed reading a Weekly CA schedule -- Command returns ThresholdCheck.Weekly.Days as day-name strings, but the SDK's SystemDayOfWeek only unmarshals integers. This is a genuine provider/SDK bug reproduction, not a harness failure."; \
	   exit 1; \
	 elif [ $$PLAN_EXIT -ne 0 ]; then \
	   echo "FAIL (harness/unexpected): terraform plan failed for a reason other than the expected #185 signature -- investigate."; \
	   exit 1; \
	 else \
	   echo "PASS: terraform plan succeeded reading a Weekly CA schedule (SDK #185 fix appears to be present)."; \
	 fi

## step5-cleanup: Reset ThresholdCheck to null via a direct API PUT so
##   subsequent terraform commands (import-test/drift-check/destroy) can
##   read the CA again. REQUIRED because step5 deliberately leaves the CA in
##   a state that crashes every terraform Read (see step5-verify header) --
##   always run this even when step5-verify FAILs, since that failure is the
##   expected repro, not a reason to skip cleanup.
step5-cleanup:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step5-cleanup CA_ID=<id>"; exit 1; fi
	$(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE) | \
	  jq --arg b64 "$(AUTHCERT_B64)" '.ThresholdCheck = null | .AuthCertificate = {"SecretValue": $$b64} | .AuthCertificatePassword = {"SecretValue": "fakepassword"}' | \
	  $(MAKE) --no-print-directory -C $(PROVIDER_ROOT) api-update-ca KEYFACTOR_ENV_FILE=$(KEYFACTOR_ENV_FILE)

# ---------------------------------------------------------------------------
# Step 6: threshold_check_daily_time declared DIRECTLY in Terraform config
# (fix #193). Unlike step4 (which proves an out-of-band Daily schedule
# survives an unrelated update), this proves the new Daily variant round-
# trips with zero drift when Terraform itself is the one managing it.
#
# Runs after step5-cleanup, when ThresholdCheck is null both server-side and
# (once step6-apply-daily's own refresh runs) in state -- inserting this
# step any earlier would fight step3/step4/step5's out-of-band ThresholdCheck
# seeding on the same field; inserting it after import-test would break
# import-drift-check's "only force_save differs" contract. step6-revert
# undeclares the attribute again (var back to its null default) so
# import-test/import-drift-check below see the same all-undeclared shape
# step1-5 left behind.
# ---------------------------------------------------------------------------
## step6-apply-daily: Declare threshold_check_daily_time via Terraform config
##   for the first time (no out-of-band seeding involved).
##   KNOWN GAP (confirmed 2026-08-08 against kfclab, Command 25.5): this is
##   expected to FAIL with "Provider produced inconsistent result after
##   apply: .threshold_check_daily_time: was cty.StringVal(\"<declared
##   date>\"), but now cty.StringVal(\"<today's date>\")". Command normalizes
##   a Daily schedule's Time to today's date server-side while preserving
##   only the time-of-day; the provider echoes back that server-normalized
##   value, which can never match a user-declared non-today date. Separate,
##   not-yet-fixed gap from the OOB-preservation fix step4 exercises.
step6-apply-daily:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=false" -var="threshold_check_daily_time=2026-01-01T04:15:00Z"

## step6-plan: Re-plan with the same value -- only reachable if
##   step6-apply-daily unexpectedly succeeds (see its header). Expect "No
##   changes" if it does.
step6-plan:
	$(LAB_ENV) $(TF) plan -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=false" -var="threshold_check_daily_time=2026-01-01T04:15:00Z"

## step6-revert: Undeclare threshold_check_daily_time again (var back to its
##   null default) so the rest of the lifecycle (import-test/
##   import-drift-check) sees the same all-undeclared shape step1-5 left
##   behind. Also re-exercises fix #194: this Update() call transitions the
##   CA away from a Daily-shaped ThresholdCheck without ever touching
##   auth_certificate, which is exactly the path that used to crash with the
##   OAuth/Client-Certificate mixing error on the FOLLOWING destroy.
step6-revert:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=false"

# ---------------------------------------------------------------------------
# Import round-trip + destroy
# ---------------------------------------------------------------------------
## import-test: Remove the demo CA from state and re-import it by id.
import-test:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make import-test CA_ID=<id>"; exit 1; fi
	$(LAB_ENV) $(TF) state rm keyfactor_certificate_authority.demo
	$(LAB_ENV) $(TF) import -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" keyfactor_certificate_authority.demo $(CA_ID)

## import-drift-check: Plan after import -- only force_save (write-only) should differ.
import-drift-check:
	$(LAB_ENV) $(TF) plan -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15"

## destroy: Destroy the demo CA
destroy:
	$(LAB_ENV) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15"

## show: Show current outputs (ca_id, schedule state)
show:
	$(LAB_ENV) $(TF) output

## clean: Remove generated local files (never touches any real lab CA)
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

# ---------------------------------------------------------------------------
# Canonical target aliases (see repo harness conventions) -- thin wrappers
# around the step*/import-test/destroy targets above, which remain the
# primary, more precisely-named entry points for this demo's variant walk.
# ---------------------------------------------------------------------------

## plan: Alias for step1-plan
plan: step1-plan

## apply: Alias for step1-apply
apply: step1-apply

## import-all: Alias for import-test (CA_ID auto-derived from state)
import-all:
	@CA_ID=$$($(LAB_ENV) $(TF) output -raw ca_id) && $(MAKE) import-test CA_ID=$$CA_ID SUFFIX=$(SUFFIX)

## drift-check: Alias for import-drift-check
drift-check: import-drift-check

## lifecycle: Full walk -- step1 (declare both intervals) -> step2 (in-place
##   update) -> step3 (out-of-band threshold_check preservation across an
##   unrelated update, Interval variant) -> step4 (out-of-band Daily
##   schedule wipe check -- fix #193) -> step5 (out-of-band Weekly schedule
##   deserialization check -- KNOWN BUG #185, expected FAIL, unrelated SDK
##   gap) -> step6 (threshold_check_daily_time declared directly in
##   Terraform config -- fix #193) -> import round-trip -> destroy.
##
##   step4/step6's own verify targets are expected to PASS now that fixes
##   #193/#194 are present; step5 is expected to keep FAILing (SDK issue
##   #185, a separate, not-yet-fixed gap). Every step's exit code is
##   captured (not chained with &&/||) so an unexpected failure anywhere
##   never skips cleanup/destroy and never gets confused with an actual
##   harness-mechanics failure in import-test/import-drift-check/destroy.
##   `make lifecycle` exits non-zero overall if step4/step6 fail OR if step5
##   unexpectedly starts passing/fails differently -- read the printed
##   summary to tell a genuine regression apart from the expected #185 gap.
lifecycle:
	$(MAKE) step1-apply SUFFIX=$(SUFFIX)
	$(MAKE) step1-plan SUFFIX=$(SUFFIX)
	$(MAKE) step2-apply SUFFIX=$(SUFFIX)
	$(MAKE) step2-plan SUFFIX=$(SUFFIX)
	@CA_ID=$$($(LAB_ENV) $(TF) output -raw ca_id); \
	 echo "==> demo CA id: $$CA_ID"; \
	 HARNESS_FAIL=0; STEP4_EXIT=0; STEP4_RAN=0; STEP5_EXIT=0; STEP5_RAN=0; STEP6_EXIT=0; STEP6_RAN=0; \
	 if ! $(MAKE) step3-seed CA_ID=$$CA_ID; then echo "FAIL (harness): step3-seed failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) step3-apply SUFFIX=$(SUFFIX); then echo "FAIL (harness): step3-apply failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) step3-verify CA_ID=$$CA_ID; then echo "FAIL (harness): step3-verify failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) step4-seed-daily CA_ID=$$CA_ID; then echo "FAIL (harness): step4-seed-daily failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) step4-apply SUFFIX=$(SUFFIX); then echo "FAIL (harness): step4-apply failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ]; then STEP4_RAN=1; if ! $(MAKE) step4-verify CA_ID=$$CA_ID; then STEP4_EXIT=1; fi; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ] && ! $(MAKE) step5-seed-weekly CA_ID=$$CA_ID; then echo "FAIL (harness): step5-seed-weekly failed -- see above."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ]; then STEP5_RAN=1; if ! $(MAKE) step5-verify SUFFIX=$(SUFFIX); then STEP5_EXIT=1; fi; fi; \
	 if [ $$STEP5_RAN -eq 1 ] && ! $(MAKE) step5-cleanup CA_ID=$$CA_ID; then echo "FAIL (harness): step5-cleanup failed -- see above. CA may be unreadable by terraform until manually reset."; HARNESS_FAIL=1; fi; \
	 if [ $$HARNESS_FAIL -eq 0 ]; then STEP6_RAN=1; \
	   if ! $(MAKE) step6-apply-daily SUFFIX=$(SUFFIX); then STEP6_EXIT=1; \
	   elif ! $(MAKE) step6-plan SUFFIX=$(SUFFIX); then STEP6_EXIT=1; \
	   fi; \
	   if ! $(MAKE) step6-revert SUFFIX=$(SUFFIX); then echo "FAIL (harness): step6-revert failed -- see above. threshold_check_daily_time may still be declared; import-test below may show unexpected drift."; HARNESS_FAIL=1; fi; \
	 fi; \
	 if ! $(MAKE) import-test CA_ID=$$CA_ID SUFFIX=$(SUFFIX); then \
	   echo "FAIL (harness): import-test failed -- see above."; HARNESS_FAIL=1; \
	 elif ! $(MAKE) import-drift-check SUFFIX=$(SUFFIX); then \
	   echo "FAIL (harness): import-drift-check failed -- see above."; HARNESS_FAIL=1; \
	 fi; \
	 if ! $(MAKE) destroy SUFFIX=$(SUFFIX); then \
	   echo "FAIL (harness): destroy failed -- see above. Demo CA $$CA_ID may be orphaned; check manually."; HARNESS_FAIL=1; \
	 fi; \
	 echo "=============================================================="; \
	 echo "ca_schedule_demo summary:"; \
	 if [ $$HARNESS_FAIL -ne 0 ]; then echo "  HARNESS FAILURE occurred -- see FAIL (harness) lines above; this is a real regression, not a known-bug repro."; fi; \
	 if [ $$STEP4_RAN -ne 1 ]; then \
	   echo "  step4 (Daily-schedule wipe check, fix #193):         SKIPPED (an earlier step failed -- see HARNESS FAILURE above)."; \
	 elif [ $$STEP4_EXIT -ne 0 ]; then \
	   echo "  step4 (Daily-schedule wipe check, fix #193):         FAIL -- schedule was wiped; #193 did not fix this."; \
	 else \
	   echo "  step4 (Daily-schedule wipe check, fix #193):         PASS (no wipe observed)."; \
	 fi; \
	 if [ $$STEP5_RAN -ne 1 ]; then \
	   echo "  step5 (Weekly-schedule deserialization, SDK #185):   SKIPPED (an earlier step failed -- see HARNESS FAILURE above)."; \
	 elif [ $$STEP5_EXIT -ne 0 ]; then \
	   echo "  step5 (Weekly-schedule deserialization, SDK #185):   KNOWN BUG #185 reproduced (expected -- separate SDK-level fix, not part of this pass)."; \
	 else \
	   echo "  step5 (Weekly-schedule deserialization, SDK #185):   PASS (unexpected -- #185 appears fixed too)."; \
	 fi; \
	 if [ $$STEP6_RAN -ne 1 ]; then \
	   echo "  step6 (threshold_check_daily_time declarative, #193): SKIPPED (an earlier step failed -- see HARNESS FAILURE above)."; \
	 elif [ $$STEP6_EXIT -ne 0 ]; then \
	   echo "  step6 (threshold_check_daily_time declarative, #193): FAIL -- see above."; \
	 else \
	   echo "  step6 (threshold_check_daily_time declarative, #193): PASS (applied with zero drift on replan)."; \
	 fi; \
	 echo "=============================================================="; \
	 if [ $$HARNESS_FAIL -ne 0 ] || [ $$STEP4_EXIT -ne 0 ] || [ $$STEP6_EXIT -ne 0 ]; then exit 1; fi

.PHONY: build authcert init validate step1-apply step1-plan step2-apply step2-plan \
        step3-seed step3-apply step3-verify \
        step4-seed-daily step4-apply step4-verify \
        step5-seed-weekly step5-verify step5-cleanup \
        step6-apply-daily step6-plan step6-revert \
        import-test import-drift-check destroy show clean \
        plan apply import-all drift-check lifecycle
