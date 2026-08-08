## ca_schedule_demo/GNUmakefile
##
## keyfactor_certificate_authority CA schedule lifecycle validation, using
## the flat interval-minutes schedule fields that actually exist in the
## released schema (full_scan_interval_minutes, incremental_scan_interval_minutes,
## threshold_check_interval_minutes) -- see main.tf's header for why this demo
## no longer references a Daily/Weekly/Monthly variant model that turned out
## not to exist in the shipped provider.
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
##   make step3-seed      # out-of-band: set threshold_check_interval_minutes via api-update-ca
##   make step3-apply     # unrelated update (monitor_thresholds toggle only)
##   make step3-verify    # re-GET: threshold_check_interval_minutes must survive verbatim
##   make import-test     # import round-trip + drift-check
##   make destroy

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
	$(MAKE) -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) | \
	  jq --arg b64 "$(AUTHCERT_B64)" '.ThresholdCheck = {"Interval": {"Minutes": 30}, "Daily": null, "Weekly": null, "Monthly": null, "ExactlyOnce": null} | .AuthCertificate = {"SecretValue": $$b64} | .AuthCertificatePassword = {"SecretValue": "fakepassword"}' | \
	  $(MAKE) -C $(PROVIDER_ROOT) api-update-ca

## step3-apply: Unrelated update (monitor_thresholds toggle only -- no
##   schedule attribute changes) to force resourceCertificateAuthority.Update() to run.
step3-apply:
	$(LAB_ENV) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="full_scan_interval_minutes=120" -var="incremental_scan_interval_minutes=15" -var="monitor_thresholds=true"

## step3-verify: Re-GET the demo CA and print ThresholdCheck.Interval.Minutes --
##   must still be the value seeded by step3-seed, verbatim.
step3-verify:
	@if [ -z "$(CA_ID)" ]; then echo "Usage: make step3-verify CA_ID=<id>"; exit 1; fi
	$(MAKE) -C $(PROVIDER_ROOT) api-get-ca CA_ID=$(CA_ID) | jq '.ThresholdCheck'

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
##   unrelated update) -> import round-trip -> destroy.
lifecycle:
	$(MAKE) step1-apply SUFFIX=$(SUFFIX)
	$(MAKE) step1-plan SUFFIX=$(SUFFIX)
	$(MAKE) step2-apply SUFFIX=$(SUFFIX)
	$(MAKE) step2-plan SUFFIX=$(SUFFIX)
	@CA_ID=$$($(LAB_ENV) $(TF) output -raw ca_id) && \
	 echo "==> demo CA id: $$CA_ID" && \
	 $(MAKE) step3-seed CA_ID=$$CA_ID && \
	 $(MAKE) step3-apply SUFFIX=$(SUFFIX) && \
	 $(MAKE) step3-verify CA_ID=$$CA_ID && \
	 $(MAKE) import-test CA_ID=$$CA_ID SUFFIX=$(SUFFIX) && \
	 $(MAKE) import-drift-check SUFFIX=$(SUFFIX) && \
	 $(MAKE) destroy SUFFIX=$(SUFFIX)

.PHONY: build authcert init validate step1-apply step1-plan step2-apply step2-plan \
        step3-seed step3-apply step3-verify import-test import-drift-check destroy show clean \
        plan apply import-all drift-check lifecycle
