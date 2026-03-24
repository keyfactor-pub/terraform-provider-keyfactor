## certificate_pfx_demo/GNUmakefile
##
## Demonstrates PFX certificate enrollment via the keyfactor_certificate resource:
##   build → init → validate → plan → apply → import → drift-check → destroy
##
## Prerequisites — set these environment variables before running:
##   export KEYFACTOR_HOSTNAME=your-command-host.example.com
##   export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
##   export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
##   export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token
##   export TF_VAR_certificate_authority="Sub-CA"
##   export TF_VAR_certificate_template="2YearTestWebServer"
##
## Usage:
##   cd terraform/certificate_pfx_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make all                # run the full workflow
##   make SUFFIX=_MYORG all  # run with a custom CN suffix

PROVIDER_ROOT := $(abspath ../..)
PROVIDER_BIN  := $(HOME)/go/bin
SUFFIX        ?= _PFX_DEMO

TF          := TF_CLI_CONFIG_FILE=.terraformrc terraform
UNSET_BASIC := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

# ---------------------------------------------------------------------------
# Lab environment helpers
# Source LAB_ENV_FILE for OAuth credentials, then set required TF_VARs.
# Override via: make LAB_ENV_FILE=~/.env_other LAB_CA="MyCA" lifecycle
# ---------------------------------------------------------------------------
SHELL         := /bin/bash
LAB_ENV_FILE  ?= $(HOME)/.env_ses2541
LAB_CA        ?= Sub-CA
LAB_PATTERN   ?= Default Pattern
LAB_TIMEOUT   ?= 600

LAB_ENV := source $(LAB_ENV_FILE) && \
           unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && \
           export TF_VAR_certificate_authority="$(LAB_CA)" \
                  TF_VAR_certificate_enrollment_pattern="$(LAB_PATTERN)" \
                  KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT) &&

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
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Enroll all demo certificates
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove all managed resources from state then re-import by certificate ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 _export_ids.py
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_certificate.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by certificate ID..."
	@while IFS=' ' read -r name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "keyfactor_certificate.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$name (ID=$$id)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt

## drift-check: Plan after import — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Revoke and delete all demo certificates
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, plan, apply, import-all, drift-check, destroy
all: build init validate plan apply import-all drift-check destroy

## demo-no-destroy: Run workflow without final destroy (leaves certificates on server)
demo-no-destroy: build init validate plan apply import-all drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source LAB_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-apply: Apply using lab credentials from LAB_ENV_FILE
lab-apply:
	$(LAB_ENV) $(MAKE) apply

## lab-import-all: Import all certificates using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

## lab-destroy: Destroy using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy

## lifecycle: Full lifecycle test: apply → import-all → apply (reconcile) → drift-check → destroy
lifecycle: lab-apply lab-import-all lab-apply lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-apply lab-import-all lab-drift-check lab-destroy lifecycle
