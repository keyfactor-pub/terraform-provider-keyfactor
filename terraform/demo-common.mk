## terraform/demo-common.mk
##
## Shared preamble + provider-build target for the terraform/*_demo/
## GNUmakefiles. Every demo's own GNUmakefile carried a byte-identical (or
## whitespace-only-different) copy of this block; consolidating it here
## means a future change to e.g. LAB_TIMEOUT or the registry .terraformrc
## path is a one-file edit instead of nineteen, and stops the whitespace
## drift already visible between copies before this consolidation.
##
## Usage: `include ../demo-common.mk` near the top of a demo's GNUmakefile,
## AFTER any demo-specific variable that participates in this file's
## conditionals or hooks (see LAB_ENV_EXTRA_EXPORTS below) is defined, and
## BEFORE any demo-specific target of the same name (init/validate/build)
## needs to override what this file provides -- GNU Make prints a harmless
## "warning: overriding recipe for target 'X'" if a demo redefines one of
## build/init/validate after including this file; that's an accepted
## tradeoff for the one demo (ca_schedule_demo) whose init/validate
## genuinely differ (they use $(LAB_ENV) instead of $(UNSET_BASIC) and
## init has an extra `authcert` prerequisite) rather than a bug.
##
## What stays local to each demo's own GNUmakefile (deliberately NOT
## extracted here): plan/apply/import-all/reconcile/drift-check/destroy/
## clean/lab-*/lifecycle/all. These differ per demo by resource type,
## Terraform variables, and import/reconcile logic -- verified NOT
## byte-identical across the 19 demos, unlike everything below.

PROVIDER_ROOT  := $(abspath ../..)
# Dev-mode provider binary dir is PER-WORKTREE (terraform/.provider-bin, gitignored),
# not the shared $(HOME)/go/bin: every worktree used to `go install` into the same
# dir and point its .terraformrc there, so a run could silently exercise another
# worktree's build. The dev_overrides CLI config (TF_DEV_RC) is GENERATED from it
# below, so no hand-copied .terraformrc files are needed.
PROVIDER_BIN   := $(PROVIDER_ROOT)/terraform/.provider-bin
TF_DEV_RC      := $(PROVIDER_ROOT)/terraform/.terraformrc.dev
HARNESS_DIR    := $(PROVIDER_ROOT)/terraform/harness
SUFFIX         ?= _TF

PROVIDER_MODE ?= registry

ifeq ($(PROVIDER_MODE),dev)
# (re)generate the dev_overrides config at parse time so even a bare `make plan
# PROVIDER_MODE=dev` or a demo that overrides init works; prints nothing.
HARNESS_DEV_RC_GEN := $(shell $(HARNESS_DIR)/gen-terraformrc.sh "$(PROVIDER_BIN)" "$(TF_DEV_RC)")
TF            := TF_CLI_CONFIG_FILE=$(TF_DEV_RC) terraform
else
TF            := TF_CLI_CONFIG_FILE=$(PROVIDER_ROOT)/terraform/.terraformrc.registry terraform
endif
# umask 077: terraform state, tf_state.json (`show -json`, plaintext sensitive values),
# plan files etc. are created owner-only (they were 0644 before).
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN; umask 077;

# ---------------------------------------------------------------------------
# Lab environment helpers
# Source KEYFACTOR_ENV_FILE for OAuth credentials.
# Override via: make KEYFACTOR_ENV_FILE=~/.env_other lifecycle
# ---------------------------------------------------------------------------
SHELL         := /bin/bash
KEYFACTOR_ENV_FILE ?= $(HOME)/.env_kfclab
LAB_TIMEOUT   ?= 600

# LAB_ENV_EXTRA_EXPORTS lets a demo inject additional `export NAME=value`
# pairs onto LAB_ENV's export line (space-separated, same syntax `export`
# itself takes) without having to redefine LAB_ENV wholesale. Set it BEFORE
# `include ../demo-common.mk`. certificate_csr_demo/certificate_pfx_demo use
# this for TF_VAR_certificate_authority/TF_VAR_certificate_enrollment_pattern.
LAB_ENV_EXTRA_EXPORTS ?=

# Recursive ('=') on purpose: KEYFACTOR_ENV_FILE/LAB_TIMEOUT/
# LAB_ENV_EXTRA_EXPORTS are re-read every time LAB_ENV is used, not frozen
# at include time, matching a `make KEYFACTOR_ENV_FILE=... lifecycle`
# command-line override.
LAB_ENV = set -a && source $(KEYFACTOR_ENV_FILE) && set +a && \
          unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && umask 077 && \
          export KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT)$(if $(LAB_ENV_EXTRA_EXPORTS), $(LAB_ENV_EXTRA_EXPORTS)) &&

# ---------------------------------------------------------------------------
# Shared out-of-band API auth preamble (full-review round 2 advisory B)
# ---------------------------------------------------------------------------
# KF_CURL_AUTH (used by several demos' lab-oob-* targets to call the Command
# API directly -- bypassing Terraform -- to mutate or inspect a resource
# out-of-band) now lives in terraform/kf-curl-auth.mk, shared with the root
# GNUmakefile's KF_API_PUT (full-review round 3 advisory: that was the last
# remaining duplicate of this same credential-handling block). See that
# file's header comment for the full history and usage.
include ../kf-curl-auth.mk

# ---------------------------------------------------------------------------
# Provider build
# ---------------------------------------------------------------------------

## build: Compile and install the provider binary into THIS worktree's terraform/.provider-bin
## (never ~/go/bin); prints the exact binary path + sha256 the dev-mode run will use
build:
	@echo "==> Building provider..."
	cd $(PROVIDER_ROOT) && GOBIN=$(PROVIDER_BIN) go install .
	@echo "==> Provider binary: $(PROVIDER_BIN)/terraform-provider-keyfactor (sha256 $$(shasum -a 256 $(PROVIDER_BIN)/terraform-provider-keyfactor | cut -c1-12))"

# ---------------------------------------------------------------------------
# Terraform lifecycle (init/validate only -- plan/apply/destroy/etc. differ
# per demo by resource type and stay in each demo's own GNUmakefile)
# ---------------------------------------------------------------------------

## init: Initialize the Terraform working directory
init:
	$(UNSET_BASIC) $(TF) init

## validate: Validate the Terraform configuration
validate:
	$(UNSET_BASIC) $(TF) validate

## state-count: Print the number of resources in this demo's local Terraform state
## (used by the failure-cleanup logic in terraform/GNUmakefile; 0 when there is no state
## file, "unknown" if terraform could not read it)
state-count:
	@$(UNSET_BASIC) out=$$($(TF) state list 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then printf '%s\n' "$$out" | grep -c . || true; \
	 elif printf '%s' "$$out" | grep -q "No state file"; then echo 0; else echo unknown; fi

.PHONY: build init validate state-count
