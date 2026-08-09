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
PROVIDER_BIN   := $(HOME)/go/bin
SUFFIX         ?= _TF

PROVIDER_MODE ?= registry

ifeq ($(PROVIDER_MODE),dev)
TF            := TF_CLI_CONFIG_FILE=.terraformrc terraform
else
TF            := TF_CLI_CONFIG_FILE=$(PROVIDER_ROOT)/terraform/.terraformrc.registry terraform
endif
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

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
          unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && \
          export KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT)$(if $(LAB_ENV_EXTRA_EXPORTS), $(LAB_ENV_EXTRA_EXPORTS)) &&

# ---------------------------------------------------------------------------
# Shared out-of-band API auth preamble (full-review round 2 advisory B)
# ---------------------------------------------------------------------------
# KF_CURL_AUTH is the round-1-hardened curl auth preamble (TLS gating via
# KEYFACTOR_SKIP_VERIFY/KEYFACTOR_CA_CERT, mktemp+chmod-600 curl -K config so
# credentials never appear on curl's argv/in `ps`, client-credentials token
# fetch, bearer-header rewrite into the same config file) that several demos'
# lab-oob-* targets use to call the Command API directly -- bypassing
# Terraform -- to mutate or inspect a resource out-of-band (proving a
# provider Read/drift-detection fix actually works against a change Terraform
# didn't make itself). Before this, the identical 6-statement block was
# pasted verbatim at 5 call sites across 4 demo GNUmakefiles; round 1 had to
# apply the same hardening edit to all 5 at once, which is exactly the
# maintenance cost this consolidates away.
#
# Recursive ('=') on purpose, matching LAB_ENV above: $$KEYFACTOR_* resolve
# at recipe-execution time (after LAB_ENV has sourced KEYFACTOR_ENV_FILE),
# not at include time.
#
# Usage: within a target's own $(LAB_ENV)-sourced recipe, splice in
# `$(KF_CURL_AUTH) \` where the preamble used to live, then keep using
# $$CURL_TLS / -K "$$KFCFG" exactly as before for the endpoint-specific
# request that follows -- this only replaces the preamble, nothing
# downstream of it.
KF_CURL_AUTH = CURL_TLS=""; if [ "$$KEYFACTOR_SKIP_VERIFY" = "true" ]; then CURL_TLS="-k"; fi; if [ -n "$$KEYFACTOR_CA_CERT" ]; then CURL_TLS="$$CURL_TLS --cacert $$KEYFACTOR_CA_CERT"; fi; KFCFG=$$(mktemp); chmod 600 "$$KFCFG"; trap 'rm -f "$$KFCFG"' EXIT; printf 'data = "grant_type=client_credentials&client_id=%s&client_secret=%s"\n' "$$KEYFACTOR_AUTH_CLIENT_ID" "$$KEYFACTOR_AUTH_CLIENT_SECRET" > "$$KFCFG"; TOKEN=$$(curl -s $$CURL_TLS -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -K "$$KFCFG" | jq -r '.access_token'); printf 'header = "Authorization: Bearer %s"\n' "$$TOKEN" > "$$KFCFG";

# ---------------------------------------------------------------------------
# Provider build
# ---------------------------------------------------------------------------

## build: Compile and install the provider binary to ~/go/bin
build:
	@echo "==> Building provider..."
	cd $(PROVIDER_ROOT) && go install .
	@echo "==> Provider installed to $(PROVIDER_BIN)/terraform-provider-keyfactor"

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

.PHONY: build init validate
