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
