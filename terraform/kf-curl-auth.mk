## terraform/kf-curl-auth.mk
##
## Shared out-of-band Command API curl-auth preamble. Included by BOTH
## terraform/demo-common.mk (used by the terraform/*_demo/ GNUmakefiles'
## lab-oob-* targets) and the root GNUmakefile (used by KF_API_PUT, which
## api-update-ca/api-update-template share) -- kept as its own file rather
## than folded into demo-common.mk because demo-common.mk also defines
## PROVIDER_ROOT/TF/LAB_ENV and demo-only targets (build/init/validate) that
## the root GNUmakefile has no business inheriting.
##
## KF_CURL_AUTH is the round-1-hardened curl auth preamble (TLS gating via
## KEYFACTOR_SKIP_VERIFY/KEYFACTOR_CA_CERT, mktemp+chmod-600 curl -K config so
## credentials never appear on curl's argv/in `ps`, client-credentials token
## fetch, bearer-header rewrite into the same config file). Before this
## consolidation the identical 6-statement block was pasted verbatim at 5 call
## sites across 4 demo GNUmakefiles (round 1 had to hand-patch all 5 for the
## same hardening edit) and, separately, inlined a sixth time in the root
## GNUmakefile's KF_API_PUT (round 2 had to patch that copy in lockstep to add
## the HTTP-status gate) -- a future change to how credentials reach curl
## (e.g. adding a proxy CA, fixing a quoting bug) is now a one-file edit
## instead of two. Full-review round 3 advisory.
##
## Recursive ('=') on purpose, matching demo-common.mk's LAB_ENV: $$KEYFACTOR_*
## resolve at recipe-execution time (after the caller has sourced
## KEYFACTOR_ENV_FILE), not at include time.
##
## Usage: within a target's own recipe, after sourcing KEYFACTOR_ENV_FILE,
## splice in `$(KF_CURL_AUTH) \` where this preamble used to live, then keep
## using $$CURL_TLS / -K "$$KFCFG" exactly as before for the endpoint-specific
## request that follows -- this only replaces the preamble, nothing
## downstream of it.
KF_CURL_AUTH = CURL_TLS=""; if [ "$$KEYFACTOR_SKIP_VERIFY" = "true" ]; then CURL_TLS="-k"; fi; if [ -n "$$KEYFACTOR_CA_CERT" ]; then CURL_TLS="$$CURL_TLS --cacert $$KEYFACTOR_CA_CERT"; fi; KFCFG=$$(mktemp); chmod 600 "$$KFCFG"; trap 'rm -f "$$KFCFG"' EXIT; printf 'data = "grant_type=client_credentials&client_id=%s&client_secret=%s"\n' "$$KEYFACTOR_AUTH_CLIENT_ID" "$$KEYFACTOR_AUTH_CLIENT_SECRET" > "$$KFCFG"; TOKEN=$$(curl -s $$CURL_TLS -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" -K "$$KFCFG" | jq -r '.access_token'); printf 'header = "Authorization: Bearer %s"\n' "$$TOKEN" > "$$KFCFG";
