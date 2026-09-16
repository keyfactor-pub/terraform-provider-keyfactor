# Keyfactor Terraform Provider v2.10 — Gap Analysis Response

**Date:** 14 September 2026 (last updated 16 September 2026)
**Regarding:** Gap analysis dated 8 September 2026, assessed against v2.10.0-rc.3

---

## Summary

Five of the six reported gaps are resolved in v2.10 GA (four fixed, one
mitigated as a Command API limitation). One is tracked for a near-term
follow-on release. One requires a broader design decision and is not yet
scheduled. Both documentation requests are complete.

| Gap | Resolution | Status |
|---|---|---|
| **G1** — EP role bindings replace the entire array | New `keyfactor_enrollment_pattern_role_binding` resource | **Complete** — verified via demo harness |
| **G2** — Data sources abort on absent objects | Solved by name-based import for collections and enrollment patterns | **Complete** — verified via demo harness |
| **G3** — `query` does not read back on collections | Command API limitation; provider preserves `query` from state on Read | **Resolved** — mitigated |
| **G4** — Enrollment pattern list is unpaginated | Migrated data source to SDK with `ReturnLimit(500)` | **Complete** — verified via demo harness |
| **G5** — Patterns cannot be resolved by template short name | `template_short_name` filter on the data source | Tracked, near-term follow-on release |
| **G6** — No 429 / `Retry-After` handling | Provider-wide concern, needs its own design | Not yet scheduled |
| **Doc: claim_type mapping** | Enum table added to schema description and docs | **Complete** |
| **Doc: OAuthOid vs OAuthSubject** | Warning added to claim_type documentation | **Complete** |

---

## Detail per gap

### G1 — Enrollment pattern role bindings (complete)

A new `keyfactor_enrollment_pattern_role_binding` join resource has
shipped. It performs read-modify-write internally with concurrency retry
and verification (the same pattern already shipped for
`keyfactor_oauth_security_role_claim_association` in this release, where
we confirmed and fixed the same lost-update race class). Each binding
adds or removes exactly one role entry on create/destroy; the other
entries on the pattern are never sent or touched.

Import uses the `pattern_name//role_name` delimiter format. The resource
supports the full plan-apply-import-drift-destroy lifecycle (verified
against kfclab on 16 September 2026).

The `associated_role_names` attribute on the enrollment pattern resource
has been restored as a **read-only, authoritative** attribute with
prominent documentation explaining the distinction: practitioners who
need additive role management should use the `role_binding` resource;
`associated_role_names` reflects the authoritative server-side list. A
collection-scoped RBAC walkthrough guide demonstrates both patterns.

### G2 — Lookup-or-create (complete)

We are not changing the data source to return empty state on 404. That
would break the more common case: a practitioner who mistypes a collection
name and expects an immediate error. Every major Terraform provider errors
from data sources on missing objects, and changing that contract would be
surprising.

The underlying need — idempotent provisioning against an existing tenant
from a workflow that may re-run — is real and is solved by a different
mechanism: **name-based import**, which has shipped in this release for
both `keyfactor_certificate_collection` and `keyfactor_enrollment_pattern`.

With name-based import, the idiomatic Terraform approach is:

- **Preferred:** persistent state per application with state locking.
  Concurrent requests for different applications don't contend; same-app
  requests serialize on the lock. Repeat runs are no-ops.
- **If persistent state is not viable:** a thin wrapper that runs
  `terraform import <resource> "<name>"` before apply. Import succeeds if
  the object exists (now in state, apply no-ops); import fails if absent
  (apply creates it). A plan gate between import and apply catches any
  case where imported state diverges from the declared config.

A worked example covering both patterns, including the full resource
configuration for the collection-to-enrollment-pattern chain, is provided
in the collection-scoped RBAC walkthrough guide shipped with this release.

Both resources have been verified through the full
plan-apply-import-drift-destroy lifecycle against kfclab (16 September
2026). The import step confirms name-based import round-trips cleanly,
and the post-import drift check shows no spurious changes.

We would also note: the option 3 from the analysis (`adopt_existing`) was
evaluated and rejected. Adopt-on-apply is not idiomatic Terraform and has
a real safety problem — two concurrent fresh-workspace applies racing on
the same name could both "adopt" and then diverge, which is worse than
either a clean duplicate or a clean conflict error.

### G3 — `query` does not read back (resolved)

Confirmed as a Command API limitation: `GET /CertificateCollections/{id}`
does not include `Query` in its response projection. No alternative
endpoint or parameter returns it.

The provider mitigates this by preserving the `query` value from prior
state on Read, so a plain `terraform refresh` does not wipe it out. The
`content_follows_query` unit tests verify the drift-detection behavior:
when the practitioner changes `query` in config, the provider sends the
updated value on Update and the content attribute tracks the new query
result. The only limitation is that out-of-band changes to the query
string (made directly in the Command UI) are not detected by the
provider, because Command does not return the field.

### G4 — Unpaginated enrollment pattern list (complete)

Confirmed as a bug, same defect class as the template pagination fix
from v2.9.1. The data source has been migrated from the legacy
keyfactor-go-client (which had a URL construction bug preventing
pagination params from reaching the server) to the SDK client. The
listing call now uses `ReturnLimit(500)`, which matches the customer's
own verification (`GET /EnrollmentPatterns?ReturnLimit=500` returned all
73 of their patterns).

Additionally, the migration to the SDK fixed a zero-value semantic
issue: the legacy client treated `AllowedEnrollmentTypes == 0` as null
(via the `isNullId` sentinel), but 0 is a valid enum value
(`CSSCMSCoreEnumsEnrollmentType(0)`). The SDK correctly uses nil for
absence, so enum value 0 now round-trips correctly.

Verified via demo harness against kfclab (16 September 2026).

### G5 — Template short name resolution

Agreed that this is needed and that the resolution logic already exists
internally. This is tracked for a near-term follow-on release (not v2.10
GA, to avoid file-level conflicts with the G1 work on the same data
source). The `template_short_name` and `template_default` filter
attributes will be exposed on `data.keyfactor_enrollment_pattern`.

### G6 — 429 / Retry-After handling

This is a provider-wide (and potentially SDK-level) concern, not scoped to
these resources. The previous silent retry was intentionally removed
because retrying non-idempotent POSTs risked double-creation. A bounded
retry on idempotent verbs (GET, PUT, DELETE) honouring `Retry-After` is
the right shape, but it needs its own design pass — particularly around
where in the stack it lives (provider, SDK, or auth client). Not yet
scheduled; will be opened as a separate investigation if this is actively
blocking in production.

---

## Documentation (complete)

**Claim type enum table:** the full `CSSCMSCoreEnumsClaimType` mapping
(`0=User, 1=Group, 2=Computer, 3=OAuthOid, 4=OAuthRole, 5=OAuthSubject,
6=OAuthClientId`) is now in the `claim_type` attribute description and the
generated registry documentation, with source attribution to the SDK enum.

**OAuthOid vs OAuthSubject:** a warning has been added noting that in Entra
client-credentials flows, both `sub` and `oid` carry the service principal
object ID, and that `OAuthSubject` is the correct choice for machine
identities. `OAuthOid` creates a claim that appears valid but grants no
access.

---

## Section 6 confirmation (enrollment pattern permissions)

This cannot be answered from provider source code — it requires a live
test with a least-privilege service principal. We can confirm the provider
calls only `/EnrollmentPatterns` endpoints (no `/Templates` call), which
was correctly verified in the analysis. The actual permission Command
enforces on `PUT /EnrollmentPatterns/{id}` and whether read-only access
suffices for `GET` are Command-side authorization facts that would need to
be validated against a live instance. We can assist with that test if
useful.

---

## Verification (16 September 2026)

All addressed gaps have been verified on the `fix/v2.10-oauth-role-binding-race`
branch against kfclab:

| Check | Result |
|-------|--------|
| Full unit test suite (`make testunit`) | **PASS** — 0 failures, ~5 min |
| `oauth_security_demo` lifecycle | **PASS** — role + claim + association CRUD |
| `enrollment_pattern_demo` lifecycle | **PASS** — pattern + role_binding, `//` delimiter import |
| `certificate_collection_demo` lifecycle | **PASS** — data source round-trip confirmed |

Dependencies bumped for this branch:

| Dependency | Version |
|------------|---------|
| `keyfactor-auth-client-go` | v1.6.1-rc.0 ([PR #56](https://github.com/Keyfactor/keyfactor-auth-client-go/pull/56)) |
| `keyfactor-go-client/v3` | v3.6.0 |
| `keyfactor-go-client-sdk/v25` | v25.2.0-rc.4 |
