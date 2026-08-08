# Unreleased

## Template Role Bindings

### Fixes

- fix: `keyfactor_template_role_binding` no longer fails with `'Policies' cannot be empty` when updating a role binding on Command 25.x. Command's `PUT /Templates` is a full-replace endpoint and derives its internal policy set from the template's key-algorithm policy; the provider now round-trips that policy from the template it just fetched instead of omitting it, so binding changes no longer silently clear unrelated policy content. Requires a keyfactor-go-client release carrying the corresponding SDK model field. Fixes [#190](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/190)

## Certificate Templates

### Fixes

- fix: `keyfactor_certificate_template` `Update` no longer clears the template's `allowed_requesters` on Command 25.x when the config simply doesn't declare that attribute. `allowed_requesters` is Optional but not Computed, so an undeclared value plans to null, and `PUT /Templates` is a full-replace endpoint that previously omitted the field outright; this could surface downstream as "Enrollment Pattern needs to have at least one associated role" once the requester list was emptied out. `Update` now fetches the template's current requesters fresh immediately before building the request and carries them forward whenever config doesn't declare the attribute, since `keyfactor_template_role_binding` can also change that same field out-of-band between applies. Fixes [#195](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/195)

## Certificate Stores

### Fixes

- fix: `keyfactor_certificate_store` `Update` no longer silently clears an existing container/application assignment when `application_name`/`container_name` is not declared in config — a resolved container ID of `0` was previously omitted from the update request entirely, which Command interprets as "unassign," destroying a real out-of-band assignment before Terraform's own consistency check could even flag it. The existing `container_id` is now preserved whenever prior state shows a real assignment and the plan gives no explicit name. Fixes [#175](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/175)
- fix: `keyfactor_certificate_store` container/application name resolution (`lookupContainerNameByID`) now retries via the list endpoint before falling back to a hint, reducing spurious `container_name`/`application_name` nulling on a single transient/permission-scoped lookup failure

## Certificate Store Types

### Fixes

- fix: `keyfactor_certificate_store_type` `entry_parameters = []` (and `properties = []`) no longer reads back as `null` after create, which previously produced "Provider produced inconsistent result after apply". Command's API always represents an empty parameter/property collection as `[]`, never `null`, so the provider could not previously tell a config-declared empty list apart from an unset one; a declared empty list now reads back as `[]` and an unset attribute still reads back as `null`. Fixes [#192](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/192)
- fix: `keyfactor_certificate_store_type` `local_store`, `server_required`, `power_shell`, and `blueprint_allowed` set explicitly to `false` in config are now actually sent to Command on `Create`/`Update`. These fields moved to nullable pointers in the underlying SDK; the previous plain-`bool` representation could never distinguish an explicit `false` from an unset field, so `false` was silently dropped from the request and Command's own default took over instead.

## Certificate Authorities

### Features

- feat: `keyfactor_certificate_authority` now supports the Daily schedule variant for `full_scan`, `incremental_scan`, and `threshold_check` via new `full_scan_daily_time`, `incremental_scan_daily_time`, and `threshold_check_daily_time` attributes (RFC3339 timestamps), mutually exclusive with the existing `*_interval_minutes` attribute per schedule.

### Fixes

- fix: `keyfactor_certificate_authority` no longer silently clears a CA's scan schedule on every apply when that schedule is configured as a Daily (time-of-day) schedule in Command rather than an Interval schedule. The provider previously only understood the Interval representation, so a Daily-shaped schedule read back as null — indistinguishable from "no schedule" — and the next full-replace update omitted it entirely, clearing it server-side.
- fix: `keyfactor_certificate_authority` `key_retention` configured as a numeric string (e.g. `"2"`) no longer produces "Provider produced inconsistent result after apply". Command accepts either a numeric string or a symbolic name on write but always returns the symbolic name (e.g. `"AfterExpiration"`) on read; the provider now preserves whichever representation was originally configured when it denotes the same value. Fixes [#191](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/191)
- fix: destroying a `keyfactor_certificate_authority` configured with client-certificate authentication no longer fails with "Fields for OAuth and Client Certificate Authentication cannot both be provided for the same CA". `token_url`/`client_id`/`scope`/`audience` are Optional+Computed and read back from Command as an empty string (not null) when OAuth isn't configured, so that empty-but-"set" value was carried forward and echoed onto every request alongside a real, configured `auth_certificate`/`auth_certificate_password` — most visibly in `Delete`'s clear-schedules-before-delete fallback, which rebuilds the update payload straight from on-disk state. The request builder now derives which auth variant is actually in use and omits every field belonging to the other variant, for `Create`, `Update`, and `Delete`'s fallback alike. Fixes [#194](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/194)

## Chores

- chore(deps): adopt `keyfactor-go-client/v3` `v3.5.6` GA (dropping the temporary local `replace` this branch carried during development). This release adds the `TemplatePolicy` model needed by the `keyfactor_template_role_binding` fix above ([#190](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/190)), and also changes `CertificateStoreType`'s `LocalStore`/`ServerRequired`/`PowerShell`/`BlueprintAllowed` fields from `bool` to `*bool` so Command's own omission of those fields can be told apart from an explicit `false` — see the `keyfactor_certificate_store_type` fix above for the resulting user-visible behavior change.

# v2.9.1

## Template Role Bindings 

### Fixes

- fix: `keyfactor_template_role_binding` no longer fails with `Error template name not found` when a template in `template_short_names` sorts beyond the first 50 templates. The template lookup now pages through the full template list instead of reading only Command's default first page of 50, so instances with more than 50 certificate templates can bind any template by short name.

## Certificates

### Fixes
- fix: `keyfactor_certificate` no longer crashes the provider with a nil-pointer dereference (SIGSEGV) during an in-place update when the certificate-context `GET /Certificates/{id}` fails or returns an empty response. `Update` now fails closed with a clear diagnostic instead of panicking; previously this surfaced as a `Plugin did not respond` / plugin crash mid-`apply` (observed when flipping `certificate_format` to PFX).

## Chores

- chore(deps): bump `keyfactor-go-client/v3` to `v3.5.6` — `GetTemplates` now paginates automatically, with a max-page safety bound, per-iteration response-body close, and audit logging.

# v2.9.0

## Certificates

### Fixes

- fix: `keyfactor_certificate` no longer returns the root CA as the leaf (`certificate_pem` / `common_name` / subject fields) when Keyfactor Command returns a non-leaf-first chain (e.g. externally-rooted chains returned root-first) — the provider now re-selects the true end-entity leaf from the combined certificate + chain set, independent of chain ordering. Covers the P7B download, PFX recovery, and PEM recovery (`UnpackPEM`) paths. Previously this poisoned state and forced certificate replacement on every plan
- fix: `keyfactor_certificate` `certificate_pem`, `certificate_chain`, and `ca_certificate` no longer drift on every plan due to CRLF line endings — Command's enrollment responses are normalized to LF on enroll so Create and Read produce byte-identical state

## Certificate Stores

### Features

- feat: `keyfactor_certificate_store` import now accepts container-scoped IDs — `containers/<idOrName>/stores/<guid>` and the explicit `stores/<guid>` form, in addition to the legacy bare `<guid>`; the container-scoped form only requires read permission on the named container, resolving an import-permissions gap for users without read-on-all-stores

### Fixes

- fix: `keyfactor_certificate_store` `application_name` no longer causes "inconsistent result after apply" when set via interpolation (Unknown at plan time, resolved during apply) — the container name is now resolved via a by-ID lookup with a plan/state hint fallback instead of a paginated scan that could miss a freshly-created container

# v2.8.1

## Certificates

### Fixes

- fix: `keyfactor_certificate` `certificate_authority` is now `Optional+Computed` — no longer required when using `certificate_template` or `certificate_enrollment_pattern`; Command auto-selects a CA when omitted
- fix: `keyfactor_certificate` automatically resolves the associated enrollment pattern when only `certificate_template` is specified on Command v25+, enabling backwards-compatible configs to work without CA enrollment permissions; returns a clear error if the template has multiple patterns with no unique default
- fix: `keyfactor_certificate` `collection_id`, `use_cn_as_friendly_name`, and `friendly_name` no longer cause "inconsistent result after apply" — Read now preserves these write-only enrollment parameters from state instead of returning null
- fix: `keyfactor_certificate` `certificate_authority` is now populated from the server response when omitted from config (enrollment pattern auto-selection); previously it remained null even when the server recorded which CA issued the certificate

## OAuth Security

### Fixes

- fix: `keyfactor_oauth_security_role` Update no longer silently wipes all claim associations — the provider now reads existing claims before PUT and preserves them
- fix: `keyfactor_oauth_security_claim` Update no longer causes perpetual plan drift — the Command Security Claims API exhibits eventual consistency (POST/PUT responses and immediate re-reads return the pre-update `description`); provider now stores plan values to avoid spurious drift
- fix: `keyfactor_oauth_security_role` Create and ImportState no longer panic when the API response has a nil `Id` field; a diagnostic error is returned instead
- fix: `keyfactor_oauth_security_claim` Create no longer panics when the API response has a nil `Id` field; a diagnostic error is returned instead
- fix: nil HTTP response body dereferences in `keyfactor_oauth_security_role` and `keyfactor_oauth_security_claim` error handling paths
- fix: OAuth pre-fetched `access_token` authentication mode now correctly forwards the token to the auth client; previously the SDK silently dropped `access_token`, `audience`, and `scopes` fields, causing fallback to environment variables or config file credentials

## Certificate Authorities

### Fixes

- fix: `keyfactor_certificate_authority` resource and data source now expose `use_for_enrollment`, `certificate_cleanup_enabled`, `delete_with_archived_key`, `time_after_expiration`, and `time_after_expiration_units` — these fields were present in the Keyfactor Command API but were accidentally omitted from the provider
- fix: `keyfactor_certificate_authority` `key_retention` field now accepts either the named form (`Disabled`, `Indefinite`, `AfterExpiration`, `FromIssuance`) or its numeric string equivalent (`"0"`–`"3"`); state is always stored as the named form. **Breaking change**: bare integer values (`key_retention = 1`) must be updated to string form (`key_retention = "Indefinite"`); existing state is migrated automatically via schema version upgrade. Fixes [#161](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/161)
- fix: `keyfactor_certificate_authority` Read no longer corrupts server settings (e.g. `use_for_enrollment`, scan schedules) due to nil pointer zero-value coercion on update
- fix: `keyfactor_certificate_authority` Delete no longer incorrectly clears scan schedules on EJBCA/HTTPS CAs when the CA has associated certificates

## Certificate Stores

### Fixes

- fix: `keyfactor_certificate_store` now supports `application_name` as an alias for `container_name` (preferred on Command v25.x+); both fields are fully supported and interchangeable without forcing resource replacement
- fix: `keyfactor_certificate_store` `inventory_schedule` is now `Computed` — no longer drops to null when omitted from config
- fix: `keyfactor_certificate_store` Read now populates `application_name`, `container_name`, and `inventory_schedule` correctly from the server response

## Certificates

### Fixes

- fix: `keyfactor_certificate` `collection_id` no longer causes perpetual plan drift or forces resource replacement on in-place updates

## PAM Providers

### Fixes

- fix: `keyfactor_pam_provider` `remote` and `area` fields no longer cause "inconsistent result after apply" — Read now uses null-safe pointer helpers instead of `GetRemote()`/`GetArea()` which returned Go zero values when the server omitted these optional fields
- fix: `keyfactor_pam_provider_type` `parameters[].display_name` and `instance_level` fields no longer cause "inconsistent result after apply" for the same reason

## Applications

### Fixes

- fix: `keyfactor_application` data source lookup by name now works correctly when the Command server has more than 50 applications — `ListApplications` previously fetched only the first page of 50 results; it now paginates to return all applications
- fix: `keyfactor_application` `schedule_immediate` no longer causes "inconsistent result after apply" — Create and Update paths now preserve the write-only trigger field from plan, matching the existing Read-path logic
- fix: `keyfactor_application` `schedule_daily_time`, `schedule_weekly_time`, `schedule_monthly_time`, `schedule_exactly_once_time` no longer drift after Update — server advances the date to the next occurrence; provider now preserves the user-supplied datetime when only the date portion changed

## Certificate Templates

### Fixes

- fix: `keyfactor_certificate_template` `template_policy.allow_key_reuse`, `allow_wildcards`, `rfc_enforcement`, `certificate_owner_role` no longer cause "inconsistent result after apply" — missing `else { Null: true }` branches caused Go zero values (`false`/`0`) to be stored when the server returned null for these optional policy fields

## Certificate Stores

### Fixes

- fix: `keyfactor_certificate_store` `display_name` (Computed) is now populated in Create, Read, Update, and ImportState paths — previously it was never set, causing "inconsistent result after apply" on first apply

# v2.8.0

## Applications

### Features

- feat: `keyfactor_application` resource and data source

## Agents

### Features

- feat: `keyfactor_agents` data source for listing all orchestrator agents

## Certificate Authorities

### Features

- feat: `keyfactor_certificate_authority` resource and data source with import support

## Certificate Store Types

### Features

- feat: `keyfactor_certificate_store_type` resource and data source
- feat: `keyfactor_certificate_store_types` data source for listing all store types

## Certificate Templates

### Features

- feat: `keyfactor_certificate_template` resource and data source (replaces legacy SDK-based data source)

## Certificates

### Features

- feat: `keyfactor_certificate` resource now supports `key_type`, `key_size`, and `curve` fields for PFX enrollment, allowing explicit control over key algorithm (`RSA`, `ECC`, `Ed25519`, `Ed448`) and key size/curve. These fields are also populated on read and available as read-only attributes on the `keyfactor_certificate` data source.

### Fixes

- fix: `keyfactor_certificate` `certificate_template` and `enrollment_pattern` can now be specified together (#146)
- fix: `keyfactor_certificate` changing `certificate_format` no longer forces resource replacement (#150)
- fix: `keyfactor_certificate` serial number and thumbprint normalized to uppercase hex

## Certificate Stores

### Features

- feat: `keyfactor_certificate_store` data source now supports lookup by GUID via the `id` field; `client_machine` and `store_path` are no longer required when `id` is provided

## Certificate Deployments

### Fixes

- fix: `keyfactor_certificate_deployment` overwrite semantics corrected; K8S store credential support fixed

## PAM Providers

### Features

- feat: `keyfactor_pam_provider` resource and data source
- feat: `keyfactor_pam_provider_type` resource and data source

# 2.7.1

## Certificates

### Fixes:

- fix(data): `keyfactor_certificate` data source schema updated and properly unpacks PFX format recovery.
- fix(data): `keyfactor_certificate` data source handles `certificate_format="PEM"` properly.

# v2.7.0

## Certificate Deployments

### Features

- feat(deployments): `keyfactor_certificate_deployment` Add support for `skip_removal` parameter to skip removal of
  existing certificates during a renewal/replacement of a certificate. Defaults to `false`.

## Certificates

### Features
- feat(certificates): `keyfactor_certificate` Add calculated fields `not_before`, `not_after` and `revocation_effective_date` to represent the
  certificate validity period.
- feat(certificates): `keyfactor_certificate` Add `revoke_on_destroy` parameter to allow for renew/`destroy` operations without revoking the certificate. Defaults to `true`.

### Fixes
- fix(certificates): `keyfactor_certificate` resource CSR enrollment now correctly passes default `certificate_format` as `PEM` when not specified.
- fix(certificates): `keyfactor_certificate` will now use `not_after` for calculating expiry.

# v2.6.0

## Enrollment Patterns

### Features

- feat(enrollment_patterns): Add new data source `keyfactor_enrollment_pattern` to look up enrollment patterns by name
  or ID.

## Certificates

### Features

- feat(certificates): `keyfactor_certificate` Add support for `owner_role_name` which can be referenced by name or ID.
- feat(certificates): `keyfactor_certificate` Add support for `enrollment_pattern` which can be referenced by name or
  ID.
- feat(certificates): `keyfactor_certificate` Add support for `certificate_format`, supported formats are
  `[PEM, JKS, PFX, ZIP]`, and defaults to `PEM`.

# v2.5.1

### Certificates

#### Fixes

- fix(certificates): `keyfactor_certificate` resource CSR enrollment response not parsing certificates properly.
- fix(certificates): `keyfactor_certificate` resource CSR enrollment does not fail on empty `[]Diagnotic`
- fix(certificates): `keyfactor_certificate` resource CSR enrollment sets `IsExpired,IsRevoked,IsPendingRevocation`
  explicitly to `false`
- fix(certificates): `keyfactor_certificate` resource CSR enrollment sets subject fields to state values to prevent
  inconsistent state.
- fix(certificates): `keyfactor_certificate` resource CSR enrollment sets `renew_eligible` to known on update.
- fix(certificates): `keyfactor_certificate` resource updates use state values for immutable fields.
- fix(certificates): `keyfactor_certificate` resource `renewal_config` block correctly triggers based on `renew_days`
- fix(certificates): `keyfactor_certificate` resource PFX enrollments w/ `renewal_config` block now correctly sets
  `renew_eligible` to `false` on create.
- fix(certificates): `keyfactor_certificate` resource `renew_eligible` calculation correction.

#### Chores

- chore(certificates): Update documentation for `keyfactor_certificate` `renewal_config` verbiage to be more clear on
  how it works.

### Authentication

#### Fixes

- fix(deps): Bump `keyfactor-go-client-sdk` to `v24.0.2` to fix scopes not being set on OAuth requests.

# v2.5.0

### OAuth Security Roles

#### Features

* feat(oauth_security_roles): Add support to read and manage security roles in Keyfactor Command (v2 API compatibility)

### OAuth Security Claims

#### Features

* feat(oauth_security_claims): Add support to read and manage security claims in Keyfactor Command

### OAuth Security Role Claims Association

#### Features

* feat(oauth_security_role_claim_association): Add support to associate an OAuth security claim to an OAuth security
  role resource.

### Security Roles

#### Chores

* chore(roles): Update documentation for Security Roles to reference list of possible permission values.

# v2.4.0

### Certificates

#### Fixes

* fix(certificates): Fix `inconsistent state` error on updates by including expiry and renewal params.
* fix(certificates): Remove comma escaping logic for enrollment subject parameters.

### Certificate Deployments

#### Features

* feat(deployments): Add support `overwrite` flag. *NOTE*: As of Keyfactor Command v12.0 if `overwrite=true` then the
  API will check if the certificate alias exists before scheduling a job.
* feat(deployments): Add support for `redeploy` flag. Which will force a certificate to be `undeployed` and then
  `redeployed`.

### Roles

* chore(docs): Add deprecation notice to `keyfactor_role` resources to be replaced with `keyfactor_security_role`
  resource.
* chore(docs): Add deprecation notice to `keyfactor_identity` resource to be replaced with `keyfactor_security_claim`
  resource.

# v2.3.0

### Certificates

#### Features

* 74e58f7 feat(certificates): Add checks for `expired` and `expiring` certificates. The provider will now warn when a
  cert is going to expire within `30` days. *NOTE* In order for this check to happen a `plan` must be run.
* 74e58f7 feat(certificates): Add check for `revoked` certificates. The provider will warn if during a `plan` it
  discovers the certificate is revoked. *NOTE* In order for this check to work a user must have `Certificates - Read`
  permissions either at the global or collection level.
* 74e58f7 feat(certificates): Add `renewal_config` block that allows for specifying renewal behavior. *NOTE* for
  renewals to work on existing certificate resources an `apply` must be run to apply the configuration first and then a
  subsequent `plan` operation.

#### Fixes

* 74e58f7 fix(certificates): Use `collection_id` when invoking `/Certificates/{id}/Download`
* 74e58f7 fix(certificates): Escape certificate subject parameters that include `,`

# v2.2.0

### Provider

#### Features

* 3acc244 feat(provider): Add parameters for PFX auto password generation.
* 77ab278 feat(provider): Add parameter for custom Keyfactor Command API Path
* 77ab278 feat(provider): Add parameters for oauth to Keyfactor Command API
* 77ab278 feat(provider): Add parameter for customer CA cert to use when connecting to Keyfactor Command API
* 77ab278 feat(provider): Add parameter for skipping TLS verification when connecting to Keyfactor Command API

### Certificates

#### Features

* 4de79ae feat(certificates): Add `friendly name` as a configurable. Default behavior remains the same and will continue
  to pass `CN` as `friendly name`.

#### Fixes

* 4de79ae fix(certs): Resolve `inconsistent state` issues on `metadata` `update` operations, by including
  `collection_id`

# v2.1.11

### Certificates

#### Fixes

* c6621a5 fix(certificates): CSR enrollments set `certificate_pem` on create.
* c6621a5 fix(certificates): Fix JSON refs in request model for `certificate/download`.

# v2.1.10

### Certificates

#### Fixes

* 128827b fix(certificates):  CSR enrollments now correctly handle `collection_id`.

# v2.1.9

### Certificates

#### Fixes

* fa3aaab fix(certificates): Remove template lookup API call as it's not needed for V2 PFX enrollments.

# v2.1.8

### Certificates

#### Fixes

* 027e500 fix(certificate): Allow for recovery using `collection_id`.
* 47a026d fix(certificate): Allow for blind wait on certificate requests that require approval.

# v2.1.7

### Certificates

#### Fixes

* 4202a3a fix(certificates): `keyfactor_certificate` resources now allow for passing of `collection_id` to the `enroll`
  method.

# v2.1.6

### Client

#### Features

* 9808312 feat(client): `keyfactor_client` now allows for global `request_timeout` to be set. Default is 30 seconds.

#### Fixes

* 9808312 fix(client): `keyfactor_client` now retries any 'Context Deadline Exceeded' errors.

### Certificates

#### Fixes

* 4d01ddd fix(certificates): `keyfactor_certificate` resources now handle enrollments requests that require approvals.
  #90

### Deployments

#### Fixes

* d7c3b46 fix(deployments): `keyfactor_certificate_deployment` resources now handles deployments that require entry
  parameters. #91

# v2.1.5

### Certificate Stores

#### Fixes

* 47f4d9c fix(stores): `keyfactor_certificate_store` resources allow for empty and null 'properties'.
* 47f4d9c fix(stores): `keyfactor_certificate_store` resources allow for 'ServerUsername', 'ServerPassword' and '
  ServerUseSsl', special properties to also be defined in the 'properties' field for legacy provider support. The
  explicit fields 'server_username', 'server_password' and 'server_use_ssl' will take precedence.

# v2.1.4

### Certificates

#### Fixes

* b0d1a49 fix(certificates): `keyfactor_certificate` data and resource types will not store auto password used to
  recover private key. `auto_password` has been removed from schema and state.
* b0d1a49 fix(certificates): `keyfactor_certificate` resource type will no longer trigger replacement if `key_password`
  is changed. #74 #79 #80
* b0d1a49 fix(certificates): When looking up a certificate by CN, `IncludeHasPrivateKey` is now included in the call to
  the Command API.
* b0d1a49 fix(certificates): `keyfactor_certificate` resource updates `ca_cert` use correct field.
* b0d1a49 fix(certificates): `keyfactor_certificate` resource updates `key_password` will now use plan value.
* b0d1a49 fix(certificates): `keyfactor_certificate` resource updates `certificate_id` field now included using state
  value.
* b0d1a49 fix(certificates): When sorting SAN lists, if length varies don't even try to sort as there is obviously a
  change and replacement must be triggered.

# v2.1.3

### Certificates

#### Fixes

* bb5498d fix(certificates): Sort SANs in the same order as state when they come back from the Command API. #66

# v2.1.2

### Certificates

#### Fixes

* e0f6c7c fix(certificates): Sort SANs when they come back from the Command API. #66

# v2.1.1

### Certificates

#### Fixes

* 0f5d1fe fix(certificates): `key_password` now takes correct precedence #72 #75
* 594677d fix(certificates): Treat deleted certs as needing replacement. #73

# v2.1.0

### Certificates

#### Fixes

* c619ce4 fix(certificates): Handle template shortname != template display name #67
* 5c2280f fix(certificates): Empty and null SAN lists #66
* e9b0de7 fix(certificates): `keyfactor_certificate` data sources now allow for null and empty password. If cert has
  private key but no password is provided no private key will be returned. #65

#### Features

* f5eabee feat(certificates): Certificate enrollments now will create a password automatically for PFX enrollments and
  populate that password in the `auto_password` field. If a `key_password` is provided `auto_password` will be set to
  the
  same value. ( #68 )

# v2.0.0

### Breaking Changes

#### Certificates

* `keyfactor_certificate` resources data structure flattened, subject attributes are now part of main object.
* `keyfactor_certificate` data and resource types `certificate_chain` now returns a full chain, including the leaf
  certificate.

#### Certificate Stores

* `keyfactor_certificate_store` resource definitions can now look up agent via GUID or `ClientMachine` via new
  attribute `agent_identifier`.
* `keyfactor_certificate_store` data sources can no longer be looked up by GUID. Instead, a combination
  of `ClientMachine` and `StorePath` will be used.
* `keyfactor_certificate_store` resource `properties` now supports special properties `ServerUseSsl`, `ServerUsername`
  and `ServerPassword`.
* `keyfactor_certificate_store` resource `store_password` can now be set to a non-empty value.

### Agents

#### Features

* feat(agents): Agent data source implemented for Keyfactor Command 10.x.

### Certificates

### Features

* 11c8209 feat(certificate): Certificate lookups can now be done using `cn`, `thumbprint` or `id`. BREAKING CHANGE:
  certificate model has been flattened, subject attributes are now part of main object.
* d69ce77 feat(certificates): `ca_certificate` attribute added to both data and resource types. #45

#### Fixes

* 140ea4e fix(certificate): `CertificateId` field added to track the Keyfactor Command certificate integer ID.
* a884694 fix(certificate): `keyfactor_certificate` metadata is correctly added on cert creation
* a884694 fix(certificate): `keyfactor_certificate` CustomFriendlyName set to CN fix(
  certificate): `keyfactor_certificate` Command returns IssuerDN on POST a string with spaces, on GET returns a string
  w/o spaces. READ will now add spaces to prevent inconsistent state.
* a884694 fix(certificate): `keyfactor_certificate` Optional string and int params now evaluate to null correctly on
  READ and UPDATE.
* a884694 fix(certificate): `keyfactor_certificate` IMPORT downloads cert and chain in correct order now.

### Certificate Stores

#### Features

* c553510 feat(stores): Store data sources can now be looked up by ClientMachine and StorePath combination as opposed to
  GUID.
* 3bef18b feat(stores): Store model now has explicit attributes for Command "special"
  fields: `ServerUsername`, `ServerPassword`, `StorePassword` and `ServerUseSsl` and will no longer be presented in
  the `Properties` attribute map on either data or resource definitions.
* 6b1df0a feat(stores): Allow agent to be specified via ClientMachine name or GUID.

#### Fixes

* c553510 fix(stores): Store data sources now parse and populate properties correctly.
* 4b6b89d fix(stores): Empty container name now evaluates to null properly on read.
* e62cd38 fix(stores): Set `StorePassword` to `No Value` when `password` field is not provided.
* 46f5f01 fix(stores)!: Updating a cert store is now compatible w/ Command 10.x. #49, #48
* 6b1df0a fix(stores): The following fields are now computed on resource
  definitions: `agent_id`, `container_id`, `agent_assigned`, `set_new_password_allowed` BREAKING CHANGE: Store resource
  definitions `agent_id` is not a computed value and is replaced by `agent_identifier` to allow for lookup of agent via
  GUID or ClientMachine name.
* 6b1df0a fix(stores): Data source added `DisplayName`

### Deployments

#### Fixes

* 140ea4e fix(deployments): Deployments now do not artificially time out, and will wait indefinitely to verify a
  certificate has been deployed.
* 140ea4e fix(deployments): Destroy now waits and verifies if a certificate has been undeployed.
* 140ea4e fix(deployments): Create now checks that both alias and cert ID are deployed as opposed to just checking
  alias.

### Provider

#### Fixes

* bd331bf fix(provider): Adding retry logic when connecting to Keyfactor Command to prevent "first connection" timeout
  error.

# v1.0.3

### Templates

#### Fixes

* fix(templates): resource `keyfactor_template_binding` ID is not updated during update.
* fix(templates): resource `keyfactor_template_binding` unbinding of roles to templates diff logic flaw.

# v1.0.0

* Initial release of the Keyfactor Terraform Provider
