# keyfactor_certificate_authority Resource

Manages a Keyfactor Command Certificate Authority (CA).

Secret fields (`explicit_password`, `auth_certificate`, `auth_certificate_password`, `client_secret`) are write-only — the server never returns plaintext values, so provider reads preserve configured values from state.

## Example Usage

### Third-party CA (EJBCA)

```hcl
resource "keyfactor_certificate_authority" "ejbca" {
  logical_name         = "My-EJBCA-CA"
  host_name            = "http://ejbca.example.com:8082/ejbca"
  ca_type              = 1
  forest_root          = "ejbca"
  configuration_tenant = "ejbca"

  allowed_enrollment_types = 3
  key_retention            = 1

  use_allowed_requesters = true
  allowed_requesters     = ["InstanceOwner"]

  allow_one_click_renewals          = true
  new_end_entity_on_renew_and_reissue = true

  full_scan_interval_minutes        = 60
  incremental_scan_interval_minutes = 10

  # OAuth credentials for EJBCA
  token_url     = "https://auth.example.com/oauth2/token"
  client_id     = "my-client-id"
  client_secret = "my-client-secret"
}
```

## Argument Reference

### Required

* `logical_name` - (String) Logical name for the certificate authority.
* `host_name` - (String) Hostname or URL of the certificate authority server.
* `ca_type` - (Number) CA type: `0` = Microsoft CA, `1` = third-party (e.g. EJBCA). Changing this forces a new resource.

### Optional

#### Delegation & Connectivity

* `delegate` - (Boolean) Whether the CA is delegated.
* `delegate_enrollment` - (Boolean) Whether enrollment is delegated.
* `forest_root` - (String) Forest root for the CA.
* `configuration_tenant` - (String) Configuration tenant for the CA.
* `remote` - (Boolean) Whether the CA is remote.
* `agent` - (String) Agent identifier (GUID).
* `standalone` - (Boolean) Whether the CA is standalone.
* `use_ca_connector` - (Boolean) Whether to use the CA connector.
* `connector_pool` - (String) Connector pool name.

#### Monitoring & Thresholds

* `monitor_thresholds` - (Boolean) Whether to monitor thresholds.
* `issuance_max` - (Number) Maximum issuance threshold.
* `issuance_min` - (Number) Minimum issuance threshold.
* `failure_max` - (Number) Maximum failure threshold.

#### Enrollment & Policy

* `rfc_enforcement` - (Boolean) Whether to enforce RFC compliance.
* `properties` - (String) JSON string of CA properties.
* `allowed_enrollment_types` - (Number) Bitmask: `0`=none, `1`=PFX, `2`=CSR, `3`=both.
* `key_retention` - (Number) Key retention policy: `0`=None, `1`=SettingDriven, `2`=Always, `3`=Never.
* `key_retention_days` - (Number) Days to retain keys.
* `enforce_unique_dn` - (Boolean) Enforce unique distinguished names.
* `subscriber_terms` - (Boolean) Whether subscriber terms are enabled.
* `allow_one_click_renewals` - (Boolean) Allow one-click renewals.
* `new_end_entity_on_renew_and_reissue` - (Boolean) Create new end entity on renew/reissue (EJBCA).

#### Requesters

* `use_allowed_requesters` - (Boolean) Restrict enrollment to specific requesters.
* `allowed_requesters` - (List of String) Allowed requester identities.

#### Explicit Credentials

* `explicit_credentials` - (Boolean) Whether explicit credentials are configured.
* `explicit_user` - (String) Username for explicit credentials.
* `explicit_password` - (String, Sensitive) Password. Write-only.

#### Auth Certificate

* `auth_certificate` - (String, Sensitive) Base64-encoded PFX data. Write-only.
* `auth_certificate_password` - (String, Sensitive) PFX password. Write-only.

#### OAuth Config

* `token_url` - (String) OAuth token URL.
* `client_id` - (String) OAuth client ID.
* `client_secret` - (String, Sensitive) OAuth client secret. Write-only.
* `scope` - (String) OAuth scope.
* `audience` - (String) OAuth audience.

#### Schedules

* `full_scan_interval_minutes` - (Number) Full scan interval in minutes.
* `incremental_scan_interval_minutes` - (Number) Incremental scan interval in minutes.
* `threshold_check_interval_minutes` - (Number) Threshold check interval in minutes.

### Read-Only

* `id` - (String) Integer ID of the certificate authority.
* `agent_name` - (String) Agent name.
* `agent_username` - (String) Agent username.
* `denial_max` - (Number) Maximum denial count.
* `last_scan` - (String) Timestamp of the last scan.
* `auth_certificate_issued_dn` - (String) Auth certificate issued DN.
* `auth_certificate_issuer_dn` - (String) Auth certificate issuer DN.
* `auth_certificate_thumbprint` - (String) Auth certificate thumbprint.

## Import

Certificate authorities can be imported using their integer ID:

```shell
terraform import keyfactor_certificate_authority.example 1
```

**Note:** Write-only secret fields (`explicit_password`, `auth_certificate`, `auth_certificate_password`, `client_secret`) cannot be recovered on import and must be re-specified in configuration.
