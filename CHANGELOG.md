# v2.1.9

### Certificates

#### Fixes
- 4129515 fix(certificates): Remove template lookup API call as it's not needed for V2 PFX enrollments.

# v2.1.8

### Certificates

#### Fixes
- 027e500 fix(certificate): Allow for recovery using `collection_id`.
- 47a026d fix(certificate): Allow for blind wait on certificate requests that require approval. 


# v2.1.7

### Certificates

#### Fixes
- 4202a3a fix(certificates): `keyfactor_certificate` resources now allow for passing of `collection_id` to the `enroll` 
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

- f5eabee feat(certificates): Certificate enrollments now will create a password automatically for PFX enrollments and
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
- 

# v1.0.0

- Initial release of the Keyfactor Terraform Provider