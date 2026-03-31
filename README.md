# Keyfactor Terraform Provider

## Integration status: Production - Ready for use in production environments.

## Overview

The Terraform provider for Keyfactor Command enables management of Keyfactor Command resources with HashiCorp Terraform.
Below are currently supported resources:

| Command Resource                      | Keyfactor Command Doc                                                                                                                   | Terraform Resource                                                                                                                                                             |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Certificate                           | [Certificate](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/Certificates.htm)                          | [keyfactor_certificate](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate)                                                     |
| Certificate Store                     | [Certificate Store](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/CertificateStores.htm)               | [keyfactor_certificate_store](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_store)                                         |
| Orchestration Job                     | [Orchestration Job](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/OrchestratorJobsPOSTCustom.htm)      | [keyfactor_certificate_deployment](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_deployment)                               |
| OAuth Security Role                   | [OAuth Security Role](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityRolesandIdentities.htm)    | [keyfactor_oauth_security_role](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/oauth_security_role)                                     |
| OAuth Security Claim                  | [OAuth Security Claims](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityClaims.htm)              | [keyfactor_oauth_security_claim](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/oauth_security_claim)                                   |
| OAuth Security Role Claim Association | [OAuth Security Claim Roles](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityClaimsGETRoles.htm) | [keyfactor_oauth_security_role_claim_association](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/oauth_security_role_claim_association) |
| Security Roles (deprecated)           | [Security Roles](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityRolesandIdentities.htm)         | [keyfactor_role](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/role)                                                                   |

## Support

In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. Keyfactor Community
software is open-source and community-supported, meaning that **no SLA** is applicable. Keyfactor will address issues as
resources become available.

* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and
  create a [Pull request](../../pulls).

## Authentication

The provider supports three authentication methods. Kerberos is evaluated first when any Kerberos field is set, then Basic, then OAuth.

### Basic Auth

```terraform
provider "keyfactor" {
  hostname = "mykfinstance.kfdelivery.com"
  username = "COMMAND\\svc_terraform"
  password = "your_password"
  domain   = "COMMAND"
}
```

Environment variables: `KEYFACTOR_HOSTNAME`, `KEYFACTOR_USERNAME`, `KEYFACTOR_PASSWORD`, `KEYFACTOR_DOMAIN`

### OAuth

```terraform
provider "keyfactor" {
  hostname      = "mykfinstance.kfdelivery.com"
  client_id     = "my_client_id"
  client_secret = "my_client_secret"
  token_url     = "https://idp.example.com/realms/Keyfactor/protocol/openid-connect/token"
  scopes        = "enroll,agents,cert:admin"
}
```

Environment variables: `KEYFACTOR_AUTH_CLIENT_ID`, `KEYFACTOR_AUTH_CLIENT_SECRET`, `KEYFACTOR_AUTH_TOKEN_URL`, `KEYFACTOR_AUTH_SCOPES`

### Kerberos / SPNEGO

Three sub-modes are supported — the provider selects automatically based on which fields are set:

| Sub-mode | Required fields |
|----------|----------------|
| Password | `kerberos_realm` + `kerberos_username` + `kerberos_password` |
| Keytab   | `kerberos_realm` + `kerberos_username` + `kerberos_keytab` |
| CCache   | `kerberos_ccache` |

```terraform
# Password-based
provider "keyfactor" {
  hostname          = "mykfinstance.kfdelivery.com"
  kerberos_realm    = "EXAMPLE.COM"
  kerberos_username = "svc_terraform"
  kerberos_password = "your_kerberos_password"
  # kerberos_disable_pafxfast = true  # required for some Active Directory environments
}

# Keytab-based
provider "keyfactor" {
  hostname          = "mykfinstance.kfdelivery.com"
  kerberos_realm    = "EXAMPLE.COM"
  kerberos_username = "svc_terraform"
  kerberos_keytab   = "/etc/keyfactor/svc_terraform.keytab"
}

# CCache (after running kinit)
provider "keyfactor" {
  hostname        = "mykfinstance.kfdelivery.com"
  kerberos_ccache = "/tmp/krb5cc_1000"
}
```

Environment variables: `KEYFACTOR_AUTH_KRB_REALM`, `KEYFACTOR_AUTH_KRB_USERNAME`, `KEYFACTOR_AUTH_KRB_PASSWORD`, `KEYFACTOR_AUTH_KRB_KEYTAB`, `KEYFACTOR_AUTH_KRB_CCACHE`, `KEYFACTOR_AUTH_KRB_CONFIG`, `KEYFACTOR_AUTH_KRB_SPN`, `KEYFACTOR_AUTH_KRB_DISABLE_PAFXFAST`

## Usage

* [Documentation](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs)
* Examples
    * [Certificate Resource](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate)
    * [Certificate Deployment](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_deployment)
    * [Certificate Store Resource](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_store)
* [Contributing](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/CONTRIBUTING.md)
* [License](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/LICENSE)

## Compatibility

| Keyfactor Command Version | Terraform Provider Version |
|---------------------------|----------------------------|
| 25.x                      | 2.5.x                      |
| 24.x                      | 2.5.x                      |
| 12.x                      | 2.2.x                      |
| 11.x                      | 2.2.x                      |
| 10.x                      | 2.0.x                      |
| 9.x                       | 1.0.x                      |

## Requirements

* [Go](https://golang.org/doc/install) 1.23.x (to build the provider plugin)
* [Terraform](https://www.terraform.io/downloads) 1.1.x
* [Keyfactor Command](https://www.keyfactor.com/) (See compatability table)
    * Keyfactor Command account with permissions to required Keyfactor features

## Install

### From terraform registry

For full details on how to use this provider from the public Terraform
registry: https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs  
Make this file: `providers.tf`

```terraform
terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">=2.2.0"
    }
  }
}

provider "keyfactor" {
  # Configuration options
}
```

Then run

```bash
terraform init
```

### From GitHub

Download a pre-built release and install it into Terraform's local filesystem mirror.

1. Download the release archive for your platform from the [releases page](https://github.com/Keyfactor/terraform-provider-keyfactor/releases).
2. Unzip the archive.
3. Move the binary to Terraform's implicit local mirror directory. The path must match the pattern:

**Linux / macOS**
```
~/.terraform.d/plugins/registry.terraform.io/keyfactor-pub/keyfactor/<VERSION>/<OS>_<ARCH>/terraform-provider-keyfactor_v<VERSION>
```

Example for Linux amd64, version 2.8.0:
```bash
PROVIDER_VERSION="2.8.0"
OS_ARCH="linux_amd64"                  # or darwin_amd64 / darwin_arm64
PLUGIN_DIR="${HOME}/.terraform.d/plugins/registry.terraform.io/keyfactor-pub/keyfactor/${PROVIDER_VERSION}/${OS_ARCH}"
mkdir -p "${PLUGIN_DIR}"
mv terraform-provider-keyfactor_v${PROVIDER_VERSION} "${PLUGIN_DIR}/"
chmod +x "${PLUGIN_DIR}/terraform-provider-keyfactor_v${PROVIDER_VERSION}"
```

**Windows (PowerShell)**
```powershell
$ProviderVersion = "2.8.0"
$OSArch = "windows_amd64"              # or windows_arm64
$PluginDir = "$env:APPDATA\terraform.d\plugins\registry.terraform.io\keyfactor-pub\keyfactor\$ProviderVersion\$OSArch"
New-Item -ItemType Directory -Force -Path $PluginDir
Move-Item terraform-provider-keyfactor.exe "$PluginDir\"
```

4. Use the standard registry source in your `versions.tf` — `terraform init` will find the local binary automatically:

```terraform
terraform {
  required_version = ">= 1.3"
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "2.8.0"
    }
  }
}
```

For more details on Terraform's implicit local mirror directories see the
[Terraform CLI configuration documentation](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories).

### From Source

#### Linux / macOS

```bash
git clone https://github.com/Keyfactor/terraform-provider-keyfactor.git
cd terraform-provider-keyfactor
PROVIDER_VERSION="2.8.0"
OS_ARCH="$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/')"
PLUGIN_DIR="${HOME}/.terraform.d/plugins/registry.terraform.io/keyfactor-pub/keyfactor/${PROVIDER_VERSION}/${OS_ARCH}"
mkdir -p "${PLUGIN_DIR}"
go build -o "${PLUGIN_DIR}/terraform-provider-keyfactor_v${PROVIDER_VERSION}"
echo "Installed to ${PLUGIN_DIR}"
```

#### Windows (PowerShell)

```powershell
git clone https://github.com/Keyfactor/terraform-provider-keyfactor.git
Set-Location terraform-provider-keyfactor

$ProviderVersion = "2.8.0"
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$PluginDir = "$env:APPDATA\terraform.d\plugins\registry.terraform.io\keyfactor-pub\keyfactor\$ProviderVersion\windows_$Arch"
New-Item -ItemType Directory -Force -Path $PluginDir

go build -o "$PluginDir\terraform-provider-keyfactor.exe"
Write-Host "Installed to $PluginDir"
```

Use the standard registry source in your `versions.tf`:

```terraform
terraform {
  required_version = ">= 1.3"
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "2.8.0"
    }
  }
}
```

### Development Overrides

Development overrides let you test a locally-built provider binary without publishing a release or managing versioned
plugin directories. Terraform loads the binary directly from a directory you specify — no `terraform init` is required
(and `init` will print a warning that dev overrides are active, which is expected).

#### Setup

1. Build and install the provider binary to your Go bin directory:

```bash
go install .
# Installs to ~/go/bin/terraform-provider-keyfactor (Linux/macOS)
# or %GOPATH%\bin\terraform-provider-keyfactor.exe (Windows, same name without version)
```

2. Add a `dev_overrides` block to your `~/.terraformrc` (Linux/macOS) or `%APPDATA%\terraform.rc` (Windows):

```hcl
provider_installation {
  dev_overrides {
    # Replace the path with the directory containing your provider binary.
    # On Linux/macOS this is typically ~/go/bin after running `go install .`
    "keyfactor-pub/keyfactor" = "/home/youruser/go/bin"
  }

  # Fall through to the public registry for all other providers.
  direct {}
}
```

3. Use the standard registry source in your `versions.tf` — no version constraint is needed:

```terraform
terraform {
  required_providers {
    keyfactor = {
      source = "keyfactor-pub/keyfactor"
    }
  }
}
```

4. Run `terraform plan` or `terraform apply` directly. Terraform will use your local binary and print:

```
╷
│ Warning: Provider development overrides are in effect
│
│   - keyfactor-pub/keyfactor in /home/youruser/go/bin
│
│ The behavior may therefore not match any released version of the provider and
│ applying changes may cause the state to become incompatible with published
│ releases.
╵
```

This warning is expected and can be ignored during local development.

#### Per-directory override (without modifying ~/.terraformrc)

To activate dev overrides only for a specific working directory, point `TF_CLI_CONFIG_FILE` at a local
`.terraformrc` file:

```bash
# .terraformrc (in your project directory)
cat > .terraformrc <<'EOF'
provider_installation {
  dev_overrides {
    "keyfactor-pub/keyfactor" = "/home/youruser/go/bin"
  }
  direct {}
}
EOF

TF_CLI_CONFIG_FILE=.terraformrc terraform plan
```

## Keyfactor Command Permissions

### Recommended

Below are minimal required Keyfactor Command global permissions to use the full functionality of this Terraform
provider:

- All > Agents > Management > Read
- All > Certificate Authorities > Read
- All > Certificate Stores >
    - Modify
    - Read
    - Schedule
- All > Certificate Templates > Read
- All > Certificates > Enroll >
    - Csr
    - Pfx
- All > Certificates > Collections >
    - Read
    - Revoke
    - Private Key Read
    - Private Key Import

![full_min_global_permissions.png](docs/screenshots/full_min_global_permissions.png)

### Resources:

Below are required Keyfactor Command permissions to use each supported Terraform resource type.

#### resource "keyfactor_certificate"

Below are minimal permissions to be able to use a Terraform `resource "keyfactor_certificate"`.

##### Global Permissions

Below are minimal global permissions for a Keyfactor Command account to issue a certificate.

- All > Certificate Templates > Read
- All > Certificates > Enroll >
    - Csr
    - Pfx
- All > Certificates > Collections >
    - Read
    - Revoke
    - Private Key Read
    - Private Key Import

![enrollments_only.png](docs/screenshots/resource_keyfactor_certificate_global_scoped_permissions.png)

##### Collection Permissions

Below are minimal permissions for a Keyfactor Command account scoped by collection. For more information on collection
permissions please review
the [product docs](https://software.keyfactor.com/Core-Hosted/v12.5/Content/ReferenceGuide/CertificatePermissions.htm?Highlight=collection%20permissions)

###### Global Permissions

- All > Certificate Templates > Read
- All > Certificates > Enroll >
    - Csr
    - Pfx

![enrollments_only_collection_scoped_global_permissions.png](docs/screenshots/resource_keyfactor_certificate_collection_scoped_global_permissions.png)

###### Collection Permissions

- Read
- Edit Metadata
- Revoke
- Download with Private Key

![enrollments_only_collection_scoped_collection_permissions.png](docs/screenshots/resource_keyfactor_certificate_collection_scoped_collection_permissions.png)

#### resource "keyfactor_certificate_store"

- All > Agents > Management > Read
- All > Certificate Stores >
    - Read
    - Schedule
    - Modify

![stores_min_global_permissions.png](docs/screenshots/resource_keyfactor_certificate_store_min_global_permissions.png)

#### resource "keyfactor_certificate_deployment"

##### Global

- All > Agents > Management > Read
- All > Certificate Stores >
    - Read
    - Schedule

![deployment_min_global_permissions.png](docs/screenshots/resource_keyfactor_certificate_deployment_min_global_permissions.png)

### Data Sources

Below are required Keyfactor Command permissions to use each supported Terraform data source type.

#### data "keyfactor_agent"

- All > Agents > Management > Read

![data_keyfactor_agent_global_permissions.png](docs/screenshots/data_keyfactor_agent_global_permissions.png)

#### data "keyfactor_certificate"

Below are minimal permissions to be able to use a Terraform `data "keyfactor_certificate"`.

##### Global Permissions

Below are minimal global permissions for a Keyfactor Command account to read a certificate.

- All > Certificate Templates > Read
- All > Certificates > Collections >
    - Read
    - Private Key Read

![data_keyfactor_certificate_global_scoped_permissions.png](docs/screenshots/data_keyfactor_certificate_global_scoped_permissions.png)

##### Collection Permissions

Below are minimal permissions for a Keyfactor Command account scoped by collection. For more information on collection
permissions please review
the [product docs](https://software.keyfactor.com/Core-Hosted/v12.5/Content/ReferenceGuide/CertificatePermissions.htm?Highlight=collection%20permissions)

###### Global Permissions

- All > Certificate Templates > Read

![data_keyfactor_certificate_template_global_permissions.png](docs/screenshots/data_keyfactor_certificate_template_global_permissions.png)

###### Collection Permissions

- Read
- Download with Private Key

![data_keyfactor_certificate_collection_scoped_global_permissions.png](docs/screenshots/data_keyfactor_certificate_collection_scoped_global_permissions.png)

#### data "keyfactor_certificate_store"

- All > Agents > Management > Read
- All > Certificate Stores >
    - Read

![data_keyfactor_ceritificate_store_global_permissions.png](docs/screenshots/data_keyfactor_certificate_store_global_permissions.png)

#### data "keyfactor_certificate_template"

- All > Certificate Templates > Read

![data_keyfactor_certificate_template_global_permissions.png](docs/screenshots/data_keyfactor_certificate_template_global_permissions.png)

## Contributing

The Keyfactor Terraform Provider is an open source project. To contribute, see
the [contribution guidelines](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/CONTRIBUTING.md).

[Issues](https://github.com/Keyfactor/terraform-provider-keyfactor/issues/new/choose) may also be reported.

## License

For license information, see [LICENSE](LICENSE). 
