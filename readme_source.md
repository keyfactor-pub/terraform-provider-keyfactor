## Usage
* [Documentation](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/docs/index.md)
* [Examples](https://github.com/Keyfactor/terraform-provider-keyfactor/tree/main/examples)
* [Contributing](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/CONTRIBUTING.md)
* [License](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/LICENSE)

## Compatibility
| Keyfactor Command Version | Terraform Provider Version |
|---------------------------|----------------------------|
| 10.x                      | 2.0.x                      |
| 9.x                       | 1.0.x                      |

## Requirements
* [Go](https://golang.org/doc/install) 1.18.x (to build the provider plugin)
* [Terraform](https://www.terraform.io/downloads) 1.1.x
* [Keyfactor Command](https://www.keyfactor.com/) v10.x
    * Keyfactor Command account with permissions to required Keyfactor features (IE certificate)

## Local install

### From GitHub
- Download the latest release from the [releases page](https://github.com/Keyfactor/terraform-provider-keyfactor/releases)
- Unzip the release
- Move the binary to a location in your local Terraform plugins directory (typically `$HOME/.terraform.d/plugins` or `%APPDATA%\terraform.d\plugins` on Windows)
  for more information refer to the [Hashicorp documentation](https://www.terraform.io/docs/cli/config/config-file.html#implied-local-mirror-directories)
- Run `terraform init` to initialize the provider

## From Source

### Mac OS/Linux
```bash
git clone https://github.com/Keyfactor/terraform-provider-keyfactor.git
cd terraform-provider-keyfactor
make install
```

### Windows
```powershell
git clone https://github.com/Keyfactor/terraform-provider-keyfactor.git
cd terraform-provider-keyfactor
go build -o %APPDATA%\terraform.d\plugins\keyfactor.com\keyfactor\keyfactor\1.0.3\terraform-provider-keyfactor.exe
```


## Contributing
The Keyfactor Terraform Provider is an open source project. To contribute, see the [contribution guidelines](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/CONTRIBUTING.md).
[Issues](https://github.com/Keyfactor/terraform-provider-keyfactor/issues/new/choose) may also be reported.
