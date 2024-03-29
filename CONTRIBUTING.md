# Developing the Keyfactor Provider for Terraform
Thank you for your interest in contributing to the Keyfactor provider. We welcome your contributions. Here you'll 
find information to help you get started with provider development. The best place to get
started with the development of Terraform providers is the [Terraform Plugin Documentation](https://www.terraform.io/plugin).

## Building the Keyfactor Provider
1. Clone the repository
    ```shell
   $ mkdir -p $GOPATH/src/github.com/Keyfactor; cd $GOPATH/src/github.com/Keyfactor
   $ git clone git@github.com:Keyfactor/terraform-provider-keyfactor.git
   ```
2. Enter the directory and build the provider
    ```shell
    $ cd $GOPATH/src/github.com/Keyfactor/terraform-provider-keyfactor
    $ make build
    ```

## Contributing to the provider
### Development Environment
Before working with the provider, [Go](http://www.golang.org) version 1.9+ is required. Ensure that a 
[GOPATH](http://golang.org/doc/code.html#GOPATH) is configured and that `$GOPATH/bin` is added to your `$PATH`. To
compile the provider, run `make build`, which will build the provider and place the binary in `$GOPATH/bin`.

The provider is configured to support debugging with a supported IDE or debugger. To enable this support, the binary
can either be run with the `-debug` flag, or a supported [GoLang IDE can be configured](https://opencredo.com/blogs/running-a-terraform-provider-with-a-debugger/).

### Running Acceptance Tests
The Terraform Acceptance tests can be run using
```bash
$ make testacc
```
or
```bash
$ go test github.com/Keyfactor/terraform-provider-keyfactor/keyfactor
```
Note that the following environment variables must exist regardless of the test case:
* ```KEYFACTOR_USERNAME```
* ```KEYFACTOR_PASSWORD```
* ```KEYFACTOR_HOSTNAME```
* ```KEYFACTOR_DOMAIN```

#### Certificate data source acceptance tests
* ```KEYFACTOR_CERTIFICATE_ID``` - Note: the certificate ID must exist in Keyfactor.
* ```KEYFACTOR_CERTIFICATE_PASSWORD``` - Should be an actions secret, and be valid for the referenced cert.

#### Certificate resource acceptance tests
* ```KEYFACTOR_CERTIFICATE_TEMPLATE_NAME``` - Note: the template must exist in Keyfactor, allow both CSR and PFX 
enrollments and the executing user should have permissions to enroll with the template.
* ```KEYFACTOR_CERTIFICATE_CA_DOMAIN```
* ```KEYFACTOR_CERTIFICATE_CA_NAME``` - Note: the CA must exist in Keyfactor and have the template specified in `KEYFACTOR_CERTIFICATE_TEMPLATE_NAME`.
* ```KEYFACTOR_CERTIFICATE_PASSWORD``` - Should be an actions secret, and be valid for the referenced cert.

#### Deploy Certificate acceptance tests
The following environment variables must exist to run acceptance tests for the Deploy Certificate resource:
* ```KEYFACTOR_DEPLOY_CERT_STOREID1``` - Note: the certificate store must exist in Keyfactor.
* ```KEYFACTOR_DEPLOY_CERT_STOREID2``` - Note: the certificate store must exist in Keyfactor.

#### Certificate Store data source acceptance tests
* ```KEYFACTOR_CERTIFICATE_STORE_ID``` - Note that the store must exist in Keyfactor.

#### Certificate Store resource acceptance tests
The following environment variables must exist to run acceptance tests for Certificate Store resources:
* ```KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE``` - Note: the client must exist in Keyfactor.
* ```KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID``` - Note: the orchestrator agent must exist in Keyfactor.
* ```KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1``` - Note: the container must exist in Keyfactor and be compatible with the store type.
* ```KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID2``` - Note: the container must exist in Keyfactor and be compatible with the store type.
* ```KEYFACTOR_CERTIFICATE_STORE_PASS``` - Should be an actions secret.

#### Security Role resource acceptance tests
The following environment variable must exist to run acceptance tests for Security Role resources:
* ```KEYFACTOR_SECURITY_ROLE_NAME``` - Note: the role must *NOT* exist in Keyfactor.

#### Security Identity resource acceptance tests
The following environment variable must exist to run acceptance tests for Security Identity resources:
* ```KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME``` - Note: the account *must exist in AD*, but *NOT* in Keyfactor.

#### Certificate Template Role Binding resource acceptance tests
The following environment variables must exist to run acceptance tests for the binding of roles to certificate templates.
It's advised that the templates specified by these environment variables are not often used, as Terraform will add 
allowed requesters as Keyfactor roles.
* ```KEYFACTOR_TEMPLATE_ROLE_BINDING_ROLE_NAME``` - Note: the role must exist in Keyfactor.
* ```KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1``` - Note: the template must exist in Keyfactor.
* ```KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME2``` - Note: the template must exist in Keyfactor.
* ```KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME3``` - Note: the template must exist in Keyfactor.

### Referencing private go repos in import() statement
* The best way to clone private repositories in the import statement is to use SSH. Create an SSH key, import the private
  key to the ~./git directory, and run the following commands
    ```bash
    git config --global url.ssh://git@github.com/.insteadOf https://github.com/
    ```

* Then, export a GOPRIVATE environment variable for the organization or repository.
    ```bash
    go env -w GOPRIVATE=github.com/<organization>
    GIT_TERMINAL_PROMPT=1
    ```

* For example:
    ```bash
    go env -w GOPRIVATE=github.com/Keyfactor
    ```

* Note: The SSH key created above must be authorized for SSO to the Keyfactor Github organization