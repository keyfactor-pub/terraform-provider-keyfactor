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

#### Certificate resource acceptance tests
To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_CERTIFICATE_TESTS=True```.

#### Deploy Certificate acceptance tests
The following environment variables must exist to run acceptance tests for the Deploy Certificate resource:
* ```KEYFACTOR_DEPLOY_CERT_STOREID1```
* ```KEYFACTOR_DEPLOY_CERT_STOREID2```

To skip acceptance tests for the Deploy Certificate resource, export ```KEYFACTOR_SKIP_DEPLOY_CERT_TESTS=True```.


#### Store resource acceptance tests
The following environment variables must exist to run acceptance tests for the Store resource:
* ```KEYFACTOR_CLIENT_MACHINE```
* ```KEYFACTOR_ORCHESTRATOR_AGENT_ID```

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_STORE_TESTS=True```.

#### Security Role resource acceptance tests
The following environment variable must exist to run acceptance tests for the Security Role resource:
* ```KEYFACTOR_SECURITY_ROLE_IDENTITY_ACCOUNTNAME``` - This account _must already exist_ in Keyfactor. Terraform acceptance
  tests create a Keyfactor security roles and attach them to the security identity configured by this environment variable.

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_ROLE_TESTS=True```.

#### Security Identity resource acceptance tests
The following environment variable must exist to run acceptance tests for the Security Identity resource:
* ```KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME``` - Note that this account must exist in AD, but not in Keyfactor.

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_IDENTITY_TESTS=True```.

#### Attach Security Role resource acceptance tests
The following environment variables must exist to run acceptance tests for the Attach Security Role resource:
* ```KEYFACTOR_ATTACH_ROLE_TEMPLATE1``` - It's advised that the templates specified by these environment variables are not
  often used, as Terraform will add allowed requesters as Keyfactor roles.
* ```KEYFACTOR_ATTACH_ROLE_TEMPLATE2```

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_ATTACH_ROLE_TESTS=True```.

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