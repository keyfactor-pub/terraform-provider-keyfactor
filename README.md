<a href="https://terraform.io">
    <img src=".github/tf.png" alt="Terraform logo" title="Terraform" align="left" height="50" />
</a>

# terraform-provider-keyfactor
Terraform provider based on the Keyfactor Go Utility to instantiate state in Keyfactor Command.

## Configure Makefile
As of now, the Makefile only works for Unix based operating systems. If running on Windows, the ```--debug``` flag can
be passed to the ```go build``` call which will start a debug server. For Unix architectures, you _must_ specify
your operating system (IE darwin, linux, etc.) and hardware architecture (IE amd64, arm64, etc.).

## Building the Keyfactor Provider from Source

1. Define the ```terraform-provider-keyfactor/``` directory as the root of the module
    ```bash
    go mod init terraform-provider-keyfactor
    ```
    * The ```go.mod``` file declares the current module and finds any dependancies required. The ```go.mod``` file
included with the repository requires that the ```keyfactor-go-client``` and ```terraform-plugin-sdk``` are included.


2. Create the ```vendor``` directory
    ```bash
    go mod vendor
    ```
    * The ```vendor``` directory holds all modules required by the package. The command ```go mod vendor``` 
      finds/downloads the dependencies, and stores them inside the ```vendor``` directory for reference by the code.


3. Install the provider using the Makefile
    ```bash
    make install
    ```
   * The ```install``` command builds the module, creates a directory inside ```~/.terraform.d/plugins/```, and moves
     the executable to it. Terraform uses the directory structure created by ```make install``` to locate the
     provider during initialization.
   * If using the ```install``` option, configure the provider configuration source as shown below:

    ```terraform
    terraform {
      required_providers {
        keyfactor = {
          version = "~> 1.0.0"
          source  = "keyfactor.com/keyfactordev/keyfactor"
        }
      }
    }
    ```

## Running Acceptance Tests
The Terraform Acceptance tests can be run using 
```bash
make testacc
```
or 
```go 
go test github.com/Keyfactor/terraform-provider-keyfactor/internal/keyfactor
```
Note that the following environment variables must exist regardless of the test case:
* ```KEYFACTOR_USERNAME```
* ```KEYFACTOR_PASSWORD```
* ```KEYFACTOR_HOSTNAME```

### Certificate resource acceptance tests
The following environment variables must exist to run acceptance tests for the Certificate resource:
* ```KEYFACTOR_CERT_TEMPLATE```
* ```KEYFACTOR_CERTIFICATE_AUTHORITY```
* ```KEYFACTOR_TEST_METADATA_FIELD```

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_CERTIFICATE_TESTS=True```.

### Store resource acceptance tests
The following environment variables must exist to run acceptance tests for the Store resource:
* ```KEYFACTOR_CLIENT_MACHINE```
* ```KEYFACTOR_ORCHESTRATOR_AGENT_ID```

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_STORE_TESTS=True```.

### Security Role resource acceptance tests
The following environment variable must exist to run acceptance tests for the Security Role resource:
* ```KEYFACTOR_SECURITY_ROLE_IDENTITY_ACCOUNTNAME``` - This account _must already exist_ in Keyfactor. Terraform acceptance
  tests create a Keyfactor security roles and attach them to the security identity configured by this environment variable. 

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_ROLE_TESTS=True```.

### Security Identity resource acceptance tests
The following environment variable must exist to run acceptance tests for the Security Identity resource:
* ```KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME``` - Note that this account must exist in AD, but not in Keyfactor.

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_IDENTITY_TESTS=True```.

### Attach Security Role resource acceptance tests
The following environment variables must exist to run acceptance tests for the Attach Security Role resource:
* ```KEYFACTOR_ATTACH_ROLE_TEMPLATE1``` - It's advised that the templates specified by these environment variables are not
  often used, as Terraform will add allowed requesters as Keyfactor roles.
* ```KEYFACTOR_ATTACH_ROLE_TEMPLATE2```

To skip acceptance tests for the Certificate resource, export ```KEYFACTOR_SKIP_ATTACH_ROLE_TESTS=True```.

## Referencing private go repos in import() statement
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