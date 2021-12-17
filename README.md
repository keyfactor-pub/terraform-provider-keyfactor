# terraform-provider-keyfactor
Terraform provider that manages Keyfactor Command API

## Configure Makefile
As of now, the Makefile only works for Unix based operating systems. If running on Windows, the ```--debug``` flag can
be passed to the ```go build``` call which will start a debug server. For Unix architectures, you _must_ specify
your operating system (IE darwin, linux, etc.) and hardware architecture (IE amd64, arm64, etc.).

## Building the Keyfactor Provider

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