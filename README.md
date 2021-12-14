# terraform-provider-keyfactor
Terraform provider that manages Keyfactor Command API

# Building the Keyfactor Provider

1. Define the ```terraform-provider-keyfactor/``` directory as the root of the module
```asm
go mod init terraform-provider-keyfactor
```

2. Create the ```vendor``` directory
```asm
go mod vendor
```

3. Build the provider using the Makefile
```asm
make build
```

# Referencing private repos in import() statement
The best way to clone private repositories in the import statement is to use SSH. Create an SSH key, import the private key to the ~./git directory, and run the following commands

```asm
git config --global url.ssh://git@github.com/.insteadOf https://github.com/
```
Then, export a GOPRIVATE environment variable for the organization or repository.
```asm
go env -w GOPRIVATE=github.com/<organization>
GIT_TERMINAL_PROMPT=1
```

For example:
```asm
go env -w GOPRIVATE=github.com/Keyfactor
```