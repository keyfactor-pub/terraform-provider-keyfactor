# terraform-provider-keyfactor
Terraform provider that manages Keyfactor Command API

# Building the Keyfactor Provider

1. Define the ```terraform-provider-keyfactor/``` directory as the root of the module
```
go mod init terraform-provider-keyfactor
```

2. Create the ```vendor``` directory
```
go mod vendor
```

3. Build the provider using the Makefile
```
make build
```

# Referencing private repos in import() statement
The best way to clone private repositories in the import statement is to use SSH. Create an SSH key, import the private key to the ~./git directory, and run the following commands

```
git config --global url.ssh://git@github.com/.insteadOf https://github.com/
go env -w GOPRIVATE="github.com/<username>"
GIT_TERMINAL_PROMPT=1
```
