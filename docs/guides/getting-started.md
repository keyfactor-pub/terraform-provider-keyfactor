---
page_title: "Getting Started with the Keyfactor Terraform Provider"
subcategory: "Security & Authentication"
description: |-
Guide to getting off the ground with the Terraform Provider for Keyfactor
  
---

# Getting Started with the Keyfactor Terraform Provider

## Requirements

* Terraform [1.1.x](https://www.terraform.io/downloads)
* Keyfactor Command [v9.x](https://www.keyfactor.com/)
	* Keyfactor Command account with permissions to required Keyfactor features (IE certificate)

## Provider Setup

The Keyfactor provider must be configured with proper credentials before use.
As of now, Keyfactor uses basic authentication for authenticating with the
API. The following is the simplest method of authentication, but is not
recommended for security reasons.

```terraform
provider "keyfactor" {
    alias       = "command"
    hostname    = "sedemo.thedemodrive.com"
    kf_username = "username"
    kf_password = "password"
}
```

Supported environment variables are:
* ```KEYFACTOR_HOSTNAME```
* ```KEYFACTOR_USERNAME```
* ```KEYFACTOR_PASSWORD```
* ```KEYFACTOR_DOMAIN```

## Enrolling a Certificate with Terraform