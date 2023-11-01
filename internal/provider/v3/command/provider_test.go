// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"testing"
)

const (
	// providerConfig is a shared configuration to combine with the actual
	// test configuration so the HashiCups client is properly configured.
	// It is also possible to use the HASHICUPS_ environment variables instead,
	// such as updating the Makefile and running the testing through that tool.
	providerConfig = `
terraform {
  required_version = ">= 1.6"
  required_providers {
    keyfactor = {
      version = "3.0.0"
      source  = "keyfactor.com/command/v3"
    }
  }
}
provider "keyfactor" {
  auth_config = "~/.keyfactor/command_config.json"
}
`
)

var (
	// testAccProtoV6ProviderFactories are used to instantiate a provider during
	// acceptance testing. The factory function will be invoked for every Terraform
	// CLI command executed to create a provider server to which the CLI can
	// reattach.
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"keyfactor": providerserver.NewProtocol6WithError(New("test")()),
	}
)

func testAccPreCheck(t *testing.T) {
	// You can add code here to run prior to any test case execution, for example assertions
	// about the appropriate environment variables being set are common to see in a pre-check
	// function.
}
