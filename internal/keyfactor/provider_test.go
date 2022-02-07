package keyfactor

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// providerFactories are used to instantiate a provider during acceptance testing.
// The factory function will be invoked for every Terraform CLI command executed
// to create a provider server to which the CLI can reattach.
var providerFactories = map[string]func() (*schema.Provider, error){
	"keyfactor": func() (*schema.Provider, error) {
		return Provider(), nil
	},
}
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ = *Provider()
}

func testAccPreCheck(t *testing.T) {
	ctx := context.TODO()
	if err := os.Getenv("KEYFACTOR_USERNAME"); err == "" {
		t.Fatal("KEYFACTOR_USERNAME must be set for acceptance tests")
	}
	if err := os.Getenv("KEYFACTOR_PASSWORD"); err == "" {
		t.Fatal("KEYFACTOR_PASSWORD must be set for acceptance tests")
	}
	if err := os.Getenv("KEYFACTOR_HOSTNAME"); err == "" {
		t.Fatal("KEYFACTOR_HOSTNAME must be set for acceptance tests")
	}

	// Configure the Keyfactor provider
	diags := testAccProvider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if diags.HasError() {
		t.Fatal(diags[0].Summary)
	}
}
