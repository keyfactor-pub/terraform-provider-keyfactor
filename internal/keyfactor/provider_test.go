package keyfactor

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
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

func testAccGenerateKeyfactorRole(conn *keyfactor.Client) (*keyfactor.Client, string, int) {
	var client *keyfactor.Client
	if conn == nil {
		var err error
		clientConfig := &keyfactor.AuthConfig{
			Hostname: os.Getenv("KEYFACTOR_HOSTNAME"),
			Username: os.Getenv("KEYFACTOR_USERNAME"),
			Password: os.Getenv("KEYFACTOR_PASSWORD"),
		}
		client, err = keyfactor.NewKeyfactorClient(clientConfig)
		if err != nil {
			return nil, "", 0
		}
	} else {
		client = conn
	}

	roleName := "terraform_acctest-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	arg := &keyfactor.CreateSecurityRoleArg{
		Name:        roleName,
		Description: "Role generated to perform Terraform acceptance test. If this role exists, it can be deleted.",
	}

	role, err := client.CreateSecurityRole(arg)
	if err != nil {
		return nil, "", 0
	}

	return client, role.Name, role.Id
}

func testAccDeleteKeyfactorRole(client *keyfactor.Client, roleId int) error {
	err := client.DeleteSecurityRole(roleId)
	if err != nil {
		return err
	}
	return nil
}
