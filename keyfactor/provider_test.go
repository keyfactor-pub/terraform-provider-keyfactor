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

// Enroll a PFX certificate based on a random template supported by Keyfactor
func enrollPFXCertificate(conn *keyfactor.Client) (error, *keyfactor.Client, *keyfactor.CertificateInformation, string) {
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
			return err, nil, nil, ""
		}
	} else {
		client = conn
	}

	// First grab a list of templates from Keyfactor
	templates, err := client.GetTemplates()
	if err != nil {
		return err, nil, nil, ""
	}
	var enrollmentTemplate string
	for _, template := range templates {
		t := template.AllowedEnrollmentTypes
		// Find the first template that supports PFX enrollment
		if t == 1 || t == 3 || t == 5 || t == 7 {
			if !template.RFCEnforcement {
				enrollmentTemplate = template.CommonName
				break
			}
		}
	}

	// Then, find the first CA from Keyfactor
	list, err := client.GetCAList()
	if err != nil {
		return err, nil, nil, ""
	}
	var caName string
	for _, ca := range list {
		if ca.LogicalName != "" && ca.HostName != "" {
			caName = ca.HostName + "\\" + ca.LogicalName
			break
		}
	}

	// Generate random CN
	cn := "terraform_acctest-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	password := acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	// Fill out the minimum required fields to enroll a PFX
	arg := &keyfactor.EnrollPFXFctArgs{
		CustomFriendlyName:   cn,
		KeyPassword:          password,
		CertificateAuthority: caName,
		Template:             enrollmentTemplate,
		IncludeChain:         true,
		CertFormat:           "STORE",
		CertificateSubject:   keyfactor.CertificateSubject{SubjectCommonName: cn},
		CertificateSANs:      &keyfactor.SANs{DNS: []string{cn}},
	}

	pfx, err := client.EnrollPFX(arg)
	if err != nil {
		return err, nil, nil, ""
	}

	return nil, client, &pfx.CertificateInformation, password
}

func revokePFXCertificate(conn *keyfactor.Client, certId int) error {
	revokeArgs := &keyfactor.RevokeCertArgs{
		CertificateIds: []int{certId}, // Certificate ID expects array of integers
		Reason:         5,             // reason = 5 means Cessation of Operation
		Comment:        "Terraform acceptance test cleanup",
	}

	err := conn.RevokeCert(revokeArgs)
	if err != nil {
		return err
	}

	return nil
}
