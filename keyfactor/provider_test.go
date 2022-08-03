package keyfactor

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"log"
	"math/rand"
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

func testAccGenerateKeyfactorRole(conn *api.Client) (*api.Client, string, int) {
	var client *api.Client
	if conn == nil {
		var err error
		clientConfig := &api.AuthConfig{
			Hostname: os.Getenv("KEYFACTOR_HOSTNAME"),
			Username: os.Getenv("KEYFACTOR_USERNAME"),
			Password: os.Getenv("KEYFACTOR_PASSWORD"),
		}
		client, err = api.NewKeyfactorClient(clientConfig)
		if err != nil {
			return nil, "", 0
		}
	} else {
		client = conn
	}

	roleName := "terraform_acctest-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	arg := &api.CreateSecurityRoleArg{
		Name:        roleName,
		Description: "Role generated to perform Terraform acceptance test. If this role exists, it can be deleted.",
	}

	role, err := client.CreateSecurityRole(arg)
	if err != nil {
		return nil, "", 0
	}

	return client, role.Name, role.Id
}

func testAccDeleteKeyfactorRole(client *api.Client, roleId int) error {
	err := client.DeleteSecurityRole(roleId)
	if err != nil {
		return err
	}
	return nil
}

func getTemporaryConnection() (*api.Client, error) {
	var err error
	clientConfig := &api.AuthConfig{
		Hostname: os.Getenv("KEYFACTOR_HOSTNAME"),
		Username: os.Getenv("KEYFACTOR_USERNAME"),
		Password: os.Getenv("KEYFACTOR_PASSWORD"),
	}
	client, err := api.NewKeyfactorClient(clientConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getCertificateTemplate(conn *api.Client) (string, *api.Client, error) {
	var client *api.Client
	if conn == nil {
		var err error
		client, err = getTemporaryConnection()
		if err != nil {
			return "", nil, err
		}
	} else {
		client = conn
	}

	// First grab a list of templates from Keyfactor
	templates, err := client.GetTemplates()
	if err != nil {
		return "", nil, err
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
	return enrollmentTemplate, client, nil
}

func findRandomMetadataField(conn *api.Client) (string, *api.Client, error) {
	var client *api.Client
	if conn == nil {
		var err error
		client, err = getTemporaryConnection()
		if err != nil {
			return "", nil, err
		}
	} else {
		client = conn
	}

	fields, err := client.GetAllMetadataFields()
	if err != nil {
		return "", nil, err
	}

	for {
		temp := fields[rand.Intn(len(fields))]
		// Search temp randomly until a metadata field with type string is found.
		if temp.DataType == 1 {
			log.Printf("Chose %s as random metadata field.", temp.Name)
			return temp.Name, client, nil
		}
	}
}

func findCompatableCA(conn *api.Client, escapeDepth int) (string, *api.Client, error) {
	var client *api.Client
	if conn == nil {
		var err error
		client, err = getTemporaryConnection()
		if err != nil {
			return "", nil, err
		}
	} else {
		client = conn
	}

	// Then, find the first CA from Keyfactor
	list, err := client.GetCAList()
	if err != nil {
		return "", nil, err
	}
	var caName string
	for _, ca := range list {
		if ca.LogicalName != "" && ca.HostName != "" {
			var escape string
			for i := 0; i < escapeDepth; i++ {
				escape += "\\"
			}
			caName = ca.HostName + escape + ca.LogicalName

			break
		}
	}
	return caName, client, nil
}

// Enroll a PFX certificate based on a random template supported by Keyfactor
func enrollPFXCertificate(conn *api.Client) (error, *api.Client, *api.CertificateInformation, string) {
	var client *api.Client
	if conn == nil {
		var err error
		client, err = getTemporaryConnection()
		if err != nil {
			return err, nil, nil, ""
		}
	} else {
		client = conn
	}

	enrollmentTemplate, _, err := getCertificateTemplate(conn)
	if err != nil {
		return err, nil, nil, ""
	}

	caName, _, err := findCompatableCA(conn, 1)
	if err != nil {
		return err, nil, nil, ""
	}

	// Generate random CN
	cn := "terraform_acctest-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	password := acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	// Fill out the minimum required fields to enroll a PFX
	arg := &api.EnrollPFXFctArgs{
		CustomFriendlyName:   cn,
		Password:             password,
		CertificateAuthority: caName,
		Template:             enrollmentTemplate,
		IncludeChain:         true,
		CertFormat:           "STORE",
		Subject:              &api.CertificateSubject{SubjectCommonName: cn},
		SANs:                 &api.SANs{DNS: []string{cn}},
	}

	pfx, err := client.EnrollPFX(arg)
	if err != nil {
		return err, nil, nil, ""
	}

	return nil, client, &pfx.CertificateInformation, password
}

func revokePFXCertificate(conn *api.Client, certId int) error {
	var client *api.Client
	if conn == nil {
		var err error
		client, err = getTemporaryConnection()
		if err != nil {
			return err
		}
	} else {
		client = conn
	}

	revokeArgs := &api.RevokeCertArgs{
		CertificateIds: []int{certId}, // Certificate ID expects array of integers
		Reason:         5,             // reason = 5 means Cessation of Operation
		Comment:        "Terraform acceptance test cleanup",
	}

	err := client.RevokeCert(revokeArgs)
	if err != nil {
		return err
	}

	return nil
}
