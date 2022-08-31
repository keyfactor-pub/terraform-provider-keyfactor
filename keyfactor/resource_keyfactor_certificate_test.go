package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

type certificateTestCase struct {
	template     string
	cn           string
	o            string
	l            string
	c            string
	ou           string
	st           string
	email        string
	ipSans       string
	dnsSans      string
	metadata     map[string]string
	keyPassword  string
	ca           string
	resourceName string
}

const CSR_CONTENT = `-----BEGIN CERTIFICATE REQUEST-----\nMIIFMTCCAxkCAQAwgesxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJPSDEVMBMGA1UE\nBxMMSW5kZXBlbmRlbmNlMUcwEAYDVQQJEwlTdWl0ZSAyMDAwEwYDVQQJEwxTZWNv\nbmQgRmxvb3IwHgYDVQQJExc2MTUwIE9hayBUcmVlIEJvdWxldmFyZDEOMAwGA1UE\nERMFNDQxMzExFzAVBgNVBAoTDktleWZhY3RvciBJbmMuMSEwHwYDVQQLExhJbnRl\nZ3JhdGlvbnMgRW5naW5lZXJpbmcxIzAhBgNVBAMMGnRlcnJhZm9ybV90ZXN0X2Nl\ncnRpZmljYXRlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy4sTj1k2\n7rabAXphqKaA/vpr61BEDdVQ/7J2nx3riSDqZZjyCKAjXGLqWsJGvBb9hbfnhH7J\nw83QwZTJab89BAYGTnHE4KB7eBFleI0aEvI09CPaNnjoiFYXc6s/Yhgv8FNUnlbR\nvkaEbKW4A4Mz83b2fNCHfJY5NnE6jr/gMmYnDjXh50yBAR4HS3t7GPZLsar39xpG\ngnKlCC8LGDRJ8CcMilkvH2bNLTo0nsckTJV9ttuDsmWLd9rANu843Va8XZzmq9ej\noWLn65MQEhqAObD5sZPNnQkH8c+5IGL+fQJW3y+nqe4zu+9L8nNEgXa6ANNJRIwy\n+Mug7+0IWlLJf5EnIB1z2stJqWFf3kVaEO1BakN8Qkv1tugpKazVKl6rs2CC97Ww\nQgXpD4tvOyCZxHs+Ok3SK183Q+GkM7WjLuBP9ainY4nJ76SbTOwPw8JVQB+4EkDo\naff1X2zctcmK1/Ri5kyMGqIQw4vQ+YZKzNJIJokNNn5K+u6ppOfxswOp0bZ4fG/M\nc1BKjAHBGDE10GaLlYFBR6/HTwLHDF5t1LpdhqzqLx8OpsaSJCN3xRUTlu5TsZa+\nn5NEgJS9bDHgqjv1dF68loZ3ILu8pebznh6vV+q3Jc8b8HIMXJ+hEoKZ1ldBgSeB\nCzHSDwVbS9L8swwzAAP54I/RDQR83pM1xH8CAwEAAaAAMA0GCSqGSIb3DQEBCwUA\nA4ICAQCV3Zw86hug66jloFFks1D0pGT7StuSkIFeYm46i0jEorVuhc4MqKYb/4C3\nVh0TnYHaNqfqlYJRHln2909tk4FMlQss8w/RxhCrSzJpr5px1XOWNKIJVnEjQAXS\n4O5//pe/qOwK1jH8J8RMEEZLdfFyWpJtav9Js+xK7lH/aXCbxExxYPDRuZCTiH9S\n6rxCIGmKkq2wtm36Tw3UsPLHp6IFdGag3WiD/ye4OpIT+6Tl0AX1qC3GV2S46/jv\ndPtr1EXFIgFX6mRzlA6/J3QgTaxBhxFITaS6dyCHUlSgEcbaVJ0rWre9zfQ38VEa\nUwpLU58Bx1ysVF7goQxYQxnHz2lVClA9WCCZt1NU3IX+QLqk1WU5idu8AfmvZXNI\nhrhcF/PCvH9eAfsqwECt/VsY3ferRtrCEves2UX7r/c4s0L/ZvYS7X9w3MxaJikc\nsewMB3Sj5xVc5XR71C6we16RrpEZ/bTtl8MPSY3b+pPf6YAqQlaziM2swdoQrp1c\n1DQElo1YlICF2gPQH9tJZcgDclw1W+1o77q34hIwktTtKDcVIs4WYTNwo8fn1Xtn\n7fU9cUBMepaIgZQfSz9KpLWG+GwbEgCtahLOpH5FNv+2e8dP0VZeWBCCAkav27oh\nxwK1aZ8hvc2E//sbJT0Swx8hIhyS+EYKpg1DzEZbwBmRch8C/g==\n-----END CERTIFICATE REQUEST-----\n`

func TestAccKeyfactorCertificateResource(t *testing.T) {

	r := certificateTestCase{
		template:     "WebServer",
		cn:           "terraform_test_certificate",
		o:            "Keyfactor Inc.",
		l:            "Independence",
		c:            "US",
		ou:           "Integrations Engineering",
		st:           "OH",
		ca:           `DC-CA.Command.local\\CommandCA1`,
		ipSans:       `["192.168.0.2", "10.10.0.9"]`,
		dnsSans:      `["tfprovider.keyfactor.com", "terraform_test_certificate"]`,
		metadata:     nil,
		email:        "",
		keyPassword:  "tf provider testing@!",
		resourceName: "keyfactor_certificate.PFXCertificate",
	}

	r2 := r
	r2.email = "kfadmin@keyfactor.com"

	// Testing PFX certificate
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateResourcePFXConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorCertificateResourcePFXConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
	// Testing CSR certificate
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateResourceCSRConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorCertificateResourcePFXConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorCertificateResourcePFXConfig(t certificateTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate" "PFXCertificate" {
  subject = {
    subject_common_name         = "%s"
    subject_organization        = "%s"
    subject_locality            = "%s"
    subject_country             = "%s"
    subject_organizational_unit = "%s"
    subject_state               = "%s"
  }

  ip_sans  = %s
  dns_sans = %s

  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "%s"
  certificate_template  = "%s"
  metadata = {
    "Email-Contact" = "%s" # Note metadata keys must be defined in Keyfactor
  }
}

`, t.cn, t.o, t.l, t.c, t.ou, t.st, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, t.email)
	return output
}
func testAccKeyfactorCertificateResourceCSRConfig(t certificateTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate" "PFXCertificate" {
  csr = "%s"

  ip_sans  = %s
  dns_sans = %s

  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "%s"
  certificate_template  = "%s"
  metadata = {
    "Email-Contact" = "%s" # Note metadata keys must be defined in Keyfactor
  }
}

`, CSR_CONTENT, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, t.email)
	return output
}
