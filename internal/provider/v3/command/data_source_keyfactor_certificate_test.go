package command

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"os"
	"strconv"
	"testing"
)

func TestAccKeyfactorCertificateDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate")
	var cID = os.Getenv("TEST_CERTIFICATE_ID")
	var colID = os.Getenv("TEST_CERTIFICATE_COLLECTION_ID")
	var cCN = os.Getenv("TEST_CERTIFICATE_CN")
	var cTP = os.Getenv("TEST_CERTIFICATE_THUMBPRINT")
	var caID = os.Getenv("TEST_CERTIFICATE_AUTHORITY_CERT_ID")
	var password = os.Getenv("TEST_CERTIFICATE_PASSWORD")
	if password == "" {
		password = generatePassword(DefaultPasswdLength, DefaultMinSpecialChar, DefaultMinNum, DefaultMinUpperCase)
	}
	if cID == "" {
		cID = "1"
	}
	if caID == "" {
		caID = "1"
	}
	if cCN == "" {
		cCN = "SANity Check"
	}
	if cTP == "" {
		t.Log("TEST_CERTIFICATE_THUMBPRINT is not set, skipping TestAccKeyfactorCertificateDataSource")
	}
	if colID == "" {
		colID = "0"
	}
	colIDInt, _ := strconv.Atoi(colID)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				// Test lookup by ID
				Config: testAccDataSourceKeyfactorCertificateBasic(t, cID, password),
				Check:  certTestValidateAll(resourceName),
			},
			{
				// Test lookup by empty ID and password
				Config:      testAccDataSourceKeyfactorCertificateBasic(t, "", ""),
				Check:       certTestValidateAll(resourceName),
				ExpectError: emptyCertRequestErrRegex,
			},
			{
				// Test lookup by ID w/ short password
				Config: testAccDataSourceKeyfactorCertificateBasic(t, cID, "hi"),
				Check:  certTestValidateAll(resourceName),
			},
			{
				// Test lookup containing collection ID
				// TODO: This needs to have limited access to properly test
				Config: testAccDataSourceKeyfactorCertificateCollectionId(t, cID, password, colIDInt),
				Check:  certTestValidateAll(resourceName),
			},
			{
				// Test lookup containing invalid collection ID
				// TODO: This needs to have limited access to properly test
				Config: testAccDataSourceKeyfactorCertificateCollectionId(t, cID, password, 9999),
				Check:  certTestValidateAll(resourceName),
			},
			{
				// Test lookup by CN
				Config: testAccDataSourceKeyfactorCertificateBasic(t, cCN, password),
				Check:  certTestValidateAll(resourceName),
			},
			{
				// Test lookup by thumbprint
				Config: testAccDataSourceKeyfactorCertificateBasic(t, cTP, password),
				Check:  certTestValidateAll(resourceName),
			},
			{
				// Test CA cert lookup by thumbprint
				Config: testAccDataSourceKeyfactorCertificateBasic(t, caID, ""),
				Check:  certTestValidateCACert(resourceName, caID),
			},
		},
	})
}

func testAccDataSourceKeyfactorCertificateBasic(t *testing.T, resourceId string, password string) string {
	output := fmt.Sprintf(`
	data "keyfactor_certificate" "test" {
		identifier = "%s"
		key_password = "%s"
	}
	`, resourceId, password)
	t.Logf("%s", output)
	return output
}

func testAccDataSourceKeyfactorCertificateCollectionId(t *testing.T, resourceId string, password string, collectionId int) string {
	output := fmt.Sprintf(`
	data "keyfactor_certificate" "test" {
		identifier = "%s"
		key_password = "%s"
		collection_id = "%d"
	}
	`, resourceId, password, collectionId)
	t.Logf("%s", output)
	return output
}

func certTestValidateAll(resourceName string) resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(resourceName, "archived_key"),
		resource.TestCheckResourceAttrSet(resourceName, "ca_record_id"),
		resource.TestCheckResourceAttrSet(resourceName, "ca_row_index"),
		resource.TestCheckResourceAttrSet(resourceName, "cert_state"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_authority"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_authority_id"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_chain"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_id"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_key_id"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_pem"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_template"),
		//resource.TestCheckResourceAttrSet(resourceName, "collection_id"),
		resource.TestCheckResourceAttrSet(resourceName, "command_request_id"),
		resource.TestCheckResourceAttrSet(resourceName, "content_bytes"),
		resource.TestCheckResourceAttrSet(resourceName, "crl_distribution_point.#"),
		resource.TestCheckResourceAttrSet(resourceName, "curve"),
		resource.TestCheckResourceAttrSet(resourceName, "detailed_key_usage.%"),
		resource.TestCheckResourceAttrSet(resourceName, "dns_sans.#"),
		resource.TestCheckResourceAttrSet(resourceName, "extended_key_usage.#"),
		resource.TestCheckResourceAttrSet(resourceName, "has_private_key"),
		resource.TestCheckResourceAttrSet(resourceName, "identifier"),
		resource.TestCheckResourceAttrSet(resourceName, "import_date"),
		//resource.TestCheckResourceAttrSet(resourceName, "include_private_key"),
		resource.TestCheckResourceAttrSet(resourceName, "ip_sans.#"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_cn"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_dn"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_email"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_ou"),
		resource.TestCheckResourceAttrSet(resourceName, "issuer_dn"),
		resource.TestCheckResourceAttrSet(resourceName, "key_bits"),
		resource.TestCheckResourceAttrSet(resourceName, "key_password"),
		resource.TestCheckResourceAttrSet(resourceName, "key_recoverable"),
		resource.TestCheckResourceAttrSet(resourceName, "key_type"),
		resource.TestCheckResourceAttrSet(resourceName, "key_usage"),
		//resource.TestCheckResourceAttrSet(resourceName, "location"),
		//resource.TestCheckResourceAttrSet(resourceName, "locations_count"),
		resource.TestCheckResourceAttrSet(resourceName, "metadata.%"),
		resource.TestCheckResourceAttrSet(resourceName, "not_after"),
		resource.TestCheckResourceAttrSet(resourceName, "not_before"),
		resource.TestCheckResourceAttrSet(resourceName, "principal_id"),
		resource.TestCheckResourceAttrSet(resourceName, "principal_name"),
		resource.TestCheckResourceAttrSet(resourceName, "private_key"),
		resource.TestCheckResourceAttrSet(resourceName, "requester_id"),
		resource.TestCheckResourceAttrSet(resourceName, "requester_name"),
		resource.TestCheckResourceAttrSet(resourceName, "revocation_comment"),
		resource.TestCheckResourceAttrSet(resourceName, "revocation_effective_date"),
		resource.TestCheckResourceAttrSet(resourceName, "revocation_reason"),
		resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
		resource.TestCheckResourceAttrSet(resourceName, "signing_algorithm"),
		//resource.TestCheckResourceAttrSet(resourceName, "ssl_location"),
		//resource.TestCheckResourceAttrSet(resourceName, "subject_alt_name_element"),
		resource.TestCheckResourceAttrSet(resourceName, "template_id"),
		resource.TestCheckResourceAttrSet(resourceName, "thumbprint"),
		resource.TestCheckResourceAttrSet(resourceName, "uri_sans.#"),
	)
}

func certTestValidateCACert(resourceName string, resourceID string) resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(resourceName, "archived_key"),
		resource.TestCheckResourceAttr(resourceName, "archived_key", "false"),
		resource.TestCheckResourceAttrSet(resourceName, "ca_record_id"),
		resource.TestCheckResourceAttrSet(resourceName, "ca_row_index"),
		resource.TestCheckResourceAttrSet(resourceName, "cert_state"),
		resource.TestCheckResourceAttr(resourceName, "cert_state", APICertStateIsCA),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_authority"),
		resource.TestCheckResourceAttr(resourceName, "certificate_authority", TestCAName),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_authority_id"),
		resource.TestCheckNoResourceAttr(resourceName, "certificate_chain"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_id"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_key_id"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_pem"),
		resource.TestCheckResourceAttrSet(resourceName, "certificate_template"),
		resource.TestCheckResourceAttr(resourceName, "certificate_template", attr.NullValueString),
		//resource.TestCheckResourceAttrSet(resourceName, "collection_id"),
		resource.TestCheckResourceAttrSet(resourceName, "command_request_id"),
		resource.TestCheckResourceAttrSet(resourceName, "content_bytes"),
		//resource.TestCheckResourceAttrSet(resourceName, "crl_distribution_point.#"),
		resource.TestCheckResourceAttrSet(resourceName, "curve"),
		resource.TestCheckResourceAttrSet(resourceName, "detailed_key_usage.%"),
		//resource.TestCheckResourceAttrSet(resourceName, "dns_sans.#"),
		//resource.TestCheckResourceAttrSet(resourceName, "extended_key_usage.#"),
		resource.TestCheckResourceAttrSet(resourceName, "has_private_key"),
		resource.TestCheckResourceAttr(resourceName, "has_private_key", "false"),
		resource.TestCheckResourceAttrSet(resourceName, "identifier"),
		resource.TestCheckResourceAttr(resourceName, "identifier", resourceID),
		resource.TestCheckResourceAttrSet(resourceName, "import_date"),
		//resource.TestCheckResourceAttrSet(resourceName, "include_private_key"),
		//resource.TestCheckResourceAttrSet(resourceName, "ip_sans.#"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_cn"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_dn"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_email"),
		resource.TestCheckResourceAttrSet(resourceName, "issued_ou"),
		resource.TestCheckResourceAttrSet(resourceName, "issuer_dn"),
		// ensure that issued_cn and issued_dn are the same
		resource.TestCheckResourceAttrPair(resourceName, "issuer_dn", resourceName, "issued_dn"),
		resource.TestCheckResourceAttrSet(resourceName, "key_bits"),
		//resource.TestCheckResourceAttrSet(resourceName, "key_password"),
		resource.TestCheckResourceAttrSet(resourceName, "key_recoverable"),
		resource.TestCheckResourceAttr(resourceName, "key_recoverable", "false"),
		resource.TestCheckResourceAttrSet(resourceName, "key_type"),
		resource.TestCheckResourceAttrSet(resourceName, "key_usage"),
		//resource.TestCheckResourceAttrSet(resourceName, "location"),
		//resource.TestCheckResourceAttrSet(resourceName, "locations_count"),
		resource.TestCheckResourceAttrSet(resourceName, "metadata.%"),
		resource.TestCheckResourceAttrSet(resourceName, "not_after"),
		resource.TestCheckResourceAttrSet(resourceName, "not_before"),
		resource.TestCheckResourceAttrSet(resourceName, "principal_id"),
		resource.TestCheckResourceAttrSet(resourceName, "principal_name"),
		resource.TestCheckNoResourceAttr(resourceName, "private_key"),
		resource.TestCheckResourceAttrSet(resourceName, "requester_id"),
		resource.TestCheckResourceAttrSet(resourceName, "requester_name"),
		resource.TestCheckResourceAttrSet(resourceName, "revocation_comment"),
		resource.TestCheckResourceAttrSet(resourceName, "revocation_effective_date"),
		resource.TestCheckResourceAttrSet(resourceName, "revocation_reason"),
		resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
		resource.TestCheckResourceAttrSet(resourceName, "signing_algorithm"),
		//resource.TestCheckResourceAttrSet(resourceName, "ssl_location"),
		//resource.TestCheckResourceAttrSet(resourceName, "subject_alt_name_element"),
		resource.TestCheckResourceAttrSet(resourceName, "template_id"),
		resource.TestCheckResourceAttrSet(resourceName, "thumbprint"),
		//resource.TestCheckResourceAttrSet(resourceName, "uri_sans.#"),
	)
}
