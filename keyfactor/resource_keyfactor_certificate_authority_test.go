package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests
//
// Certificate authorities cannot be created with fake hostnames — the server
// validates connectivity during creation. These tests discover the existing
// CA on the lab and exercise import + read operations.
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateAuthorityResourceImport(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	cas, err := client.GetCAList()
	if err != nil || len(cas) == 0 {
		t.Skip("Skipping: no certificate authority found in lab")
	}
	ca := cas[0]
	caID := strconv.Itoa(ca.Id)
	caName := ca.LogicalName
	caHost := ca.HostName

	t.Logf("Using existing CA: ID=%s Name=%q Host=%q", caID, caName, caHost)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// Prevent test framework from running destroy at the end (we don't own this CA)
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			{
				// Import the existing CA by ID
				Config:            testAccCertificateAuthorityImportConfig(caName, caHost),
				ResourceName:      "keyfactor_certificate_authority.test",
				ImportState:       true,
				ImportStateId:     caID,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keyfactor_certificate_authority.test", "id", caID),
					resource.TestCheckResourceAttr("keyfactor_certificate_authority.test", "logical_name", caName),
					resource.TestCheckResourceAttr("keyfactor_certificate_authority.test", "host_name", caHost),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

func TestUnitKeyfactorCertificateAuthorityResource(t *testing.T) {
	cassetteName := "certificate_authority_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var caID, caName, caHost string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		if client == nil {
			t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
		}
		cas, err := client.GetCAList()
		if err != nil || len(cas) == 0 {
			t.Skip("Skipping: no certificate authority found in lab")
		}
		caID = strconv.Itoa(cas[0].Id)
		caName = cas[0].LogicalName
		caHost = cas[0].HostName
		writeCATestParams(cassettePath, caTestParams{CAID: caID, CAName: caName, CAHost: caHost})
	} else {
		params := readCATestParams(cassettePath)
		caID = params.CAID
		caName = params.CAName
		caHost = params.CAHost
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_authority.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		CheckDestroy:             nil,
		Steps: []resource.TestStep{
			{
				Config:            testAccCertificateAuthorityImportConfig(caName, caHost),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     caID,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", caID),
					resource.TestCheckResourceAttr(resourceName, "logical_name", caName),
					resource.TestCheckResourceAttrSet(resourceName, "host_name"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateAuthorityResourceUpdate imports an existing CA and
// applies an update to the monitor_thresholds field, verifying the change is
// reflected in state. The field value is toggled from its current lab value so
// the update always produces a real diff.
//
// Note: delete is called by the test framework at the end (cleanup); for CAs
// this may fail if the server rejects deletion of in-use CAs, which is
// acceptable — the test only verifies the update path.
func TestIntKeyfactorCertificateAuthorityResourceUpdate(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	cas, err := client.GetCAList()
	if err != nil || len(cas) == 0 {
		t.Skip("Skipping: no certificate authority found in lab")
	}
	ca := cas[0]
	caID := strconv.Itoa(ca.Id)
	caName := ca.LogicalName
	caHost := ca.HostName
	// Toggle from current value to ensure a real update is applied.
	newMonitorThresholds := !ca.MonitorThresholds

	t.Logf("Using CA: ID=%s Name=%q Host=%q, toggling monitor_thresholds %v→%v",
		caID, caName, caHost, ca.MonitorThresholds, newMonitorThresholds)

	resourceName := "keyfactor_certificate_authority.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             nil,
		Steps: []resource.TestStep{
			{
				// Step 1: Import the existing CA and persist state for Step 2.
				Config:             testAccCertificateAuthorityImportConfig(caName, caHost),
				ResourceName:       resourceName,
				ImportState:        true,
				ImportStateId:      caID,
				ImportStateVerify:  false,
				ImportStatePersist: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", caID),
					resource.TestCheckResourceAttr(resourceName, "logical_name", caName),
					resource.TestCheckResourceAttr(resourceName, "host_name", caHost),
				),
			},
			{
				// Step 2: Apply update — toggle monitor_thresholds.
				Config: testAccCertificateAuthorityUpdateConfig(caName, caHost, newMonitorThresholds),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", caID),
					resource.TestCheckResourceAttr(resourceName, "logical_name", caName),
					resource.TestCheckResourceAttr(resourceName, "monitor_thresholds", strconv.FormatBool(newMonitorThresholds)),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccCertificateAuthorityImportConfig(logicalName, hostName string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_authority" "test" {
  logical_name = "%s"
  host_name    = "%s"
  ca_type      = 1

  forest_root          = "ejbca"
  configuration_tenant = "ejbca"
}
`, logicalName, hostName)
}

// testAccCertificateAuthorityUpdateConfig generates a config that updates
// monitor_thresholds on an existing CA. Only the required fields plus the
// field being changed are specified; all other Optional+Computed attributes
// are preserved from state via UseStateForUnknown plan modifiers.
func testAccCertificateAuthorityUpdateConfig(logicalName, hostName string, monitorThresholds bool) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_authority" "test" {
  logical_name       = "%s"
  host_name          = "%s"
  ca_type            = 1
  monitor_thresholds = %t

  forest_root          = "ejbca"
  configuration_tenant = "ejbca"
}
`, logicalName, hostName, monitorThresholds)
}
