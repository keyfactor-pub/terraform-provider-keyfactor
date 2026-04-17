package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	keyfactor "github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
//
// A t.Cleanup restores the CA to its pre-test state (best-effort) so that
// re-runs of this test see consistent initial conditions.
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

	// Snapshot the full CA config via raw GET before the test runs so we can
	// restore it afterwards. This is needed because:
	//   1. The test deliberately mutates monitor_thresholds.
	//   2. The Terraform destroy step always fails (CA has certificates), so the
	//      provider's own restore logic in Delete never runs for this code path.
	//   3. The delete attempt clears FullScan/IncrementalScan schedules before
	//      realising it cannot delete the CA, leaving the CA in a degraded state.
	// We capture the raw JSON response and PUT it back verbatim after the test
	// so that subsequent test runs start from a known-good baseline.
	rawCAJSON, _, snapshotErr := commandHTTPDo(client, "GET",
		fmt.Sprintf("CertificateAuthority/%s", caID), nil)
	if snapshotErr != nil {
		t.Logf("WARNING: could not snapshot CA %s before test: %s — cleanup will be skipped", caID, snapshotErr)
	}

	t.Cleanup(func() {
		if snapshotErr != nil || len(rawCAJSON) == 0 {
			t.Logf("cleanup: no CA snapshot available, skipping restore")
			return
		}

		// Unmarshal the snapshot into the typed SDK request struct.  The GET
		// response and PUT request share all relevant JSON field names, so a
		// straight unmarshal works for the restore.  Server-only fields that
		// don't appear in the request struct are simply ignored.
		var caReq v1.CertificateAuthoritiesCertificateAuthorityRequest
		if err := json.Unmarshal(rawCAJSON, &caReq); err != nil {
			t.Logf("cleanup: could not parse CA snapshot JSON: %s — skipping restore", err)
			return
		}

		// Overwrite MonitorThresholds back to the original value captured
		// before the test toggled it.
		origVal := ca.MonitorThresholds
		caReq.MonitorThresholds = &origVal

		// Use the SDK directly so the request goes to PUT /CertificateAuthority
		// (no ID in the URL path — the ID lives in the request body), matching
		// what the provider's own Update function does.  commandHTTPDo cannot be
		// used here because it embeds the query string in the URL path segment,
		// which net/url percent-encodes the '?' and causes a 405.
		sdkClient := keyfactor.NewAPIClientWithAuth(client.AuthClient)
		ctx := context.Background()
		_, httpResp, err := sdkClient.V1.CertificateAuthorityApi.
			NewUpdateCertificateAuthorityRequest(ctx).
			CertificateAuthoritiesCertificateAuthorityRequest(caReq).
			ForceSave(true).
			Execute()
		status := 0
		if httpResp != nil {
			status = httpResp.StatusCode
		}
		if err != nil || status < 200 || status >= 300 {
			t.Logf("cleanup: CA %s restore PUT failed (status=%d): %s",
				caID, status, err)
			return
		}
		t.Logf("cleanup: CA %s restored to pre-test state (status=%d)", caID, status)
	})

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

// ---------------------------------------------------------------------------
// Unit tests — caResponseToState nil-safe conversion
// ---------------------------------------------------------------------------

// TestUnitCertificateAuthorityResponseToState verifies that caResponseToState
// returns types.Bool{Null:true} / types.Int64{Null:true} for pointer fields
// that are nil in the server response, rather than the Go zero value (false/0).
//
// This is the regression test for the nil-safe helper fix: before the fix,
// GetDelegateEnrollment() on a nil pointer returned false, which subsequent PUT
// requests would then send, silently overwriting the server's "use for
// enrollment" setting.
func TestUnitCertificateAuthorityResponseToState(t *testing.T) {
	t.Parallel()

	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)

	t.Run("nil pointer fields become Null", func(t *testing.T) {
		t.Parallel()

		// Build a minimal response with all pointer fields left as nil.
		resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
		resp.SetId(42)
		resp.SetLogicalName("Test-CA")
		resp.SetHostName("http://ca.example.com/ejbca")
		resp.CAType = &caType

		state := caResponseToState(resp)

		if !state.DelegateEnrollment.Null {
			t.Errorf("DelegateEnrollment: want Null=true (nil ptr), got Value=%v Null=%v",
				state.DelegateEnrollment.Value, state.DelegateEnrollment.Null)
		}
		if !state.Delegate.Null {
			t.Errorf("Delegate: want Null=true (nil ptr), got Value=%v Null=%v",
				state.Delegate.Value, state.Delegate.Null)
		}
		if !state.MonitorThresholds.Null {
			t.Errorf("MonitorThresholds: want Null=true (nil ptr), got Value=%v Null=%v",
				state.MonitorThresholds.Value, state.MonitorThresholds.Null)
		}
		if !state.AllowedEnrollmentTypes.Null {
			t.Errorf("AllowedEnrollmentTypes: want Null=true (nil ptr), got Value=%v Null=%v",
				state.AllowedEnrollmentTypes.Value, state.AllowedEnrollmentTypes.Null)
		}
		if !state.NewEndEntityOnRenewAndReissue.Null {
			t.Errorf("NewEndEntityOnRenewAndReissue: want Null=true (nil ptr), got Value=%v Null=%v",
				state.NewEndEntityOnRenewAndReissue.Value, state.NewEndEntityOnRenewAndReissue.Null)
		}
		if !state.EnforceUniqueDN.Null {
			t.Errorf("EnforceUniqueDN: want Null=true (nil ptr), got Value=%v Null=%v",
				state.EnforceUniqueDN.Value, state.EnforceUniqueDN.Null)
		}
	})

	t.Run("non-nil pointer fields carry their value", func(t *testing.T) {
		t.Parallel()

		delegateEnroll := true
		monitorThresh := false
		et := v1.CSSCMSCoreEnumsEnrollmentType(3) // both PFX and CSR
		newEE := true

		resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
		resp.SetId(7)
		resp.SetLogicalName("Lab-CA")
		resp.SetHostName("http://ca.lab/ejbca")
		resp.CAType = &caType
		resp.DelegateEnrollment = &delegateEnroll
		resp.MonitorThresholds = &monitorThresh
		resp.AllowedEnrollmentTypes = &et
		resp.NewEndEntityOnRenewAndReissue = &newEE

		state := caResponseToState(resp)

		assertBool := func(name string, got types.Bool, wantNull bool, wantVal bool) {
			t.Helper()
			if got.Null != wantNull {
				t.Errorf("%s: Null mismatch: want %v got %v", name, wantNull, got.Null)
			}
			if !got.Null && got.Value != wantVal {
				t.Errorf("%s: Value mismatch: want %v got %v", name, wantVal, got.Value)
			}
		}
		assertInt64 := func(name string, got types.Int64, wantNull bool, wantVal int64) {
			t.Helper()
			if got.Null != wantNull {
				t.Errorf("%s: Null mismatch: want %v got %v", name, wantNull, got.Null)
			}
			if !got.Null && got.Value != wantVal {
				t.Errorf("%s: Value mismatch: want %v got %v", name, wantVal, got.Value)
			}
		}

		assertBool("DelegateEnrollment", state.DelegateEnrollment, false, true)
		assertBool("MonitorThresholds", state.MonitorThresholds, false, false)
		assertBool("NewEndEntityOnRenewAndReissue", state.NewEndEntityOnRenewAndReissue, false, true)
		assertInt64("AllowedEnrollmentTypes", state.AllowedEnrollmentTypes, false, 3)
	})

	t.Run("force_save is always Null from server", func(t *testing.T) {
		t.Parallel()

		resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
		resp.SetId(1)
		resp.SetLogicalName("CA")
		resp.SetHostName("http://ca/ejbca")
		resp.CAType = &caType

		state := caResponseToState(resp)

		if !state.ForceSave.Null {
			t.Errorf("ForceSave: want Null=true (write-only), got Value=%v Null=%v",
				state.ForceSave.Value, state.ForceSave.Null)
		}
	})
}
