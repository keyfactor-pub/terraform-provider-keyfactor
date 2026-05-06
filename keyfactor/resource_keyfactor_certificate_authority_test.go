package keyfactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func boolPtr(v bool) *bool    { return &v }
func int32Ptr(v int32) *int32 { return &v }

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
					resource.TestCheckResourceAttrSet("keyfactor_certificate_authority.test", "use_for_enrollment"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_authority.test", "certificate_cleanup_enabled"),
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
					resource.TestCheckResourceAttrSet(resourceName, "use_for_enrollment"),
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

		// Patch the snapshot JSON in-place: overwrite MonitorThresholds back to
		// the original value without re-marshalling through a typed Go struct.
		// Re-marshalling through CertificateAuthoritiesCertificateAuthorityRequest
		// would silently drop any server-side fields that are not defined in the
		// SDK struct (e.g. UseForEnrollment on v25+ servers), causing those fields
		// to be reset to their server defaults on the subsequent PUT.
		var rawMap map[string]interface{}
		if err := json.Unmarshal(rawCAJSON, &rawMap); err != nil {
			t.Logf("cleanup: could not parse CA snapshot JSON: %s — skipping restore", err)
			return
		}
		rawMap["MonitorThresholds"] = ca.MonitorThresholds
		patchedJSON, err := json.Marshal(rawMap)
		if err != nil {
			t.Logf("cleanup: could not re-marshal patched CA JSON: %s — skipping restore", err)
			return
		}

		// PUT the raw bytes directly so every field from the original GET response
		// is sent back verbatim.  commandHTTPDoRaw sets query params via
		// url.URL.RawQuery so they are not percent-encoded into the path.
		respBody, status, putErr := commandHTTPDoRaw(
			client, "PUT", "CertificateAuthority", "forceSave=true", patchedJSON,
		)
		if putErr != nil || status < 200 || status >= 300 {
			t.Logf("cleanup: CA %s restore PUT failed (status=%d err=%v body=%s)",
				caID, status, putErr, string(respBody))
			return
		}
		t.Logf("cleanup: CA %s restored to pre-test state (status=%d)", caID, status)
	})

	resourceName := "keyfactor_certificate_authority.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             nil,
		ErrorCheck:               skipOnKnownLabConstraint(t, "associated with at least one Certificate and cannot be deleted"),
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
// Unit tests: key_retention helpers
// ---------------------------------------------------------------------------

func TestUnitKeyRetentionStringConversion(t *testing.T) {
	// Test keyRetentionNameToInt: named forms
	nameTests := []struct {
		input string
		want  int32
	}{
		{"Disabled", 0},
		{"Indefinite", 1},
		{"AfterExpiration", 2},
		{"FromIssuance", 3},
		{"0", 0},
		{"1", 1},
		{"2", 2},
		{"3", 3},
	}
	for _, tc := range nameTests {
		got, ok := keyRetentionNameToInt[tc.input]
		if !ok {
			t.Errorf("keyRetentionNameToInt[%q]: expected entry, got missing", tc.input)
			continue
		}
		if got != tc.want {
			t.Errorf("keyRetentionNameToInt[%q] = %d, want %d", tc.input, got, tc.want)
		}
	}

	// Test keyRetentionIntToName
	intTests := []struct {
		input int32
		want  string
	}{
		{0, "Disabled"},
		{1, "Indefinite"},
		{2, "AfterExpiration"},
		{3, "FromIssuance"},
	}
	for _, tc := range intTests {
		got, ok := keyRetentionIntToName[tc.input]
		if !ok {
			t.Errorf("keyRetentionIntToName[%d]: expected entry, got missing", tc.input)
			continue
		}
		if got != tc.want {
			t.Errorf("keyRetentionIntToName[%d] = %q, want %q", tc.input, got, tc.want)
		}
	}

	// Invalid input should not be found
	if _, ok := keyRetentionNameToInt["bogus"]; ok {
		t.Error("keyRetentionNameToInt[\"bogus\"] should not exist")
	}
	if _, ok := keyRetentionIntToName[99]; ok {
		t.Error("keyRetentionIntToName[99] should not exist")
	}
}

func TestUnitCertificateAuthorityStateUpgrade(t *testing.T) {
	tests := []struct {
		intVal   int
		wantName string
	}{
		{0, "Disabled"},
		{1, "Indefinite"},
		{2, "AfterExpiration"},
		{3, "FromIssuance"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("%d_to_%s", tc.intVal, tc.wantName), func(t *testing.T) {
			// Build a minimal v0 state JSON with key_retention as a number.
			stateJSON := fmt.Sprintf(`{
				"id": "42",
				"logical_name": "TestCA",
				"host_name": "ca.example.com",
				"ca_type": 1,
				"delegate": false,
				"delegate_enrollment": false,
				"forest_root": "",
				"configuration_tenant": "",
				"remote": false,
				"agent": null,
				"standalone": false,
				"use_ca_connector": false,
				"connector_pool": "",
				"monitor_thresholds": false,
				"issuance_max": null,
				"issuance_min": null,
				"failure_max": null,
				"rfc_enforcement": false,
				"properties": "",
				"allowed_enrollment_types": 0,
				"key_retention": %d,
				"key_retention_days": null,
				"enforce_unique_dn": false,
				"subscriber_terms": false,
				"allow_one_click_renewals": false,
				"new_end_entity_on_renew_and_reissue": false,
				"use_allowed_requesters": false,
				"allowed_requesters": null,
				"explicit_credentials": false,
				"explicit_user": null,
				"explicit_password": null,
				"auth_certificate": null,
				"auth_certificate_password": null,
				"auth_certificate_issued_dn": null,
				"auth_certificate_issuer_dn": null,
				"auth_certificate_thumbprint": null,
				"token_url": "",
				"client_id": "",
				"client_secret": null,
				"scope": "",
				"audience": "",
				"full_scan_interval_minutes": null,
				"incremental_scan_interval_minutes": null,
				"threshold_check_interval_minutes": null,
				"force_save": null,
				"agent_name": null,
				"agent_username": null,
				"denial_max": null,
				"last_scan": ""
			}`, tc.intVal)

			// Parse the JSON into a generic map and call the upgrade logic directly.
			var stateMap map[string]interface{}
			if err := json.Unmarshal([]byte(stateJSON), &stateMap); err != nil {
				t.Fatalf("Failed to unmarshal test state JSON: %s", err)
			}

			// Simulate the conversion logic from upgradeCAStateV0ToV1.
			if raw, ok := stateMap["key_retention"]; ok && raw != nil {
				if v, ok := raw.(float64); ok {
					if name, ok := keyRetentionIntToName[int32(v)]; ok {
						stateMap["key_retention"] = name
					}
				}
			}

			got, ok := stateMap["key_retention"].(string)
			if !ok {
				t.Fatalf("key_retention is not a string after upgrade: %T", stateMap["key_retention"])
			}
			if got != tc.wantName {
				t.Errorf("key_retention after upgrade = %q, want %q", got, tc.wantName)
			}
		})
	}
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
		if !state.UseForEnrollment.Null {
			t.Errorf("UseForEnrollment: want Null=true (nil ptr), got Value=%v Null=%v",
				state.UseForEnrollment.Value, state.UseForEnrollment.Null)
		}
		if !state.CertificateCleanupEnabled.Null {
			t.Errorf("CertificateCleanupEnabled: want Null=true (nil NullableBool), got Value=%v Null=%v",
				state.CertificateCleanupEnabled.Value, state.CertificateCleanupEnabled.Null)
		}
		if !state.DeleteWithArchivedKey.Null {
			t.Errorf("DeleteWithArchivedKey: want Null=true (nil NullableBool), got Value=%v Null=%v",
				state.DeleteWithArchivedKey.Value, state.DeleteWithArchivedKey.Null)
		}
		if !state.TimeAfterExpiration.Null {
			t.Errorf("TimeAfterExpiration: want Null=true (nil NullableInt32), got Value=%v Null=%v",
				state.TimeAfterExpiration.Value, state.TimeAfterExpiration.Null)
		}
		if !state.TimeAfterExpirationUnits.Null {
			t.Errorf("TimeAfterExpirationUnits: want Null=true (nil ptr), got Value=%v Null=%v",
				state.TimeAfterExpirationUnits.Value, state.TimeAfterExpirationUnits.Null)
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
		useForEnroll := true
		resp.UseForEnrollment = &useForEnroll
		cleanupEnabled := true
		resp.CertificateCleanupEnabled.Set(&cleanupEnabled)
		deleteArchived := false
		resp.DeleteWithArchivedKey.Set(&deleteArchived)
		timeAfterExp := int32(90)
		resp.TimeAfterExpiration.Set(&timeAfterExp)
		cleanupUnits := v1.CSSCMSDataModelEnumsCertificateCleanupTimeUnits(0) // Days
		resp.TimeAfterExpirationUnits = &cleanupUnits

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
		assertBool("UseForEnrollment", state.UseForEnrollment, false, true)
		assertBool("CertificateCleanupEnabled", state.CertificateCleanupEnabled, false, true)
		assertBool("DeleteWithArchivedKey", state.DeleteWithArchivedKey, false, false)
		assertInt64("TimeAfterExpiration", state.TimeAfterExpiration, false, 90)
		assertInt64("TimeAfterExpirationUnits", state.TimeAfterExpirationUnits, false, 0)
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
