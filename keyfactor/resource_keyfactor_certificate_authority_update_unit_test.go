package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	kfsdk "github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// newCAMockSDKClient builds a kfsdk.APIClient backed by an httptest server,
// for framework-realistic unit tests of the certificate authority resource's
// Update() method (which calls through r.p.sdkClient.V1.CertificateAuthorityApi).
// Modeled on newOAuthRoleClaimAssocMockClient
// (resource_keyfactor_oauth_security_role_claim_association_unit_test.go).
func newCAMockSDKClient(server *httptest.Server) *kfsdk.APIClient {
	return kfsdk.NewAPIClientWithAuth(newSDKMockAuthConfig(server))
}

// caScheduleWireCapture decodes just the parts of a
// CertificateAuthoritiesCertificateAuthorityRequest PUT body this test cares
// about: whether FullScan carries an Interval, a Daily, or neither.
type caScheduleWireCapture struct {
	FullScan *struct {
		Interval *struct {
			Minutes *int32 `json:"Minutes"`
		} `json:"Interval"`
		Daily *struct {
			Time *string `json:"Time"`
		} `json:"Daily"`
	} `json:"FullScan"`
}

// TestUnitCAUpdateVariantSwitchSendsDailyNotInterval is the framework-realistic
// red/green regression test for F182-1: a schedule variant switch (Interval ->
// Daily) must send Command exactly the newly-declared Daily schedule, never a
// stale/resurrected Interval value alongside it.
//
// The plan value here is deliberately constructed to be what the OLD
// tfsdk.UseStateForUnknown()-based schema (pre-pairedWith) would have produced
// for full_scan_interval_minutes: Known and equal to the PRIOR STATE value
// (60), because UseStateForUnknown blindly resurrects prior state whenever the
// incoming plan value is Unknown -- it has no notion of "but the sibling
// variant was just declared, so this one should go Null instead." Config is
// what the practitioner actually wrote: full_scan_interval_minutes undeclared,
// full_scan_daily_time = "07:00:00" (the switch).
//
// Before the fix (config-keyed preserveCAUpdateFields with the F182-1
// defense-in-depth Null-enforcement on the undeclared half of a declared
// pair), preserveCAUpdateFields's old plan-Null-keyed check saw
// plan.FullScanIntervalMinutes as Known (not Null) and concluded the user
// declared it, leaving both Interval=60 and Daily="07:00:00" Known
// simultaneously -- buildCARequest/buildSchedule would then send Interval
// (its precedence order) and silently drop the very Daily value the user just
// configured, or (after the dual-known guard in buildSchedule) error out
// entirely. Either way, the PUT does not match what Command's tagged-union
// schedule model allows, and does not reflect the user's declared config.
func TestUnitCAUpdateVariantSwitchSendsDailyNotInterval(t *testing.T) {
	ctx := context.Background()

	var capturedPutBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/CertificateAuthority", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		capturedPutBody = body

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"Id": 42,
			"LogicalName": "tf-unit-ca-variant-switch",
			"HostName": "ca.lab.example.com",
			"CAType": 1,
			"FullScan": {"Daily": {"Time": "2000-01-01T07:00:00Z"}}
		}`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	sdkClient := newCAMockSDKClient(server)

	schema, sDiags := resourceCertificateAuthorityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	// Prior state: a live Interval schedule (60 minutes), as a real CA GET
	// would have populated it.
	state := caAllSchedulesNull
	state.ID = types.String{Value: "42"}
	state.LogicalName = types.String{Value: "tf-unit-ca-variant-switch"}
	state.HostName = types.String{Value: "ca.lab.example.com"}
	state.CAType = types.Int64{Value: 1}
	state.FullScanIntervalMinutes = types.Int64{Value: 60}

	// Config: the practitioner's actual declaration -- switched to Daily.
	config := caAllSchedulesNull
	config.ID = state.ID
	config.LogicalName = state.LogicalName
	config.HostName = state.HostName
	config.CAType = state.CAType
	config.FullScanDailyTime = types.String{Value: "07:00:00"}

	// Plan: exactly what the OLD UseStateForUnknown modifier would have
	// produced -- the prior Interval value resurrected as Known, alongside
	// the newly-declared Daily value (also Known).
	plan := caAllSchedulesNull
	plan.ID = state.ID
	plan.LogicalName = state.LogicalName
	plan.HostName = state.HostName
	plan.CAType = state.CAType
	plan.FullScanIntervalMinutes = types.Int64{Value: 60}
	plan.FullScanDailyTime = types.String{Value: "07:00:00"}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceCertificateAuthority{p: provider{configured: true, sdkClient: sdkClient}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostic errors: %+v", resp.Diagnostics)
	}

	if len(capturedPutBody) == 0 {
		t.Fatal("expected the PUT /CertificateAuthority request body to have been captured")
	}

	var wire caScheduleWireCapture
	if err := json.Unmarshal(capturedPutBody, &wire); err != nil {
		t.Fatalf("failed to unmarshal captured PUT body: %s\nbody: %s", err, capturedPutBody)
	}

	if !assert.NotNil(t, wire.FullScan, "the PUT body must carry a FullScan schedule") {
		return
	}
	assert.Nil(t, wire.FullScan.Interval,
		"a variant switch to Daily must NOT send the stale Interval value from prior state")
	if assert.NotNil(t, wire.FullScan.Daily, "the PUT body's FullScan must carry the newly-declared Daily value") {
		assert.NotNil(t, wire.FullScan.Daily.Time)
	}
}
