package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- PR #210 full-review finding FIX-5:
//
// The vendored SDK's decode() (vendor/github.com/Keyfactor/keyfactor-go-
// client-sdk/v25/api/keyfactor/v1/client.go) returns (nil, httpResp, nil) --
// no error at all -- for any 2xx response with an empty body, because
// json.Unmarshal is never invoked when the body length is 0. Before this
// fix, every Create/Read/Update/ImportState path in resource_keyfactor_
// enrollment_pattern.go checked `if err != nil` and then immediately
// dereferenced the response pointer (enrollmentPatternResponseToState(resp),
// preserveUndeclaredEnrollmentPatternFields(&plan, current)) with no nil
// guard at all -- a real, remotely-triggerable panic from a compromised/
// malicious Command server, a MITM (this provider supports
// KEYFACTOR_SKIP_VERIFY), or a buggy proxy/load balancer returning an empty
// 200. Each call site now checks `resp == nil` / `current == nil`
// immediately after the err-check block and returns a diagnostics error
// instead of proceeding.
//
// These tests serve an empty-body 200 response for every request the
// resource makes and confirm each entry point returns a diagnostics error
// -- not a panic -- instead of reaching the conversion functions.
// ---------------------------------------------------------------------------

// emptyBody200Server answers every request with a 2xx status and a
// completely empty body, reproducing the vendored SDK's decode() nil-
// response-nil-error shape.
func emptyBody200Server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestUnitEnrollmentPatternCreateHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := enrollmentPatternSchemaForTest(t, ctx)

	config := blankEnrollmentPatternState()
	config.Name = types.String{Value: "Demo Pattern_TF"}
	config.TemplateId = types.Int64{Value: 6}
	config.Policies = &EnrollmentPatternResourcePolicy{}
	config.AssociatedRoleNames = types.Set{Null: true, ElemType: types.StringType}

	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}
	planObj := tfsdk.Plan{Schema: schema, Raw: scratch.Raw}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.CreateResourceRequest{Config: configObj, Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Create panicked on a nil (empty-body 200) API response: %v", r)
			}
		}()
		r.Create(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Create with a nil API response should return a diagnostics error, got none")
	}
}

func TestUnitEnrollmentPatternReadHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	state.AssociatedRoleNames = types.Set{Null: true, ElemType: types.StringType}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Read panicked on a nil (empty-body 200) API response: %v", r)
			}
		}()
		r.Read(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Read with a nil API response should return a diagnostics error, got none")
	}
}

func TestUnitEnrollmentPatternUpdateHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	state.Policies = &EnrollmentPatternResourcePolicy{}
	state.AssociatedRoleNames = types.Set{Null: true, ElemType: types.StringType}

	config := state

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}
	planObj := tfsdk.Plan{Schema: schema, Raw: scratch.Raw}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf(
					"Update panicked on a nil (empty-body 200) API response -- this covers both the pre-update GET "+
						"(preserveUndeclaredEnrollmentPatternFields) and the PUT response itself: %v", r,
				)
			}
		}()
		r.Update(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Update with a nil API response should return a diagnostics error, got none")
	}
}

func TestUnitEnrollmentPatternImportStateHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := enrollmentPatternSchemaForTest(t, ctx)

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ImportResourceStateRequest{ID: "42"}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ImportState panicked on a nil (empty-body 200) API response: %v", r)
			}
		}()
		r.ImportState(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("ImportState with a nil API response should return a diagnostics error, got none")
	}
}
