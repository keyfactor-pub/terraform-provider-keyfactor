package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: nil API response guard (certificate_
// collection side):
//
// Same nil-response-nil-error shape as resource_keyfactor_enrollment_
// pattern_nil_response_unit_test.go -- see that file's doc comment for the
// full root-cause explanation. resource_keyfactor_certificate_collection.go's
// Create/Read/Update/ImportState each dereferenced their Execute() response
// with no nil guard at all before this fix.
// ---------------------------------------------------------------------------

func certificateCollectionSchemaForTest(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceCertificateCollectionType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("test setup: GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

func TestUnitCertificateCollectionCreateHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := certificateCollectionSchemaForTest(t, ctx)

	plan := KeyfactorCertificateCollectionState{
		Name:  types.String{Value: "Demo Collection_TF"},
		Query: types.String{Value: `IssuedDN -contains "demo"`},
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.CreateResourceRequest{Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Create panicked on a nil (empty-body 200) API response: %v", rec)
			}
		}()
		r.Create(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Create with a nil API response should return a diagnostics error, got none")
	}
}

func TestUnitCertificateCollectionReadHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := certificateCollectionSchemaForTest(t, ctx)

	state := KeyfactorCertificateCollectionState{
		ID:    types.Int64{Value: 8},
		Name:  types.String{Value: "Demo Collection_TF"},
		Query: types.String{Value: `IssuedDN -contains "demo"`},
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Read panicked on a nil (empty-body 200) API response: %v", rec)
			}
		}()
		r.Read(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Read with a nil API response should return a diagnostics error, got none")
	}
}

func TestUnitCertificateCollectionUpdateHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := certificateCollectionSchemaForTest(t, ctx)

	state := KeyfactorCertificateCollectionState{
		ID:    types.Int64{Value: 8},
		Name:  types.String{Value: "Demo Collection_TF"},
		Query: types.String{Value: `IssuedDN -contains "demo"`},
	}
	plan := state

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: planObj.Raw}

	r := resourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf(
					"Update panicked on a nil (empty-body 200) API response -- this covers both the pre-update "+
						"GET and the update response itself: %v", rec,
				)
			}
		}()
		r.Update(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Update with a nil API response should return a diagnostics error, got none")
	}
}

func TestUnitCertificateCollectionImportStateHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := certificateCollectionSchemaForTest(t, ctx)

	r := resourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ImportResourceStateRequest{ID: "8"}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("ImportState panicked on a nil (empty-body 200) API response: %v", rec)
			}
		}()
		r.ImportState(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("ImportState with a nil API response should return a diagnostics error, got none")
	}
}
