package keyfactor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitSecurityRoleUpdateArgPermissions is a regression test for two
// distinct bugs found in buildSecurityRoleUpdateArg, in order of discovery:
//
//  1. (original) A Null (undeclared) permissions attribute resolved to a nil
//     Go slice that was still wrapped in a non-nil pointer (&permissions).
//     The non-nil pointer bypassed the SDK's `omitempty`, so the request
//     marshaled as `"Permissions": null` and cleared every permission the
//     role had.
//  2. (found validating PR179 live against a real Command instance, NOT
//     catchable by any mock/VCR test that doesn't model the server's actual
//     merge semantics) Command's PUT /Security/Roles is a full-replace
//     endpoint: omitting the "Permissions" key from the request body
//     entirely -- not just avoiding an explicit null -- STILL resets the
//     role's permissions to an empty list server-side. Unlike Enabled/Private
//     (which Command preserves when omitted), Permissions gets clear-if-absent
//     handling. So "omit the field to preserve" was never actually true for
//     this endpoint; the only way to genuinely preserve permissions across an
//     Update that omits `permissions` from config is to resend the role's
//     current (state) permissions explicitly. buildSecurityRoleUpdateArg now
//     takes the state's permissions as a fallback for exactly this.
func TestUnitSecurityRoleUpdateArgPermissions(t *testing.T) {
	ctx := context.Background()

	statePermissions := types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "certificates:read"},
		types.String{Value: "auditing:read"},
	}}

	t.Run("undeclared permissions resends state permissions (preserve)", func(t *testing.T) {
		plan := SecurityRole{
			Name:        types.String{Value: "role"},
			Permissions: types.List{Null: true, ElemType: types.StringType},
		}
		declared := types.List{Null: true, ElemType: types.StringType}
		arg := buildSecurityRoleUpdateArg(ctx, plan, declared, statePermissions, 5)
		if assert.NotNil(t, arg.Permissions,
			"undeclared permissions must still be sent explicitly -- Command's PUT clears permissions when the field is absent, it does not preserve them") {
			assert.ElementsMatch(t, []string{"certificates:read", "auditing:read"}, *arg.Permissions,
				"undeclared permissions must resend the role's current state permissions, not omit the field")
		}
	})

	t.Run("explicit empty list clears", func(t *testing.T) {
		plan := SecurityRole{
			Name:        types.String{Value: "role"},
			Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{}},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, plan.Permissions, statePermissions, 5)
		if assert.NotNil(t, arg.Permissions, "explicit permissions=[] must be sent as a clear signal") {
			assert.Equal(t, []string{}, *arg.Permissions,
				"an explicit empty permissions list must serialize as [] (clear), not preserved from state")
		}
	})

	t.Run("populated permissions are sent", func(t *testing.T) {
		plan := SecurityRole{
			Name: types.String{Value: "role"},
			Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{
				types.String{Value: "certificates:read"},
				types.String{Value: "auditing:read"},
			}},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, plan.Permissions, statePermissions, 5)
		if assert.NotNil(t, arg.Permissions) {
			assert.ElementsMatch(t, []string{"certificates:read", "auditing:read"}, *arg.Permissions)
		}
	})
}

// TestUnitSecurityRoleResource_UpdatePreservesPlanPermissionsOrder is a
// regression test for permissions being written to state as an
// alphabetically-sorted copy of the server's Permissions response.
// permissions is Optional (not Computed): the post-apply state value must
// equal what the plan declared, in the order the config listed it, or
// Terraform reports "Provider produced inconsistent result after apply" for
// any config that lists permissions in a non-alphabetical order.
//
// This exercises the real Update() path end-to-end against a mock Command
// server that deliberately returns permissions in a DIFFERENT (alphabetical)
// order than the plan declared, guarding against a future regression that
// writes remoteState.Permissions (server order) into result state instead of
// plan.Permissions (config order).
func TestUnitSecurityRoleResource_UpdatePreservesPlanPermissionsOrder(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Server returns permissions alphabetically sorted -- a different
		// order than the plan below, which is deliberately non-alphabetical.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":          5,
			"Name":        "tf-unit-role",
			"Description": "Unit test role",
			"Permissions": []string{"Certificates:EditMetadata", "Certificates:Read"},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	// Plan declares permissions in non-alphabetical order.
	planPermissions := types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "Certificates:Read"},
		types.String{Value: "Certificates:EditMetadata"},
	}}

	plan := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role"},
		Description: types.String{Value: "Unit test role"},
		Permissions: planPermissions,
	}
	state := plan

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	// Config mirrors the plan here (permissions is explicitly declared) --
	// Update() now reads request.Config to distinguish "declared" from
	// "omitted", since permissions is Optional+Computed (see
	// permissionsResultForUpdate's doc comment).
	config := plan
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityRole
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var permissions []string
	for _, e := range result.Permissions.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected permissions element to be types.String, got %T", e)
		}
		permissions = append(permissions, s.Value)
	}

	assert.Equal(
		t, []string{"Certificates:Read", "Certificates:EditMetadata"}, permissions,
		"Update() must write permissions to state in the plan's declared order, not a re-sorted server copy, or Terraform sees drift on any non-alphabetical config",
	)
}

// TestUnitSecurityRoleResource_UpdateSurfacesRealServerDrift is the companion
// regression test to TestUnitSecurityRoleResource_UpdatePreservesPlanPermissionsOrder:
// unconditionally echoing plan.Permissions back into state (to avoid the
// ordering-drift bug above) also masks genuine server-side drift -- e.g.
// Command rejecting or dropping a permission during Update. When the
// server's response Permissions is NOT the same set as the plan's declared
// permissions (regardless of order), Update() must write the server's
// permissions into state so the next plan surfaces the real drift, instead
// of silently echoing back permissions Command never actually persisted.
func TestUnitSecurityRoleResource_UpdateSurfacesRealServerDrift(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Server drops "Certificates:EditMetadata" -- simulating Command
		// rejecting/dropping a permission during update. This is a genuinely
		// different set than the plan, not just a different order.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":          5,
			"Name":        "tf-unit-role",
			"Description": "Unit test role",
			"Permissions": []string{"Certificates:Read"},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	planPermissions := types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "Certificates:Read"},
		types.String{Value: "Certificates:EditMetadata"},
	}}

	plan := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role"},
		Description: types.String{Value: "Unit test role"},
		Permissions: planPermissions,
	}
	state := plan

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	// Config mirrors the plan here (permissions is explicitly declared) --
	// Update() now reads request.Config to distinguish "declared" from
	// "omitted", since permissions is Optional+Computed (see
	// permissionsResultForUpdate's doc comment).
	config := plan
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityRole
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var permissions []string
	for _, e := range result.Permissions.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected permissions element to be types.String, got %T", e)
		}
		permissions = append(permissions, s.Value)
	}

	assert.Equal(
		t, []string{"Certificates:Read"}, permissions,
		"Update() must write the server's actual permissions into state when they genuinely differ from the plan (real drift), not silently echo back the plan's declared permissions",
	)
}

// TestUnitSecurityRoleResource_ReadDetectsOutOfBandDrift is a regression test
// for resourceSecurityRole.Read never actually contacting Keyfactor Command:
// since the resource was first written (2022-09-01, commit dc082e2), the
// GetSecurityRole call in Read was commented out and Read simply re-set
// whatever was already in Terraform state. Consequence: if a role's name,
// description, or permissions were changed directly in Command (out-of-band),
// `terraform plan`/refresh never detected the drift.
//
// This exercises the real Read() path against a mock Command server that
// returns a Description (and Permissions) different from prior state, proving
// Read now surfaces the server's current values instead of echoing back
// stale state.
func TestUnitSecurityRoleResource_ReadDetectsOutOfBandDrift(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/5", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Server reports a Description and Permissions set that differ from
		// prior state -- simulating an out-of-band change made directly in
		// Keyfactor Command.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":          5,
			"Name":        "tf-unit-role",
			"Description": "Changed out-of-band in Command",
			"Permissions": []string{"Certificates:Read"},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	// Prior state reflects what Terraform last knew -- stale relative to the
	// server's current values above.
	priorState := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role"},
		Description: types.String{Value: "Original description"},
		Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Certificates:Read"},
			types.String{Value: "Certificates:EditMetadata"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityRole
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	assert.Equal(
		t, "Changed out-of-band in Command", result.Description.Value,
		"Read() must surface the server's current description, not silently re-set stale prior state -- this is the out-of-band drift detection bug",
	)

	var permissions []string
	for _, e := range result.Permissions.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected permissions element to be types.String, got %T", e)
		}
		permissions = append(permissions, s.Value)
	}
	assert.Equal(
		t, []string{"Certificates:Read"}, permissions,
		"Read() must surface the server's actual permission set when it genuinely differs from prior state (real drift), not echo back stale state",
	)
}

// TestUnitSecurityRoleResource_ReadPreservesPermissionsOrderWhenUnchanged is
// the companion test to
// TestUnitSecurityRoleResource_ReadDetectsOutOfBandDrift: it guards against a
// naive fix that always writes the server's (alphabetically sorted)
// permissions into state on Read, which would introduce a spurious
// "permissions reordered" diff on every refresh even when nothing changed.
// When the server's permission set is unchanged (same set, any order), Read
// must preserve the state's declared order.
func TestUnitSecurityRoleResource_ReadPreservesPermissionsOrderWhenUnchanged(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/5", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Server returns the same set of permissions as prior state, but
		// alphabetically sorted -- a different order.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":          5,
			"Name":        "tf-unit-role",
			"Description": "Unit test role",
			"Permissions": []string{"Certificates:EditMetadata", "Certificates:Read"},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	// Prior state declares permissions in non-alphabetical order.
	priorState := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role"},
		Description: types.String{Value: "Unit test role"},
		Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Certificates:Read"},
			types.String{Value: "Certificates:EditMetadata"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityRole
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var permissions []string
	for _, e := range result.Permissions.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected permissions element to be types.String, got %T", e)
		}
		permissions = append(permissions, s.Value)
	}

	assert.Equal(
		t, []string{"Certificates:Read", "Certificates:EditMetadata"}, permissions,
		"Read() must preserve prior state's declared permissions order when the server's set is unchanged, not write back a re-sorted server copy",
	)
}

// TestUnitSecurityRoleResource_ReadRemovesResourceOn404 is a regression test
// for resourceSecurityRole.Read unconditionally AddError-ing on any error
// from GetSecurityRole. GetSecurityRole (github.com/Keyfactor/keyfactor-go-
// client/v3/api) converts an HTTP 404 into a non-nil Go error rather than a
// structured status code, so a role deleted out-of-band in Keyfactor Command
// previously bricked every subsequent `terraform plan`/refresh/destroy for
// that resource until the user manually ran `terraform state rm`.
//
// This exercises the real Read() path against a mock Command server that
// returns HTTP 404 for the role, proving Read now removes the resource from
// state (so Terraform plans a re-create) instead of erroring.
func TestUnitSecurityRoleResource_ReadRemovesResourceOn404(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/5", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Message": "Role not found",
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role"},
		Description: types.String{Value: "Original description"},
		Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Certificates:Read"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)

	assert.False(t, resp.Diagnostics.HasError(),
		"Read() must not error on a 404 -- it should remove the resource from state so Terraform plans a re-create, not brick plan/refresh/destroy: %+v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull(),
		"Read() must remove the resource from state (State.Raw must be null) when the role is not found on Keyfactor")
}

// TestUnitSecurityRoleResource_ReadErrorsOnNon404 is the companion regression
// test to TestUnitSecurityRoleResource_ReadRemovesResourceOn404: it guards
// against a naive fix that treats ANY GetSecurityRole error as "not found"
// and silently removes the resource from state, which would mask real
// errors (5xx, auth, network) as spurious deletes. A non-404 error from
// GetSecurityRole must still fail Read with an error diagnostic.
func TestUnitSecurityRoleResource_ReadErrorsOnNon404(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/5", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Message": "Internal Server Error",
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role"},
		Description: types.String{Value: "Original description"},
		Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Certificates:Read"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)

	assert.True(t, resp.Diagnostics.HasError(),
		"Read() must surface a non-404 error (e.g. HTTP 500) as an error diagnostic, not silently remove the resource from state")
}

// TestUnitSecurityRoleSchema_PermissionsIsComputedWithUseStateForUnknown is a
// regression test for "Provider produced inconsistent result after apply:
// .permissions: was null, but now cty.ListVal(...)" -- the identical defect to
// the one fixed for keyfactor_identity's `roles` attribute (see
// TestUnitSecurityIdentitySchema_RolesIsComputedWithUseStateForUnknown in
// resource_keyfactor_security_identity_unit_test.go).
//
// permissions was Optional but NOT Computed. permissionsResultForUpdate (used
// by Update()) deliberately writes a concrete, non-null permissions list into
// the result whenever the config omits permissions, to preserve the role's
// existing permissions across an unrelated Update. But for a non-Computed
// attribute, Terraform Core plans directly from config with no path for a
// provider-side plan modifier to intervene, so an omitted-from-config
// permissions attribute always plans as Null. Any role with permissions
// already assigned then failed apply with "Provider produced inconsistent
// result after apply" on any unrelated Update.
//
// Why this shipped: this repo's TestUnit* harness for this resource
// (TestUnitSecurityRoleResource_UpdatePreservesPlanPermissionsOrder etc.,
// above) calls resourceSecurityRole's methods directly via hand-built
// tfsdk.Plan/tfsdk.State values -- it never drives a real Terraform Core
// plan/apply cycle, so a schema-shape defect like this one is invisible to
// it (Update()'s return value looks correct in isolation). Unlike
// TestUnitKeyfactorIdentityResource, this resource's one VCR-backed
// resource.UnitTest (TestUnitKeyfactorSecurityRoleResource) never has a step
// that omits permissions from config -- extending its cassette would require
// recording a new interaction against a live lab, out of scope for this fix.
// The strongest regression test achievable without that is asserting the
// schema fix directly, mirroring
// TestUnitTemplateSchema_V25CleanupFieldsUseStateForUnknown's approach for
// the same bug class on a different resource.
func TestUnitSecurityRoleSchema_PermissionsIsComputedWithUseStateForUnknown(t *testing.T) {
	ctx := context.Background()

	schema, diags := resourceSecurityRoleType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", diags)
	}

	attribute, ok := schema.Attributes["permissions"]
	if !ok {
		t.Fatalf("expected schema attribute %q to exist", "permissions")
	}

	if !attribute.Optional || !attribute.Computed {
		t.Fatalf("attribute %q: expected Optional+Computed, got Optional=%v Computed=%v", "permissions", attribute.Optional, attribute.Computed)
	}

	found := false
	for _, m := range attribute.PlanModifiers {
		if _, ok := m.(tfsdk.UseStateForUnknownModifier); ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("attribute %q: expected UseStateForUnknown plan modifier so an omitted-from-config value carries forward from state instead of planning Null, but none was found (modifiers: %+v)", "permissions", attribute.PlanModifiers)
	}
}

// TestUnitSecurityRoleResource_UpdatePreservesPermissionsWhenConfigOmitsThem
// is a functional companion to the schema-level test above: it exercises the
// real Update() path with a Config that omits permissions (Null) but a Plan
// that already carries the prior state's permissions forward -- reproducing
// exactly what UseStateForUnknownModifier hands Update() once the schema fix
// is in place (see UseStateForUnknownModifier.Modify in
// vendor/.../tfsdk/attribute_plan_modification.go: it copies AttributeState
// into AttributePlan when AttributeConfig is null and AttributePlan is
// unknown). It asserts Update()'s returned Permissions is IDENTICAL to the
// planned value, which is the actual invariant Terraform Core enforces ("the
// final value of a Known planned attribute must not change") -- not just "the
// right permissions in some form."
//
// NOTE on red/green: this test's mock server models Command's REAL PUT
// /Security/Roles full-replace semantics (confirmed live against
// int25-4-1.kftestlab.com while validating PR179 end-to-end): a request body
// that omits the "Permissions" key entirely is treated as clearing
// permissions to [], not as "leave unchanged". An earlier version of this
// mock unconditionally echoed back a fixed Permissions list regardless of
// what the request actually sent, which made it pass even against the
// original pre-fix buildSecurityRoleUpdateArg (nil/omitted Permissions on an
// undeclared config) -- masking the exact data-loss bug a real Terraform
// apply cycle against a live Command instance caught. With the body-aware
// mock below, this test now genuinely fails if buildSecurityRoleUpdateArg
// omits Permissions instead of resending the state's current permissions.
//
// The server response deliberately matches the prior state's permission set
// exactly (same set, different case-preserved order is irrelevant here since
// the plan/state list is already used verbatim): this isolates the
// "undeclared config" code path from permissionsResultForUpdate's separate
// drift-detection behavior, which is already covered by
// TestUnitSecurityRoleResource_UpdateSurfacesRealServerDrift above.
func TestUnitSecurityRoleResource_UpdatePreservesPermissionsWhenConfigOmitsThem(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Permissions *[]string `json:"Permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		// Mimic Command's real full-replace behavior: an absent/null
		// Permissions key clears permissions to an empty list; the field is
		// never treated as "leave unchanged".
		permissions := []string{}
		if body.Permissions != nil {
			permissions = *body.Permissions
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":          5,
			"Name":        "tf-unit-role-preserve",
			"Description": "Updated description, unrelated to permissions",
			"Permissions": permissions,
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorPermissions := types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "Certificates:Read"},
	}}

	state := SecurityRole{
		ID:          types.Int64{Value: 5},
		Name:        types.String{Value: "tf-unit-role-preserve"},
		Description: types.String{Value: "Original description"},
		Permissions: priorPermissions,
	}

	// The plan is what UseStateForUnknownModifier produces: the prior
	// state's permissions copied forward because config is null and the raw
	// plan was unknown. Only description changes, mirroring an unrelated
	// Update.
	plan := state
	plan.Description = types.String{Value: "Updated description, unrelated to permissions"}

	// The config is what the practitioner actually wrote: permissions is
	// genuinely absent (Null).
	config := SecurityRole{
		ID:          state.ID,
		Name:        state.Name,
		Description: plan.Description,
		Permissions: types.List{Null: true, ElemType: types.StringType},
	}

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

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityRole
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var gotPermissions []string
	for _, e := range result.Permissions.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected permissions element to be types.String, got %T", e)
		}
		gotPermissions = append(gotPermissions, s.Value)
	}

	assert.Equal(
		t, []string{"Certificates:Read"}, gotPermissions,
		"Update() must write exactly the planned permissions into state when config omits the attribute -- Terraform Core already committed to this planned value, so any divergence is an inconsistent-result-after-apply error",
	)
}
