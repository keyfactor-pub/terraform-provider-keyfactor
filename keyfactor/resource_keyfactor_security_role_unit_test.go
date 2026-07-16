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

// TestUnitSecurityRoleUpdateArgPermissions is a regression test for the bug
// where a Null (undeclared) permissions attribute resolved to a nil Go slice
// that was still wrapped in a non-nil pointer (&permissions). The non-nil
// pointer bypassed the SDK's `omitempty`, so the request marshaled as
// `"Permissions": null` and cleared every permission the role had. permissions
// is Optional (not Computed): Null must omit the field (preserve), while an
// explicit empty list must be sent as [] (clear).
func TestUnitSecurityRoleUpdateArgPermissions(t *testing.T) {
	ctx := context.Background()

	t.Run("undeclared permissions omits the field (preserve)", func(t *testing.T) {
		plan := SecurityRole{
			Name:        types.String{Value: "role"},
			Permissions: types.List{Null: true, ElemType: types.StringType},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, 5)
		assert.Nil(t, arg.Permissions,
			"undeclared permissions must be omitted so Command preserves the role's existing permissions")
	})

	t.Run("explicit empty list clears", func(t *testing.T) {
		plan := SecurityRole{
			Name:        types.String{Value: "role"},
			Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{}},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, 5)
		if assert.NotNil(t, arg.Permissions, "explicit permissions=[] must be sent as a clear signal") {
			assert.Equal(t, []string{}, *arg.Permissions,
				"an explicit empty permissions list must serialize as [] (clear), not null")
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
		arg := buildSecurityRoleUpdateArg(ctx, plan, 5)
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

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
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
// ordering-drift bug above) also masks genuine server-side drift — e.g.
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

	r := resourceSecurityRole{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
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
