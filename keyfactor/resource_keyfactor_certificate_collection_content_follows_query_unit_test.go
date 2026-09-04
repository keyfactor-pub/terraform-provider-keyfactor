package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: content-follows-query.
//
// content is a Computed attribute mirroring the server-normalized form of
// query. It used a plain tfsdk.UseStateForUnknown(), which unconditionally
// pins content to its PRIOR state value whenever content's own plan is
// Unknown -- including when query is CHANGING this apply. Since Update()'s
// response (collectionResponseToState(resp)) carries the newly-normalized
// content for the NEW query, the pinned (stale) planned value and the
// applied (fresh) value disagree, and Terraform Core hard-errors with
// "Provider produced inconsistent result after apply" on this resource's
// primary, defining update path (editing query) -- unless normalization
// happens to coincidentally produce the same string.
//
// followsDriverModifier[types.String] fixes this the same way as F2/F4:
// content is only pinned to prior state when query is NOT changing;
// otherwise it is left Unknown so Update()'s response-derived value can
// land in the final state without a planned-vs-applied mismatch.
// ---------------------------------------------------------------------------

// certificateCollectionSchemaForTest is defined in
// resource_keyfactor_certificate_collection_nil_response_unit_test.go and
// reused here.

// TestUnitCertificateCollectionContentUsesFollowsDriverModifier is the
// schema-level regression test for F3.
func TestUnitCertificateCollectionContentUsesFollowsDriverModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := certificateCollectionSchemaForTest(t, ctx)

	attr, ok := schema.Attributes["content"]
	if !ok {
		t.Fatal("schema has no content attribute")
	}

	found := false
	for _, m := range attr.PlanModifiers {
		if fd, ok := m.(followsDriverModifier[types.String]); ok {
			found = true
			wantPath := path.Root("query")
			if fd.driverPath.String() != wantPath.String() {
				t.Errorf("content: followsDriverModifier.driverPath = %q, want %q", fd.driverPath.String(), wantPath.String())
			}
		}
		if _, ok := m.(tfsdk.UseStateForUnknownModifier); ok {
			t.Error(
				"content: still has a plain tfsdk.UseStateForUnknown() attached -- this pins content to its " +
					"stale prior server-normalized form even when query is changing this apply, which is " +
					"exactly the bug F3 fixes",
			)
		}
	}
	if !found {
		t.Error("content: expected followsDriverModifier[types.String] among PlanModifiers")
	}
}

func blankCertificateCollectionState() KeyfactorCertificateCollectionState {
	nullStr := types.String{Null: true}
	nullBool := types.Bool{Null: true}
	nullInt := types.Int64{Null: true}
	return KeyfactorCertificateCollectionState{
		ID:                 nullInt,
		Name:               types.String{Value: ""},
		Description:        nullStr,
		Query:              nullStr,
		Content:            nullStr,
		DuplicationField:   nullInt,
		ShowOnDashboard:    nullBool,
		Favorite:           nullBool,
		EstimatedCertCount: nullInt,
		LastEstimated:      nullStr,
	}
}

func asCertificateCollectionConfig(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateCollectionState) tfsdk.Config {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.Config{Schema: schema, Raw: p.Raw}
}

func asCertificateCollectionState(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateCollectionState) tfsdk.State {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.State{Schema: schema, Raw: p.Raw}
}

// TestUnitCertificateCollectionContentFollowsDriverModifierPlansCorrectly is
// the root-bug regression test: simulates Terraform Core's plan phase for
// content/query by invoking followsDriverModifier[types.String] directly
// against a real Config/State built from the actual certificate_collection
// schema.
func TestUnitCertificateCollectionContentFollowsDriverModifierPlansCorrectly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := certificateCollectionSchemaForTest(t, ctx)

	tests := []struct {
		name         string
		driverState  types.String
		driverConfig types.String
		wantUnknown  bool
	}{
		{
			name:         "query re-declared with its current value -- not changing, pin content to prior state",
			driverState:  types.String{Value: `IssuedDN -contains "demo"`},
			driverConfig: types.String{Value: `IssuedDN -contains "demo"`},
			wantUnknown:  false,
		},
		{
			name:         "query changing to a new value -- leave content unknown",
			driverState:  types.String{Value: `IssuedDN -contains "demo"`},
			driverConfig: types.String{Value: `IssuedDN -contains "updated"`},
			wantUnknown:  true,
		},
		{
			name:         "query config itself unknown (chained value) -- leave content unknown",
			driverState:  types.String{Value: `IssuedDN -contains "demo"`},
			driverConfig: types.String{Unknown: true},
			wantUnknown:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := blankCertificateCollectionState()
			config.Query = tc.driverConfig
			state := blankCertificateCollectionState()
			state.Query = tc.driverState
			state.Content = types.String{Value: "prior-normalized-content"}

			cfg := asCertificateCollectionConfig(t, ctx, schema, config)
			st := asCertificateCollectionState(t, ctx, schema, state)

			m := followsDriverModifier[types.String]{driverPath: path.Root("query")}
			req := tfsdk.ModifyAttributePlanRequest{
				Config:          cfg,
				State:           st,
				AttributeConfig: types.String{Null: true}, // content is Computed-only; config is always null
				AttributeState:  types.String{Value: "prior-normalized-content"},
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if got.Unknown != tc.wantUnknown {
				t.Errorf("plan.Unknown = %v, want %v (plan=%+v)", got.Unknown, tc.wantUnknown, got)
			}
			if !tc.wantUnknown && (got.Unknown || got.Value != "prior-normalized-content") {
				t.Errorf("plan = %+v, want the prior state value %q preserved", got, "prior-normalized-content")
			}
		})
	}
}
