package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests — full-review round 1 finding #1 (correctness, high):
//
// template_regexes/template_defaults/enrollment_fields/metadata_fields were
// Optional but NOT Computed and carried no plan modifiers (unlike
// allowed_requesters, which was made Optional+Computed with
// useStateOrNullModifier for exactly this reason -- see
// resource_keyfactor_certificate_template_inconsistent_result_unit_test.go).
// An HCL config that omits one of these four attributes (the exact shape
// preserveUndeclaredTemplateFields exists to support) plans that attribute to
// Null. Update() -> preserveUndeclaredTemplateFields then legitimately fills
// the plan from a fresh GET when the server's current collection is
// non-empty, and templateResponseToState writes that non-empty collection
// into the final applied state. Terraform core compares the applied state to
// the recorded (Null) plan and hard-fails every such apply with "Provider
// produced inconsistent result after apply" -- a permanent loop, since the
// next Read() repopulates the same non-empty collection and the next plan
// shows the identical diff.
//
// The fix mirrors allowed_requesters exactly: make the four attributes
// Optional+Computed with useStateOrNullModifier, so an undeclared attribute
// legally resolves to the prior state's value (which preserveUndeclaredTemplateFields
// then keeps in sync with the server) instead of Null.
// ---------------------------------------------------------------------------

// TestUnitCertificateTemplateWritableCollectionsAreComputed is the
// schema-level regression test: all four collections must be Computed (in
// addition to Optional) with at least one plan modifier, so that an
// undeclared value can legally resolve to a non-empty server value without
// the framework flagging "Provider produced inconsistent result after
// apply". Before the fix these attributes were Optional only.
func TestUnitCertificateTemplateWritableCollectionsAreComputed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := templateSchema(t, ctx)

	for _, name := range []string{"template_regexes", "template_defaults", "enrollment_fields", "metadata_fields"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			schemaAttr, ok := schema.Attributes[name]
			if !ok {
				t.Fatalf("schema has no %s attribute", name)
			}
			if !schemaAttr.Optional {
				t.Errorf("%s: expected Optional=true", name)
			}
			if !schemaAttr.Computed {
				t.Fatalf(
					"%s: expected Computed=true, got false -- without Computed, an undeclared %s plans to "+
						"Null, and preserveUndeclaredTemplateFields legitimately returning the server's real "+
						"non-empty collection produces \"Provider produced inconsistent result after apply\"",
					name, name,
				)
			}
			if len(schemaAttr.PlanModifiers) == 0 {
				t.Errorf(
					"%s: expected a plan modifier (e.g. useStateOrNullModifier) so an undeclared value "+
						"resolves to the prior state instead of staying Unknown", name,
				)
			}
		})
	}
}

// TestUnitCertificateTemplateCollectionsModifierPreservesNonEmptyPriorState is
// the modifier-level regression test proving the schema fix is actually
// effective: when config leaves one of the four collections undeclared
// (Null) and prior state holds a non-empty collection, useStateOrNullModifier
// must resolve the plan to that non-empty prior value -- not leave it Unknown
// (which would panic reflect.Into on the native Go slice field) and
// critically not Null (the pre-fix behavior with no Computed/modifier at
// all), which is what made the applied state's later non-empty value
// "inconsistent" with the plan.
func TestUnitCertificateTemplateCollectionsModifierPreservesNonEmptyPriorState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := templateSchema(t, ctx)

	state := blankTemplateState()
	state.ID = types.Int64{Value: 7}
	state.TemplateRegexes = []TemplateRegexEntry{
		{
			SubjectPart:   types.String{Value: "CN"},
			Regex:         types.String{Value: ".*"},
			Error:         types.String{Null: true},
			CaseSensitive: types.Bool{Value: false},
		},
	}
	state.TemplateDefaults = []TemplateDefaultEntry{
		{SubjectPart: types.String{Value: "O"}, Value: types.String{Value: "Keyfactor"}},
	}
	state.EnrollmentFields = []TemplateEnrollmentFieldEntry{
		{
			ID:       types.Int64{Value: 1},
			Name:     types.String{Value: "field1"},
			DataType: types.Int64{Value: 1},
			Options:  types.List{Null: true, ElemType: types.StringType},
		},
	}
	state.MetadataFields = []TemplateMetadataFieldEntry{
		{
			ID:            types.Int64{Value: 1},
			MetadataID:    types.Int64{Value: 1},
			DefaultValue:  types.String{Null: true},
			Validation:    types.String{Null: true},
			Enrollment:    types.Int64{Value: 1},
			Message:       types.String{Null: true},
			CaseSensitive: types.Bool{Value: false},
		},
	}

	stObj := tfsdk.State{Schema: schema}
	if d := stObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: State.Set returned diagnostics: %+v", d)
	}

	for _, name := range []string{"template_regexes", "template_defaults", "enrollment_fields", "metadata_fields"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var stateVal attr.Value
			if d := stObj.GetAttribute(ctx, path.Root(name), &stateVal); d.HasError() {
				t.Fatalf("GetAttribute(%s): %+v", name, d)
			}
			if stateVal == nil || stateVal.IsNull() || stateVal.IsUnknown() {
				t.Fatalf("%s: prior state value unexpectedly nil/null/unknown: %+v", name, stateVal)
			}

			m := useStateOrNullModifier{}
			req := tfsdk.ModifyAttributePlanRequest{
				AttributeConfig: types.Bool{Null: true}, // undeclared in config; concrete type is immaterial to the modifier
				AttributeState:  stateVal,
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Bool{Unknown: true}}

			m.Modify(ctx, req, resp)

			if resp.AttributePlan == nil || resp.AttributePlan.IsUnknown() {
				t.Fatalf(
					"%s: plan left Unknown -- reflect.Into cannot decode Unknown into this resource's native "+
						"Go slice field, and even if it could, an Unknown plan for this field would still not "+
						"match the non-empty value Update() legitimately writes to final state", name,
				)
			}
			if resp.AttributePlan.IsNull() {
				t.Fatalf(
					"%s: plan resolved to Null, want the non-empty prior state value preserved -- this "+
						"reproduces finding #1: a Null plan for a non-empty server-side collection is exactly "+
						"what makes preserveUndeclaredTemplateFields's later non-null write to state "+
						"\"inconsistent\" with the plan", name,
				)
			}
			list, ok := resp.AttributePlan.(types.List)
			if !ok {
				t.Fatalf("%s: resp.AttributePlan is not types.List: %T", name, resp.AttributePlan)
			}
			if len(list.Elems) == 0 {
				t.Errorf("%s: plan list has 0 elements, want the prior state's single entry preserved", name)
			}
		})
	}
}

// newCollectionsFieldPreservationTestServer returns an httptest server whose
// GET /Templates/{id} response carries non-empty
// TemplateRegexes/TemplateDefaults/EnrollmentFields/MetadataFields (the
// exact server-side shape that triggers finding #1), and which captures any
// PUT /Templates request body into *capturedPUTBody while echoing enough of
// it back that templateResponseToState can decode the response.
func newCollectionsFieldPreservationTestServer(t *testing.T, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	buildCanned := func() v1.TemplatesTemplateRetrievalResponse {
		resp := v1.TemplatesTemplateRetrievalResponse{}
		resp.SetId(7)
		resp.SetCommonName("AnyCA_lab-root-role")
		resp.SetTemplateName("AnyCA Lab Root Role")
		resp.SetFriendlyName("OldFriendlyName")

		rx := v1.TemplatesTemplateRegexRequestResponseModel{}
		rx.SetSubjectPart("CN")
		rx.SetRegex(".*")
		resp.TemplateRegexes = []v1.TemplatesTemplateRegexRequestResponseModel{rx}

		def := v1.TemplatesTemplateDefaultRequestResponseModel{}
		def.SetSubjectPart("O")
		def.SetValue("Keyfactor")
		resp.TemplateDefaults = []v1.TemplatesTemplateDefaultRequestResponseModel{def}

		ef := v1.TemplatesTemplateEnrollmentFieldRequestResponseModel{}
		ef.SetId(1)
		ef.SetName("field1")
		ef.SetDataType(v1.CSSCMSCoreEnumsTemplateEnrollmentFieldType(1))
		resp.EnrollmentFields = []v1.TemplatesTemplateEnrollmentFieldRequestResponseModel{ef}

		mf := v1.TemplatesTemplateMetadataFieldRequestResponseModel{}
		mf.SetId(1)
		mf.SetMetadataId(1)
		resp.MetadataFields = []v1.TemplatesTemplateMetadataFieldRequestResponseModel{mf}

		return resp
	}

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			resp := buildCanned()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode GET response: %v", err)
			}
		case r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			*capturedPUTBody = body
			// Echo the canned collections back unconditionally, standing in for
			// Command's actual full-replace PUT response.
			resp := buildCanned()
			resp.SetFriendlyName("NewFriendlyName")
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode PUT response: %v", err)
			}
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitCertificateTemplateUpdatePreservesNonEmptyCollections is the
// direct end-to-end regression test for finding #1: an Update() whose plan
// declares ONLY friendly_name (leaving all four collections undeclared) must
// carry the server's current non-empty collections through the PUT
// /Templates payload AND into the final applied state -- proving planned
// (via useStateOrNullModifier, exercised implicitly by prior state already
// matching the server) and applied (via preserveUndeclaredTemplateFields +
// templateResponseToState) agree, which is exactly what Terraform core's
// post-apply consistency check requires.
func TestUnitCertificateTemplateUpdatePreservesNonEmptyCollections(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newCollectionsFieldPreservationTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	// Prior local state matches the server's current (pre-update) non-empty
	// collections -- the common, no-drift case.
	state := blankTemplateState()
	state.ID = types.Int64{Value: 7}
	state.FriendlyName = types.String{Value: "OldFriendlyName"}
	state.TemplateRegexes = []TemplateRegexEntry{
		{SubjectPart: types.String{Value: "CN"}, Regex: types.String{Value: ".*"}, Error: types.String{Null: true}, CaseSensitive: types.Bool{Value: false}},
	}
	state.TemplateDefaults = []TemplateDefaultEntry{
		{SubjectPart: types.String{Value: "O"}, Value: types.String{Value: "Keyfactor"}},
	}
	state.EnrollmentFields = []TemplateEnrollmentFieldEntry{
		{ID: types.Int64{Value: 1}, Name: types.String{Value: "field1"}, DataType: types.Int64{Value: 1}, Options: types.List{Null: true, ElemType: types.StringType}},
	}
	state.MetadataFields = []TemplateMetadataFieldEntry{
		{ID: types.Int64{Value: 1}, MetadataID: types.Int64{Value: 1}, DefaultValue: types.String{Null: true}, Validation: types.String{Null: true}, Enrollment: types.Int64{Null: true}, Message: types.String{Null: true}, CaseSensitive: types.Bool{Value: false}},
	}

	// Plan: config declares ONLY friendly_name -- all four collections are
	// undeclared (Null in the pre-fix schema; with the fix, planned via
	// useStateOrNullModifier to the prior state's non-empty value, which we
	// simulate directly here since planObj.Set writes the Go struct value as
	// given).
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 7}
	plan.FriendlyName = types.String{Value: "NewFriendlyName"}
	plan.TemplateRegexes = state.TemplateRegexes
	plan.TemplateDefaults = state.TemplateDefaults
	plan.EnrollmentFields = state.EnrollmentFields
	plan.MetadataFields = state.MetadataFields

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	// Config: mirrors planObj's Raw verbatim -- this test builds plan directly
	// rather than via PlanResourceChange, so plan's shape already IS what
	// config declared (see full-review round 5 [HIGH]).
	configObj := tfsdk.Config{Schema: schema, Raw: planObj.Raw}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if len(putBody) == 0 {
		t.Fatal("no PUT /Templates request was captured")
	}
	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	if regexes, ok := onWire["TemplateRegexes"].([]interface{}); !ok || len(regexes) != 1 {
		t.Errorf(
			"TemplateRegexes on the wire = %v, want exactly 1 entry preserved from the server. Full payload: %s",
			onWire["TemplateRegexes"], putBody,
		)
	}
	if defaults, ok := onWire["TemplateDefaults"].([]interface{}); !ok || len(defaults) != 1 {
		t.Errorf(
			"TemplateDefaults on the wire = %v, want exactly 1 entry preserved from the server. Full payload: %s",
			onWire["TemplateDefaults"], putBody,
		)
	}
	if fields, ok := onWire["EnrollmentFields"].([]interface{}); !ok || len(fields) != 1 {
		t.Errorf(
			"EnrollmentFields on the wire = %v, want exactly 1 entry preserved from the server. Full payload: %s",
			onWire["EnrollmentFields"], putBody,
		)
	}
	if fields, ok := onWire["MetadataFields"].([]interface{}); !ok || len(fields) != 1 {
		t.Errorf(
			"MetadataFields on the wire = %v, want exactly 1 entry preserved from the server. Full payload: %s",
			onWire["MetadataFields"], putBody,
		)
	}

	// The applied final state (resp.State, built from the PUT response via
	// templateResponseToState) must also carry the same non-empty
	// collections -- this is the actual post-apply value Terraform core
	// compares against the plan for the consistency check.
	var finalState KeyfactorCertificateTemplateState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}
	if len(finalState.TemplateRegexes) != 1 {
		t.Errorf("final state TemplateRegexes has %d entries, want 1", len(finalState.TemplateRegexes))
	}
	if len(finalState.TemplateDefaults) != 1 {
		t.Errorf("final state TemplateDefaults has %d entries, want 1", len(finalState.TemplateDefaults))
	}
	if len(finalState.EnrollmentFields) != 1 {
		t.Errorf("final state EnrollmentFields has %d entries, want 1", len(finalState.EnrollmentFields))
	}
	if len(finalState.MetadataFields) != 1 {
		t.Errorf("final state MetadataFields has %d entries, want 1", len(finalState.MetadataFields))
	}
}
