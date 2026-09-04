package keyfactor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// Regression test — keyfactor_enrollment_pattern Create() fails with
// "Value Conversion Error: ... unhandled unknown value" on a first apply
// whenever any Computed-only/Optional+Computed attribute this schema derives
// entirely from the server response is left undeclared in config.
//
// Reproduced live against kfclab via terraform/enrollment_pattern_demo, whose
// config declares template_id/name/policies={} but leaves
// certificate_authority_ids undeclared, and leaves policies'
// primary_key_algorithms/alternative_key_algorithms sub-fields undeclared:
//
//	Error: Value Conversion Error
//	An unexpected error was encountered trying to build a value. This is
//	always an error in the provider. ... unhandled unknown value
//
// Root cause: on Create there is no prior Terraform state at all, so every
// plan modifier that would normally carry a Computed attribute's value
// forward from state (useStateOrNullModifier, tfsdk.UseStateForUnknown())
// has nothing to carry forward and leaves the attribute's PLANNED value
// Unknown -- correct in general, since Create()'s own API response is what
// actually fills these in. But several of these attributes
// (template, associated_roles, certificate_authorities, and Policies'
// nested primary_key_algorithms/alternative_key_algorithms) are backed by
// raw Go slice/pointer-to-struct types in KeyfactorEnrollmentPatternState
// (not attr.Value types like types.List), which cannot represent an Unknown
// tftypes value at all. The original Create() decoded straight from
// request.Plan:
//
//	diags := request.Plan.Get(ctx, &plan)
//
// which hits exactly this Unknown-into-raw-Go-type conversion failure
// before any of Create()'s own logic runs.
//
// The fix: decode from request.Config instead of request.Plan. Config
// reflects only what the user actually wrote in HCL, never the framework's
// "known after apply" placeholders, so every Computed-only or
// Optional+Computed-and-undeclared attribute reliably decodes as Null (which
// every one of these raw Go types handles fine) instead of Unknown. This is
// safe because Create()'s own response (enrollmentPatternResponseToState)
// is what actually populates these fields in the end -- Create() never
// needed their still-forming Plan value in the first place.
// ---------------------------------------------------------------------------

// enrollmentPatternCreateMockAuthConfig points the keyfactor-go-client-sdk/v25
// API client at a local httptest server instead of a real Command instance.
// Mirrors templateUpdateMockAuthConfig (resource_keyfactor_certificate_
// template_allowed_requesters_unit_test.go) exactly; kept separate only so
// this file has no compile-time dependency on that one's naming.
func newEnrollmentPatternCreateTestServer(t *testing.T, capturedPOSTBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read POST request body: %v", err)
		}
		*capturedPOSTBody = body

		// Canned Create response. All fields besides Id/Name/AssociatedRoles
		// are optional pointers/slices on the SDK model, and
		// enrollmentPatternResponseToState is nil-safe for every one of them
		// (nullableStringToTfString, boolPtrToTfBool, etc.) -- a minimal
		// response is otherwise sufficient to exercise the Create() code
		// path under test. AssociatedRoles echoes back the "InstanceAdmin"
		// role the test declares in config, matching real Command behavior
		// (the create response's AssociatedRoles expansion is what
		// associated_role_names is now derived from -- see
		// enrollmentPatternResponseToState's doc comment).
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id": 42, "Name": "Demo Pattern_TF", "AssociatedRoles": [{"Id": 1, "Name": "InstanceAdmin"}]}`))
	}))
}

// blankEnrollmentPatternState returns a KeyfactorEnrollmentPatternState with
// every scalar attribute explicitly Null and every nested/slice attribute
// nil, matching the full schema from resourceEnrollmentPatternType.GetSchema
// -- mirrors blankTemplateState's role for KeyfactorCertificateTemplateState.
func blankEnrollmentPatternState() KeyfactorEnrollmentPatternState {
	nullStr := types.String{Null: true}
	nullBool := types.Bool{Null: true}
	nullInt := types.Int64{Null: true}
	nullStrSet := types.Set{Null: true, ElemType: types.StringType}
	nullIntSet := types.Set{Null: true, ElemType: types.Int64Type}
	return KeyfactorEnrollmentPatternState{
		ID:                      nullInt,
		Name:                    nullStr,
		Description:             nullStr,
		TemplateId:              nullInt,
		Template:                nil,
		TemplateDefault:         nullBool,
		UseADPermissions:        nullBool,
		AssociatedRoleNames:     nullStrSet,
		AssociatedRoles:         nil,
		CertificateAuthorityIds: nullIntSet,
		CertificateAuthorities:  nil,
		AllowedEnrollmentTypes:  nullInt,
		Regexes:                 nil,
		MetadataFields:          nil,
		RestrictCAs:             nullBool,
		Policies:                nil,
		Defaults:                nil,
		EnrollmentFields:        nil,
		ForceTemplateDefault:    nullBool,
	}
}

// TestUnitEnrollmentPatternCreateResolvesUndeclaredComputedFieldsFromConfig
// is the direct end-to-end regression test: a Create() request whose Config
// declares template_id/name/policies={} but leaves
// certificate_authority_ids and policies.primary_key_algorithms/
// alternative_key_algorithms undeclared (Null in Config), while its Plan
// carries the realistic Unknown values the framework's own plan modifiers
// would actually produce for those same attributes on a true first apply
// (including Unknown values for the raw-Go-slice-backed
// primary_key_algorithms/alternative_key_algorithms, which cannot be
// decoded at all -- this is the exact shape that crashed Plan.Get live
// against kfclab), must succeed by decoding from Config rather than Plan.
func TestUnitEnrollmentPatternCreateResolvesUndeclaredComputedFieldsFromConfig(t *testing.T) {
	ctx := context.Background()

	var postBody []byte
	server := newEnrollmentPatternCreateTestServer(t, &postBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)

	schema, diags := resourceEnrollmentPatternType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	// Config: exactly what the user wrote in HCL. Undeclared Computed-only/
	// Optional+Computed attributes are Null, never Unknown -- this is what
	// Create() must actually decode.
	config := blankEnrollmentPatternState()
	config.Name = types.String{Value: "Demo Pattern_TF"}
	config.TemplateId = types.Int64{Value: 6}
	config.Policies = &EnrollmentPatternResourcePolicy{}
	config.AllowedEnrollmentTypes = types.Int64{Value: 3}
	config.TemplateDefault = types.Bool{Value: false}
	config.RestrictCAs = types.Bool{Value: false}
	config.AssociatedRoleNames = types.Set{
		ElemType: types.StringType,
		Elems:    []attr.Value{types.String{Value: "InstanceAdmin"}},
	}
	// certificate_authority_ids left at its blank-state Null default.

	// tfsdk.Config has no Set method (only Get/GetAttribute) -- build the
	// raw value via a scratch Plan.Set, then copy Raw/Schema into a Config.
	configScratchPlan := tfsdk.Plan{Schema: schema}
	if d := configScratchPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Raw: configScratchPlan.Raw, Schema: schema}

	// Plan: what the framework's own plan modifiers would actually produce
	// for a true first apply -- Unknown for every field this schema derives
	// entirely from the server response, since useStateOrNullModifier/
	// tfsdk.UseStateForUnknown() have no prior state to carry forward. This
	// is deliberately NOT decoded by the fixed Create().
	//
	// template and policies.primary_key_algorithms/alternative_key_algorithms
	// are backed by raw Go types (*EnrollmentPatternResourceTemplate,
	// []EnrollmentPatternResourceAlgorithm) that cannot represent Unknown at
	// all -- there is no Go value that .Set() could encode as Unknown for
	// them, so a genuine Unknown at these paths has to be built by starting
	// from a well-formed, fully-known Plan and then surgically replacing
	// those specific tftypes.Value nodes with an Unknown value of the same
	// type via tftypes.Transform. This is exactly the shape the real
	// framework produces and handed to Create() live against kfclab.
	plan := config
	plan.CertificateAuthorityIds = types.Set{Unknown: true, ElemType: types.Int64Type}
	plan.Policies = &EnrollmentPatternResourcePolicy{
		AllowKeyReuse:                   types.Bool{Unknown: true},
		AllowWildcards:                  types.Bool{Unknown: true},
		RFCEnforcement:                  types.Bool{Unknown: true},
		CertificateOwnerRole:            types.Int64{Unknown: true},
		DefaultCertificateOwnerRoleId:   types.Int64{Unknown: true},
		DefaultCertificateOwnerRoleName: types.String{Unknown: true},
		DefaultCertificateOwnerOverride: types.Bool{Unknown: true},
		// PrimaryKeyAlgorithms/AlternativeKeyAlgorithms left nil here (Null
		// once encoded) -- the tftypes.Transform below overwrites their
		// encoded value with a genuine Unknown, which no Go value assigned
		// here could represent directly.
	}

	planScratch := tfsdk.Plan{Schema: schema}
	if d := planScratch.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	templatePath := tftypes.NewAttributePath().WithAttributeName("template")
	primaryAlgosPath := tftypes.NewAttributePath().WithAttributeName("policies").WithAttributeName("primary_key_algorithms")
	altAlgosPath := tftypes.NewAttributePath().WithAttributeName("policies").WithAttributeName("alternative_key_algorithms")
	unknownRaw, err := tftypes.Transform(
		planScratch.Raw, func(p *tftypes.AttributePath, v tftypes.Value) (tftypes.Value, error) {
			if p.Equal(templatePath) || p.Equal(primaryAlgosPath) || p.Equal(altAlgosPath) {
				return tftypes.NewValue(v.Type(), tftypes.UnknownValue), nil
			}
			return v, nil
		},
	)
	if err != nil {
		t.Fatalf("test setup: tftypes.Transform failed: %v", err)
	}
	planObj := tfsdk.Plan{Raw: unknownRaw, Schema: schema}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.CreateResourceRequest{Config: configObj, Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf(
			"Create returned diagnostics (this is the live repro: fwserver's reflection-based Get/Set rejects "+
				"an Unknown value decoded into a raw Go type with \"Value Conversion Error ... unhandled unknown "+
				"value\"): %+v",
			resp.Diagnostics,
		)
	}

	var finalState KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}

	// AssociatedRoleNames is now derived directly from the Create response's
	// AssociatedRoles expansion (enrollmentPatternResponseToState), not
	// carried forward from plan/config -- so the final state must reflect
	// exactly what the canned response echoed back ("InstanceAdmin"), not
	// merely "not Unknown."
	if finalState.AssociatedRoleNames.Unknown {
		t.Error("final state associated_role_names is Unknown, want a resolved value")
	}
	var gotRoles []string
	finalState.AssociatedRoleNames.ElementsAs(ctx, &gotRoles, false)
	if len(gotRoles) != 1 || gotRoles[0] != "InstanceAdmin" {
		t.Errorf(
			"final state associated_role_names = %v, want [InstanceAdmin] (derived from the Create response)",
			gotRoles,
		)
	}
	// certificate_authority_ids was left undeclared in config, and the
	// canned response has no CertificateAuthorities -- derives to Null.
	if finalState.CertificateAuthorityIds.Unknown {
		t.Error("final state certificate_authority_ids is Unknown, want Null")
	}
	if !finalState.CertificateAuthorityIds.Null {
		t.Errorf("final state certificate_authority_ids = %+v, want Null", finalState.CertificateAuthorityIds)
	}
}

// ---------------------------------------------------------------------------
// Regression test — keyfactor_enrollment_pattern ImportState() fails with
// "cannot convert Set to tftypes.Value if ElemType field is not set".
//
// Originally reproduced live against kfclab via terraform/enrollment_pattern_
// demo's `terraform import`: GetById's response never carries a flat
// AssociatedRoleNames/CertificateAuthorityIds field (Command only ever
// returns the expanded AssociatedRoles/CertificateAuthorities objects -- see
// KeyfactorEnrollmentPatternState's doc comment), and at the time this test
// was written enrollmentPatternResponseToState never derived either field
// from that expansion, so ImportState's newState left them at Go's zero
// value for types.List -- {Null: false, Unknown: false, ElemType: nil}. That
// is not a valid "Null" value: response.State.Set's encoder requires
// ElemType to be set even for a null value, and errors accordingly before
// the import can complete.
//
// enrollmentPatternResponseToState now derives associated_role_names/
// certificate_authority_ids directly from the same AssociatedRoles/
// CertificateAuthorities expansion on every Create/Read/Update/Import (see
// its doc comment) -- including a properly-typed Null Set, with ElemType
// set, when the response has no roles/CAs at all (the case this test
// exercises). This test now guards that derivation path specifically,
// rather than an ImportState-only hardcoded assignment.
// ---------------------------------------------------------------------------

// newEnrollmentPatternImportTestServer serves a canned GetById response for
// ImportState, mirroring newEnrollmentPatternCreateTestServer's role for
// Create's POST.
func newEnrollmentPatternImportTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id": 21, "Name": "Demo Pattern_TF"}`))
	}))
}

// TestUnitEnrollmentPatternImportStateSetsValidNullForWriteOnlyLists is the
// direct end-to-end regression test: ImportState against a minimal GetById
// response (no AssociatedRoles/CertificateAuthorities in the response --
// the common case for a pattern with no roles/CAs configured) must succeed,
// and must leave associated_role_names/certificate_authority_ids as a
// proper Null (not the zero-value/malformed list that used to reach
// State.Set).
func TestUnitEnrollmentPatternImportStateSetsValidNullForWriteOnlyLists(t *testing.T) {
	ctx := context.Background()

	server := newEnrollmentPatternImportTestServer(t)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)

	schema, diags := resourceEnrollmentPatternType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ImportResourceStateRequest{ID: "21"}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	r.ImportState(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf(
			"ImportState returned diagnostics (this is the live repro: response.State.Set rejects a malformed "+
				"zero-value types.Set with \"cannot convert Set to tftypes.Value if ElemType field is not "+
				"set\"): %+v",
			resp.Diagnostics,
		)
	}

	var finalState KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}

	if !finalState.AssociatedRoleNames.Null {
		t.Errorf("associated_role_names = %+v, want Null", finalState.AssociatedRoleNames)
	}
	if finalState.AssociatedRoleNames.ElemType != types.StringType {
		t.Errorf("associated_role_names.ElemType = %v, want %v", finalState.AssociatedRoleNames.ElemType, types.StringType)
	}
	if !finalState.CertificateAuthorityIds.Null {
		t.Errorf("certificate_authority_ids = %+v, want Null", finalState.CertificateAuthorityIds)
	}
	if finalState.CertificateAuthorityIds.ElemType != types.Int64Type {
		t.Errorf("certificate_authority_ids.ElemType = %v, want %v", finalState.CertificateAuthorityIds.ElemType, types.Int64Type)
	}
}

// ---------------------------------------------------------------------------
// Regression test — a nested (object/list) Computed attribute that is NOT
// also Optional plans to an explicit Null on a brand-new resource's first
// apply -- not "(known after apply)" -- because there is no prior Terraform
// state for useStateOrNullModifier to carry forward. When Create()'s real
// API response then populates that attribute with genuine data (every one
// of template/associated_roles/certificate_authorities always has *some*
// server value once a pattern exists), Terraform rejects the apply with
// "Provider produced inconsistent result after apply: .template: was null,
// but now cty.ObjectVal(...)" (same for .associated_roles).
//
// Reproduced live against kfclab via terraform/enrollment_pattern_demo's
// first `lab-apply`: before this fix, "template" and "associated_roles"
// were Computed-only (no Optional) and hit exactly this error immediately
// after the server-side create succeeded. "certificate_authorities" has the
// identical shape but happened not to error in that specific run only
// because this lab's demo pattern has zero restricted CAs (RestrictCAs =
// false), so its real value was an empty/nil list indistinguishable from
// the wrongly-planned Null -- it would fail the same way for any pattern
// that actually restricts CAs.
//
// Every other nested attribute in this schema (policies, regexes,
// metadata_fields, defaults, enrollment_fields) already declared Optional
// alongside Computed and never showed this bug -- this test encodes that
// as a schema invariant so a future nested attribute can't reintroduce the
// same class of bug by copy-pasting a Computed-only attribute definition.
// ---------------------------------------------------------------------------

// TestUnitEnrollmentPatternNestedComputedAttributesAreAlsoOptional walks the
// resource's top-level schema and fails if any attribute with a nested
// Attributes definition (SingleNestedAttributes/ListNestedAttributes) is
// Computed without also being Optional.
func TestUnitEnrollmentPatternNestedComputedAttributesAreAlsoOptional(t *testing.T) {
	ctx := context.Background()

	schema, diags := resourceEnrollmentPatternType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	for name, a := range schema.Attributes {
		if a.Attributes == nil {
			continue // not a nested attribute -- this invariant doesn't apply
		}
		if a.Computed && !a.Optional {
			t.Errorf(
				"attribute %q is a nested (Computed-only, not Optional) attribute -- this plans to an explicit "+
					"Null (not \"known after apply\") on a brand-new resource's first create, which then conflicts "+
					"with Create()'s real, non-null response value and fails the apply with \"Provider produced "+
					"inconsistent result after apply\". Add Optional: true alongside Computed: true, matching "+
					"every other nested attribute in this schema.",
				name,
			)
		}
	}
}
