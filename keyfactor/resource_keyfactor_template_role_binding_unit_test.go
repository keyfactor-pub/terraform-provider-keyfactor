package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitTemplateRoleBindingUpdateArgPreservesUnrelatedFields is a regression
// test for the bug where the role attach/detach paths rebuilt the UpdateTemplate
// request with only a handful of fields and ran them through zero-collapsing
// pointer helpers. Because Command's UpdateTemplate is a full replacement, every
// omitted field was reset server-side — so attaching or detaching a role
// silently wiped template settings this resource does not even manage
// (RequiresApproval, KeyRetentionDays, KeyArchival, EnrollmentFields,
// MetadataFields, TemplateRegexes) along with any empty/zero FriendlyName /
// KeyRetention / AllowedEnrollmentTypes.
func TestUnitTemplateRoleBindingUpdateArgPreservesUnrelatedFields(t *testing.T) {
	template := &api.GetTemplateResponse{
		Id:                     42,
		CommonName:             "WebServer",
		TemplateName:           "WebServer",
		Oid:                    "1.2.3.4",
		KeySize:                "2048",
		KeyType:                "RSA",
		ForestRoot:             "example.com",
		FriendlyName:           "Web Server Template",
		KeyRetention:           "Indefinite",
		KeyRetentionDays:       365,
		KeyArchival:            true,
		AllowedEnrollmentTypes: 3,
		RFCEnforcement:         true,
		RequiresApproval:       true,
		AllowedRequesters:      []string{"Existing-Role"},
		EnrollmentFields:       []api.TemplateEnrollmentFields{{Id: 1, Name: "field-a"}},
		MetadataFields:         []api.TemplateMetadataFields{{Id: 2, MetadataId: 9}},
		TemplateRegexes:        []api.TemplateRegex{{TemplateId: 42, SubjectPart: "CN", RegEx: ".*"}},
	}

	assertPreserved := func(t *testing.T, arg *api.UpdateTemplateArg) {
		t.Helper()
		// Scalar settings this resource does not manage must round-trip.
		if assert.NotNil(t, arg.RequiresApproval) {
			assert.True(t, *arg.RequiresApproval, "RequiresApproval must be preserved, not reset")
		}
		if assert.NotNil(t, arg.KeyRetentionDays) {
			assert.Equal(t, 365, *arg.KeyRetentionDays, "KeyRetentionDays must be preserved")
		}
		if assert.NotNil(t, arg.KeyArchival) {
			assert.True(t, *arg.KeyArchival, "KeyArchival must be preserved")
		}
		if assert.NotNil(t, arg.RFCEnforcement) {
			assert.True(t, *arg.RFCEnforcement, "RFCEnforcement must be preserved")
		}
		if assert.NotNil(t, arg.FriendlyName) {
			assert.Equal(t, "Web Server Template", *arg.FriendlyName, "FriendlyName must be preserved")
		}
		if assert.NotNil(t, arg.KeyRetention) {
			assert.Equal(t, "Indefinite", *arg.KeyRetention, "KeyRetention must be preserved")
		}
		if assert.NotNil(t, arg.AllowedEnrollmentTypes) {
			assert.Equal(t, 3, *arg.AllowedEnrollmentTypes, "AllowedEnrollmentTypes must be preserved")
		}
		// Collection settings this resource does not manage must round-trip.
		assert.NotNil(t, arg.EnrollmentFields, "EnrollmentFields must be preserved, not reset")
		assert.NotNil(t, arg.MetadataFields, "MetadataFields must be preserved, not reset")
		assert.NotNil(t, arg.TemplateRegexes, "TemplateRegexes must be preserved, not reset")
		// Identity is preserved.
		assert.Equal(t, "WebServer", arg.CommonName)
		assert.Equal(t, 42, arg.Id)
	}

	t.Run("attach adds the role and preserves everything else", func(t *testing.T) {
		arg := buildTemplateRoleBindingUpdateArg(template, []string{"Existing-Role", "New-Role"}, true)
		if assert.NotNil(t, arg.AllowedRequesters) {
			assert.ElementsMatch(t, []string{"Existing-Role", "New-Role"}, *arg.AllowedRequesters)
		}
		if assert.NotNil(t, arg.UseAllowedRequesters) {
			assert.True(t, *arg.UseAllowedRequesters)
		}
		assertPreserved(t, arg)
	})

	t.Run("detach removes the last role and preserves everything else", func(t *testing.T) {
		// Detaching the only role leaves an empty (but non-nil) requester list.
		arg := buildTemplateRoleBindingUpdateArg(template, []string{}, false)
		if assert.NotNil(t, arg.AllowedRequesters, "an emptied requester list must be sent as [] not dropped") {
			assert.Len(t, *arg.AllowedRequesters, 0)
		}
		if assert.NotNil(t, arg.UseAllowedRequesters) {
			assert.False(t, *arg.UseAllowedRequesters)
		}
		assertPreserved(t, arg)
	})
}

// TestUnitTemplateRoleBindingUpdateArgPreservesTemplatePolicy is a regression
// test for GitHub issue #180: attaching or detaching a role from a template
// linked to an enrollment pattern failed on every attempt with
// "'Policies' cannot be empty", because api.UpdateTemplateArg had no field to
// carry the template's TemplatePolicy (PrimaryKeyAlgorithms /
// AlternativeKeyAlgorithms, AllowKeyReuse, AllowWildcards, etc) forward, so
// buildTemplateRoleBindingUpdateArg could never populate it even though
// GetTemplate always returns it for enrollment-pattern-linked templates.
// Command's PUT /Templates is a full replacement: omitting TemplatePolicy
// collapses its internally-derived policy set to empty and the server
// rejects the request outright (confirmed against a live Command 25.4.1
// instance). Templates with no policy configured (nil TemplatePolicy) must
// not have one fabricated.
func TestUnitTemplateRoleBindingUpdateArgPreservesTemplatePolicy(t *testing.T) {
	allowKeyReuse := true
	allowWildcards := true
	policy := &api.TemplatePolicy{
		TemplateId:     4,
		AllowKeyReuse:  &allowKeyReuse,
		AllowWildcards: &allowWildcards,
		PrimaryKeyAlgorithms: []api.TemplateKeyAlgorithm{
			{Name: "RSA", BitLengths: []int{2048, 3072, 4096}},
			{Name: "Ed25519", BitLengths: []int{255}},
		},
	}

	t.Run("template with a configured policy round-trips it on attach", func(t *testing.T) {
		template := &api.GetTemplateResponse{
			Id:             4,
			CommonName:     "Server_tlsServerAuth-1y",
			TemplatePolicy: policy,
		}

		arg := buildTemplateRoleBindingUpdateArg(template, []string{"Administrator"}, true)

		if assert.NotNil(t, arg.TemplatePolicy, "TemplatePolicy must be preserved, not dropped") {
			assert.Same(t, policy, arg.TemplatePolicy)
			if assert.Len(t, arg.TemplatePolicy.PrimaryKeyAlgorithms, 2) {
				assert.Equal(t, "RSA", arg.TemplatePolicy.PrimaryKeyAlgorithms[0].Name)
			}
		}
	})

	t.Run("template with no configured policy leaves TemplatePolicy nil", func(t *testing.T) {
		template := &api.GetTemplateResponse{
			Id:         5,
			CommonName: "Admin_Authentication-2048-3y",
			// TemplatePolicy intentionally nil, matching what GetTemplate
			// returns for templates that have never had one configured.
		}

		arg := buildTemplateRoleBindingUpdateArg(template, []string{"Administrator"}, true)

		assert.Nil(t, arg.TemplatePolicy, "TemplatePolicy must stay nil when the template has none configured")
	})
}

// TestUnitTemplateNamesStillAttached is a direct regression test for the
// helper extracted from Read(): it must drop any template name whose template
// no longer lists roleName as an allowed requester (out-of-band detach),
// while keeping names that are still genuinely attached.
func TestUnitTemplateNamesStillAttached(t *testing.T) {
	kfTemplates := []api.GetTemplateResponse{
		{
			CommonName:           "WebServer",
			UseAllowedRequesters: true,
			AllowedRequesters:    []string{"tf-unit-role"},
		},
		{
			// Role was detached out-of-band: UseAllowedRequesters is still true,
			// but tf-unit-role is no longer in the list.
			CommonName:           "Database",
			UseAllowedRequesters: true,
			AllowedRequesters:    []string{"Some-Other-Role"},
		},
		{
			// UseAllowedRequesters itself was turned off out-of-band.
			CommonName:           "Workstation",
			UseAllowedRequesters: false,
			AllowedRequesters:    []string{"tf-unit-role"},
		},
	}

	attached := templateNamesStillAttached(kfTemplates, "tf-unit-role", []string{"WebServer", "Database", "Workstation"})
	assert.Equal(t, []string{"WebServer"}, attached, "only templates that still list the role as an allowed requester must be reported as attached")
}

// TestUnitTemplateRoleBindingRead_DetectsOutOfBandDetach is a regression test
// for Read() never re-verifying that the role is still actually attached to
// the stored templates on Command. Read() previously only checked that the
// template names still EXISTED (verifyTemplateNames) and then wrote back the
// unchanged prior state, so a role detached from a template out-of-band
// reported stale "still attached" success instead of drift.
//
// This drives Read() end-to-end against a mock Command server where one of
// the two previously-bound templates no longer lists the role as an allowed
// requester, and asserts the resulting state drops that template.
func TestUnitTemplateRoleBindingRead_DetectsOutOfBandDetach(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Templates/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"Id":                   1,
				"CommonName":           "WebServer",
				"UseAllowedRequesters": true,
				"AllowedRequesters":    []string{"tf-unit-role"},
			},
			{
				// Detached out-of-band: role no longer in AllowedRequesters.
				"Id":                   2,
				"CommonName":           "Database",
				"UseAllowedRequesters": true,
				"AllowedRequesters":    []string{"Some-Other-Role"},
			},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := CertificateTemplateRoleBinding{
		ID:       types.String{Value: "deadbeef"},
		RoleName: types.String{Value: "tf-unit-role"},
		TemplateNames: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "WebServer"},
			types.String{Value: "Database"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplateRoleBinding{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result CertificateTemplateRoleBinding
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var names []string
	for _, e := range result.TemplateNames.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected template_short_names element to be types.String, got %T", e)
		}
		names = append(names, s.Value)
	}

	assert.Equal(t, []string{"WebServer"}, names, "Read() must drop templates the role was detached from out-of-band, not echo back stale prior state")
}

// TestUnitTemplateRoleBindingRead_SurfacesGetTemplatesError is a regression
// test for Read() silently swallowing a GetTemplates() API error:
//
//	kfTemplates, err := kfClient.GetTemplates()
//	if err != nil {
//		return
//	}
//
// This returned with NO diagnostic and no logging, so a transient API failure
// during Read (e.g. Command unreachable, auth expired) looked identical to a
// completely successful, no-op refresh -- `terraform plan`/refresh would
// silently keep stale state instead of surfacing the error, and worse, execution
// would have fallen through to the un-set `state` if the early return had been
// removed by a future edit. Create()'s identical GetTemplates() call already
// handles this correctly (AddError + return); Read() must mirror it.
//
// This drives Read() end-to-end against a mock Command server whose /Templates
// endpoint returns 500, and asserts response.Diagnostics.HasError() is true
// with the same ERR_SUMMARY_TEMPLATE_READ summary Create() uses.
func TestUnitTemplateRoleBindingRead_SurfacesGetTemplatesError(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Templates/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Message":"simulated Command outage"}`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := CertificateTemplateRoleBinding{
		ID:       types.String{Value: "deadbeef"},
		RoleName: types.String{Value: "tf-unit-role"},
		TemplateNames: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "WebServer"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplateRoleBinding{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("Read() must surface a diagnostic when GetTemplates() fails, not silently return success")
	}

	found := false
	for _, d := range resp.Diagnostics {
		if d.Summary() == ERR_SUMMARY_TEMPLATE_READ {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a diagnostic with summary %q (matching Create()'s handling of the same GetTemplates() error), got: %+v", ERR_SUMMARY_TEMPLATE_READ, resp.Diagnostics)
}

// TestUnitTemplateRoleBindingUpdatePreservesKeyUsage is a regression test for
// F173-1: buildTemplateRoleBindingUpdateArg never copied KeyUsage from the
// GetTemplate response onto the UpdateTemplate request, so every role
// attach/detach silently reset the template's KeyUsage bitmask to 0 on
// Command, even though this resource does not manage KeyUsage at all.
//
// This drives addAllowedRequesterToTemplate end-to-end against a mock Command
// server: GET /Templates/{id} returns KeyUsage 160 (digitalSignature |
// keyEncipherment), and the test captures the PUT /Templates body to assert
// KeyUsage 160 round-trips through unchanged. On the unfixed code the PUT
// body has no "KeyUsage" field at all (omitempty on a nil *int), which
// Command's full-replacement UpdateTemplate interprets as clearing it to 0.
func TestUnitTemplateRoleBindingUpdatePreservesKeyUsage(t *testing.T) {
	ctx := context.Background()

	var capturedPUTBody []byte

	mux := http.NewServeMux()
	mux.HandleFunc(
		"/KeyfactorAPI/Templates/", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(
					map[string]interface{}{
						"Id":                   42,
						"CommonName":           "WebServer",
						"TemplateName":         "WebServer",
						"KeyUsage":             160,
						"AllowedRequesters":    []string{},
						"UseAllowedRequesters": false,
					},
				)
			case http.MethodPut:
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("reading PUT body: %v", err)
				}
				capturedPUTBody = body
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"Id": 42})
			default:
				t.Fatalf("unexpected method %s", r.Method)
			}
		},
	)
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	diags := addAllowedRequesterToTemplate(ctx, client, "tf-unit-role", "42")
	if diags.HasError() {
		t.Fatalf("addAllowedRequesterToTemplate returned unexpected diagnostics: %+v", diags)
	}

	if capturedPUTBody == nil {
		t.Fatal("expected UpdateTemplate to PUT a request body, got none")
	}

	var putArg map[string]interface{}
	if err := json.Unmarshal(capturedPUTBody, &putArg); err != nil {
		t.Fatalf("unmarshaling captured PUT body: %v", err)
	}

	keyUsage, ok := putArg["KeyUsage"]
	if !assert.True(t, ok, "PUT body must carry a KeyUsage field, not omit it: %s", string(capturedPUTBody)) {
		return
	}
	assert.Equal(t, float64(160), keyUsage, "KeyUsage must round-trip from GetTemplate onto UpdateTemplate unchanged")
}
