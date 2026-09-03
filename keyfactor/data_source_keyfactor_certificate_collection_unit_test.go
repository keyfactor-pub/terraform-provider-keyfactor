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
// Regression tests -- PR #210 full-review findings FIX-5 and FIX-9
// (data.keyfactor_certificate_collection):
//
// FIX-5: same nil-response-nil-error shape covered by resource_keyfactor_
// enrollment_pattern_nil_response_unit_test.go's doc comment -- Read()
// dereferenced its Execute() response with no nil guard.
//
// FIX-9: when both id and name are declared, the data source looked up the
// collection by id only and overwrote state.Name unconditionally from the
// server response -- if the configured name didn't actually match the
// collection resolved by id, there was no diagnostic at all, just a
// silently different result than what the config's name implied. The fix
// cross-checks the resolved name against the configured name when both are
// declared, and returns a diagnostics error (not a warning) on mismatch.
// ---------------------------------------------------------------------------

func dataSourceCertificateCollectionSchemaForTest(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := dataSourceCertificateCollectionType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("test setup: GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

func TestUnitCertificateCollectionDataSourceHandlesNilResponseWithoutPanic(t *testing.T) {
	ctx := context.Background()

	server := emptyBody200Server(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	config := CertificateCollectionDataSourceState{
		ID: types.Int64{Value: 8},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}

	d := dataSourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadDataSourceRequest{Config: configObj}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Read panicked on a nil (empty-body 200) API response: %v", rec)
			}
		}()
		d.Read(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Error("Read with a nil API response should return a diagnostics error, got none")
	}
}

// idAndNameMismatchServer answers GetById requests (path contains a numeric
// segment, not "/name") with a collection actually named "Real Name" --
// deliberately different from whatever `name` the test declares in config.
func idAndNameMismatchServer(t *testing.T, actualName string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id": 8, "Name": "` + actualName + `", "Content": "IssuedDN -contains \"demo\""}`))
	}))
}

func TestUnitCertificateCollectionDataSourceIdNameMismatchIsError(t *testing.T) {
	ctx := context.Background()

	server := idAndNameMismatchServer(t, "Real Name")
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	// Both id and name declared, but name doesn't match what id actually
	// resolves to.
	config := CertificateCollectionDataSourceState{
		ID:   types.Int64{Value: 8},
		Name: types.String{Value: "Wrong Name"},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}

	d := dataSourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadDataSourceRequest{Config: configObj}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal(
			"Read with a declared name that doesn't match the collection resolved by id should return a " +
				"diagnostics error (silently-wrong-data risk), got none",
		)
	}
	if !hasAttributeError(resp.Diagnostics, "Certificate collection id/name mismatch") {
		t.Errorf("diags = %+v, want the id/name mismatch error", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Regression test -- full-review round 6 finding FIX-P:
//
// `name` was schema'd as Optional-only (no Computed), while `id` was
// correctly Optional+Computed. Read() unconditionally resolves and writes
// the server's real name into state regardless of which lookup key was
// declared in config. For an id-only lookup (name undeclared in config),
// that means state.Name ends up non-null while config's `name` is null --
// which Terraform Core rejects for a non-Computed attribute ("Provider
// produced inconsistent result after apply" / invalid data source result).
// This is invisible to a test that calls Read() directly (as the other
// tests in this file do), since only Terraform Core enforces the
// config/state consistency contract for non-Computed attributes -- so this
// test instead asserts the schema property itself, mirroring the dual
// "either X or Y" lookup precedent in data_source_keyfactor_certificate_
// store.go (its `id` and `client_machine`/`store_path` alternates are all
// marked Optional+Computed for exactly this reason).
// ---------------------------------------------------------------------------

func TestUnitCertificateCollectionDataSourceNameAttributeIsComputed(t *testing.T) {
	ctx := context.Background()
	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	nameAttr, ok := schema.Attributes["name"]
	if !ok {
		t.Fatal("schema has no \"name\" attribute")
	}
	if !nameAttr.Optional {
		t.Error("\"name\" attribute should remain Optional (either name or id may be used to look up the collection)")
	}
	if !nameAttr.Computed {
		t.Error(
			"\"name\" attribute must be Computed, matching \"id\"'s Optional+Computed treatment -- " +
				"otherwise an id-only lookup (name undeclared) has Read() write a server-resolved, " +
				"non-null name into state for a non-Computed attribute, which Terraform Core rejects " +
				"as an inconsistent result",
		)
	}

	idAttr, ok := schema.Attributes["id"]
	if !ok {
		t.Fatal("schema has no \"id\" attribute")
	}
	if !idAttr.Optional || !idAttr.Computed {
		t.Errorf("\"id\" attribute should be Optional+Computed, got Optional=%v Computed=%v", idAttr.Optional, idAttr.Computed)
	}
}

// TestUnitCertificateCollectionDataSourceIdOnlyLookupSucceeds exercises the
// id-only lookup path (name undeclared in config) end-to-end through Read(),
// confirming it resolves cleanly and populates state.Name from the server.
// It cannot itself detect the Core-level consistency violation (Read() is
// called directly, bypassing Core), but combined with the schema-Computed
// assertion above, this documents the exact scenario FIX-P addresses.
func TestUnitCertificateCollectionDataSourceIdOnlyLookupSucceeds(t *testing.T) {
	ctx := context.Background()

	server := idAndNameMismatchServer(t, "Server Resolved Name")
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	// Only id declared -- name is explicitly left Null/undeclared in config,
	// exactly the shape that would violate Core's non-Computed-attribute
	// contract if the schema's `name` attribute weren't Computed. (Go's
	// zero-value types.String{} is Null:false/Value:"", NOT the same as an
	// undeclared config attribute -- it must be set explicitly here to
	// accurately simulate "name omitted from config".)
	config := CertificateCollectionDataSourceState{
		ID:   types.Int64{Value: 8},
		Name: types.String{Null: true},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}

	d := dataSourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadDataSourceRequest{Config: configObj}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned diagnostics for an id-only lookup: %+v", resp.Diagnostics)
	}

	var result CertificateCollectionDataSourceState
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("state.Get returned diagnostics: %+v", d)
	}
	if result.Name.Null || result.Name.Value != "Server Resolved Name" {
		t.Errorf("result.Name = %+v, want non-null \"Server Resolved Name\"", result.Name)
	}
}

func TestUnitCertificateCollectionDataSourceIdNameMatchSucceeds(t *testing.T) {
	ctx := context.Background()

	server := idAndNameMismatchServer(t, "Demo Collection_TF")
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	// Both id and name declared, and they agree.
	config := CertificateCollectionDataSourceState{
		ID:   types.Int64{Value: 8},
		Name: types.String{Value: "Demo Collection_TF"},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}

	d := dataSourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadDataSourceRequest{Config: configObj}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned diagnostics for a matching id/name pair: %+v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Regression test -- full-review finding F9:
//
// The id/name cross-check above (FIX-9) compared the resolved and
// configured names with a byte-for-byte `!=`. Keyfactor Command's name
// resolution is case-insensitive (SQL Server default collation), so
// id=5/name="dashboard certs" against a collection actually named
// "Dashboard Certs" is NOT a real mismatch from Command's point of view,
// but the byte comparison hard-errored on it anyway. strings.EqualFold
// (this repo's own convention for the identical problem -- see
// resource_keyfactor_security_identity.go's role-name comparisons) fixes
// this while still catching a genuinely different name.
// ---------------------------------------------------------------------------

func TestUnitCertificateCollectionDataSourceIdNameCaseInsensitiveMatchSucceeds(t *testing.T) {
	ctx := context.Background()

	server := idAndNameMismatchServer(t, "Dashboard Certs")
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	// Both id and name declared; name differs from the server's stored
	// value ONLY in case -- Command itself treats these as the same
	// collection (case-insensitive name resolution), so this must NOT
	// error.
	config := CertificateCollectionDataSourceState{
		ID:   types.Int64{Value: 8},
		Name: types.String{Value: "dashboard certs"},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}

	d := dataSourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadDataSourceRequest{Config: configObj}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf(
			"Read returned diagnostics for an id/name pair differing only in case (Command's name resolution "+
				"is case-insensitive, so this is not a real mismatch): %+v", resp.Diagnostics,
		)
	}
}

// TestUnitCertificateCollectionDataSourceIdNameGenuineMismatchStillErrors
// confirms F9's EqualFold fix did not weaken the FIX-9 check itself: a
// genuinely different name (not just a case variant) must still error.
// TestUnitCertificateCollectionDataSourceIdNameMismatchIsError above already
// covers this with "Real Name" vs. "Wrong Name" (unrelated strings); this
// test additionally confirms a name that is a case-insensitive NON-match
// (differs in more than case) is still rejected.
func TestUnitCertificateCollectionDataSourceIdNameGenuineMismatchStillErrors(t *testing.T) {
	ctx := context.Background()

	server := idAndNameMismatchServer(t, "Dashboard Certs")
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := dataSourceCertificateCollectionSchemaForTest(t, ctx)

	config := CertificateCollectionDataSourceState{
		ID:   types.Int64{Value: 8},
		Name: types.String{Value: "dashboard certificates"}, // genuinely different, not just a case variant
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: scratch.Raw}

	d := dataSourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadDataSourceRequest{Config: configObj}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}

	d.Read(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("Read with a genuinely different (not just case-variant) declared name should still error, got none")
	}
	if !hasAttributeError(resp.Diagnostics, "Certificate collection id/name mismatch") {
		t.Errorf("diags = %+v, want the id/name mismatch error", resp.Diagnostics)
	}
}
