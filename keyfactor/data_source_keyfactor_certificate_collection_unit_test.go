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
