package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Shared test helpers for the certificate authority resource's unit tests
// (auth-variant mutual exclusion and auth-variant sibling modifier
// reconciliation). Factored out of the now-removed CA Daily-schedule test
// file so they survive independently of that feature.
// ---------------------------------------------------------------------------

// blankCAConfig returns a KeyfactorCertificateAuthority with every attribute
// explicitly set to a well-typed value (Required attributes get a concrete
// value; every Optional/Computed attribute is explicit Null, including the
// only List-typed attribute, which additionally needs its ElemType set). This
// is a test-only helper so callers can flip just the field(s) under test
// without hand-populating ~40 unrelated struct fields, while still producing
// a struct that tfsdk.Plan.Set / tfsdk.Config-via-Plan.Set can serialize
// without a schema/type mismatch.
func blankCAConfig() KeyfactorCertificateAuthority {
	nullStr := types.String{Null: true}
	nullBool := types.Bool{Null: true}
	nullInt := types.Int64{Null: true}
	return KeyfactorCertificateAuthority{
		ID:                             nullStr,
		LogicalName:                    types.String{Value: "Test-CA"},
		HostName:                       types.String{Value: "http://ca.example.com/ejbca"},
		CAType:                         types.Int64{Value: 1},
		Delegate:                       nullBool,
		DelegateEnrollment:             nullBool,
		ForestRoot:                     nullStr,
		ConfigurationTenant:            nullStr,
		Remote:                         nullBool,
		Agent:                          nullStr,
		Standalone:                     nullBool,
		UseCAConnector:                 nullBool,
		ConnectorPool:                  nullStr,
		MonitorThresholds:              nullBool,
		IssuanceMax:                    nullInt,
		IssuanceMin:                    nullInt,
		FailureMax:                     nullInt,
		RFCEnforcement:                 nullBool,
		Properties:                     nullStr,
		AllowedEnrollmentTypes:         nullInt,
		KeyRetention:                   nullStr,
		KeyRetentionDays:               nullInt,
		EnforceUniqueDN:                nullBool,
		SubscriberTerms:                nullBool,
		AllowOneClickRenewals:          nullBool,
		NewEndEntityOnRenewAndReissue:  nullBool,
		UseForEnrollment:               nullBool,
		CertificateCleanupEnabled:      nullBool,
		DeleteWithArchivedKey:          nullBool,
		TimeAfterExpiration:            nullInt,
		TimeAfterExpirationUnits:       nullInt,
		UseAllowedRequesters:           nullBool,
		AllowedRequesters:              types.List{Null: true, ElemType: types.StringType},
		ExplicitCredentials:            nullBool,
		ExplicitUser:                   nullStr,
		ExplicitPassword:               nullStr,
		AuthCertificate:                nullStr,
		AuthCertificatePassword:        nullStr,
		AuthCertificateIssuedDN:        nullStr,
		AuthCertificateIssuerDN:        nullStr,
		AuthCertificateThumbprint:      nullStr,
		TokenURL:                       nullStr,
		ClientID:                       nullStr,
		ClientSecret:                   nullStr,
		Scope:                          nullStr,
		Audience:                       nullStr,
		FullScanIntervalMinutes:        nullInt,
		IncrementalScanIntervalMinutes: nullInt,
		ThresholdCheckIntervalMinutes:  nullInt,
		ForceSave:                      nullBool,
		AgentName:                      nullStr,
		AgentUsername:                  nullStr,
		DenialMax:                      nullInt,
		LastScan:                       nullStr,
	}
}

// asConfig round-trips a KeyfactorCertificateAuthority through a tfsdk.Plan
// (which has a .Set method Config lacks in this framework version) and
// reuses the resulting Raw value to build a tfsdk.Config with the same
// underlying representation -- Plan/State/Config are all thin wrappers over
// {Raw tftypes.Value; Schema Schema}.
func asConfig(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateAuthority) tfsdk.Config {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.Config{Schema: schema, Raw: p.Raw}
}

// asState is asConfig's State-typed counterpart, needed by tests exercising
// authVariantSiblingModifier's unknownTriggerPaths, which compares a trigger path's CONFIG value against its own
// prior STATE value to distinguish an incoming/rotating auth_certificate
// from a steadily-redeclared one.
func asState(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateAuthority) tfsdk.State {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.State{Schema: schema, Raw: p.Raw}
}

// caSchema returns the certificate authority resource's schema for tests that
// need to inspect or exercise its plan modifiers directly.
func caSchema(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceCertificateAuthorityType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}
