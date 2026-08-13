package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests — full-review round 3 finding (correctness, medium):
//
// Switching an existing CA between auth variants (OAuth <-> client-
// certificate) in a single apply always failed with "Provider produced
// inconsistent result after apply." token_url/client_id/scope/audience
// (OAuth) and auth_certificate_issued_dn/issuer_dn/thumbprint (client-
// certificate auth metadata) were Optional+Computed or Computed with only a
// bare tfsdk.UseStateForUnknown(): switching away from a variant leaves that
// variant's attributes undeclared in config, core marks their now-Unknown
// plan, and the bare modifier blindly pins that Unknown back to the OLD
// known state value (it has no notion that the OTHER variant is taking
// over). clearAuthVariant then strips those same fields from the PUT at
// apply time (issue #194), and the server's post-switch representation
// zeroes them out, so Terraform core hard-errors comparing the pinned
// stale plan value against the cleared final state -- the exact mechanism
// scheduleSiblingModifier already fixes for the three schedule pairs
// (resource_keyfactor_certificate_authority_schedule_sibling_modifier_unit_test.go),
// left unhandled for the auth-variant pair.
//
// The fix (authVariantSiblingModifier, resource_keyfactor_certificate_authority.go)
// reads the OTHER variant's trigger attribute(s) from CONFIG at plan time and
// nulls this attribute instead of resurrecting its stale state value
// whenever the other variant is genuinely taking over.
// ---------------------------------------------------------------------------

// TestUnitCABareUseStateForUnknownResurrectsStaleAuthOnVariantSwitch is the
// concrete "red" reproduction, run against the actual pre-fix modifier
// (tfsdk.UseStateForUnknownModifier{}, what token_url/client_id/scope/
// audience and the auth_certificate_* metadata attributes used before this
// change) rather than a hand-edited schema: switching an OAuth-configured CA
// to client-certificate auth, the bare modifier pins token_url's plan back
// to the stale OAuth value because it has no notion of the auth_certificate
// sibling taking over.
func TestUnitCABareUseStateForUnknownResurrectsStaleAuthOnVariantSwitch(t *testing.T) {
	t.Parallel()

	// State: OAuth configured (token_url known). Config: switches to
	// client-certificate auth -- token_url undeclared.
	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.String{Value: "https://idp.example.com/oauth/token"},
		AttributeConfig: types.String{Null: true}, // undeclared in the new config
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

	tfsdk.UseStateForUnknownModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
	}
	if got.Null || got.Value != "https://idp.example.com/oauth/token" {
		t.Fatalf(
			"reproduces the bug: the pre-fix bare UseStateForUnknown modifier resurrected the stale "+
				"token_url=%q from state even though auth_certificate is taking over this apply -- got "+
				"Null=%v Value=%v, want the stale value resurrected to prove this really is the root cause "+
				"the finding fixes",
			"https://idp.example.com/oauth/token", got.Null, got.Value,
		)
	}
}

// TestUnitCAAuthVariantSiblingModifierNullsOAuthOnSwitchToCertAuth is the
// direct "green" regression test: switching an existing OAuth CA to
// client-certificate auth (auth_certificate declared, token_url/client_id/
// scope/audience undeclared) must null each stale OAuth attribute's plan
// instead of resurrecting it from state.
func TestUnitCAAuthVariantSiblingModifierNullsOAuthOnSwitchToCertAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
	config.AuthCertificatePassword = types.String{Value: "s3cr3t"}
	cfg := asConfig(t, ctx, schema, config)

	oauthAttrs := []string{"token_url", "client_id", "scope", "audience"}
	staleValues := map[string]string{
		"token_url": "https://idp.example.com/oauth/token",
		"client_id": "my-client-id",
		"scope":     "ca.read ca.write",
		"audience":  "https://command.example.com",
	}

	for _, attrName := range oauthAttrs {
		attrName := attrName
		t.Run(attrName, func(t *testing.T) {
			t.Parallel()

			req := tfsdk.ModifyAttributePlanRequest{
				AttributeState:  types.String{Value: staleValues[attrName]},
				AttributeConfig: types.String{Null: true},
				Config:          cfg,
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m := authVariantSiblingModifier{triggerPaths: []path.Path{path.Root("auth_certificate")}, nullValue: types.String{Null: true}}
			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if !got.Null {
				t.Fatalf(
					"%s plan = %+v, want Null -- auth_certificate is declared in config and taking over this "+
						"apply, so this attribute's stale prior-state value (%q) must not be resurrected onto "+
						"the plan (that is exactly what produces \"Provider produced inconsistent result after "+
						"apply\" once clearAuthVariant strips it at apply time)",
					attrName, got, staleValues[attrName],
				)
			}
		})
	}
}

// TestUnitCAAuthVariantSiblingModifierNullsCertMetadataOnSwitchToOAuth is the
// symmetric "green" regression test: switching an existing client-
// certificate-auth CA to OAuth (client_id/token_url declared, auth_certificate
// undeclared) must null each stale auth_certificate_* metadata attribute's
// plan instead of resurrecting it from state.
func TestUnitCAAuthVariantSiblingModifierNullsCertMetadataOnSwitchToOAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	metadataAttrs := []string{"auth_certificate_issued_dn", "auth_certificate_issuer_dn", "auth_certificate_thumbprint"}
	triggerPaths := []path.Path{path.Root("client_id"), path.Root("token_url"), path.Root("scope"), path.Root("audience")}

	t.Run("triggered by client_id", func(t *testing.T) {
		t.Parallel()
		config := blankCAConfig()
		config.ClientID = types.String{Value: "my-client-id"}
		config.TokenURL = types.String{Value: "https://idp.example.com/oauth/token"}
		cfg := asConfig(t, ctx, schema, config)

		for _, attrName := range metadataAttrs {
			attrName := attrName
			t.Run(attrName, func(t *testing.T) {
				t.Parallel()

				req := tfsdk.ModifyAttributePlanRequest{
					AttributeState:  types.String{Value: "CN=stale-cert-metadata"},
					AttributeConfig: types.String{Null: true},
					Config:          cfg,
				}
				resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

				m := authVariantSiblingModifier{triggerPaths: triggerPaths, nullValue: types.String{Null: true}}
				m.Modify(ctx, req, resp)

				got, ok := resp.AttributePlan.(types.String)
				if !ok {
					t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
				}
				if !got.Null {
					t.Fatalf(
						"%s plan = %+v, want Null -- client_id/token_url are declared in config and OAuth is "+
							"taking over this apply, so this attribute's stale prior-state certificate metadata "+
							"must not be resurrected onto the plan",
						attrName, got,
					)
				}
			})
		}
	})
}

// TestUnitCAAuthVariantSiblingModifierCarriesForwardWhenNeitherDeclared is
// the negative-space companion: when config declares NEITHER auth variant,
// the modifier must behave exactly like plain UseStateForUnknown and carry
// the prior state value forward -- there is no variant switch to reconcile.
func TestUnitCAAuthVariantSiblingModifierCarriesForwardWhenNeitherDeclared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig() // neither auth_certificate nor any OAuth field declared
	cfg := asConfig(t, ctx, schema, config)

	t.Run("OAuth attribute", func(t *testing.T) {
		t.Parallel()
		req := tfsdk.ModifyAttributePlanRequest{
			AttributeState:  types.String{Value: "https://idp.example.com/oauth/token"},
			AttributeConfig: types.String{Null: true},
			Config:          cfg,
		}
		resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

		m := authVariantSiblingModifier{triggerPaths: []path.Path{path.Root("auth_certificate")}, nullValue: types.String{Null: true}}
		m.Modify(ctx, req, resp)

		got, ok := resp.AttributePlan.(types.String)
		if !ok {
			t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
		}
		if got.Null || got.Unknown || got.Value != "https://idp.example.com/oauth/token" {
			t.Errorf(
				"token_url plan = %+v, want the prior state value carried forward (neither auth variant is "+
					"declared in config, so there is nothing to reconcile -- ordinary UseStateForUnknown "+
					"semantics apply)", got,
			)
		}
	})

	t.Run("cert metadata attribute", func(t *testing.T) {
		t.Parallel()
		req := tfsdk.ModifyAttributePlanRequest{
			AttributeState:  types.String{Value: "CN=prior-cert"},
			AttributeConfig: types.String{Null: true},
			Config:          cfg,
		}
		resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

		m := authVariantSiblingModifier{
			triggerPaths: []path.Path{path.Root("client_id"), path.Root("token_url"), path.Root("scope"), path.Root("audience")},
			nullValue:    types.String{Null: true},
		}
		m.Modify(ctx, req, resp)

		got, ok := resp.AttributePlan.(types.String)
		if !ok {
			t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
		}
		if got.Null || got.Unknown || got.Value != "CN=prior-cert" {
			t.Errorf(
				"auth_certificate_issued_dn plan = %+v, want the prior state value carried forward (neither "+
					"auth variant is declared in config)", got,
			)
		}
	})
}

// TestUnitCAAuthVariantSiblingModifierLeavesUnknownWhenTriggerItselfUnknown
// covers the conservative branch: if a trigger attribute's own config value
// is Unknown (e.g. it references another resource's attribute not yet
// applied this run), the modifier cannot yet tell whether the other variant
// is taking over, so it must leave this attribute Unknown too rather than
// guess.
func TestUnitCAAuthVariantSiblingModifierLeavesUnknownWhenTriggerItselfUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	// Build a config whose auth_certificate is Unknown by round-tripping a
	// plan with an Unknown value through the schema, then reusing the Raw
	// representation as Config -- mirroring scheduleSiblingModifier's own
	// test technique.
	config := blankCAConfig()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	if d := p.SetAttribute(ctx, path.Root("auth_certificate"), types.String{Unknown: true}); d.HasError() {
		t.Fatalf("test setup: Plan.SetAttribute returned diagnostics: %+v", d)
	}
	cfg := tfsdk.Config{Schema: schema, Raw: p.Raw}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.String{Value: "https://idp.example.com/oauth/token"},
		AttributeConfig: types.String{Null: true},
		Config:          cfg,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

	m := authVariantSiblingModifier{triggerPaths: []path.Path{path.Root("auth_certificate")}, nullValue: types.String{Null: true}}
	m.Modify(ctx, req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
	}
	if !got.Unknown {
		t.Errorf(
			"token_url plan = %+v, want Unknown -- auth_certificate's own config value is itself Unknown "+
				"(depends on some other not-yet-known value this apply), so whether it is taking over cannot "+
				"yet be determined; guessing either way risks the same inconsistent-result class this modifier "+
				"exists to prevent", got,
		)
	}
}

// TestUnitCAAuthVariantSiblingModifierNoOpWhenSelfDeclared documents (and
// locks in) the early-return guard shared with tfsdk.UseStateForUnknownModifier
// and scheduleSiblingModifier: when this attribute's OWN plan is already
// known (because config declared it directly), the modifier must not touch
// it at all -- it only ever intervenes on an Unknown plan.
func TestUnitCAAuthVariantSiblingModifierNoOpWhenSelfDeclared(t *testing.T) {
	t.Parallel()

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.String{Value: "https://old-idp.example.com/token"},
		AttributeConfig: types.String{Value: "https://new-idp.example.com/token"},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Value: "https://new-idp.example.com/token"}} // already known -- config declared it

	m := authVariantSiblingModifier{triggerPaths: []path.Path{path.Root("auth_certificate")}, nullValue: types.String{Null: true}}
	m.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
	}
	if got.Null || got.Unknown || got.Value != "https://new-idp.example.com/token" {
		t.Errorf("token_url plan = %+v, want the declared config value left untouched", got)
	}
}

// TestUnitCAAuthAttributesUseSiblingModifier is the schema-level regression
// test: all seven auth-variant attributes (the four OAuth attributes and the
// three client-certificate auth metadata attributes) must be wired to
// authVariantSiblingModifier with the correct trigger path(s), not a bare
// tfsdk.UseStateForUnknown(), so the variant-switch reconciliation above
// actually runs during a real plan.
func TestUnitCAAuthAttributesUseSiblingModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	cases := []struct {
		attrName            string
		triggerNames        []string
		unknownTriggerNames []string
	}{
		{"token_url", []string{"auth_certificate"}, nil},
		{"client_id", []string{"auth_certificate"}, nil},
		{"scope", []string{"auth_certificate"}, nil},
		{"audience", []string{"auth_certificate"}, nil},
		{"auth_certificate_issued_dn", []string{"client_id", "token_url", "scope", "audience"}, []string{"auth_certificate"}},
		{"auth_certificate_issuer_dn", []string{"client_id", "token_url", "scope", "audience"}, []string{"auth_certificate"}},
		{"auth_certificate_thumbprint", []string{"client_id", "token_url", "scope", "audience"}, []string{"auth_certificate"}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.attrName, func(t *testing.T) {
			t.Parallel()
			schemaAttr, ok := schema.Attributes[c.attrName]
			if !ok {
				t.Fatalf("schema has no %s attribute", c.attrName)
			}
			if len(schemaAttr.PlanModifiers) != 1 {
				t.Fatalf("%s: want exactly 1 plan modifier, got %d", c.attrName, len(schemaAttr.PlanModifiers))
			}
			m, ok := schemaAttr.PlanModifiers[0].(authVariantSiblingModifier)
			if !ok {
				t.Fatalf(
					"%s: plan modifier is %T, want authVariantSiblingModifier -- a bare tfsdk.UseStateForUnknown() "+
						"here reproduces the round 3 finding: switching CA auth variants would resurrect the "+
						"stale outgoing-variant value onto the plan, failing apply with \"Provider produced "+
						"inconsistent result after apply\"", c.attrName, schemaAttr.PlanModifiers[0],
				)
			}
			if len(m.triggerPaths) != len(c.triggerNames) {
				t.Fatalf("%s: modifier has %d trigger paths, want %d", c.attrName, len(m.triggerPaths), len(c.triggerNames))
			}
			for i, wantName := range c.triggerNames {
				if m.triggerPaths[i].String() != path.Root(wantName).String() {
					t.Errorf("%s: triggerPaths[%d] = %q, want %q", c.attrName, i, m.triggerPaths[i].String(), path.Root(wantName).String())
				}
			}
			if len(m.unknownTriggerPaths) != len(c.unknownTriggerNames) {
				t.Fatalf(
					"%s: modifier has %d unknownTriggerPaths, want %d -- full-review round 4 finding #1: without "+
						"an unknownTriggerPaths entry for auth_certificate, this attribute has no way to know its "+
						"own variant is incoming/rotating, and resurrects stale/null metadata onto the plan",
					c.attrName, len(m.unknownTriggerPaths), len(c.unknownTriggerNames),
				)
			}
			for i, wantName := range c.unknownTriggerNames {
				if m.unknownTriggerPaths[i].String() != path.Root(wantName).String() {
					t.Errorf("%s: unknownTriggerPaths[%d] = %q, want %q", c.attrName, i, m.unknownTriggerPaths[i].String(), path.Root(wantName).String())
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Regression tests — full-review round 4 finding #1 (correctness, medium):
//
// authVariantSiblingModifier's cert-metadata triggerPaths only ever cover the
// OUTGOING direction (an OAuth attribute becoming declared). There was no
// trigger at all for the INCOMING/rotating direction -- auth_certificate
// itself becoming declared or changing -- so an OAuth->cert-auth switch, or
// rotating auth_certificate on an already cert-auth CA, resurrected stale
// (null, for a switch; old, for a rotation) metadata onto the plan while the
// PUT response carries the server's freshly computed values: "Provider
// produced inconsistent result after apply" on the very switch round 3
// fixed for the OAuth attributes, and on every cert rotation.
//
// unknownTriggerPaths fixes this by leaving the plan Unknown (not null, not
// resurrected) whenever auth_certificate is genuinely declared AND its
// config value differs from its own prior state value.
// ---------------------------------------------------------------------------

// TestUnitCAAuthVariantSiblingModifierLeavesMetadataUnknownOnSwitchToCertAuth
// covers the OAuth->cert-auth switch: the CA's prior state has no cert
// metadata (it was an OAuth CA), config declares auth_certificate for the
// first time, and the metadata attributes' own plan must stay Unknown so the
// server's freshly computed DN/thumbprint isn't compared against a
// null we pinned onto the plan ourselves.
func TestUnitCAAuthVariantSiblingModifierLeavesMetadataUnknownOnSwitchToCertAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----new-cert-----END CERTIFICATE-----"}
	cfg := asConfig(t, ctx, schema, config)

	// Prior state: an OAuth CA. auth_certificate was never declared, so its
	// state value is Null -- the same shape preserveSecrets leaves it in for
	// any CA that has never used client-certificate auth.
	priorState := blankCAConfig()
	priorState.AuthCertificate = types.String{Null: true}
	st := asState(t, ctx, schema, priorState)

	metadataAttrs := []string{"auth_certificate_issued_dn", "auth_certificate_issuer_dn", "auth_certificate_thumbprint"}
	for _, attrName := range metadataAttrs {
		attrName := attrName
		t.Run(attrName, func(t *testing.T) {
			t.Parallel()

			req := tfsdk.ModifyAttributePlanRequest{
				AttributeState:  types.String{Null: true}, // OAuth CA: no cert metadata in prior state
				AttributeConfig: types.String{Null: true},
				Config:          cfg,
				State:           st,
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m := authVariantSiblingModifier{
				triggerPaths:        caOAuthTriggerPaths,
				unknownTriggerPaths: caCertAuthTriggerPaths,
				nullValue:           types.String{Null: true},
			}
			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if !got.Unknown {
				t.Fatalf(
					"%s plan = %+v, want Unknown -- auth_certificate is newly declared (incoming variant), so the "+
						"server will compute fresh metadata that cannot be predicted at plan time; a Null plan "+
						"here would still mismatch the server's known-non-null applied value, producing "+
						"\"Provider produced inconsistent result after apply\"",
					attrName, got,
				)
			}
		})
	}
}

// TestUnitCAAuthVariantSiblingModifierLeavesMetadataUnknownOnCertRotation
// covers rotating auth_certificate on an already cert-auth CA: neither
// triggerPaths (OAuth attrs, still undeclared) nor a naive "is
// auth_certificate declared" check would catch this, because
// auth_certificate is declared on every single apply of a cert-auth CA
// (write-only, not Computed) -- only comparing against the PRIOR state
// value distinguishes a genuine rotation from steady-state redeclaration.
func TestUnitCAAuthVariantSiblingModifierLeavesMetadataUnknownOnCertRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----new-rotated-cert-----END CERTIFICATE-----"}
	cfg := asConfig(t, ctx, schema, config)

	priorState := blankCAConfig()
	priorState.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----old-cert-----END CERTIFICATE-----"}
	st := asState(t, ctx, schema, priorState)

	metadataAttrs := []string{"auth_certificate_issued_dn", "auth_certificate_issuer_dn", "auth_certificate_thumbprint"}
	for _, attrName := range metadataAttrs {
		attrName := attrName
		t.Run(attrName, func(t *testing.T) {
			t.Parallel()

			req := tfsdk.ModifyAttributePlanRequest{
				AttributeState:  types.String{Value: "CN=old-cert-metadata"}, // real prior metadata for the OLD cert
				AttributeConfig: types.String{Null: true},
				Config:          cfg,
				State:           st,
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m := authVariantSiblingModifier{
				triggerPaths:        caOAuthTriggerPaths,
				unknownTriggerPaths: caCertAuthTriggerPaths,
				nullValue:           types.String{Null: true},
			}
			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if !got.Unknown {
				t.Fatalf(
					"%s plan = %+v, want Unknown -- auth_certificate's config value differs from its prior state "+
						"value (a genuine rotation), so the server will compute fresh metadata for the NEW "+
						"certificate; pinning the OLD metadata (%q) onto the plan mismatches the server's applied "+
						"value, producing \"Provider produced inconsistent result after apply\"",
					attrName, got, "CN=old-cert-metadata",
				)
			}
		})
	}
}

// TestUnitCAAuthVariantSiblingModifierCarriesForwardMetadataOnStableCertAuth
// is the no-perpetual-diff companion: a steady-state cert-auth CA
// re-declares the SAME auth_certificate value every apply (it is write-only
// and not Computed, so config must keep supplying it or clearAuthVariant
// treats it as cleared) -- unknownTriggerPaths must not mistake that steady
// redeclaration for an incoming/rotating switch, or every plan on an
// unchanged cert-auth CA would show its metadata as "(known after apply)"
// forever.
func TestUnitCAAuthVariantSiblingModifierCarriesForwardMetadataOnStableCertAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	const stableCert = "-----BEGIN CERTIFICATE-----stable-cert-----END CERTIFICATE-----"

	config := blankCAConfig()
	config.AuthCertificate = types.String{Value: stableCert}
	cfg := asConfig(t, ctx, schema, config)

	priorState := blankCAConfig()
	priorState.AuthCertificate = types.String{Value: stableCert} // identical to config: unchanged
	st := asState(t, ctx, schema, priorState)

	metadataAttrs := []string{"auth_certificate_issued_dn", "auth_certificate_issuer_dn", "auth_certificate_thumbprint"}
	for _, attrName := range metadataAttrs {
		attrName := attrName
		t.Run(attrName, func(t *testing.T) {
			t.Parallel()

			req := tfsdk.ModifyAttributePlanRequest{
				AttributeState:  types.String{Value: "CN=stable-cert-metadata"},
				AttributeConfig: types.String{Null: true},
				Config:          cfg,
				State:           st,
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m := authVariantSiblingModifier{
				triggerPaths:        caOAuthTriggerPaths,
				unknownTriggerPaths: caCertAuthTriggerPaths,
				nullValue:           types.String{Null: true},
			}
			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if got.Unknown || got.Null || got.Value != "CN=stable-cert-metadata" {
				t.Fatalf(
					"%s plan = %+v, want the prior state value (%q) carried forward -- auth_certificate is "+
						"unchanged from state, so this is steady-state redeclaration, not an incoming/rotating "+
						"switch; forcing Unknown here would show a perpetual diff on every apply of an unchanged "+
						"cert-auth CA",
					attrName, got, "CN=stable-cert-metadata",
				)
			}
		})
	}
}

// TestUnitCAAuthVariantSiblingModifierWithoutUnknownTriggerResurrectsStaleMetadataOnRotation
// is the concrete "red" reproduction for the cert-rotation half of finding
// #1: run the SAME rotation scenario as
// TestUnitCAAuthVariantSiblingModifierLeavesMetadataUnknownOnCertRotation
// above through a modifier configured exactly like the pre-round-4 schema
// wiring (triggerPaths only, no unknownTriggerPaths) to prove
// unknownTriggerPaths -- not the tail's IsNull guard -- is what fixes
// rotation: the metadata attribute's own prior state here is non-null (a
// real cert-auth CA's real prior metadata), so the IsNull guard alone never
// fires, and without unknownTriggerPaths there is no signal at all that
// auth_certificate changed.
func TestUnitCAAuthVariantSiblingModifierWithoutUnknownTriggerResurrectsStaleMetadataOnRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----new-rotated-cert-----END CERTIFICATE-----"}
	cfg := asConfig(t, ctx, schema, config)

	priorState := blankCAConfig()
	priorState.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----old-cert-----END CERTIFICATE-----"}
	st := asState(t, ctx, schema, priorState)

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.String{Value: "CN=old-cert-metadata"},
		AttributeConfig: types.String{Null: true},
		Config:          cfg,
		State:           st,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

	// Deliberately the pre-round-4 shape: no unknownTriggerPaths.
	m := authVariantSiblingModifier{triggerPaths: caOAuthTriggerPaths, nullValue: types.String{Null: true}}
	m.Modify(ctx, req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
	}
	if got.Unknown || got.Null || got.Value != "CN=old-cert-metadata" {
		t.Fatalf(
			"reproduces the bug: without unknownTriggerPaths, the modifier has no way to notice auth_certificate "+
				"changed and resurrects the stale OLD metadata (%q) from state -- got %+v, want the stale value "+
				"resurrected to prove unknownTriggerPaths (not the tail's IsNull guard) is what fixes cert "+
				"rotation", "CN=old-cert-metadata", got,
		)
	}
}

// TestUnitCAAuthVariantSiblingModifierPreRound4TailPinsNullMetadataOnSwitch
// is the concrete "red" reproduction for the OAuth->cert-auth switch half of
// finding #1, run against the tail logic AS IT EXISTED BEFORE this fix
// (mirrored verbatim below -- an IsUnknown()-only guard, no IsNull() guard --
// since that exact code no longer exists in the modifier to call directly):
// a genuinely-null prior metadata state (an OAuth CA that never had
// client-certificate auth) got pinned onto the plan as an explicit Null
// instead of staying Unknown, which still mismatches the server's non-null
// applied value once the switch to auth_certificate completes.
func TestUnitCAAuthVariantSiblingModifierPreRound4TailPinsNullMetadataOnSwitch(t *testing.T) {
	t.Parallel()

	// req.AttributeState mirrors an OAuth CA's cert-metadata attribute: it
	// has never been set, so it is Null (not Unknown, and not the Go-nil
	// interface the framework itself already guards at the top of Modify).
	state := types.String{Null: true}

	// Pre-round-4 tail (resource_keyfactor_certificate_authority.go, before
	// this fix): only checked IsUnknown(), so a Null state value fell
	// through to being copied onto the plan verbatim.
	var plan attr.Value = types.String{Unknown: true}
	if !state.IsUnknown() {
		plan = state
	}

	got, ok := plan.(types.String)
	if !ok {
		t.Fatalf("plan is not types.String: %T", plan)
	}
	if !got.Null {
		t.Fatalf(
			"reproduces the bug: the pre-round-4 tail (IsUnknown()-only guard) pinned the metadata plan to an "+
				"explicit Null (got %+v) instead of leaving it Unknown, even though the OAuth->cert-auth switch "+
				"this apply means the server will return real non-null metadata -- \"Provider produced "+
				"inconsistent result after apply\" on the null-vs-known-string mismatch. The fix adds an "+
				"IsNull() guard to the tail (matching tfsdk.UseStateForUnknownModifier's own contract) so this "+
				"case is left Unknown instead", got,
		)
	}
}
