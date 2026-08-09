package keyfactor

import (
	"context"
	"testing"

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
		attrName     string
		triggerNames []string
	}{
		{"token_url", []string{"auth_certificate"}},
		{"client_id", []string{"auth_certificate"}},
		{"scope", []string{"auth_certificate"}},
		{"audience", []string{"auth_certificate"}},
		{"auth_certificate_issued_dn", []string{"client_id", "token_url", "scope", "audience"}},
		{"auth_certificate_issuer_dn", []string{"client_id", "token_url", "scope", "audience"}},
		{"auth_certificate_thumbprint", []string{"client_id", "token_url", "scope", "audience"}},
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
		})
	}
}
