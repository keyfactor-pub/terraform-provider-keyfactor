package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Unit tests — CA auth-variant mutual exclusion.
//
// Live repro (provider v2.9.1 -> Command 25.5): destroying a
// keyfactor_certificate_authority configured with client-certificate auth
// (auth_certificate/auth_certificate_password, ca_type=1) failed because
// Delete()'s clear-schedules-before-delete fallback rebuilt the PUT payload
// from raw on-disk state, which carries token_url/client_id/scope/audience
// forward as known, non-null EMPTY STRINGS -- not Null -- because those
// attributes are Optional+Computed with UseStateForUnknown, and Command's own
// GET response represents "no OAuth configured" as "" rather than as a null
// field (see caResponseToState's use of nullableStringToTfString). Sending
// those empty-but-"set" OAuth fields alongside the real, populated
// AuthCertificate/AuthCertificatePassword fields triggered Command's
// mutual-exclusion validation: "Fields for OAuth and Client Certificate
// Authentication cannot both be provided for the same CA."
//
// The fix (clearAuthVariant, called from buildCARequest itself) derives which
// auth variant is genuinely in use and unsets -- not just empties -- every
// field belonging to the other variant, for every buildCARequest caller
// (Create, Update, and Delete's fallback) identically.
// ---------------------------------------------------------------------------

// TestUnitCABuildRequestClientCertAuthOmitsOAuthFields is the direct
// regression test for the auth-variant mutual exclusion bug: a plan/state shaped like a real
// client-certificate-auth CA (AuthCertificate/AuthCertificatePassword
// populated, OAuth fields carried forward as known empty strings) must
// produce a request with every OAuth field genuinely unset -- not merely set
// to "" -- so Command never sees it as "OAuth fields provided."
func TestUnitCABuildRequestClientCertAuthOmitsOAuthFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	plan := blankCAConfig()
	plan.CAType = types.Int64{Value: 1}
	plan.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
	plan.AuthCertificatePassword = types.String{Value: "s3cr3t"}
	// Simulates what a real Delete()/Update() call would hand buildCARequest:
	// token_url/client_id/scope/audience carried forward from a prior Read as
	// known, non-null empty strings -- NOT Null -- because they are
	// Optional+Computed with UseStateForUnknown and the server's GET response
	// represents "no OAuth" as "" rather than a null field.
	plan.TokenURL = types.String{Value: ""}
	plan.ClientID = types.String{Value: ""}
	plan.Scope = types.String{Value: ""}
	plan.Audience = types.String{Value: ""}
	plan.ClientSecret = types.String{Null: true}

	req, diags := buildCARequest(ctx, plan)
	if diags.HasError() {
		t.Fatalf("buildCARequest returned diagnostics: %+v", diags)
	}

	if req.TokenURL.IsSet() {
		t.Errorf(
			"TokenURL: want unset (client-certificate auth is in use), got IsSet=true Value=%v -- "+
				"this reproduces the bug: Command rejects a request carrying fields for both auth variants",
			req.TokenURL.Get(),
		)
	}
	if req.ClientId.IsSet() {
		t.Errorf("ClientId: want unset (client-certificate auth is in use), got IsSet=true Value=%v", req.ClientId.Get())
	}
	if req.ClientSecret != nil {
		t.Errorf("ClientSecret: want nil (client-certificate auth is in use), got non-nil")
	}
	if req.Scope.IsSet() {
		t.Errorf("Scope: want unset (client-certificate auth is in use), got IsSet=true Value=%v", req.Scope.Get())
	}
	if req.Audience.IsSet() {
		t.Errorf("Audience: want unset (client-certificate auth is in use), got IsSet=true Value=%v", req.Audience.Get())
	}
	if req.AuthCertificate == nil {
		t.Errorf("AuthCertificate: want populated (client-certificate auth is in use), got nil")
	}
	if req.AuthCertificatePassword == nil {
		t.Errorf("AuthCertificatePassword: want populated (client-certificate auth is in use), got nil")
	}
}

// TestUnitCABuildRequestOAuthOmitsCertAuthFields is the symmetric case: a
// genuinely OAuth-configured CA must never send client-certificate auth
// fields, even defensively (they are expected to already be Null here since
// auth_certificate is not Computed, but clearAuthVariant clears them anyway).
func TestUnitCABuildRequestOAuthOmitsCertAuthFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	plan := blankCAConfig()
	plan.CAType = types.Int64{Value: 1}
	plan.TokenURL = types.String{Value: "https://idp.example.com/oauth/token"}
	plan.ClientID = types.String{Value: "my-client-id"}
	plan.ClientSecret = types.String{Value: "my-client-secret"}
	plan.Scope = types.String{Value: "ca.read ca.write"}
	plan.Audience = types.String{Value: "https://command.example.com"}
	plan.AuthCertificate = types.String{Null: true}
	plan.AuthCertificatePassword = types.String{Null: true}

	req, diags := buildCARequest(ctx, plan)
	if diags.HasError() {
		t.Fatalf("buildCARequest returned diagnostics: %+v", diags)
	}

	if req.AuthCertificate != nil {
		t.Errorf("AuthCertificate: want nil (OAuth is in use), got non-nil")
	}
	if req.AuthCertificatePassword != nil {
		t.Errorf("AuthCertificatePassword: want nil (OAuth is in use), got non-nil")
	}
	if !req.TokenURL.IsSet() || req.TokenURL.Get() == nil || *req.TokenURL.Get() != "https://idp.example.com/oauth/token" {
		t.Errorf("TokenURL: want the configured OAuth token URL preserved, got IsSet=%v Value=%v", req.TokenURL.IsSet(), req.TokenURL.Get())
	}
	if !req.ClientId.IsSet() || req.ClientId.Get() == nil || *req.ClientId.Get() != "my-client-id" {
		t.Errorf("ClientId: want the configured OAuth client ID preserved, got IsSet=%v Value=%v", req.ClientId.IsSet(), req.ClientId.Get())
	}
	if req.ClientSecret == nil {
		t.Errorf("ClientSecret: want populated (OAuth is in use), got nil")
	}
}

// TestUnitCABuildRequestNeitherAuthVariantOmitsBoth covers the DCOM-CA /
// explicit-credentials case: neither auth_certificate nor OAuth is genuinely
// configured, so even stale carried-forward empty-string OAuth fields must
// not be echoed onto the wire.
func TestUnitCABuildRequestNeitherAuthVariantOmitsBoth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	plan := blankCAConfig()
	plan.CAType = types.Int64{Value: 0} // DCOM
	plan.TokenURL = types.String{Value: ""}
	plan.ClientID = types.String{Value: ""}
	plan.Scope = types.String{Value: ""}
	plan.Audience = types.String{Value: ""}
	plan.AuthCertificate = types.String{Null: true}
	plan.AuthCertificatePassword = types.String{Null: true}
	plan.ClientSecret = types.String{Null: true}

	req, diags := buildCARequest(ctx, plan)
	if diags.HasError() {
		t.Fatalf("buildCARequest returned diagnostics: %+v", diags)
	}

	if req.TokenURL.IsSet() {
		t.Errorf("TokenURL: want unset (no auth variant configured), got IsSet=true")
	}
	if req.ClientId.IsSet() {
		t.Errorf("ClientId: want unset (no auth variant configured), got IsSet=true")
	}
	if req.Scope.IsSet() {
		t.Errorf("Scope: want unset (no auth variant configured), got IsSet=true")
	}
	if req.Audience.IsSet() {
		t.Errorf("Audience: want unset (no auth variant configured), got IsSet=true")
	}
	if req.ClientSecret != nil {
		t.Errorf("ClientSecret: want nil (no auth variant configured), got non-nil")
	}
	if req.AuthCertificate != nil {
		t.Errorf("AuthCertificate: want nil (no auth variant configured), got non-nil")
	}
	if req.AuthCertificatePassword != nil {
		t.Errorf("AuthCertificatePassword: want nil (no auth variant configured), got non-nil")
	}
}

// TestUnitCADeleteClearScheduleFallbackDoesNotConflictAuthVariants
// reproduces the exact live-repro shape from the auth-variant mutual exclusion bug: Delete()'s
// clear-schedules-before-delete fallback copies raw on-disk state (not a
// freshly-resolved plan) into clearState, nulls only the schedule fields, and
// passes the result straight to buildCARequest. Before the fix, this path
// carried the client-cert CA's real AuthCertificate/AuthCertificatePassword
// alongside the empty-but-"set" OAuth fields Command's GET response leaves
// behind, and Command rejected the resulting PUT.
func TestUnitCADeleteClearScheduleFallbackDoesNotConflictAuthVariants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Shape of on-disk tfstate for a real client-cert-auth HTTPS CA after at
	// least one successful Read: OAuth fields read back as "" (see
	// caResponseToState / nullableStringToTfString), not Null.
	state := blankCAConfig()
	state.CAType = types.Int64{Value: 1}
	state.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
	state.AuthCertificatePassword = types.String{Value: "s3cr3t"}
	state.TokenURL = types.String{Value: ""}
	state.ClientID = types.String{Value: ""}
	state.Scope = types.String{Value: ""}
	state.Audience = types.String{Value: ""}
	state.ClientSecret = types.String{Null: true}
	state.FullScanIntervalMinutes = types.Int64{Value: 60}

	// Mirrors Delete()'s clear-schedules-before-delete fallback exactly.
	clearState := state
	clearState.FullScanIntervalMinutes = types.Int64{Null: true}
	clearState.IncrementalScanIntervalMinutes = types.Int64{Null: true}
	clearState.ThresholdCheckIntervalMinutes = types.Int64{Null: true}

	req, diags := buildCARequest(ctx, clearState)
	if diags.HasError() {
		t.Fatalf("buildCARequest returned diagnostics: %+v", diags)
	}

	if req.TokenURL.IsSet() || req.ClientId.IsSet() || req.Scope.IsSet() || req.Audience.IsSet() || req.ClientSecret != nil {
		t.Fatalf(
			"clear-schedules-before-delete request carries OAuth fields alongside AuthCertificate -- "+
				"this reproduces the bug's \"Fields for OAuth and Client Certificate Authentication cannot "+
				"both be provided for the same CA\" error: TokenURL.IsSet=%v ClientId.IsSet=%v Scope.IsSet=%v "+
				"Audience.IsSet=%v ClientSecret!=nil=%v",
			req.TokenURL.IsSet(), req.ClientId.IsSet(), req.Scope.IsSet(), req.Audience.IsSet(), req.ClientSecret != nil,
		)
	}
	if req.AuthCertificate == nil || req.AuthCertificatePassword == nil {
		t.Errorf("AuthCertificate/AuthCertificatePassword: want populated (client-certificate auth is in use), got nil")
	}
	if req.FullScan != nil {
		t.Errorf("FullScan: want nil (schedule was cleared for the pre-delete update), got non-nil")
	}
}

// ---------------------------------------------------------------------------
// Regression tests: missing cross-field validation.
//
// Before this fix, nothing at plan time rejected a config that declares BOTH
// auth_certificate AND client_id/token_url on the same CA. clearAuthVariant's
// switch prefers client-certificate auth (hasCertAuth case first), so it
// silently stripped the user's declared OAuth fields from the request --
// Command never saw the conflict and never returned its own actionable
// "Fields for OAuth and Client Certificate Authentication cannot both be
// provided for the same CA" error. Instead, because client_id/token_url are
// Optional+Computed (a known, declared config value plans directly to
// itself), Terraform recorded a plan with the user's declared client_id,
// while the actually-created CA has no OAuth config at all -- caResponseToState
// returns null/empty ClientID, and the framework rejects the resulting apply
// with a confusing "Provider produced inconsistent result after apply:
// .client_id" instead of a clear, actionable plan-time error naming both
// attributes.
//
// The fix adds a ValidateConfig-time cross-field check
// (validateCAConfigConstraints) rejecting both variants declared with a
// genuinely non-empty value at once.
// ---------------------------------------------------------------------------

// TestUnitCAValidateConfigRejectsBothAuthVariantsDeclared is the direct
// regression test: declaring both auth_certificate and client_id (or
// token_url) with genuinely non-empty values must be rejected at plan time.
func TestUnitCAValidateConfigRejectsBothAuthVariantsDeclared(t *testing.T) {
	t.Parallel()

	t.Run("auth_certificate + client_id", func(t *testing.T) {
		t.Parallel()
		cfg := blankCAConfig()
		cfg.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
		cfg.ClientID = types.String{Value: "my-client-id"}

		diags := validateCAConfigConstraints(cfg)
		if !diags.HasError() {
			t.Fatalf(
				"expected validateCAConfigConstraints to reject auth_certificate + client_id declared " +
					"together, got no error -- without this check, clearAuthVariant silently strips the " +
					"declared client_id from the request, and the framework surfaces a confusing " +
					"\"Provider produced inconsistent result after apply: .client_id\" instead of an " +
					"actionable plan-time error",
			)
		}
	})

	t.Run("auth_certificate + token_url", func(t *testing.T) {
		t.Parallel()
		cfg := blankCAConfig()
		cfg.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
		cfg.TokenURL = types.String{Value: "https://idp.example.com/oauth/token"}

		diags := validateCAConfigConstraints(cfg)
		if !diags.HasError() {
			t.Fatalf("expected validateCAConfigConstraints to reject auth_certificate + token_url declared together, got no error")
		}
	})
}

// TestUnitCAValidateConfigAllowsEachAuthVariantAlone is the negative-space
// companion: declaring exactly one auth variant (or neither) must never be
// rejected by this check.
func TestUnitCAValidateConfigAllowsEachAuthVariantAlone(t *testing.T) {
	t.Parallel()

	t.Run("client-certificate auth alone", func(t *testing.T) {
		t.Parallel()
		cfg := blankCAConfig()
		cfg.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
		cfg.AuthCertificatePassword = types.String{Value: "s3cr3t"}

		if diags := validateCAConfigConstraints(cfg); diags.HasError() {
			t.Errorf("expected no error for auth_certificate declared alone, got: %+v", diags)
		}
	})

	t.Run("OAuth alone", func(t *testing.T) {
		t.Parallel()
		cfg := blankCAConfig()
		cfg.ClientID = types.String{Value: "my-client-id"}
		cfg.TokenURL = types.String{Value: "https://idp.example.com/oauth/token"}

		if diags := validateCAConfigConstraints(cfg); diags.HasError() {
			t.Errorf("expected no error for client_id/token_url declared alone, got: %+v", diags)
		}
	})

	t.Run("neither declared", func(t *testing.T) {
		t.Parallel()
		cfg := blankCAConfig()

		if diags := validateCAConfigConstraints(cfg); diags.HasError() {
			t.Errorf("expected no error when neither auth variant is declared, got: %+v", diags)
		}
	})

	t.Run("client_id unknown alongside declared auth_certificate", func(t *testing.T) {
		t.Parallel()
		// An Unknown client_id (e.g. referencing another not-yet-known
		// resource's output) can never be resolved at config-validation time --
		// must not be treated as "declared."
		cfg := blankCAConfig()
		cfg.AuthCertificate = types.String{Value: "-----BEGIN CERTIFICATE-----..."}
		cfg.ClientID = types.String{Unknown: true}

		if diags := validateCAConfigConstraints(cfg); diags.HasError() {
			t.Errorf("expected no error when client_id is Unknown (not yet resolvable), got: %+v", diags)
		}
	})
}
