package keyfactor

import (
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: keyfactor_certificate_authority with key_retention = "2" produced
// "Provider produced inconsistent result after apply" because Command
// accepts either a numeric string ("2") or a symbolic name
// ("AfterExpiration") on write, but always returns the symbolic name on
// read. caResponseToState (via keyRetentionIntToTfString) unconditionally
// used the symbolic name, so a numeric-string config could never match the
// post-apply Read/Create response.
//
// preserveKeyRetentionRepresentation fixes this by preferring the user's
// originally configured representation whenever it denotes the same
// underlying enum value as what the server returned -- mirroring the
// certificate resource's certificate_authority name-normalization pattern.
// ---------------------------------------------------------------------------

func TestUnitCAPreserveKeyRetentionRepresentation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured string // representation the user configured (prior state/plan)
		fromServer string // representation caResponseToState produced from the API response
		want       string // representation expected in final state
	}{
		{
			name:       "numeric config, symbolic server response -> preserve numeric",
			configured: "2",
			fromServer: "AfterExpiration",
			want:       "2",
		},
		{
			name:       "symbolic config, symbolic server response -> unchanged",
			configured: "AfterExpiration",
			fromServer: "AfterExpiration",
			want:       "AfterExpiration",
		},
		{
			name:       "numeric config, matching numeric server response -> unchanged",
			configured: "0",
			fromServer: "Disabled",
			want:       "0",
		},
		{
			name:       "config value denotes a different enum than server -- do not clobber server value",
			configured: "1",
			fromServer: "AfterExpiration",
			want:       "AfterExpiration",
		},
		{
			name:       "unknown/unrecognized server value is left alone",
			configured: "2",
			fromServer: "SomeFutureEnumName",
			want:       "SomeFutureEnumName",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := KeyfactorCertificateAuthority{
				KeyRetention: types.String{Value: tc.fromServer},
			}
			source := KeyfactorCertificateAuthority{
				KeyRetention: types.String{Value: tc.configured},
			}

			preserveKeyRetentionRepresentation(&target, source)

			if target.KeyRetention.Value != tc.want {
				t.Errorf("KeyRetention = %q, want %q", target.KeyRetention.Value, tc.want)
			}
		})
	}

	t.Run("null/unknown source or target are left alone", func(t *testing.T) {
		t.Parallel()

		target := KeyfactorCertificateAuthority{KeyRetention: types.String{Value: "AfterExpiration"}}
		source := KeyfactorCertificateAuthority{KeyRetention: types.String{Null: true}}
		preserveKeyRetentionRepresentation(&target, source)
		if target.KeyRetention.Value != "AfterExpiration" || target.KeyRetention.Null {
			t.Errorf("expected target unchanged when source is null, got %+v", target.KeyRetention)
		}

		target2 := KeyfactorCertificateAuthority{KeyRetention: types.String{Null: true}}
		source2 := KeyfactorCertificateAuthority{KeyRetention: types.String{Value: "2"}}
		preserveKeyRetentionRepresentation(&target2, source2)
		if !target2.KeyRetention.Null {
			t.Errorf("expected target to remain null, got %+v", target2.KeyRetention)
		}
	})
}

// TestUnitCACreateReadRoundTripsNumericKeyRetention exercises the full
// caResponseToState + preserveKeyRetentionRepresentation flow the way
// Create/Read/Update call it, confirming a numeric-string config value
// round-trips without drift.
func TestUnitCACreateReadRoundTripsNumericKeyRetention(t *testing.T) {
	t.Parallel()

	kr := v1.CSSCMSCoreEnumsKeyRetentionPolicy(2) // AfterExpiration

	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(42)
	resp.SetLogicalName("Test-CA")
	resp.SetHostName("http://ca.example.com/ejbca")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	resp.KeyRetention = &kr

	plan := KeyfactorCertificateAuthority{
		KeyRetention: types.String{Value: "2"},
	}

	state := caResponseToState(resp)
	if state.KeyRetention.Value != "AfterExpiration" {
		t.Fatalf("precondition: caResponseToState should return the symbolic name before normalization, got %q", state.KeyRetention.Value)
	}

	preserveKeyRetentionRepresentation(&state, plan)

	if state.KeyRetention.Value != "2" {
		t.Errorf("state.KeyRetention = %q, want %q (config's original numeric representation)", state.KeyRetention.Value, "2")
	}
}
