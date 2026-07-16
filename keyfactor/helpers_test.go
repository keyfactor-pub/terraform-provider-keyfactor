package keyfactor

import (
	"context"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
)

func TestMapOAuthSecurityClaim(t *testing.T) {
	tests := []struct {
		name                     string
		claimType                string
		localClaimValue          string
		localProviderAuthScheme  string
		remoteClaimValue         string
		remoteProviderAuthScheme string

		expectedClaimType          string
		expectedClaimValue         string
		expectedProviderAuthScheme string
	}{
		{
			name:                     "Unknown security claim test",
			claimType:                "OAuthSubject",
			localClaimValue:          "12345678",
			localProviderAuthScheme:  "unknown",
			remoteProviderAuthScheme: "Unknown",
			remoteClaimValue:         "12345678",

			expectedClaimType:          "OAuthSubject",
			expectedClaimValue:         "12345678",
			expectedProviderAuthScheme: "unknown",
		},
		{
			name:                     "Active Directory security claim test - no domain prefix",
			claimType:                "User",
			localClaimValue:          "Terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "Terraformer",

			expectedClaimType:          "User",
			expectedClaimValue:         "Terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - domain prefix",
			claimType:                "User",
			localClaimValue:          "Terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\Terraformer",

			expectedClaimType:          "User",
			expectedClaimValue:         "Terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - multiple domains",
			claimType:                "User",
			localClaimValue:          "Something\\Terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\Something\\Terraformer",

			expectedClaimType:          "User",
			expectedClaimValue:         "Something\\Terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - value mismatch",
			claimType:                "User",
			localClaimValue:          "Terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "Terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - case mismatch domain",
			claimType:                "User",
			localClaimValue:          "keyfactor\\Terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "keyfactor\\Terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - case mismatch username",
			claimType:                "User",
			localClaimValue:          "KEYFACTOR\\Terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "KEYFACTOR\\Terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - case mismatch domain + username",
			claimType:                "User",
			localClaimValue:          "keyfactor\\terraformer",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "keyfactor\\terraformer",
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - value mismatch (no domain on input)",
			claimType:                "User",
			localClaimValue:          "terraformer123",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "KEYFACTOR\\TERRAFORMER", // Should store remote value -- let Terraform handle the mismatch
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - value mismatch (with domain on input)",
			claimType:                "User",
			localClaimValue:          "FOOBAR\\terraformer123",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "KEYFACTOR\\TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "KEYFACTOR\\TERRAFORMER", // Should store remote value -- let Terraform handle the mismatch
			expectedProviderAuthScheme: "Active Directory",
		},
		{
			name:                     "Active Directory security claim test - value mismatch (no domain on input or remote)",
			claimType:                "User",
			localClaimValue:          "terraformer123",
			localProviderAuthScheme:  "Active Directory",
			remoteProviderAuthScheme: "Active Directory",
			remoteClaimValue:         "TERRAFORMER",

			expectedClaimType:          "User",
			expectedClaimValue:         "TERRAFORMER", // Should store remote value -- let Terraform handle the mismatch
			expectedProviderAuthScheme: "Active Directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionResponse{
				Id:          ptr(int32(1234)),
				Description: *kfv1.NewNullableString(ptr("Test")),
				ClaimType:   *kfv1.NewNullableString(&tt.claimType),
				ClaimValue:  *kfv1.NewNullableString(&tt.remoteClaimValue),
				Provider: ptr(kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionProviderResponse{
					Id:                   ptr("cd0a5d39-ffeb-42ff-bd59-a791c1dbd8a5"),
					AuthenticationScheme: *kfv1.NewNullableString(&tt.remoteProviderAuthScheme),
					DisplayName:          *kfv1.NewNullableString(ptr("Test")),
				}),
			}

			local := OAuthSecurityClaim{
				Description:                  getStringType(ptr("Test")),
				ClaimType:                    getStringType(&tt.claimType),
				ClaimValue:                   getStringType(&tt.localClaimValue),
				ProviderAuthenticationScheme: getStringType(&tt.localProviderAuthScheme),
			}

			result := mapOAuthSecurityClaim(context.Background(), &claim, &local)

			assert.NotNil(t, result)
			assert.Equal(t, tt.expectedClaimType, result.ClaimType.Value)
			assert.Equal(t, tt.expectedClaimValue, result.ClaimValue.Value)
			assert.Equal(t, tt.expectedProviderAuthScheme, result.ProviderAuthenticationScheme.Value)
		})
	}
}

func TestAddOAuthSecurityClaimToRole(t *testing.T) {
	t.Run("Unique claim added", func(t *testing.T) {
		existingClaims := []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
				ClaimType:                    kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthClientId,
				ClaimValue:                   "Test",
				ProviderAuthenticationScheme: "System",
				Description:                  "Claim 1",
			},
		}

		claim1 := kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthSubject, // Different claim type
			ClaimValue:                   "Test",
			ProviderAuthenticationScheme: "System",
			Description:                  "Claim 2",
		}
		claim2 := kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthClientId,
			ClaimValue:                   "Test1", // Different claim value
			ProviderAuthenticationScheme: "System",
			Description:                  "Claim 3",
		}
		claim3 := kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthClientId,
			ClaimValue:                   "Test",
			ProviderAuthenticationScheme: "System1", // Different provider auth scheme
			Description:                  "Claim 4",
		}

		ctx := context.Background()

		result1 := addOAuthSecurityClaimToRole(ctx, existingClaims, claim1)
		assert.Equal(t, 2, len(result1))

		result2 := addOAuthSecurityClaimToRole(ctx, existingClaims, claim2)
		assert.Equal(t, 2, len(result2))

		result3 := addOAuthSecurityClaimToRole(ctx, existingClaims, claim3)
		assert.Equal(t, 2, len(result3))
	})

	t.Run("Duplicate claim added", func(t *testing.T) {
		existingClaims := []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
				ClaimType:                    kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthClientId,
				ClaimValue:                   "Test",
				ProviderAuthenticationScheme: "System",
				Description:                  "Claim 1",
			},
		}

		claim := kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthClientId,
			ClaimValue:                   "Test",
			ProviderAuthenticationScheme: "System",
			Description:                  "Claim 1",
		}

		ctx := context.Background()

		result := addOAuthSecurityClaimToRole(ctx, existingClaims, claim)
		assert.Equal(t, 1, len(result)) // Should not have added duplicate claim
	})
}

// TestUnitMapOAuthSecurityClaimsFromRole_NilProviderDoesNotPanic is the
// red/green regression test for the nil-pointer dereference in
// mapOAuthSecurityClaimsFromRole: `provider := *claim.Provider` dereferenced
// the Provider sub-object unconditionally, even though it is documented as
// nilable (the exact same "API omits the sub-object" scenario already handled
// defensively in mapOAuthSecurityClaim, e.g. Command 25.5.1 + Authentik OIDC).
// A role whose claim omits Provider crashes the provider mid-apply during
// Create()/Delete()/Update() of keyfactor_oauth_security_role and
// keyfactor_oauth_security_role_claim_association, all of which call this
// function to rebuild the claims list before a PUT.
func TestUnitMapOAuthSecurityClaimsFromRole_NilProviderDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	claimType := "OAuthSubject"
	claimValue := "test-subject"
	description := "a claim with no Provider sub-object"

	remoteState := &kfv2.SecuritySecurityRolesSecurityRoleResponse{
		Id: ptr(int32(99)),
		Claims: []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionResponse{
			{
				Id:          ptr(int32(1)),
				Description: *kfv2.NewNullableString(&description),
				ClaimType:   *kfv2.NewNullableString(&claimType),
				ClaimValue:  *kfv2.NewNullableString(&claimValue),
				Provider:    nil, // the exact condition this test reproduces
			},
		},
	}

	var diagnostics diag.Diagnostics
	var result *[]kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest
	var ok bool

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("mapOAuthSecurityClaimsFromRole panicked (nil-deref regression): %v", rec)
			}
		}()
		result, ok = mapOAuthSecurityClaimsFromRole(ctx, &diagnostics, remoteState, nil)
	}()

	if !ok {
		t.Fatalf("expected mapOAuthSecurityClaimsFromRole to succeed, got diagnostics: %+v", diagnostics)
	}
	if diagnostics.HasError() {
		t.Fatalf("expected no diagnostic errors, got: %+v", diagnostics)
	}
	if result == nil || len(*result) != 1 {
		t.Fatalf("expected exactly one mapped claim, got: %+v", result)
	}

	mapped := (*result)[0]
	assert.Equal(t, kfv2.CSSCMSCOREENUMSCLAIMTYPE_OAuthSubject, mapped.ClaimType)
	assert.Equal(t, claimValue, mapped.ClaimValue)
	assert.Equal(t, description, mapped.Description)
	// No Provider sub-object was present on the remote claim, so the
	// authentication scheme has no known value: it must degrade to the
	// zero-value "" (matching getStringType's null-safe convention used
	// elsewhere in this file), never panic.
	assert.Equal(t, "", mapped.ProviderAuthenticationScheme)

	// Silently substituting "" here is itself a corruption risk on the
	// full-replace PUT this feeds (see the doc comment on
	// mapOAuthSecurityClaimsFromRole): if Command omitted Provider due to the
	// known bug rather than the claim genuinely having none, this update
	// would clear a real provider association. A warning must surface so the
	// risk is visible instead of masked.
	foundWarning := false
	for _, d := range diagnostics.Warnings() {
		if d.Summary() == "OAuth security claim missing provider association" {
			foundWarning = true
			break
		}
	}
	assert.True(t, foundWarning, "expected a warning diagnostic flagging the missing Provider sub-object, got: %+v", diagnostics)
}

func TestNormalizeSerialNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"hex uppercase", "77BFBF38D702AA41CE4EE2B1C7713CE6705B9D2E", "77BFBF38D702AA41CE4EE2B1C7713CE6705B9D2E"},
		{"hex lowercase", "77bfbf38d702aa41ce4ee2b1c7713ce6705b9d2e", "77BFBF38D702AA41CE4EE2B1C7713CE6705B9D2E"},
		{"decimal from big.Int", "683646001849179623094227348073945305115006836014", "77BFBF38D702AA41CE4EE2B1C7713CE6705B9D2E"},
		{"empty string", "", ""},
		{"nil string", "<nil>", ""},
		{"hex with colons", "77:BF:BF:38:D7:02:AA:41", "77BFBF38D702AA41"},
		{"small decimal", "255", "FF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeSerialNumber(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeThumbprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"uppercase", "746F0BCE6AF15060042380D65D8B438CF27C6192", "746f0bce6af15060042380d65d8b438cf27c6192"},
		{"lowercase", "746f0bce6af15060042380d65d8b438cf27c6192", "746f0bce6af15060042380d65d8b438cf27c6192"},
		{"with colons", "74:6F:0B:CE:6A:F1", "746f0bce6af1"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeThumbprint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizePEMLineEndings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CRLF converted to LF",
			input:    "-----BEGIN CERTIFICATE-----\r\nMIIBIjANBgkqhkiG\r\n-----END CERTIFICATE-----\r\n",
			expected: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG\n-----END CERTIFICATE-----\n",
		},
		{
			name:     "LF-only input unchanged",
			input:    "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG\n-----END CERTIFICATE-----\n",
			expected: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG\n-----END CERTIFICATE-----\n",
		},
		{
			name:     "lone CR converted to LF",
			input:    "-----BEGIN CERTIFICATE-----\rMIIBIjANBgkqhkiG\r-----END CERTIFICATE-----\r",
			expected: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG\n-----END CERTIFICATE-----\n",
		},
		{
			name:     "empty string unchanged",
			input:    "",
			expected: "",
		},
		{
			name:     "chained PEM with CRLF normalized",
			input:    "-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n-----BEGIN CERTIFICATE-----\r\nBBBB\r\n-----END CERTIFICATE-----\r\n",
			expected: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePEMLineEndings(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.NotContains(t, result, "\r", "result must contain no carriage return characters")
		})
	}
}
