package keyfactor

import (
	"context"
	"errors"
	"fmt"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v2"
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

// TestUnitIsNotFoundError guards against a regression found during the
// full-review adjudication of PR #203: isNotFoundError previously matched
// the raw substring "404" anywhere in an error message. The legacy
// api.Client's sendRequest embeds the full request path -- including any
// numeric resource ID -- into its "Unknown error connecting to Keyfactor
// ..." fallback message for EVERY non-2xx status code when the response
// body fails to JSON-decode. That meant a genuine transient 5xx/gateway
// error against a resource whose ID happens to contain "404" as a digit
// substring (e.g. "Security/Roles/1404") was misclassified as a confirmed
// not-found, causing callers (resource_keyfactor_security_role.go,
// resource_keyfactor_certificate_deploy.go) to silently drop a still-extant
// resource from Terraform state.
func TestUnitIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error is not a not-found error",
			err:      nil,
			expected: false,
		},
		{
			name:     "genuine not-found text from the client is detected",
			err:      errors.New("agent 1404 not found"),
			expected: true,
		},
		{
			name:     "genuine 404 status-code-shaped message is detected",
			err:      fmt.Errorf("%d - the requested resource was not found. Please check the request and try again.", 404),
			expected: true,
		},
		{
			name:     "standalone 404 token is detected",
			err:      errors.New("http 404: resource missing"),
			expected: true,
		},
		{
			name: "5xx fallback message with resource ID 1404 is NOT misclassified as not-found",
			err: fmt.Errorf(
				"%d - Unknown error connecting to Keyfactor %s, please check your connection.",
				503,
				"Security/Roles/1404",
			),
			expected: false,
		},
		{
			name: "5xx fallback message with resource ID 40498 is NOT misclassified as not-found",
			err: fmt.Errorf(
				"%d - Unknown error connecting to Keyfactor %s, please check your connection.",
				502,
				"CertificateStores/40498",
			),
			expected: false,
		},
		{
			name: "404 fallback (decode failure) with embedded status code is treated as unknown, not confirmed not-found",
			err: fmt.Errorf(
				"%d - Unknown error connecting to Keyfactor %s, please check your connection.",
				404,
				"Security/Roles/5",
			),
			expected: false,
		},
		{
			name:     "unrelated error with a resource ID containing 404 digits is not a false positive",
			err:      errors.New("permission denied for Security/Roles/1404"),
			expected: false,
		},
		{
			name:     "unrelated 5xx error is not a not-found error",
			err:      errors.New("503 Service Unavailable"),
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
