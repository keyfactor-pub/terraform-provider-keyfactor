package keyfactor

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
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
				Id:          to.Ptr(int32(1234)),
				Description: *kfv1.NewNullableString(to.Ptr("Test")),
				ClaimType:   *kfv1.NewNullableString(&tt.claimType),
				ClaimValue:  *kfv1.NewNullableString(&tt.remoteClaimValue),
				Provider: to.Ptr(kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionProviderResponse{
					Id:                   to.Ptr("cd0a5d39-ffeb-42ff-bd59-a791c1dbd8a5"),
					AuthenticationScheme: *kfv1.NewNullableString(&tt.remoteProviderAuthScheme),
					DisplayName:          *kfv1.NewNullableString(to.Ptr("Test")),
				}),
			}

			local := OAuthSecurityClaim{
				Description:                  getStringType(to.Ptr("Test")),
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
