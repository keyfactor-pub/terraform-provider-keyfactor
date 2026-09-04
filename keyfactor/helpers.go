// Package keyfactor provides helper functions for interacting with the Keyfactor Command API
// and managing certificate-related operations in Terraform providers.
//
// This package includes utilities for:
// - Certificate and private key management
// - Subject and metadata handling
// - Password generation
// - Data type conversions between Terraform and Go
// - PKCS#12/PFX file operations

package keyfactor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	mathRand "math/rand"

	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var (
	lowerCharSet   = "abcdedfghijklmnopqrst"
	upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialCharSet = "!@#$%&*"
	numberSet      = "0123456789"
	allCharSet     = lowerCharSet + upperCharSet + numberSet
)

// generatePassword creates a random password with specified requirements.
//
// Parameters:
//   - passwordLength: The total length of the password to generate
//   - minSpecialChar: Minimum number of special characters required
//   - minNum: Minimum number of numeric characters required
//   - minUpperCase: Minimum number of uppercase characters required
//
// Returns:
//   - A string containing the generated password meeting all specified requirements
func generatePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) string {
	var password strings.Builder

	//Set special character
	for i := 0; i < minSpecialChar; i++ {
		random := mathRand.Intn(len(specialCharSet))
		password.WriteString(string(specialCharSet[random]))
	}

	//Set numeric
	for i := 0; i < minNum; i++ {
		random := mathRand.Intn(len(numberSet))
		password.WriteString(string(numberSet[random]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random := mathRand.Intn(len(upperCharSet))
		password.WriteString(string(upperCharSet[random]))
	}

	remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
	for i := 0; i < remainingLength; i++ {
		random := mathRand.Intn(len(allCharSet))
		password.WriteString(string(allCharSet[random]))
	}
	inRune := []rune(password.String())
	mathRand.Shuffle(
		len(inRune), func(i, j int) {
			inRune[i], inRune[j] = inRune[j], inRune[i]
		},
	)
	return string(inRune)
}

// Gets the value of an environment variable or skips the test if the variable is not set.
func getEnvOrSkip(t *testing.T, envVar string) string {
	value := os.Getenv(envVar)
	if value == "" {
		t.Skipf("Skipping test: because %s is not set", envVar)
	}
	return value
}

// expandSubject extracts subject fields from a given string and returns them as Terraform types.
//
// Parameters:
//   - subject: A string containing the subject to be parsed
//
// Returns:
//   - A tuple of Terraform types.String values representing the extracted subject fields
func expandSubject(subject string) (
	types.String,
	types.String,
	types.String,
	types.String,
	types.String,
	types.String,
) {
	var (
		cn string
		ou string
		o  string
		l  string
		st string
		c  string
	)
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				cn = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				ou = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				c = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				l = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				st = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				o = strings.Replace(field, "O=", "", 1)
			}
		}
	}
	return types.String{Value: cn}, types.String{Value: ou}, types.String{Value: o}, types.String{Value: l}, types.String{Value: st}, types.String{Value: c}
}

// flattenSubject converts a subject string into a Terraform-compatible `types.Object`.
//
// Parameters:
//   - subject: A string containing the subject to be converted
//
// Returns:
//   - A `types.Object` where each attribute is a Terraform `types.String` value representing a subject field
func flattenSubject(subject string) types.Object {
	data := make(map[string]string) // Inner subject interface is a string mapped interface
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				data["subject_common_name"] = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				data["subject_organizational_unit"] = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				data["subject_country"] = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				data["subject_locality"] = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				data["subject_state"] = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				data["subject_organization"] = strings.Replace(field, "O=", "", 1)
			}
		}

	}
	result := types.Object{
		Attrs: map[string]attr.Value{
			"subject_common_name":         types.String{Value: data["subject_common_name"]},
			"subject_locality":            types.String{Value: data["subject_locality"]},
			"subject_organization":        types.String{Value: data["subject_organization"]},
			"subject_state":               types.String{Value: data["subject_state"]},
			"subject_country":             types.String{Value: data["subject_country"]},
			"subject_organizational_unit": types.String{Value: data["subject_organizational_unit"]},
		},
		AttrTypes: map[string]attr.Type{
			"subject_common_name":         types.StringType,
			"subject_locality":            types.StringType,
			"subject_organization":        types.StringType,
			"subject_state":               types.StringType,
			"subject_country":             types.StringType,
			"subject_organizational_unit": types.StringType,
		},
	}

	return result
}

func flattenMetadata(metadata interface{}) types.Map {
	data := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata.(map[string]interface{}) {
			data[k] = v.(string)
		}
	}

	// Return an empty map (not null) so that state is always a known value.
	// The metadata schema is Optional+Computed with useStateOrNullModifier so
	// an absent config block copies the empty-map state to the plan, producing
	// zero drift. If the user explicitly sets metadata = null, parseMetadata
	// sends {} to the server (clearing all entries) and this still returns {}.
	if len(data) == 0 {
		return types.Map{Elems: map[string]attr.Value{}, ElemType: types.StringType}
	}

	result := types.Map{
		Elems:    map[string]attr.Value{},
		ElemType: types.StringType,
	}
	for k, v := range data {
		result.Elems[k] = types.String{Value: v}
	}

	return result
}

func mapAuthenticationProviderType(id string, authScheme string, displayName string) types.Object {
	return types.Object{
		Attrs: map[string]attr.Value{
			"id":                    types.String{Value: id},
			"authentication_scheme": types.String{Value: authScheme},
			"display_name":          types.String{Value: displayName},
		},
		AttrTypes: OAuthSecurityClaimAuthenticationProviderType,
	}
}

// Maps an OAuth Security Role from a SecuritySecurityRolesSecurityRoleResponse response model
func mapOAuthSecurityRole(ctx context.Context, data *kfv2.SecuritySecurityRolesSecurityRoleResponse) OAuthSecurityRole {
	var permissionValues []attr.Value
	sort.Strings(data.Permissions)
	for _, perm := range data.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %s", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	var result = OAuthSecurityRole{
		ID:              types.Int64{Value: int64(*data.Id)},
		Name:            getStringType(data.Name.Get()),
		Description:     getStringType(data.Description.Get()),
		EmailAddress:    getStringType(data.EmailAddress.Get()),
		Immutable:       types.Bool{Value: *data.Immutable},
		Permissions:     types.Set{ElemType: types.StringType, Elems: permissionValues},
		PermissionSetId: getStringType(data.PermissionSetId),
	}
	return result
}

func mapOAuthSecurityClaim(
	ctx context.Context,
	remote *kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionResponse,
	local *OAuthSecurityClaim,
) OAuthSecurityClaim {
	// remote.Provider may be nil when the API omits the sub-object (Command 25.5.1 + Authentik OIDC).
	var providerAuthScheme *string
	if remote.Provider != nil {
		providerAuthScheme = remote.Provider.AuthenticationScheme.Get()
	}
	claimValue := remote.ClaimValue.Get()

	if local != nil {
		// In rare cases (like "unknown"), the remote scheme value may differ from local value.
		providerAuthScheme = &local.ProviderAuthenticationScheme.Value

		// For Active Directory, claim values may resolve on the remote side with domain prefixes / different casing.
		// If we ignore the domain prefix and the claim value matches, that's good.
		// Otherwise, let Terraform handle the discrepancy (update, inconsistent state, etc.)
		if *providerAuthScheme == "Active Directory" {

			localClaimValue := strings.ToLower(local.ClaimValue.Value)
			remoteClaimValue := strings.ToLower(*claimValue)

			// If value from remote == local (case insensitive), great.
			// Otherwise, do some comparison on username value (without domain)
			if localClaimValue == remoteClaimValue {
				claimValue = &local.ClaimValue.Value
			} else {
				sep := "\\"
				split := strings.Split(remoteClaimValue, sep)

				if len(split) > 0 {
					split = split[1:]
					val := strings.Join(split, sep)

					// At this point, we've confirmed the username matches (case insensitive).
					// To prevent inconsistent state issues, store the Terraform plan value into the state.
					if val == localClaimValue {
						claimValue = &local.ClaimValue.Value
					}
				}
			}
		}
	}

	// Safely dereference optional pointer fields from the provider sub-object.
	providerIdStr := ""
	providerAuthSchemeStr := ""
	providerDisplayNameStr := ""
	if remote.Provider != nil {
		if remote.Provider.Id != nil {
			providerIdStr = *remote.Provider.Id
		}
		if ptrVal := remote.Provider.AuthenticationScheme.Get(); ptrVal != nil {
			providerAuthSchemeStr = *ptrVal
		}
		if ptrVal := remote.Provider.DisplayName.Get(); ptrVal != nil {
			providerDisplayNameStr = *ptrVal
		}
	}

	var remoteId int64
	if remote.Id != nil {
		remoteId = int64(*remote.Id)
	}

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: remoteId},
		Description:                  getStringType(remote.Description.Get()),
		ClaimType:                    getStringType(remote.ClaimType.Get()),
		ClaimValue:                   getStringType(claimValue),
		ProviderAuthenticationScheme: getStringType(providerAuthScheme),
		Provider: mapAuthenticationProviderType(
			providerIdStr,
			providerAuthSchemeStr,
			providerDisplayNameStr,
		),
	}
	return result
}

func mapOAuthSecurityRoleClaimAssociation(
	ctx context.Context,
	roleId int32,
	claimId int32,
) OAuthSecurityRoleClaimAssociation {
	result := OAuthSecurityRoleClaimAssociation{
		ID:      types.String{Value: fmt.Sprintf("%d/%d", roleId, claimId)},
		RoleID:  types.Int64{Value: int64(roleId)},
		ClaimID: types.Int64{Value: int64(claimId)},
	}
	return result
}

func mapOAuthSecurityClaimsFromRole(
	ctx context.Context,
	diagnostics *diag.Diagnostics,
	remoteState *kfv2.SecuritySecurityRolesSecurityRoleResponse,
	deletedClaimId *int32,
) (*[]kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest, bool) {
	claims := []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{}
	for _, claim := range remoteState.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))

		// Skip adding claim to claims array -- delete the claim from the security role
		if claim.Id != nil && deletedClaimId != nil && *claim.Id == *deletedClaimId {
			continue
		}

		provider := *claim.Provider
		claimTypeEnum, err := kfv2.ParseCSSCMSCoreEnumsClaimType(*claim.ClaimType.Get())

		// This shouldn't happen since the claim type is coming from the API
		// But just in case
		if err != nil {
			diagnostics.AddError(
				"Error creating security identity.",
				"Could not create identity role claim association, error parsing claim type "+err.Error(),
			)
			return nil, false
		}

		temp := kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   *claim.ClaimValue.Get(),
			ProviderAuthenticationScheme: *provider.AuthenticationScheme.Get(),
			Description:                  *claim.Description.Get(),
		}
		claims = append(claims, temp)
	}

	return &claims, true
}

// To fix an issue where duplicate claims on a security role corrupts a security role, perform a check that the new claim being added is not a duplicate
func addOAuthSecurityClaimToRole(
	ctx context.Context,
	existingClaims []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest,
	newClaim kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest,
) []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest {
	var result []kfv2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest
	for _, claim := range existingClaims {
		// If we detect that the claim is being duplicated, we will skip over that claim and add it toward the end
		if claim.ClaimType == newClaim.ClaimType && claim.ClaimValue == newClaim.ClaimValue && claim.ProviderAuthenticationScheme == newClaim.ProviderAuthenticationScheme {
			continue
		}
		result = append(result, claim)
	}
	result = append(result, newClaim)
	return result
}

// DNSSANStoTerraform converts a slice of DNS SANs (Subject Alternative Names) into a Terraform-compatible
// `types.List`. The function can either allow duplicates or ensure unique entries based on the
// `allowDuplicates` parameter.
//
// Parameters:
//   - sans: A slice of strings representing the DNS SANs to be converted.
//   - allowDuplicates: A boolean flag indicating whether duplicates should be preserved in the result.
//
// Returns:
//   - A `types.List` where each element is a Terraform `types.String` value representing a DNS SAN.
//     If `allowDuplicates` is false, the list contains only unique DNS SAN strings.
func DNSSANStoTerraform(sans []string, allowDuplicates bool) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     true,
	}

	// Return result with duplicates
	if allowDuplicates {
		for _, dns := range sans {
			result.Elems = append(result.Elems, types.String{Value: dns})
			result.Null = false
		}
		return result
	}

	// Return result without duplicates
	uniqueSans := make(map[string]struct{})
	for _, dns := range sans {
		if _, exists := uniqueSans[dns]; !exists {
			uniqueSans[dns] = struct{}{}
			result.Elems = append(result.Elems, types.String{Value: dns})
			result.Null = false
		}
	}
	return result
}

// IPSANStoTerraform converts a slice of IP SANs (Subject Alternative Names) into a Terraform-compatible
// `types.List`. The function can either allow duplicates or ensure unique entries based on the
// `allowDuplicates` parameter.
//
// Parameters:
//   - ips: A slice of `net.IP` values representing the IP SANs to be converted.
//   - allowDuplicates: A boolean flag indicating whether duplicates should be preserved in the result.
//
// Returns:
//   - A `types.List` where each element is a Terraform `types.String` value representing an IP SAN.
//     If `allowDuplicates` is false, the list contains only unique IP SAN strings. Each `net.IP` value
//     is properly converted into a string format (e.g., IPv4 or IPv6).
func IPSANStoTerraform(ips []net.IP, allowDuplicates bool) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     true,
	}

	// Return result with duplicates
	if allowDuplicates {
		for _, ip := range ips {
			result.Elems = append(result.Elems, types.String{Value: ip.String()})
			result.Null = false
		}
		return result
	}

	// Return result without duplicates
	uniqueIps := make(map[string]struct{})
	for _, ip := range ips {
		if _, exists := uniqueIps[ip.String()]; !exists {
			uniqueIps[ip.String()] = struct{}{}
			result.Elems = append(result.Elems, types.String{Value: ip.String()})
			result.Null = false
		}
	}
	return result
}

// URISANStoTerraform converts a slice of URI SANs (Subject Alternative Names) into a Terraform-compatible
// `types.List`. The function can either allow duplicates or ensure unique entries based on the
// `allowDuplicates` parameter.
//
// If any of the elements in the input slice is `nil`, those entries are ignored.
//
// Parameters:
//   - uris: A slice of pointers to `url.URL` representing the URI SANs to be converted.
//   - allowDuplicates: A boolean flag indicating whether duplicates should be preserved in the result.
//
// Returns:
//   - A `types.List` where each element is a Terraform `types.String` value representing a URI SAN.
//     If `allowDuplicates` is false, the list contains only unique URI SAN strings. Nil values in the
//     input slice are ignored.
func URISANStoTerraform(uris []*url.URL, allowDuplicates bool) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     true,
	}

	// Return result with duplicates
	if allowDuplicates {
		for _, uri := range uris {
			if uri != nil { // Check for nil to prevent possible null pointer dereference
				result.Elems = append(result.Elems, types.String{Value: uri.String()})
				result.Null = false
			}
		}
		return result
	}

	// Return result without duplicates
	uniqueUris := make(map[string]struct{})
	for _, uri := range uris {
		if uri != nil { // Check for nil before referencing uri.String()
			if _, exists := uniqueUris[uri.String()]; !exists {
				uniqueUris[uri.String()] = struct{}{}
				result.Elems = append(result.Elems, types.String{Value: uri.String()})
				result.Null = false
			}
		}
	}
	return result
}

func unescapeJSON(jsonData string) ([]byte, error) {
	unescapedJSON, err := strconv.Unquote(jsonData)
	if err != nil {
		return []byte(jsonData), err
	}
	return []byte(unescapedJSON), nil
}

func flattenEnrollmentFields(efs []api.TemplateEnrollmentFields) types.List {

	result := types.List{
		ElemType: types.MapType{},
		Elems:    []attr.Value{},
	}
	for _, ef := range efs {
		var options []attr.Value
		for _, op := range ef.Options {
			options = append(
				options, types.String{
					Value: op,
				},
			)
		}
		result.Elems = append(
			result.Elems, types.Map{
				ElemType: types.StringType,
				Elems: map[string]attr.Value{
					"id":   types.Int64{Value: int64(ef.Id)},
					"name": types.String{Value: ef.Name},
					"type": types.String{Value: strconv.Itoa(ef.DataType)},
					"options": types.List{
						Elems:    options,
						ElemType: types.StringType,
					},
				},
			},
		)
	}

	return result
}

// parsePrivateKey encodes a private key (RSA, ECDSA, or ED25519) into a PEM-formatted string.
//
// This function takes a private key as an interface and determines its type (e.g., RSA, ECDSA, ED25519).
// Once the type is identified, it converts the key into its appropriate PEM-encoded representation.
//
// Parameters:
//   - ctx: The context for logging and diagnostics within the function.
//   - pkey: The private key as an interface{} that will be processed and encoded.
//
// Supported Private Key Types:
//   - *rsa.PrivateKey: Encoded as "RSA PRIVATE KEY"
//   - *ecdsa.PrivateKey: Encoded as "EC PRIVATE KEY"
//   - ed25519.PrivateKey: Encoded as "OPENSSH PRIVATE KEY"
//
// Unsupported key types will result in a warning log but will not cause the function to fail.
//
// Returns:
//   - (string): A PEM-formatted string representing the private key, or an empty string if the key
//     cannot be processed.
//   - (diag.Diagnostics): A diagnostic object that may contain warnings or relevant logs.
func parsePrivateKey(ctx context.Context, pkey interface{}) (string, diag.Diagnostics) {
	var pkeyPEM string
	diags := diag.Diagnostics{}

	switch key := pkey.(type) {
	case *rsa2.PrivateKey:
		tflog.Debug(ctx, "Recovered RSA private key from Keyfactor Command.")
		if buf := x509.MarshalPKCS1PrivateKey(key); len(buf) > 0 {
			tflog.Debug(ctx, "Encoding RSA private key from Keyfactor Command.")
			pkeyPEM = string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "RSA PRIVATE KEY",
						Bytes: buf,
					},
				),
			)
		} else {
			tflog.Warn(ctx, "Empty RSA private key recovered from Keyfactor Command.")
			diags.AddWarning(
				"Empty private key recovered",
				"Keyfactor Command returned an empty private key. This may be due to the private key being in a format that is not supported by Terraform. Please check the Keyfactor Command logs for more information.",
			)
			break
		}
	case *ecdsa.PrivateKey:
		tflog.Debug(ctx, "Recovered ECC private key from Keyfactor Command.")
		buf, err := x509.MarshalECPrivateKey(key)
		if err == nil && len(buf) > 0 {
			tflog.Debug(ctx, "Encoding ECC private key from Keyfactor Command.")
			pkeyPEM = string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "EC PRIVATE KEY",
						Bytes: buf,
					},
				),
			)
		} else if err != nil {
			tflog.Warn(ctx, "Failed to marshal ECC private key: "+err.Error())
		}
	case ed25519.PrivateKey:
		tflog.Debug(ctx, "Recovered Ed25519 private key from Keyfactor Command.")
		buf := key.Seed()
		if len(buf) > 0 {
			tflog.Debug(ctx, "Encoding Ed25519 private key from Keyfactor Command.")
			pkeyPEM = string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "OPENSSH PRIVATE KEY",
						Bytes: buf,
					},
				),
			)
		} else {
			tflog.Warn(ctx, "Empty Ed25519 private key recovered from Keyfactor Command.")
			diags.AddWarning(
				"Empty private key recovered",
				"Keyfactor Command returned an empty private key. This may be due to the private key being in a format that is not supported by Terraform. Please check the Keyfactor Command logs for more information.",
			)
		}
	default:
		tflog.Warn(ctx, "Unsupported private key type provided.")
		diags.AddError(
			"Unsupported private key type",
			fmt.Sprintf("Unsupported private key type %s provided.", reflect.TypeOf(key)),
		)
	}

	return pkeyPEM, diags
}

// normalizePEMLineEndings strips \r characters so PEM strings always use \n-only line endings.
func normalizePEMLineEndings(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// recoverPrivateKeyFromKeyfactorCommand retrieves the private key, leaf certificate, and certificate chain
// for a specific certificate from Keyfactor Command.
//
// This function communicates with the Keyfactor Command API to recover a private key and its associated
// certificate data. It validates input parameters, handles potential errors during data retrieval, and converts
// the resulting data into PEM-encoded strings.
//
// Parameters:
//   - ctx: The context for logging and diagnostics during the function's execution.
//   - certId: The ID of the certificate for which private key recovery is requested.
//   - collectionId: The ID of the Keyfactor collection in which the certificate resides.
//   - lookupPassword: The password for accessing the private key in Keyfactor Command.
//   - client: A Keyfactor API client used to retrieve the certificate and its private key.
//
// Returns:
//   - (string): A PEM-encoded private key if successfully recovered, otherwise an empty string.
//   - (string): A PEM-encoded certificate (leaf certificate) if successfully recovered, otherwise an empty string.
//   - (string): A PEM-encoded certificate chain (if available), otherwise an empty string.
func recoverPrivateKeyFromKeyfactorCommand(
	ctx context.Context,
	certId int,
	collectionId int,
	lookupPassword string,
	client *api.Client,
	certificateFormat string,
) (string, string, string, *string, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	if client == nil {
		tflog.Error(ctx, "Keyfactor Command client is nil. Unable to recover private key for certificate.")
		diags.AddError(
			"Error recovering private key from Keyfactor Command",
			"Keyfactor Command client is nil.",
		)
		return "", "", "", nil, diags
	}

	tflog.Info(ctx, "Attempting to recover private key from Keyfactor Command.")
	pkey, leaf, certChain, rawBytes, recErr := client.RecoverCertificate(
		certId,
		"",
		"",
		"",
		lookupPassword,
		collectionId,
		certificateFormat,
	)
	if recErr != nil {
		errMsg := fmt.Sprintf(
			"Unable to recover private key for certificate '%v' from Keyfactor Command: %v",
			certId,
			recErr.Error(),
		)
		tflog.Error(ctx, errMsg)
		diags.AddError("Error recovering private key from Keyfactor Command", errMsg)
		return "", "", "", rawBytes, diags
	}

	if (certificateFormat == "PFX" || certificateFormat == "pfx") && pkey == nil {
		tflog.Debug(ctx, "Unpacking PFX data to extract private key.")
		pfxPrivateKey, pfxLeaf, pfxChain, unpackErr := api.UnpackPkcs12(rawBytes, lookupPassword)
		if unpackErr != nil {
			// Unknown algorithm (e.g. Ed448 OID 1.3.101.113) means Go's pkcs12/x509
			// library cannot parse the key — log a warning and return empty strings
			// without adding an error so callers can fall back gracefully.
			if strings.Contains(unpackErr.Error(), "unknown algorithm") {
				tflog.Warn(ctx, fmt.Sprintf(
					"Cannot unpack PFX for certificate %d — unsupported key algorithm: %v",
					certId, unpackErr,
				))
				return "", "", "", rawBytes, diags
			}
			errMsg := fmt.Sprintf("Unable to unpack PFX data for certificate '%v': %v", certId, unpackErr.Error())
			tflog.Error(ctx, errMsg)
			diags.AddError("Error unpacking PFX data", errMsg)
			return "", "", "", rawBytes, diags
		}
		return pfxPrivateKey, normalizePEMLineEndings(pfxLeaf), normalizePEMLineEndings(strings.Join(pfxChain, "")), rawBytes, diags
	}

	if (certificateFormat == "PEM" || certificateFormat == "pem") && pkey == nil {
		tflog.Debug(ctx, "Unpacking PEM data to extract private key.")
		pemPrivateKey, pemLeaf, pemChain, unpackErr := api.UnpackPEM(rawBytes, lookupPassword)
		if unpackErr != nil {
			errMsg := fmt.Sprintf("Unable to unpack PEM data for certificate '%v': %v", certId, unpackErr.Error())
			tflog.Error(ctx, errMsg)
			diags.AddError("Error unpacking PEM data", errMsg)
			return "", "", "", rawBytes, diags
		}
		return pemPrivateKey, normalizePEMLineEndings(pemLeaf), normalizePEMLineEndings(strings.Join(pemChain, "")), rawBytes, diags
	}

	if pkey == nil {
		errMsg := fmt.Sprintf(
			"Private key not available for certificate '%v' from Keyfactor Command.", certId,
		)
		tflog.Error(ctx, errMsg)
		diags.AddError("No private key returned", errMsg)
		return "", "", "", rawBytes, diags
	}

	tflog.Info(ctx, "Private key successfully recovered from Keyfactor Command.")
	pkeyPEM, pkeyDiags := parsePrivateKey(ctx, pkey)
	if pkeyDiags.HasError() {
		errMsg := "Error parsing private key from Keyfactor Command."
		tflog.Error(ctx, errMsg)
		diags.AddError(errMsg, errMsg)
		return "", "", "", rawBytes, diags
	}

	certPEM, _ := encodeCertificate(ctx, leaf, certId)

	chainPEM := encodeCertificateChain(ctx, certChain, certId)

	return pkeyPEM, normalizePEMLineEndings(certPEM), normalizePEMLineEndings(chainPEM), rawBytes, diags
}

// encodeCertificate encodes a provided certificate into a PEM-formatted string and returns it.
//
// This function supports the following types for the `leaf` parameter:
//   - *x509.Certificate: Encodes the raw certificate bytes into PEM format.
//   - *string: Returns the string as-is, assuming it is already PEM-formatted.
//   - *[]byte: Wraps the byte slice into a PEM block and encodes it.
//
// If the input is invalid (nil, empty, or unsupported type), the function logs
// appropriate warnings and returns an error indicating the issue.
//
// Parameters:
//   - ctx: The context for logging using tflog.
//   - leaf: The certificate data to be converted to PEM format. Can be one of:
//     *x509.Certificate, *string, or *[]byte.
//   - certId: An integer identifier for the certificate, used for logging purposes.
//
// Returns:
//   - string: The PEM-formatted certificate string, or an empty string if an error occurs.
//   - error: An error describing any issue with the input or processing.
//
// Example Usage:
//
//	// Using *x509.Certificate as input
//	cert := &x509.Certificate{Raw: []byte{0x30, 0x82, 0x02}} // Example certificate
//	pemString, err := encodeCertificate(ctx, cert, 12345)
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("PEM Certificate:", pemString)
//	}
//
//	// Using *string as input
//	certString := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq...\n-----END CERTIFICATE-----"
//	pemString, err := encodeCertificate(ctx, &certString, 12345)
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("PEM Certificate:", pemString)
//	}
//
//	// Using *[]byte as input
//	certBytes := []byte{0x30, 0x82, 0x02} // Example byte slice
//	pemString, err := encodeCertificate(ctx, &certBytes, 12345)
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("PEM Certificate:", pemString)
//	}
func encodeCertificate(ctx context.Context, leaf any, certId int) (string, error) {
	if leaf == nil {
		err := fmt.Errorf("no leaf certificate provided for certificate %v", certId)
		tflog.Warn(ctx, err.Error())
		return "", err
	}

	var rawBytes []byte
	switch v := leaf.(type) {
	case *x509.Certificate:
		tflog.Debug(ctx, "Leaf certificate provided as *x509.Certificate.")
		rawBytes = v.Raw
		break
	case x509.Certificate:
		tflog.Debug(ctx, "Leaf certificate provided as x509.Certificate.")
		rawBytes = v.Raw
		break
	case *string:
		tflog.Debug(ctx, "Leaf certificate provided as *string.")
		if v != nil && *v != "" {
			// check if already in PEM format by looking for the PEM header and footer
			if strings.Contains(*v, "-----BEGIN CERTIFICATE-----") && strings.Contains(
				*v,
				"-----END CERTIFICATE-----",
			) {
				tflog.Debug(ctx, "Leaf certificate is already in PEM format.")
				return *v, nil // Return as-is, assuming it's already a PEM formatted string
			} else {
				tflog.Debug(ctx, "Leaf certificate is not in PEM format, encoding to PEM.")
				rawBytes = []byte(*v) // Convert string to byte slice for PEM encoding
			}
		}
		break
	case string:
		if v != "" {
			// check if already in PEM format by looking for the PEM header and footer
			if strings.Contains(v, "-----BEGIN CERTIFICATE-----") && strings.Contains(v, "-----END CERTIFICATE-----") {
				tflog.Debug(ctx, "Leaf certificate is already in PEM format.")
				return v, nil // Return as-is, assuming it's already a PEM formatted string
			} else {
				tflog.Debug(ctx, "Leaf certificate is not in PEM format, encoding to PEM.")
				rawBytes = []byte(v) // Convert string to byte slice for PEM encoding
			}
		}
	case *[]byte:
		tflog.Debug(ctx, "Leaf certificate provided as *[]byte.")
		if v != nil && len(*v) > 0 {
			rawBytes = *v
		}
	case []byte:
		tflog.Debug(ctx, "Leaf certificate provided as []byte.")
		if len(v) > 0 {
			rawBytes = v
		}
		break
	default:
		err := fmt.Errorf("invalid leaf type provided for certificate %v", certId)
		tflog.Warn(ctx, err.Error())
		return "", err
	}

	if len(rawBytes) == 0 {
		err := fmt.Errorf("empty or invalid data for certificate %v", certId)
		tflog.Warn(ctx, err.Error())
		return "", err
	}

	if decoded, err := base64.StdEncoding.DecodeString(string(rawBytes)); err == nil && len(decoded) > 0 {
		rawBytes = decoded
	}

	pemString := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawBytes}))
	tflog.Debug(ctx, "Certificate successfully encoded to PEM format.")
	return pemString, nil
}

// encodeCertificateChain encodes a certificate chain into a PEM-formatted string.
//
// This function iterates through the provided certificate chain, encoding each certificate
// into its PEM representation and concatenating them into a single string.
//
// Parameters:
//   - ctx: The context for logging using tflog.
//   - certChain: A slice of *x509.Certificate representing the certificate chain.
//   - certId: An integer identifier for the certificate, used for logging purposes.
//
// Returns:
//   - string: The PEM-formatted certificate chain string, or an empty string if no chain is provided.
func encodeCertificateChain(ctx context.Context, certChain []*x509.Certificate, certId int) string {
	if certChain == nil {
		tflog.Warn(
			ctx, fmt.Sprintf(
				"No certificate chain returned from Keyfactor Command for certificate %v.", certId,
			),
		)
		return ""
	}

	var chainPEM string
	tflog.Debug(ctx, "Recovering certificate chain from Keyfactor Command.")
	for i, cert := range certChain {
		if cert == nil {
			continue
		}
		tflog.Trace(ctx, fmt.Sprintf("Encoding chain certificate %d", i))
		chainPEM += string(
			pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				},
			),
		)
	}
	return chainPEM
}

func flattenTemplateRegexes(regexes []api.TemplateRegex) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	for _, regex := range regexes {
		result.Elems = append(result.Elems, types.String{Value: regex.RegEx})
	}
	return result
}

func flattenAllowedRequesters(requesters []string) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}

	if len(requesters) > 0 {
		for _, requester := range requesters {
			result.Elems = append(result.Elems, types.String{Value: requester})
		}
	}

	return result
}

func isNullString(s string) bool {
	switch s {
	case "", "null":
		return true
	default:
		return false
	}
}

func isNullId(i int) bool {
	if i <= 0 {
		return true
	}
	return false
}

// downloadCertificateFromKeyfactorCommand retrieves the leaf certificate and certificate chain
// for a specific certificate from Keyfactor Command.
//
// This function communicates with the Keyfactor Command API to download the requested certificate
// and its chain. It handles errors gracefully, ensuring that partial data (such as the leaf certificate
// or chain) is returned if available.
//
// Parameters:
//   - ctx: The context for logging and diagnostics during execution.
//   - certId: The ID of the certificate to be downloaded.
//   - collectionId: The ID of the Keyfactor collection to which the certificate belongs (currently not used).
//   - client: A Keyfactor API client for interacting with the Keyfactor Command system.
//
// Returns:
//   - (string): The PEM-encoded leaf certificate if successfully retrieved, otherwise an empty string.
//   - (string): The PEM-encoded certificate chain if successfully retrieved, otherwise an empty string.
//   - (diag.Diagnostics): Diagnostics information, including errors or warnings encountered during the process.
//
// Behavior:
//   - Returns an error if the client is nil or the certificate cannot be downloaded.
//   - Logs warnings if only partial data (e.g., leaf without chain) is retrieved.
//   - Uses helper functions `encodeCertificate` and `encodeCertificateChain` to convert the certificates into PEM format.
//
// Notes:
//   - Collection ID is currently a placeholder and not used in the function.
//   - The function ensures partial success when either the leaf certificate or chain is available.
func downloadCertificateFromKeyfactorCommand(
	ctx context.Context,
	certId int,
	collectionId int,
	client *api.Client,
) (string, string, *string, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	if client == nil {
		tflog.Error(ctx, "Keyfactor Command client is nil. Unable to download the certificate.")
		diags.AddError(ERR_SUMMARY_CERTIFICATE_DOWNLOAD, "Keyfactor Command client is nil.")
		return "", "", nil, diags
	}

	tflog.Debug(ctx, "Downloading certificate and chain from Keyfactor Command.")
	leaf, chain, rawData, dErr := client.DownloadCertificate(
		certId,
		"",
		"",
		"",
		collectionId,
		"P7B",
	)
	if dErr != nil {
		errMsg := "Error downloading certificate from Keyfactor Command: " + dErr.Error()
		if leaf == nil && chain == nil {
			tflog.Error(ctx, errMsg)
			diags.AddError(ERR_SUMMARY_CERTIFICATE_DOWNLOAD, errMsg)
			return "", "", rawData, diags
		}
		tflog.Warn(ctx, errMsg)
		diags.AddWarning("Certificate download warning", errMsg)
	}

	leafPEM, leafErr := encodeCertificate(ctx, leaf, certId)
	if leafErr != nil {
		errMsg := "unable to encode leaf certificate from Keyfactor Command: " + leafErr.Error()
		if chain == nil {
			tflog.Error(ctx, errMsg)
			diags.AddError(ERR_SUMMARY_CERTIFICATE_DOWNLOAD, errMsg)
			return "", "", rawData, diags
		}

		tflog.Warn(ctx, errMsg)
	}
	chainPEM := encodeCertificateChain(ctx, chain, certId)

	return leafPEM, chainPEM, rawData, diags
}

// terraformBoolToGoBool converts a Terraform boolean string to a Go boolean.
//
// Parameters:
//   - tfBool: A string representing the Terraform boolean value ("true" or "false").
//
// Returns:
//   - A boolean value: true if the input is "true", false if the input is "false".
//   - An error if the input is not a valid Terraform boolean string.
func terraformBoolToGoBool(tfBool string) (bool, error) {
	tfBool = strings.ToLower(tfBool)
	if tfBool == "true" {
		return true, nil
	} else if tfBool == "false" {
		return false, nil
	}
	return false, fmt.Errorf("invalid Terraform bool: %s", tfBool)
}

// parseProperties extracts and returns the server username, password, and SSL usage from the provided properties string.
//
// Parameters:
//   - properties: A string containing the properties to be parsed.
//
// Returns:
//   - A Terraform types.Map containing the parsed properties.
//   - A Terraform types.String containing the server username.
//   - A Terraform types.String containing the server password.
//   - A Terraform types.Bool indicating whether SSL is used.
//   - A diag.Diagnostics object containing any errors or warnings encountered during parsing.
func parseProperties(properties string) (types.Map, types.String, types.String, types.Bool, diag.Diagnostics) {
	var (
		serverUsername types.String
		serverPassword types.String
		//storePassword  types.String
		serverUseSsl types.Bool
		diags        diag.Diagnostics
	)
	propElems := make(map[string]attr.Value)
	propsObj := make(map[string]interface{})
	diags = diag.Diagnostics{}
	if properties != "" {
		//convert JSON string to map
		unescapedJSON, _ := unescapeJSON(properties)
		jsonErr := json.Unmarshal(unescapedJSON, &propsObj)
		if jsonErr != nil {
			diags.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				"Error reading certificate store: %s"+jsonErr.Error(),
			)
			return types.Map{}, types.String{Value: ""}, types.String{Value: ""}, types.Bool{Value: false}, diags
		}
	}

	for k, v := range propsObj {
		// The single-store GET endpoint may return special properties as nested
		// objects (e.g. {"Value": {"SecretValue": "..."}}) rather than plain
		// strings. Use a safe string conversion to avoid panics.
		strVal, _ := v.(string)
		switch k {
		case "ServerUsername":
			serverUsername = types.String{Value: strVal}
		case "ServerPassword":
			serverPassword = types.String{Value: strVal}
		case "ServerUseSsl":
			// Convert terraform True/False to bool true/false
			val, valErr := terraformBoolToGoBool(strVal)
			if valErr != nil {
				val = true // Default to true if we can't convert
			}
			serverUseSsl = types.Bool{Value: val}
		default:
			propElems[k] = types.String{Value: strVal}
		}
	}

	return types.Map{ElemType: types.StringType, Elems: propElems}, serverUsername, serverPassword, serverUseSsl, diags
}

// parseStorePassword extracts and returns the store password from the provided StorePasswordConfig.
//
// Parameters:
//   - sPassword: A pointer to the StorePasswordConfig structure containing the store password.
//
// Returns:
//   - A Terraform types.String containing the store password, or an empty string if the input is nil.
func parseStorePassword(sPassword *api.StorePasswordConfig) types.String {
	if sPassword == nil {
		return types.String{Value: ""}
	} else {
		if sPassword.Value != nil {
			return types.String{Value: *sPassword.Value}
		} else {
			return types.String{Value: ""}
		}
	}
}

// LogFunctionEntry logs the entry of a function.
//
// Parameters:
//   - ctx: The context for logging.
//   - methodName: The name of the function being logged.
func LogFunctionEntry(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("entered: %s", methodName))
	return
}

// LogFunctionExit logs the exit of a function.
//
// Parameters:
//   - ctx: The context for logging.
//   - methodName: The name of the function being logged.
func LogFunctionExit(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("exited: %s", methodName))
	return
}

// LogFunctionCall logs the calling of a function.
//
// Parameters:
//   - ctx: The context for logging.
//   - methodName: The name of the function being logged.
func LogFunctionCall(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("calling: %s", methodName))
	return
}

// LogFunctionReturned logs the return of a function.
//
// Parameters:
//   - ctx: The context for logging.
//   - methodName: The name of the function being logged.
func LogFunctionReturned(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("returned: %s", methodName))
	return
}

// recoverOrDownloadCertificate attempts to recover/download the certificate when context is unavailable.
func recoverOrDownloadCertificate(
	ctx context.Context,
	id, collectionID int,
	password string,
	client *api.Client,
	certificateFormat string,
) (leafPEM, chainPEM, pKeyPEM string, rawBytes *string, diagnostics diag.Diagnostics) {
	// Attempt private key recovery
	diags := diag.Diagnostics{}
	if password == "" {
		password = generatePassword(
			PFXPasswordLength,
			PFXPasswordSpecialChars,
			PFXPasswordDigits,
			PFXPasswordUpperCases,
		)
	}
	tflog.Debug(ctx, "Calling recoverPrivateKeyFromKeyfactorCommand()")
	pKeyPEM, leafPEM, chainPEM, rawBytes, diags = recoverPrivateKeyFromKeyfactorCommand(
		ctx,
		id,
		collectionID,
		password,
		client,
		certificateFormat,
	)

	// For binary formats (PFX/JKS/ZIP), recovery is the only path — the P7B
	// download fallback only produces PEM data so it cannot help.  If we got
	// rawBytes back that's success for a binary format even without leafPEM.
	effectiveFmt := effectiveCertificateFormat(certificateFormat)
	if effectiveFmt == "PFX" || effectiveFmt == "JKS" || effectiveFmt == "ZIP" {
		if rawBytes != nil && *rawBytes != "" {
			// Recovery succeeded — clear any non-fatal diagnostics that may
			// have been added (e.g. "private key not returned").
			diags = diag.Diagnostics{}
		}
		return leafPEM, chainPEM, pKeyPEM, rawBytes, diags
	}

	if leafPEM == "" || diags.HasError() {
		// Attempt to download certificate as a fallback
		tflog.Debug(ctx, "Unable to recover private key. Attempting to download certificate from Keyfactor Command.")
		leafPEM, chainPEM, _, diags = downloadCertificateFromKeyfactorCommand(ctx, id, collectionID, client)
	}

	return leafPEM, chainPEM, pKeyPEM, rawBytes, diags
}

// enrollmentTimeoutSkew is subtracted from the enrollment start timestamp when
// searching for a possibly-orphaned certificate after a client-side timeout.
// It absorbs clock skew between this process and the Keyfactor Command
// server; it does not materially widen the search window enough to catch an
// unrelated, pre-existing certificate with the same CN.
//
// NOTE: this is applied to the candidate's ImportDate (when Command's
// record of the certificate was created), NOT its NotBefore. CAs commonly
// backdate NotBefore by several minutes to absorb clock skew on the
// *validating* side (EJBCA's default certificate.validityoffset is -10m;
// Microsoft ADCS's default ClockSkewMinutes is 10) -- a certificate issued
// moments after enrollStartTime can easily have a NotBefore many minutes
// BEFORE enrollStartTime. Using NotBefore as the freshness signal would make
// it impossible to ever match a genuinely-orphaned certificate issued within
// that backdating window, which is the common case. ImportDate is a
// Command-side wall-clock timestamp of when the record was created and does
// not get backdated by CA policy, so it's the correct freshness signal here.
const enrollmentTimeoutSkew = 2 * time.Minute

// enrollmentTimeoutSkewTightened is used instead of enrollmentTimeoutSkew
// when neither Template nor CertificateAuthority is available as a
// discriminator for this request (orphanRecoveryCriteria.weakSignalPath --
// the mainstream v25+ enrollment-pattern path). CommonName, freshness, and
// requester identity are carrying more of the load in that path, so the
// freshness window is narrowed accordingly: 2 minutes of skew tolerance is
// reasonable when it's one signal among six, but leaves an unnecessarily
// wide gap for colliding with a genuinely unrelated, concurrent enrollment
// of the same CN by the same requester when it's one of only three. 30
// seconds still comfortably absorbs realistic clock skew between this
// process and Command (the scenario enrollmentTimeoutSkew exists for) while
// meaningfully narrowing that collision window.
const enrollmentTimeoutSkewTightened = 30 * time.Second

// Historical note: this package used to keep the plaintext PFX enrollment
// password (auto-generated or user-supplied via key_password) out of
// TF_LOG=DEBUG output via a maskPFXEnrollmentPasswordInLogs helper that
// called tflog.MaskFieldValuesWithFieldKeys / MaskAllFieldValuesStrings /
// MaskMessageStrings with the RAW password value -- i.e. masking a literal
// substring of the raw secret out of already-rendered/serialized log text.
//
// That approach had the same JSON-escaping bypass as
// maskCertificateStoreCredentialsInLogs (see redactUpdateStoreFctArgsForLogging
// above): resource_keyfactor_certificate.go's PFX enrollment path marshaled
// *api.EnrollPFXFctArgsV2 (carrying the real password in its Password field)
// to JSON before logging it, and encoding/json escapes '"' and '\\' when
// serializing a string field, so a password containing either character no
// longer appears as a contiguous substring of the raw password in the
// JSON-rendered text -- confirmed via direct reproduction. The fix now
// redacts the Password field on a copy of *api.EnrollPFXFctArgsV2 BEFORE
// marshaling for logging (see enrollPFXV2 in resource_keyfactor_certificate.go),
// rather than masking the rendered JSON afterward; no helper function is
// needed for that single-field case, unlike the certificate-store case
// which also has to rebuild a nested pre-serialized PropertiesString.

// redactedSecretLogPlaceholder replaces a plaintext secret value in a
// logging-only copy of a struct/map, in place of the real value, wherever
// this file redacts-before-formatting rather than masking already-rendered
// text (see redactUpdateStoreFctArgsForLogging).
const redactedSecretLogPlaceholder = "***REDACTED***"

// redactUpdateStoreFctArgsForLogging returns a copy of args safe to log at
// TF_LOG=DEBUG, with plaintext certificate-store credentials -- store_password
// (Password.SecretValue), and server_username/server_password (embedded in
// both the Properties map and the pre-serialized PropertiesString) -- replaced
// with redactedSecretLogPlaceholder BEFORE any %v/json.Marshal formatting
// happens, instead of masking substrings of the raw secret out of already
// rendered/serialized text.
//
// This replaces an earlier approach (maskCertificateStoreCredentialsInLogs,
// removed) that called tflog.MaskMessageStrings / tflog.MaskAllFieldValuesStrings
// to strip the RAW secret value as a literal substring out of the rendered
// log text. That worked for the %v struct-dump call in Update() (fmt.Sprintf
// ("...: %v", *updateStoreArgs)) because %v on a pointer field only prints its
// address, never expanding the actual secret bytes unescaped -- but it did NOT
// work for the json.Marshal-based dump (fmt.Sprintf("...: %s", json.Marshal
// (updateStoreArgs))): encoding/json escapes '"', '\\', and other characters
// in string field values, so a secret containing any of those no longer
// appears as a contiguous substring of the raw secret in the JSON-rendered
// text, and the substring mask misses it entirely (confirmed via direct
// reproduction with a password containing a literal '"'). Redacting the
// value itself, before either formatting call, closes this class of bypass
// rather than patching around it.
//
// Only a shallow copy is made: Properties is copied into a new map (so the
// caller's original map is untouched), and Password -- if it carries a
// SecretValue -- is copied into a new *UpdateStorePasswordConfig with a
// redacted SecretValue. All other fields are copied as-is; none of them are
// documented Sensitive: true attributes in the keyfactor_certificate_store
// schema.
func redactUpdateStoreFctArgsForLogging(args *api.UpdateStoreFctArgs) (*api.UpdateStoreFctArgs, error) {
	if args == nil {
		return nil, nil
	}

	redacted := *args

	if len(args.Properties) > 0 {
		redactedProperties := make(map[string]interface{}, len(args.Properties))
		for k, v := range args.Properties {
			redactedProperties[k] = v
		}
		if _, ok := redactedProperties["ServerUsername"]; ok {
			redactedProperties["ServerUsername"] = redactedSecretLogPlaceholder
		}
		if _, ok := redactedProperties["ServerPassword"]; ok {
			redactedProperties["ServerPassword"] = redactedSecretLogPlaceholder
		}
		redacted.Properties = redactedProperties

		// Rebuild PropertiesString from the REDACTED map rather than masking
		// the already-serialized string -- this is the JSON-escaping-bypass
		// call site the doc comment above describes.
		redactedPropertiesStr, err := mapToEscapedJSONString(redactedProperties)
		if err != nil {
			return nil, err
		}
		redacted.PropertiesString = redactedPropertiesStr
	}

	if args.Password != nil && args.Password.SecretValue != nil {
		placeholder := redactedSecretLogPlaceholder
		redactedPassword := *args.Password
		redactedPassword.SecretValue = &placeholder
		redacted.Password = &redactedPassword
	}

	return &redacted, nil
}

// updateStoreResponseCredentialPropertyKeys lists the property names Command
// itself treats as credential-shaped for a certificate store (see the
// identical set in specialProps / the ServerUsername/ServerPassword/Password
// switch in resource_keyfactor_certificate_store.go's parseSpecialProperties-
// style helpers, and parseProperties in this file). Kept as its own name
// here -- rather than importing those call sites' local maps -- because this
// list is specifically the redaction allowlist for logging, not a functional
// parsing table.
var updateStoreResponseCredentialPropertyKeys = map[string]bool{
	"ServerUsername": true,
	"ServerPassword": true,
	"Password":       true,
}

// redactUpdateStoreResponseForLogging returns a copy of resp safe to log,
// with plaintext certificate-store credentials redacted out of
// PropertiesString.
//
// Command's PUT /CertificateStores (UpdateStore) response ECHOES BACK the
// store's server_username/server_password inside PropertiesString in
// cleartext -- confirmed via a real recorded cassette fixture
// (testdata/cassettes/certificate_store_resource_container_preservation_update.yaml),
// where the Update response body contains
// "Properties":"{...,\"ServerPassword\":\"<plaintext>\",...,\"ServerUsername\":\"<plaintext>\"}".
// resource_keyfactor_certificate_store.go's Update() previously logged this
// response directly at Trace level (fmt.Sprintf("UpdateStoreResponse: %v",
// *updateResponse)) with no redaction at all.
//
// This mirrors redactUpdateStoreFctArgsForLogging's redact-before-format
// approach: PropertiesString is decoded, the credential-shaped keys are
// replaced with redactedSecretLogPlaceholder, and it is re-serialized BEFORE
// being handed to any logging call -- rather than masking substrings out of
// already-rendered text, which is bypassed by JSON's escaping of characters
// like '"' and '\\' in secret values (see the doc comment on
// redactUpdateStoreFctArgsForLogging for the full rationale). Only a shallow
// copy of resp is made; the caller's original response (with real
// credential values) is untouched and still used to build Terraform state.
func redactUpdateStoreResponseForLogging(resp *api.UpdateStoreResponse) (*api.UpdateStoreResponse, error) {
	if resp == nil {
		return nil, nil
	}

	redacted := *resp

	if redacted.PropertiesString == "" {
		return &redacted, nil
	}

	var properties map[string]interface{}
	if err := json.Unmarshal([]byte(redacted.PropertiesString), &properties); err != nil {
		return nil, err
	}

	redactedAny := false
	for key := range properties {
		if updateStoreResponseCredentialPropertyKeys[key] {
			properties[key] = redactedSecretLogPlaceholder
			redactedAny = true
		}
	}
	if !redactedAny {
		return &redacted, nil
	}

	redactedPropertiesStr, err := mapToEscapedJSONString(properties)
	if err != nil {
		return nil, err
	}
	redacted.PropertiesString = redactedPropertiesStr

	return &redacted, nil
}

// certificatesOrphanSearchPageSize is the page size requested on each call
// when paginating Command's GET /Certificates to build the COMPLETE,
// CN-scoped candidate set for orphan-certificate recovery (see
// searchCertificatesForOrphanRecovery). It matches Command's own documented
// default ReturnLimit for the endpoint; there's no benefit to requesting a
// different size since every page is now followed to completion.
const certificatesOrphanSearchPageSize = 50

// certificatesOrphanSearchHardCap bounds how many CN-scoped candidates
// orphan recovery will collect via pagination before refusing to guess.
//
// This replaces an earlier, much narrower guard that refused whenever a
// SINGLE unpaginated page of results hit Command's default ReturnLimit (50)
// -- true even when a documented, supported provider setting
// (revoke_on_destroy = false, or renewal_config.revoke_on_renew = false)
// left many past certificates for a repeatedly-cycled CN active and
// unexpired (they're never revoked), or when the same CN was also issued by
// a non-Terraform source (ACME, an orchestrator, another team). Once that
// count reached 50, recovery was refused PERMANENTLY and UNCONDITIONALLY for
// that CN, degrading straight back into the duplicate-certificate bug this
// mechanism exists to fix -- and it could never self-heal, since every
// enrollment retry added another duplicate.
//
// Now that the full CN-scoped result set is paginated to completion instead
// of trusting a single page, this cap only fires for a pathologically large
// number of same-CN certificates, where continuing to scan stops being a
// reasonable thing to do during an interactive apply.
const certificatesOrphanSearchHardCap = 1000

// isTimeoutShapedError reports whether err looks like a client-side timeout
// rather than a definitive rejection from Keyfactor Command (e.g. a 400/403
// response, which should NOT trigger orphan-recovery since nothing was
// created server-side). It covers:
//   - context.DeadlineExceeded (context-based timeouts)
//   - any error implementing net.Error with Timeout() == true (covers both
//     "net/http: timeout awaiting response headers" and the http.Client's
//     own "Client.Timeout exceeded while awaiting headers")
//   - a couple of well-known substrings as a fallback for wrapped errors that
//     don't preserve the net.Error interface across error-wrapping boundaries
func isTimeoutShapedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "timeout awaiting response headers") ||
		strings.Contains(msg, "Client.Timeout exceeded") ||
		strings.Contains(msg, "context deadline exceeded")
}

// parseCommandTimestamp parses a Keyfactor Command timestamp. Command
// typically returns RFC3339 with fractional seconds (e.g.
// "2026-03-07T02:48:19.393Z"), but some endpoints/versions have been seen to
// omit the fractional part or the "Z" suffix, so a couple of fallback
// layouts are tried.
func parseCommandTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"}
	var lastErr error
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, lastErr
}

// orphanRecoveryIdentity holds the identity string(s) that Keyfactor Command
// might plausibly use to populate a certificate's RequesterName when the
// enrollment request was made by the identity this provider is
// authenticated as. Which of these apply depends on the provider's
// configured auth type (basic/Kerberos vs OAuth), so this is best-effort.
type orphanRecoveryIdentity struct {
	// candidates holds lowercased acceptable RequesterName values. An empty
	// slice means this provider's own identity could not be determined
	// (e.g. Kerberos, or a future auth type without a username/client ID).
	candidates []string

	// permanentlyUnavailable is true when candidates is empty AND that
	// emptiness is a KNOWN, structural property of the configured auth mode
	// -- not just an incidental "nothing relevant happened to be configured"
	// case. Kerberos authentication via a credential cache
	// (kerberos_ccache) without an explicit kerberos_username is the one
	// confirmed case today (F3, round 3): keyfactor-auth-client-go's
	// CommandAuthConfigKerberos.ValidateAuthConfig never requires or derives
	// Username for that combination, so GetServerConfig().Username is ALWAYS
	// empty for every request made under this auth mode -- even though the
	// gokrb5 client it builds via client.NewFromCCache actually has the real
	// principal available internally (Client.Credentials.UserName()/
	// Domain()); it is simply never surfaced through GetServerConfig(). The
	// correct fix is upstream in keyfactor-auth-client-go (populate Username
	// from the ccache's default principal there); independently re-parsing
	// the ccache file from this provider would duplicate that auth-layer's
	// responsibility in the wrong module, for what is -- even when it works
	// -- only a best-effort discriminator. Until that lands,
	// findOrphanedCertificateMatch treats this as reduced confidence
	// (tightened freshness window, matching weakSignalPath's treatment)
	// rather than silently conflating "not populated" with "nothing to
	// verify" the way matches() does for the ordinary empty-candidates case.
	permanentlyUnavailable bool
}

// orphanRecoveryIdentityForClient builds the set of identity strings Command
// might return as RequesterName for requests made by client.
func orphanRecoveryIdentityForClient(client *api.Client) orphanRecoveryIdentity {
	if client == nil || client.AuthClient == nil {
		return orphanRecoveryIdentity{}
	}
	cfg := client.AuthClient.GetServerConfig()
	if cfg == nil {
		return orphanRecoveryIdentity{}
	}
	var candidates []string
	if cfg.Username != "" {
		candidates = append(candidates, strings.ToLower(cfg.Username))
		if cfg.Domain != "" {
			candidates = append(candidates, strings.ToLower(cfg.Domain+"\\"+cfg.Username))
			candidates = append(candidates, strings.ToLower(cfg.Domain+"/"+cfg.Username))
		}
	}
	if cfg.ClientID != "" {
		candidates = append(candidates, strings.ToLower(cfg.ClientID))
	}
	// Kerberos-via-credential-cache without an explicit kerberos_username is
	// a KNOWN case where candidates will ALWAYS be empty -- see
	// permanentlyUnavailable's doc comment. This is distinct from other auth
	// modes where an empty candidates slice just means nothing relevant
	// happened to be configured for THIS request.
	permanentlyUnavailable := len(candidates) == 0 &&
		strings.EqualFold(cfg.AuthType, "kerberos") && cfg.KerberosCCache != ""
	return orphanRecoveryIdentity{candidates: candidates, permanentlyUnavailable: permanentlyUnavailable}
}

// matches reports whether requesterName is consistent with this provider's
// own identity. If either side has nothing to compare (this provider's
// identity is unknown, or Command didn't return a RequesterName) the
// discriminator is not applicable and matches returns true -- there's
// nothing to verify, not a mismatch.
func (id orphanRecoveryIdentity) matches(requesterName string) bool {
	if requesterName == "" || len(id.candidates) == 0 {
		return true
	}
	rn := strings.ToLower(requesterName)
	for _, c := range id.candidates {
		if c == rn {
			return true
		}
	}
	return false
}

// parseSubjectDNAttributes performs a lightweight parse of a comma-separated
// X.509 subject DN string (e.g. `CN=foo,OU=bar,O=Baz\, Inc,C=US`) into a map
// of uppercased attribute type -> value, honoring backslash-escaped commas.
// It does not attempt full RFC 4514 parsing (multi-valued RDNs, hex-encoded
// values, etc.) -- Keyfactor Command's IssuedDN values are simple
// comma-separated "TYPE=value" pairs in practice. "S" is normalized to "ST"
// (both are used for state/province across CA vendors). Returns nil if dn
// yields no attributes, so callers can fail closed instead of silently
// treating an unparsable DN as a match.
func parseSubjectDNAttributes(dn string) map[string]string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil
	}
	var parts []string
	var cur strings.Builder
	escaped := false
	for _, r := range dn {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())

	attrs := map[string]string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.Index(p, "=")
		if eq <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(p[:eq]))
		if key == "S" {
			key = "ST"
		}
		attrs[key] = strings.TrimSpace(p[eq+1:])
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// orphanRecoverySubjectMatches reports whether candidateDN (a candidate
// certificate's IssuedDN) is consistent with the non-CN subject fields
// actually populated in the original enrollment request. CN itself is
// checked separately (against the dedicated IssuedCN field, which is more
// reliable than parsing it back out of the DN). Only fields the request
// populated are evaluated -- a field never sent is not a discriminator. If
// the request populated at least one such field but candidateDN cannot be
// parsed at all, that is treated as "cannot verify" and rejected.
func orphanRecoverySubjectMatches(candidateDN string, expected *api.CertificateSubject) bool {
	if expected == nil {
		return true
	}
	fields := map[string]string{
		"O":  expected.SubjectOrganization,
		"OU": expected.SubjectOrganizationalUnit,
		"L":  expected.SubjectLocality,
		"ST": expected.SubjectState,
		"C":  expected.SubjectCountry,
	}
	anySet := false
	for _, v := range fields {
		if v != "" {
			anySet = true
			break
		}
	}
	if !anySet {
		return true
	}
	attrs := parseSubjectDNAttributes(candidateDN)
	if attrs == nil {
		return false
	}
	for key, want := range fields {
		if want == "" {
			continue
		}
		if got, ok := attrs[key]; !ok || !strings.EqualFold(got, want) {
			return false
		}
	}
	return true
}

// SAN "Type" values as returned in GetCertificateResponse.SubjectAltNameElements,
// per the Keyfactor Command API reference (these mirror the ASN.1 GeneralName
// CHOICE tag numbers): 2 = dNSName, 6 = uniformResourceIdentifier, 7 = iPAddress.
const (
	sanTypeDNS = 2
	sanTypeURI = 6
	sanTypeIP  = 7
)

// orphanRecoverySANsMatch reports whether a candidate certificate's
// SubjectAltNameElements are consistent with the SANs actually submitted in
// the original enrollment request. Only SAN types the request populated are
// evaluated (e.g. this provider does not currently submit IPv6 SANs, so that
// type is never a discriminator); when a type WAS populated, the candidate's
// set of values for that type must match it exactly (no fewer, no more).
func orphanRecoverySANsMatch(candidateSANs []SubjectAltNameElement, expected *api.SANs) bool {
	if expected == nil {
		return true
	}
	if len(expected.DNS) > 0 && !sanSetEquals(expected.DNS, candidateSANs, sanTypeDNS, true) {
		return false
	}
	if len(expected.IP4) > 0 && !sanSetEquals(expected.IP4, candidateSANs, sanTypeIP, false) {
		return false
	}
	if len(expected.URI) > 0 && !sanSetEquals(expected.URI, candidateSANs, sanTypeURI, false) {
		return false
	}
	return true
}

// SubjectAltNameElement is a minimal, decoupled mirror of
// api.SubjectAltNameElements{Type, Value} used so orphanRecoverySANsMatch
// doesn't have to import the full SDK type into its signature.
type SubjectAltNameElement struct {
	Type  int
	Value string
}

func sanSetEquals(expected []string, actual []SubjectAltNameElement, sanType int, caseInsensitive bool) bool {
	got := map[string]bool{}
	for _, el := range actual {
		if el.Type != sanType {
			continue
		}
		v := el.Value
		if caseInsensitive {
			v = strings.ToLower(v)
		}
		got[v] = true
	}
	if len(got) != len(expected) {
		return false
	}
	for _, v := range expected {
		if caseInsensitive {
			v = strings.ToLower(v)
		}
		if !got[v] {
			return false
		}
	}
	return true
}

// orphanRecoveryTemplateMatches reports whether a candidate's template is
// consistent with the template actually submitted in the original enrollment
// request. expectedTemplateName is empty when the request used an enrollment
// pattern instead of a template name (Command resolves the template
// server-side in that case, and the request never sent one) -- Template is
// then simply not a discriminator for this Create attempt.
//
// Command's certificate record (GetCertificateResponse.TemplateName) always
// carries the template's DISPLAY name (e.g. "Server (tlsServerAuth-1y)"),
// while the enrollment request -- and the schema's documented, common
// configuration -- sends the SHORT name (e.g. "Server_tlsServerAuth-1y").
// Comparing those two strings directly therefore almost never matches for
// the mainstream case, silently defeating recovery. When the caller was
// able to resolve expectedTemplateName to a numeric template ID (see
// resolveTemplateIDByName), IDs are compared instead -- that's unambiguous
// regardless of which name form either side uses. If resolution wasn't
// possible (lookup failed, or the template couldn't be found by that name),
// fall back to a name comparison, but do so case-insensitively without
// assuming which form either side is in; this is weaker than the ID-based
// check but still strictly better than requiring an exact string match
// between two fields that are documented to use different naming
// conventions.
func orphanRecoveryTemplateMatches(candidateTemplateId int, candidateTemplateName string, expectedTemplateId int, expectedTemplateName string) bool {
	if expectedTemplateName == "" {
		return true
	}
	if expectedTemplateId > 0 && candidateTemplateId > 0 {
		return candidateTemplateId == expectedTemplateId
	}
	return strings.EqualFold(candidateTemplateName, expectedTemplateName)
}

// orphanRecoveryCAMatches reports whether a candidate's
// CertificateAuthorityName is consistent with the certificate_authority
// actually submitted in the original enrollment request. Command returns CA
// names as "hostname\\LogicalName" (Microsoft CAs) or a full CA URL followed
// by "\\LogicalName" (EJBCA), while expectedCA is normally just the logical
// name a user supplies -- mirrors the normalization already applied when
// populating certificate_authority in Read (see
// resource_keyfactor_certificate.go). expectedCA is empty when the request
// didn't pin a CA (Command auto-selects one matching the template/pattern),
// in which case CA is not a discriminator.
func orphanRecoveryCAMatches(candidateCA, expectedCA string) bool {
	if expectedCA == "" {
		return true
	}
	if strings.EqualFold(candidateCA, expectedCA) {
		return true
	}
	lowerCA, lowerExpected := strings.ToLower(candidateCA), strings.ToLower(expectedCA)
	return strings.HasSuffix(lowerCA, "\\"+lowerExpected) || strings.HasSuffix(lowerCA, "\\\\"+lowerExpected)
}

// orphanRecoveryCriteria bundles the enrollment request's identifying
// attributes used to strictly narrow a set of search results down to (at
// most) the single certificate this Create attempt actually produced before
// timing out.
//
// Every discriminator the request actually populated MUST match the
// candidate exactly (see the per-field orphanRecovery*Matches helpers for
// exactly what "match" means for each). A discriminator the request did NOT
// populate (e.g. Template when an enrollment pattern was used, or
// CertificateAuthority when Command was left to auto-select) is not
// evaluated at all -- there's nothing to verify it against. That is
// different from a discriminator that WAS populated but whose candidate data
// can't confirm it (e.g. a subject field we sent but the candidate's
// IssuedDN can't be parsed): that is treated as "cannot verify" and fails
// closed, rejecting the candidate.
//
// Honest accounting of the mainstream v25+ enrollment-pattern path: when an
// enrollment pattern resolves (see enrollPFXV2), Template is deliberately
// blanked before the request is sent (Command resolves it server-side from
// the pattern), and CertificateAuthority is commonly left unset too
// (Optional+Computed, auto-selected). In that path Template and
// CertificateAuthority are NOT usable discriminators -- there is nothing the
// request sent for them to be checked against -- leaving CommonName,
// ImportDate freshness, Subject/SANs (when the plan populated them), and
// requester identity (when derivable) as what's actually available. Two
// mitigations narrow the residual exposure this leaves for that path
// specifically (see findOrphanedCertificateMatch and
// recoverOrphanedPFXEnrollment): the freshness window is tightened when
// Template and CertificateAuthority are both empty, and -- when Command's
// certificate record exposes it (25.1.0+) -- the resolved EnrollmentPatternId
// for this request is cross-checked against the sole surviving candidate as
// an extra, out-of-band confirmation.
//
// Requester-identity discriminator gap for Kerberos-via-credential-cache
// (F3, round 3): when this provider authenticates via kerberos_ccache
// without an explicit kerberos_username, the client's own username can NEVER
// be determined from GetServerConfig() (see
// orphanRecoveryIdentity.permanentlyUnavailable) -- this is a permanent,
// structural gap for that auth mode specifically, not the ordinary
// "nothing to compare" case every other auth mode can also hit incidentally.
// The requester-identity check is one of the few discriminators still
// meaningful in the weak-signal path above, so this narrows that path's
// residual margin further for Kerberos-ccache users specifically. Mitigation:
// findOrphanedCertificateMatch tightens the freshness window for this case
// exactly as it does for the Template/CertificateAuthority-blank path, even
// outside that path. The proper fix -- populating Username from the ccache's
// principal upstream in keyfactor-auth-client-go -- is out of scope here (see
// permanentlyUnavailable's doc comment for why); this is a documented,
// deliberate mitigation of a known gap, not a silent one.
//
// Residual risk (documented, not eliminated): a concurrent enrollment of the
// IDENTICAL subject, SANs, template, CA, and requester identity within the
// same freshness window as the timed-out request would still be
// indistinguishable from the genuine orphan. This is considered acceptable
// because it requires the same account to be enrolling the exact same
// certificate twice, concurrently -- a materially narrower and less likely
// condition than "any certificate with this CN issued recently", which is
// what this replaces. That residual window is widest precisely in the
// pattern-based path described above, which is why it gets the additional
// mitigations rather than relying on the same margins as the
// template/CA-populated path.
type orphanRecoveryCriteria struct {
	CommonName           string
	Subject              *api.CertificateSubject
	SANs                 *api.SANs
	Template             string
	TemplateId           int
	CertificateAuthority string
	Identity             orphanRecoveryIdentity
	EnrollStartTime      time.Time
	// EnrollmentPatternId is the enrollment pattern ID resolved for this
	// request (0 if none was used/resolved). Used as an additional
	// post-match confirmation signal in the pattern-based path -- see
	// recoverOrphanedPFXEnrollment.
	EnrollmentPatternId int
}

// weakSignalPath reports whether neither Template nor CertificateAuthority
// is available as a discriminator for this request -- the mainstream v25+
// enrollment-pattern path (see orphanRecoveryCriteria doc comment). This
// governs which findOrphanedCertificateMatch/recoverOrphanedPFXEnrollment
// mitigations apply.
func (c orphanRecoveryCriteria) weakSignalPath() bool {
	return c.Template == "" && c.CertificateAuthority == ""
}

// findOrphanedCertificateMatch narrows a set of search results (already
// filtered server-side by CN, and paginated to completion -- see
// searchCertificatesForOrphanRecovery) down to the single certificate that is
// plausibly the one this Create attempted to enroll before timing out, per
// criteria (see orphanRecoveryCriteria for the exact matching rules and
// documented residual risk).
//
// Returns the single match, or an error describing why adoption isn't safe
// (zero matches, or more than one -- ambiguous, so we refuse to guess).
func findOrphanedCertificateMatch(
	certs []api.GetCertificateResponse,
	criteria orphanRecoveryCriteria,
) (*api.GetCertificateResponse, error) {
	skew := enrollmentTimeoutSkew
	if criteria.weakSignalPath() || criteria.Identity.permanentlyUnavailable {
		// Template and CertificateAuthority aren't usable discriminators for
		// this request (see orphanRecoveryCriteria doc comment) -- CN,
		// freshness, and requester identity are carrying more of the load, so
		// tighten the freshness window rather than relying on the same
		// margin as the template/CA-populated path. The same tightening
		// applies whenever the requester-identity discriminator itself is
		// known to be structurally unavailable for this request's auth mode
		// (see orphanRecoveryIdentity.permanentlyUnavailable -- e.g.
		// Kerberos-via-credential-cache without an explicit username), even
		// OUTSIDE the Template/CertificateAuthority-blank path, since that
		// request is also missing a discriminator other configurations would
		// have.
		skew = enrollmentTimeoutSkewTightened
	}
	threshold := criteria.EnrollStartTime.Add(-skew)
	var candidates []api.GetCertificateResponse
	// seenCandidateIds dedups by certificate Id (F1 hardening, round 3):
	// defense in depth against a duplicate row appearing in certs (e.g. if a
	// certificate for this exact CN was inserted while
	// searchCertificatesForOrphanRecovery's multi-page walk was in flight,
	// shifting an already-returned row across a page boundary despite the
	// stable Id-ascending sort that function now requests). Without this, two
	// identical entries for the SAME certificate would trivially satisfy
	// every discriminator below and trip the len(candidates) > 1 "ambiguous"
	// refusal, spuriously refusing an otherwise-uniquely-recoverable orphan.
	seenCandidateIds := map[int]bool{}
	for _, cert := range certs {
		if !strings.EqualFold(cert.IssuedCN, criteria.CommonName) {
			continue
		}
		importDate, parseErr := parseCommandTimestamp(cert.ImportDate)
		if parseErr != nil || importDate.Before(threshold) {
			continue
		}
		if !orphanRecoverySubjectMatches(cert.IssuedDN, criteria.Subject) {
			continue
		}
		sanElements := make([]SubjectAltNameElement, 0, len(cert.SubjectAltNameElements))
		for _, el := range cert.SubjectAltNameElements {
			sanElements = append(sanElements, SubjectAltNameElement{Type: el.Type, Value: el.Value})
		}
		if !orphanRecoverySANsMatch(sanElements, criteria.SANs) {
			continue
		}
		if !orphanRecoveryTemplateMatches(cert.TemplateId, cert.TemplateName, criteria.TemplateId, criteria.Template) {
			continue
		}
		if !orphanRecoveryCAMatches(cert.CertificateAuthorityName, criteria.CertificateAuthority) {
			continue
		}
		if !criteria.Identity.matches(cert.RequesterName) {
			continue
		}
		if seenCandidateIds[cert.Id] {
			continue
		}
		seenCandidateIds[cert.Id] = true
		candidates = append(candidates, cert)
	}

	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf(
			"no certificate matching the enrollment request (CN '%s', issued on or after %s) was found in "+
				"Keyfactor Command",
			criteria.CommonName, criteria.EnrollStartTime.UTC().Format(time.RFC3339),
		)
	case 1:
		return &candidates[0], nil
	default:
		ids := make([]string, 0, len(candidates))
		for _, c := range candidates {
			ids = append(ids, fmt.Sprintf("%d", c.Id))
		}
		return nil, fmt.Errorf(
			"%d certificates matching the enrollment request (CN '%s', issued on or after %s) were found in "+
				"Keyfactor Command (ids: %s) -- cannot safely determine which one this Create attempted to enroll",
			len(candidates), criteria.CommonName, criteria.EnrollStartTime.UTC().Format(time.RFC3339),
			strings.Join(ids, ", "),
		)
	}
}

// orphanRecoveryWireFormat maps a PFX-enrollment certificateFormat value to
// the format string that should actually be requested from Command's
// Certificates/Recover endpoint. This intentionally does NOT reuse
// effectiveCertificateFormat: that helper normalizes ""/"STORE" to "PEM" for
// the Read/Import recovery path, but enrollPFXV2's own result-building
// switch (see certificateFormat handling below) treats "STORE"
// (DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT) identically to explicit "PFX" --
// requesting "PEM" instead would silently change which Command endpoint
// behavior orphan recovery exercises for the common (unset-format) case.
func orphanRecoveryWireFormat(certificateFormat string) string {
	switch certificateFormat {
	case "JKS":
		return "JKS"
	case "ZIP":
		return "ZIP"
	default:
		// "PFX", DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT ("STORE"), or anything
		// else falls back to requesting PFX, mirroring enrollPFXV2's
		// `case "PFX", DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT:` branch.
		return "PFX"
	}
}

// formatCertificateSubjectDN renders the non-empty fields of subject as a
// display-only "CN=...,OU=...,O=...,L=...,ST=...,C=..." string, for use in
// diagnostics messages. It is not intended to be byte-for-byte identical to
// how Command or any particular CA renders the same subject.
func formatCertificateSubjectDN(subject *api.CertificateSubject) string {
	if subject == nil {
		return ""
	}
	var parts []string
	add := func(attr, value string) {
		if value != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", attr, value))
		}
	}
	add("CN", subject.SubjectCommonName)
	add("OU", subject.SubjectOrganizationalUnit)
	add("O", subject.SubjectOrganization)
	add("L", subject.SubjectLocality)
	add("ST", subject.SubjectState)
	add("C", subject.SubjectCountry)
	return strings.Join(parts, ",")
}

// sdkCertToLegacyCertificateResponse adapts a v25 SDK
// CertificatesCertificateRetrievalBulkResponse (the per-item shape returned
// by the paginated GET /Certificates list endpoint that
// searchCertificatesForOrphanRecovery calls -- distinct from
// CertificatesCertificateRetrievalResponse, the single-certificate-by-ID GET
// shape) into the legacy api.GetCertificateResponse shape
// findOrphanedCertificateMatch's discriminators already operate on. Carries
// forward every field they read: Id, IssuedCN, IssuedDN, ImportDate,
// TemplateId, TemplateName, CertificateAuthorityName, RequesterName,
// SubjectAltNameElements, plus Thumbprint/SerialNumber/IssuerDN/CertRequestId
// (used when building the adopted EnrollResponseV2 after a match is found).
func sdkCertToLegacyCertificateResponse(c kfv1.CertificatesCertificateRetrievalBulkResponse) api.GetCertificateResponse {
	var sans []api.SubjectAltNameElements
	for _, el := range c.GetSubjectAltNameElements() {
		sans = append(sans, api.SubjectAltNameElements{
			Id:    int(el.GetId()),
			Value: el.GetValue(),
			Type:  int(el.GetType()),
		})
	}
	var importDate string
	if t := c.GetImportDate(); !t.IsZero() {
		importDate = t.UTC().Format(time.RFC3339Nano)
	}
	return api.GetCertificateResponse{
		Id:                       int(c.GetId()),
		Thumbprint:               c.GetThumbprint(),
		SerialNumber:             c.GetSerialNumber(),
		IssuedDN:                 c.GetIssuedDN(),
		IssuedCN:                 c.GetIssuedCN(),
		ImportDate:               importDate,
		IssuerDN:                 c.GetIssuerDN(),
		TemplateId:               int(c.GetTemplateId()),
		TemplateName:             c.GetTemplateName(),
		CertificateAuthorityName: c.GetCertificateAuthorityName(),
		RequesterName:            c.GetRequesterName(),
		CertRequestId:            int(c.GetCertRequestId()),
		SubjectAltNameElements:   sans,
	}
}

// searchCertificatesForOrphanRecovery pages through Command's GET
// /Certificates (via the vendored v24 SDK client, which exposes
// PageReturned/ReturnLimit pagination that the legacy api.Client's
// ListCertificates does not) scoped server-side to IssuedCN, collecting the
// COMPLETE matching result set -- up to certificatesOrphanSearchHardCap --
// instead of trusting a single, possibly-truncated page. See
// certificatesOrphanSearchHardCap for why a single-page truncation guard was
// not an acceptable long-term answer here. Mirrors the ReturnLimit/
// PageReturned pagination pattern already used by
// getSecurityPermissionSetByName.
//
// F1 hardening (round 3): the request explicitly sorts by the certificate's
// auto-incrementing primary key ascending -- unique and monotonically
// increasing -- so it gives offset-based PageReturned/ReturnLimit pagination
// a deterministic, stable total order across pages. Without an explicit sort,
// Command's default ordering is not guaranteed stable call-to-call; if a new
// certificate for this exact CN is imported WHILE this multi-page search is
// in flight, unsorted offset-based pagination can shift an already-returned
// row across a page boundary, causing it to be fetched (and counted) twice.
// Sorting by the primary key specifically (rather than e.g. ImportDate) also
// avoids tie-breaking ambiguity: a newly-inserted row always sorts after
// every row already seen by an in-progress page walk, so it can never be
// inserted "behind" the pagination cursor and shift a previously-returned row
// forward. findOrphanedCertificateMatch additionally deduplicates by Id as
// defense in depth, in case a duplicate row still appears despite the stable
// sort (e.g. against a Command version/configuration that doesn't honor
// SortField for this endpoint).
//
// The sort field name is "CertId", NOT "Id" -- confirmed against a live
// Command instance (kfclab) 2026-08-16: Command's /Certificates SortField
// validates its value against the endpoint's own PQL-sortable field names,
// which do NOT include the response JSON's "Id" property name, only "CertId"
// (Command rejects "Id" outright with HTTP 400 "Invalid sort field: Id.").
// An earlier version of this code used "Id" and was only ever exercised
// against permissive mock servers (this file's TestUnitEnrollPFX_* suite)
// that don't validate SortField the way real Command does, so the 400 was
// never caught until a live-lab run. "CertId" returns the identical
// certificate set/ordering as "Id" would have (same underlying column; see
// the live-lab request/response captured in the PR this comment shipped
// with) -- this is a field-name fix only, not a behavior change.
func searchCertificatesForOrphanRecovery(
	ctx context.Context,
	sdkClient *keyfactor.APIClient,
	commonName string,
) ([]api.GetCertificateResponse, error) {
	if sdkClient == nil || sdkClient.V1 == nil {
		return nil, fmt.Errorf("keyfactor SDK client is not configured")
	}

	if strings.Contains(commonName, `"`) {
		return nil, fmt.Errorf("orphan-recovery search cannot safely construct a PQL query for a common name containing double-quote characters; use `terraform import` to adopt the certificate manually if it exists")
	}

	query := fmt.Sprintf(`IssuedCN -eq "%s"`, commonName)
	var all []api.GetCertificateResponse
	for page := int32(1); ; page++ {
		tflog.Debug(ctx, fmt.Sprintf("Querying orphan-recovery candidates for CN '%s', page %d", commonName, page))
		results, _, err := sdkClient.V1.CertificateApi.NewGetCertificatesRequest(ctx).
			QueryString(query).
			PageReturned(page).
			ReturnLimit(certificatesOrphanSearchPageSize).
			SortField("CertId").
			SortAscending(kfv1.KEYFACTORCOMMONQUERYABLEEXTENSIONSSORTORDER__0).
			Execute()
		if err != nil {
			return nil, fmt.Errorf("searching Keyfactor Command for CN %q (page %d): %w", commonName, page, err)
		}

		for _, r := range results {
			all = append(all, sdkCertToLegacyCertificateResponse(r))
		}

		if len(all) > certificatesOrphanSearchHardCap {
			return nil, fmt.Errorf(
				"Keyfactor Command returned more than %d certificates matching CN %q across a fully-paginated "+
					"search; refusing to guess which one (if any) this Create attempted to enroll",
				certificatesOrphanSearchHardCap, commonName,
			)
		}

		if len(results) < certificatesOrphanSearchPageSize {
			// Last page -- fewer results than requested means there's no more.
			break
		}
	}
	return all, nil
}

// recoverOrphanedPFXEnrollment attempts to recover from a client-side timeout
// during PFX enrollment by searching Keyfactor Command for a certificate that
// the timed-out request may have actually created server-side, and if
// findOrphanedCertificateMatch identifies exactly one certificate matching
// every discriminator available from the original request (see
// orphanRecoveryCriteria), recovering its key material so the caller can
// adopt it into state instead of returning an error (which would otherwise
// cause the next apply to enroll a duplicate certificate).
//
// The certificate's key material is fetched from Command's
// Certificates/Recover endpoint in certificateFormat (PFX/JKS/ZIP), matching
// what a non-timeout enrollment in that format would have produced.
//
// lookupPassword controls how Command ENCRYPTS/packages the recovered
// response -- it is not an authorization check and does NOT gate which
// certificate can be recovered. Any password Command accepts for the
// request succeeds regardless of what password (if any) was used for the
// original enrollment; Recover is authorization-gated by the caller's
// Command RBAC permissions, not by password matching. All of the safety
// here comes from findOrphanedCertificateMatch's strict, multi-discriminator
// matching having already identified the correct certificate -- not from
// this password.
func recoverOrphanedPFXEnrollment(
	ctx context.Context,
	client *api.Client,
	sdkClient *keyfactor.APIClient,
	criteria orphanRecoveryCriteria,
	collectionId int,
	lookupPassword string,
	certificateFormat string,
) (*api.EnrollResponseV2, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	commonName := criteria.CommonName

	tflog.Debug(ctx, fmt.Sprintf("Searching Keyfactor Command for a possibly-orphaned certificate matching CN '%s'", commonName))
	certs, listErr := searchCertificatesForOrphanRecovery(ctx, sdkClient, commonName)
	if listErr != nil {
		diags.AddError(
			"Could not search for orphaned certificate after enrollment timeout",
			fmt.Sprintf("Searching Keyfactor Command for CN '%s' failed: %s", commonName, listErr.Error()),
		)
		return nil, diags
	}

	match, matchErr := findOrphanedCertificateMatch(certs, criteria)
	if matchErr != nil {
		diags.AddError(
			"Could not safely recover from enrollment timeout",
			matchErr.Error(),
		)
		return nil, diags
	}

	// F2 pattern-based-path hardening: when Template and CertificateAuthority
	// were both unavailable as discriminators (weakSignalPath -- see
	// orphanRecoveryCriteria), CommonName, freshness, and requester identity
	// did the narrowing above. If this request resolved a specific enrollment
	// pattern and Command's certificate record exposes EnrollmentPatternId
	// (25.1.0+), cross-check it against the sole surviving candidate as an
	// extra, independent confirmation. An explicit disagreement (both sides
	// non-zero and different) is rejected outright. A server that doesn't
	// return the field at all (pre-25.1, or this specific candidate omitted
	// it) means "cannot verify" -- not a mismatch -- so recovery proceeds on
	// the already-tightened freshness window alone, consistent with this
	// path's documented residual risk.
	//
	// Round 3 (F2) hardening: a FAILED confirmation call (ctxErr != nil --
	// transient network error, rate limiting, anything) is deliberately NOT
	// treated the same as "the field is absent" above. "Absent" is an
	// expected, steady-state shape (older Command versions never send this
	// field at all); an API error is a one-off failure of a check that, had
	// it succeeded, could have confirmed OR refuted the match. Silently
	// falling back to tflog.Warn-only and proceeding on the freshness-only
	// signal alone would degrade EXACTLY the confirmation this weak-signal
	// path added this check to get, with no operator-visible record
	// distinguishing "the check ran and passed" from "the check errored and
	// was skipped" -- an auditor reviewing `terraform apply` output could not
	// tell the difference. Given this path's discriminators are already
	// thin, fail closed instead: refuse the adoption and surface a distinct,
	// explicit diagnostic. The cost of a spurious refusal here is a retried
	// apply; the cost of a wrong fail-open adoption is Terraform state bound
	// to the wrong certificate's private key material.
	if criteria.weakSignalPath() && criteria.EnrollmentPatternId > 0 && client != nil {
		ctxCert, ctxErr := client.GetCertificateContext(&api.GetCertificateContextArgs{Id: match.Id})
		if ctxErr != nil {
			diags.AddError(
				"Could not safely recover from enrollment timeout",
				fmt.Sprintf(
					"Certificate %d matches CN '%s' and every other available discriminator, but this request used "+
						"an enrollment pattern with Template and CertificateAuthority both unavailable as "+
						"discriminators, so confirming the candidate's enrollment pattern (expected %d) against "+
						"Command's own record of it is relied on more heavily here. That confirmation could NOT be "+
						"performed -- fetching full certificate context for %d failed: %s. Refusing to adopt this "+
						"certificate on the weaker freshness-only signal alone; retry the apply once the underlying "+
						"error clears, or import certificate %d manually with `terraform import` after confirming "+
						"it is the one this request enrolled.",
					match.Id, commonName, criteria.EnrollmentPatternId, match.Id, ctxErr.Error(), match.Id,
				),
			)
			return nil, diags
		} else if ctxCert != nil && ctxCert.EnrollmentPatternId > 0 && ctxCert.EnrollmentPatternId != criteria.EnrollmentPatternId {
			diags.AddError(
				"Could not safely recover from enrollment timeout",
				fmt.Sprintf(
					"Certificate %d matches CN '%s' and every other available discriminator, but was issued under "+
						"enrollment pattern %d, not the requested pattern %d -- refusing to adopt a certificate "+
						"that disagrees with the enrollment pattern this request actually used.",
					match.Id, commonName, ctxCert.EnrollmentPatternId, criteria.EnrollmentPatternId,
				),
			)
			return nil, diags
		}
	}

	effectiveFmt := orphanRecoveryWireFormat(certificateFormat)
	tflog.Debug(
		ctx, fmt.Sprintf(
			"Found orphaned certificate %d matching CN '%s'; recovering private key material in %s format",
			match.Id, commonName, effectiveFmt,
		),
	)
	_, _, _, rawBytes, recoverDiags := recoverPrivateKeyFromKeyfactorCommand(
		ctx, match.Id, collectionId, lookupPassword, client, effectiveFmt,
	)

	// For binary formats (PFX/JKS/ZIP), non-empty rawBytes is success even if
	// recoverDiags carries an error: keyfactor-go-client's RecoverCertificate
	// only special-cases "PFX"/"jks" formats (bundled together); "ZIP" falls
	// through to its default branch, which always attempts a PKCS#12 decode
	// of the raw response and returns that decode error ALONGSIDE the
	// (perfectly valid, just non-PKCS#12) rawBytes for a ZIP payload. This
	// mirrors the same tolerance recoverOrDownloadCertificate already applies.
	binaryFormat := effectiveFmt == "PFX" || effectiveFmt == "JKS" || effectiveFmt == "ZIP"
	recoverySucceeded := rawBytes != nil && *rawBytes != "" && (binaryFormat || !recoverDiags.HasError())
	if !recoverySucceeded {
		diags.AddError(
			"Found orphaned certificate but could not recover its private key",
			fmt.Sprintf(
				"Certificate %d matching CN '%s' exists in Keyfactor Command, but recovering its private key "+
					"material failed. It cannot be safely adopted automatically; import it manually with "+
					"`terraform import` once you've confirmed its enrollment password.",
				match.Id, commonName,
			),
		)
		diags.Append(recoverDiags...)
		return nil, diags
	}

	return &api.EnrollResponseV2{
		CertificateInformation: api.CertificateInformation{
			SerialNumber:       match.SerialNumber,
			IssuerDN:           match.IssuerDN,
			Thumbprint:         match.Thumbprint,
			KeyfactorID:        match.Id,
			KeyfactorRequestID: match.CertRequestId,
			PKCS12Blob:         *rawBytes,
			RequestDisposition: "ISSUED",
		},
	}, diags
}

// logInitialCertificateFields logs common certificate fields.
func logInitialCertificateFields(
	ctx context.Context, id int, cn, thumbprint string,
	collectionID int,
) context.Context {
	ctx = tflog.SetField(ctx, "certificate_id", id)
	ctx = tflog.SetField(ctx, "certificate_cn", cn)
	ctx = tflog.SetField(ctx, "certificate_thumbprint", thumbprint)
	ctx = tflog.SetField(ctx, "collection_id", collectionID)
	return ctx
}

// prepareCertificateContextArgs creates arguments for fetching the certificate context.
func prepareCertificateContextArgs(id, collectionID int, thumbprint, commonName string) *api.GetCertificateContextArgs {
	return &api.GetCertificateContextArgs{
		IncludeMetadata:      boolToPointer(true),
		IncludeLocations:     boolToPointer(true),
		IncludeHasPrivateKey: boolToPointer(true),
		CollectionId:         intToPointer(collectionID),
		Id:                   id,
		CommonName:           commonName,
		Thumbprint:           thumbprint,
	}
}

// nilAPIResponseDiagnostics builds a diagnostics error for the case where an
// SDK Execute() call returns a nil response body AND a nil error.
//
// The vendored SDK's decode() (vendor/github.com/Keyfactor/keyfactor-go-
// client-sdk/v25/api/keyfactor/v1/client.go) returns (nil, httpResp, nil)
// -- no error at all -- for any 2xx response with an empty body, because
// json.Unmarshal is never invoked when the body length is 0. Every
// *ResponseToState conversion function in this codebase correctly
// nil-checks individual *fields* on a response (via nullableStringToTfString
// etc.) but assumes the top-level response pointer itself is never nil.
// Without an explicit guard immediately after every Execute() call, an
// empty-body 2xx response (from a compromised/malicious Command server, a
// MITM -- this provider supports KEYFACTOR_SKIP_VERIFY -- or a buggy proxy/
// load balancer) reaches the very next line as a nil pointer dereference:
// a real, remotely-triggerable panic. Callers should check `resp == nil`
// immediately after the err-check block on every Execute() call whose
// response is subsequently dereferenced, and append this diagnostic instead
// of proceeding. See PR #210 full-review finding FIX-5.
func nilAPIResponseDiagnostics(summary, operation string) diag.Diagnostics {
	var diags diag.Diagnostics
	diags.AddError(
		summary,
		fmt.Sprintf(
			"Keyfactor Command returned a successful (2xx) HTTP response with an empty body while %s, so no data "+
				"could be parsed from it. This can happen if a proxy or load balancer between Terraform and Command "+
				"stripped the response body, or (if KEYFACTOR_SKIP_VERIFY is enabled) if a man-in-the-middle is "+
				"intercepting the connection. Retry the operation; if this persists, investigate the network path "+
				"and TLS configuration between Terraform and Command.",
			operation,
		),
	)
	return diags
}

// hasAPIErrors processes errors from the API response; returns true if terminal.
func hasAPIErrors(
	ctx context.Context,
	err error,
	certID string,
	diags *diag.Diagnostics,
) bool {
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error calling GET Certificates/%s", certID))
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s': %s", certID, err.Error()),
		)
		return true
	}
	return false
}

// notFoundStatusCodePattern matches a standalone "404" status-code token
// (e.g. the leading "404" in "404 - Unknown error connecting to Keyfactor
// ..."). Word boundaries prevent it from matching "404" when it's merely a
// substring of a longer number, such as a resource ID embedded in an error
// message ("Security/Roles/1404", "40498").
var notFoundStatusCodePattern = regexp.MustCompile(`\b404\b`)

// isNotFoundError reports whether err represents an HTTP 404 / "not found"
// response from Keyfactor Command as surfaced by the legacy api.Client
// (github.com/Keyfactor/keyfactor-go-client/v3/api). That client's
// sendRequest doesn't preserve a structured status code on its returned
// error -- for a 404 it returns errors.New(body["Message"]), so callers on
// this code path must pattern-match the error string. This mirrors the
// existing idiom in resource_keyfactor_certificate_store_type.go's Read
// (strings.Contains(err.Error(), "404")), broadened to also catch "not
// found" text, matching resource_keyfactor_certificate_deploy.go's Read.
//
// The "unable to find" / "does not exist" patterns below were confirmed
// against a live Command 25.5.x instance (kfclab) on 2026-08-26 by hitting
// five different endpoints with nonexistent IDs and capturing the actual
// 404 response Message field that sendRequest returns verbatim as the Go
// error (client.go's 404 branch builds a "the requested resource was not
// found" string, but that string is only ever log.Printf'd -- it is never
// the error returned to callers). Observed real Command messages:
//
//   - Security/Roles/999999            -> "Unable to find 'Security Role' with Id '999999'"
//   - CertificateStoreTypes/999999      -> "The certificate store type with StoreType '999999' does not exist."
//   - CertificateStores/{bogus-guid}    -> "Certificate store with id '{bogus-guid}' does not exist."
//   - Certificates/999999999           -> "Unable to find 'Certificate' with Id '999999999'"
//   - Agents/{bogus-guid}               -> "Agent with id of '{bogus-guid}' does not exist"
//
// None of these contain "404" or "not found", so relying on either of
// those alone (as this function once did) is a false negative against
// real Command responses -- "unable to find" and "does not exist" are the
// patterns that actually recur.
//
// Three safeguards keep this from false-positiving on a genuine non-404 error:
//
//  1. sendRequest's decode-failure fallback -- "%d - Unknown error
//     connecting to Keyfactor %s, please check your connection." -- is
//     built the same way for EVERY non-2xx status code and embeds the raw
//     request path, including any numeric resource ID, in %s. A real
//     5xx/gateway error against e.g. "Security/Roles/1404" produces a
//     message containing "404" purely because of the resource ID digits,
//     not because the resource is confirmed gone. Because this shape is
//     definitionally "the body didn't decode, so we don't actually know
//     what happened," it is never treated as a confirmed not-found here,
//     regardless of what status code got embedded in it.
//  2. Absent that fallback shape, "404" is only matched as a standalone
//     status-code token (via notFoundStatusCodePattern's word boundaries),
//     not as a substring of a longer digit run -- so a resource ID like
//     "1404" or "40498" appearing elsewhere in a message can't trigger a
//     false positive either.
//  3. "unable to find" and "does not exist" are themselves specific enough
//     phrases (they're not generic substrings like "404") that they don't
//     require the same digit-boundary treatment.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	lower := strings.ToLower(msg)

	if strings.Contains(lower, "unknown error connecting to keyfactor") {
		return false
	}

	if strings.Contains(lower, "not found") {
		return true
	}

	if strings.Contains(lower, "unable to find") {
		return true
	}

	if strings.Contains(lower, "does not exist") {
		return true
	}

	return notFoundStatusCodePattern.MatchString(msg)
}

// notFoundAgentPattern matches a standalone "agent" token (case-insensitive)
// in an error message. Used only by isAgentMissingNotFoundError, and only
// meaningful after isNotFoundError(err) has already been confirmed true --
// see that function's doc comment for the real observed Command message
// ("Agent with id of '<guid>' does not exist") this exists to recognize.
var notFoundAgentPattern = regexp.MustCompile(`(?i)\bagent\b`)

// isAgentMissingNotFoundError reports whether an error already confirmed by
// isNotFoundError to be a "not found"-shaped error is specifically about a
// missing orchestrator AGENT, rather than about the deployment/store/alias/
// certificate itself being gone.
//
// resource_keyfactor_certificate_deploy.go's Delete() is the one call site
// that needs this disambiguation: removeCertificateAliasFromStore's
// underlying RemoveCertificateFromStores call can fail because the STORE'S
// BACKING ORCHESTRATOR AGENT has been deleted out-of-band (confirmed live
// Command 25.5.x message, kfclab, 2026-08-26: "Agent with id of '<guid>'
// does not exist"), a scenario where the certificate, alias, and store may
// all still exist -- and the certificate may still be physically deployed
// on the target -- but there is no agent left to run the removal job.
// isNotFoundError's "does not exist" pattern matches this message just as
// readily as it matches a genuinely-gone deployment, so that call site
// additionally checks isAgentMissingNotFoundError to avoid treating "the
// agent is gone" as "safe to drop from state," which would otherwise leave
// Terraform believing a still-deployed certificate/key had been cleanly
// removed.
//
// This is deliberately NOT folded into isNotFoundError itself: the other
// two isNotFoundError call sites (resource_keyfactor_security_role.go,
// resource_keyfactor_certificate_store_type.go) are simple single-resource
// GETs where "does not exist" is unambiguous -- there is exactly one thing
// being read, so any not-found error about it is safe to treat as "already
// gone." Only the certificate-deploy Delete() path involves a dependency
// (the agent) that is distinct from the resource being deleted (the
// deployment), so only that call site needs the extra check.
// Open verification gap: notFoundAgentPattern was confirmed against the
// Agents/{id} GET endpoint's real not-found message ("Agent with id of
// '<guid>' does not exist"). The call site that consumes this function
// (resource_keyfactor_certificate_deploy.go's Delete(), via
// removeCertificateAliasFromStore) never calls that endpoint directly --
// it calls GetCertificateContext and RemoveCertificateFromStores instead.
// What Command's real "the deployment itself is genuinely gone" message
// looks like for THAT call path (and whether it happens to contain the
// substring "agent") has not been directly confirmed: no existing VCR
// cassette captures a not-found response from either endpoint, and
// confirming this would require reproducing the condition against a live
// lab. If it turns out to contain "agent", this function would incorrectly
// treat a genuinely-gone deployment as an unsafe-to-remove agent-missing
// case -- an unnecessary hard error, not a data-loss or leak risk, so this
// is left as a known gap rather than blocking on live-lab access to close
// it.
func isAgentMissingNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return notFoundAgentPattern.MatchString(err.Error())
}

// effectiveCertificateFormat normalizes a certificate_format value to the
// effective download format. Empty string and "STORE" both resolve to PEM
// (since the STORE format produces PEM output in the Read path).
func effectiveCertificateFormat(format string) string {
	f := strings.ToUpper(strings.TrimSpace(format))
	if f == "" || f == "STORE" {
		return "PEM"
	}
	return f
}

// determineCertificateIdType determines if the given ID is a certificate Thumbprint or CN.
func determineCertificateIdType(certID string) (thumbprint, commonName string) {
	if len(certID) == CERTIFICATE_THUMBPRINT_LENGTH {
		return certID, ""
	}
	return "", certID
}

// parseSubjectToTfState extracts x509.Subject fields and maps them to the corresponding Terraform state attributes.
func parseSubjectToTfState(cert x509.Certificate) (
	commonName, locality, state, country, organization,
	organizationalUnit types.String,
) {
	// Extract and map Common Name (CN)
	if cert.Subject.CommonName != "" {
		commonName = types.String{Value: cert.Subject.CommonName}
	} else {
		commonName = types.String{Value: "", Null: true}
	}

	// Extract and map Locality (L)
	if len(cert.Subject.Locality) > 0 {
		locality = types.String{Value: strings.Join(cert.Subject.Locality, ",")}
	} else {
		locality = types.String{Value: "", Null: true}
	}

	// Extract and map State (ST)
	if len(cert.Subject.Province) > 0 {
		state = types.String{Value: strings.Join(cert.Subject.Province, ",")}
	} else {
		state = types.String{Value: "", Null: true}
	}

	// Extract and map Country (C)
	if len(cert.Subject.Country) > 0 {
		country = types.String{Value: strings.Join(cert.Subject.Country, ",")}
	} else {
		country = types.String{Value: "", Null: true}
	}

	// Extract and map Organization (O)
	if len(cert.Subject.Organization) > 0 {
		organization = types.String{Value: strings.Join(cert.Subject.Organization, ",")}
	} else {
		organization = types.String{Value: "", Null: true}
	}

	// Extract and map Organizational Unit (OU)
	if len(cert.Subject.OrganizationalUnit) > 0 {
		organizationalUnit = types.String{Value: strings.Join(cert.Subject.OrganizationalUnit, ",")}
	} else {
		organizationalUnit = types.String{Value: "", Null: true}
	}

	return
}

func isRevoked(c *api.GetCertificateResponse) bool {
	if c == nil {
		return false
	}

	switch {
	case c.RevocationComment != "":
		return true
	case c.RevocationEffDate != "":
		return true
	case c.RevocationReason > 0:
		return true
	}

	return false

}

func isExpired(ctx context.Context, c *x509.Certificate) (bool, *string) {
	if c != nil {
		// convert string to date and compare to now
		if c.NotAfter.Before(time.Now()) {
			expDateStr := c.NotAfter.String()
			return true, &expDateStr
		}
	}
	return false, nil
}

func isExpiring(ctx context.Context, c *x509.Certificate, renewalNumberOfDays int) (bool, *string, *int) {
	eligible := false
	tflog.Debug(ctx, "Checking expiration of certificate.")
	var expDateStr *string
	var numDaysRemaining *int
	if c != nil {
		// Determine the expiration threshold date
		//expirationThreshold := time.Now().AddDate(0, 0, renewalNumberOfDays)
		expDate := c.NotAfter.String()
		expDateStr = &expDate
		// Check if the certificate expiration date is before the threshold
		if c.NotAfter.IsZero() {
			tflog.Warn(ctx, "Certificate NotAfter date is zero, cannot determine expiration.")
			return false, nil, nil
		}

		eligible = c.NotAfter.Before(time.Now().AddDate(0, 0, renewalNumberOfDays))

		ctx = tflog.SetField(ctx, "certificate_expiration_eligible", eligible)

		// Calculate the number of days remaining until expiration
		remDays := int(c.NotAfter.Sub(time.Now()).Hours() / 24)
		numDaysRemaining = &remDays

		// Set context fields for logging
		ctx = tflog.SetField(ctx, "certificate_expiration_date", c.NotAfter)
		ctx = tflog.SetField(ctx, "certificate_expiration_date_str", expDateStr)
		ctx = tflog.SetField(ctx, "certificate_expiration_days", renewalNumberOfDays)
		ctx = tflog.SetField(ctx, "certificate_expiration_days_remaining", numDaysRemaining)

		if remDays <= renewalNumberOfDays || remDays <= 0 {
			eligible = true
		}
	}
	tflog.Debug(ctx, "Certificate expiration check completed.")
	return eligible, expDateStr, numDaysRemaining
}

func checkCertDiags(
	ctx context.Context, cert *api.GetCertificateResponse, expWithinDays int,
	leaf *x509.Certificate,
) (revoked bool, expiring bool, expired bool, diags diag.Diagnostics) {
	diags = diag.Diagnostics{}
	if ctx == nil {
		ctx = context.Background()
	}

	tflog.Debug(ctx, "Entered checkCertDiags()")
	if cert == nil {
		diags.AddWarning(
			"Revocation Check Warning",
			"Unable to check if certificate is revoked.",
		)
	} else {
		ctx = tflog.SetField(ctx, "certificate_id", cert.Id)
		ctx = tflog.SetField(ctx, "certificate_cn", cert.IssuedCN)
		ctx = tflog.SetField(ctx, "certificate_dn", cert.IssuedDN)
		ctx = tflog.SetField(ctx, "certificate_thumbprint", cert.Thumbprint)
		ctx = tflog.SetField(ctx, "certificate_revocation_comment", cert.RevocationComment)
		ctx = tflog.SetField(ctx, "certificate_revocation_date", cert.RevocationEffDate)
		ctx = tflog.SetField(ctx, "certificate_revocation_reason", cert.RevocationReason)
		revoked = isRevoked(cert)
		if revoked {
			tflog.Warn(ctx, "Certificate is revoked")
			diags.AddWarning(
				"Certificate Revoked",
				fmt.Sprintf(
					"Certificate '%s' is revoked. Please renew the certificate.", cert.Thumbprint,
				),
			)
			return revoked, expiring, expired, diags
		}
	}

	var expDate *string
	expired, expDate = isExpired(ctx, leaf)
	if expired {
		tflog.Warn(ctx, "Certificate is expired")
		diags.AddWarning(
			"Certificate Expired",
			fmt.Sprintf(
				"Certificate '%s' is expired as of %s. Please renew the certificate.", cert.Thumbprint, *expDate,
			),
		)
		return revoked, expiring, expired, diags
	}

	var remDays *int
	expiring, expDate, remDays = isExpiring(ctx, leaf, expWithinDays)
	if expiring {
		ctx = tflog.SetField(ctx, "expiring_date", *expDate)
		tflog.Warn(ctx, fmt.Sprintf("Certificate is expiring in %d days", *remDays))
		diags.AddWarning(
			"Certificate Expiring Soon",
			fmt.Sprintf(
				"Certificate '%s' is expiring soon on `%s` in `%d` days. Please renew the certificate.",
				cert.Thumbprint,
				*expDate,
				*remDays,
			),
		)
	}

	return revoked, expiring, expired, diags
}

// decodeToPEM decodes a base64-encoded DER blob and returns PEM-encoded certificate(s).
// If the DER contains one or more X.509 certs they will be emitted individually;
// otherwise the raw DER will be emitted inside a single CERTIFICATE PEM block.
func decodeToPEM(b64 string) (string, error) {
	// remove any whitespace/newlines that might be in the input
	clean := strings.Map(
		func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, b64,
	)

	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	var buf bytes.Buffer

	// Try parsing as one or more X.509 certificates
	if certs, err := x509.ParseCertificates(der); err == nil && len(certs) > 0 {
		for _, c := range certs {
			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
				return "", fmt.Errorf("pem encode: %w", err)
			}
		}
		return buf.String(), nil
	}

	// Fallback: emit raw DER in a single CERTIFICATE block
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", fmt.Errorf("pem encode fallback: %w", err)
	}

	return buf.String(), nil
}

// parseAllCerts parses every CERTIFICATE block found in pemData, de-duplicating
// by raw DER. Non-certificate blocks and unparseable certs are skipped.
func parseAllCerts(pemData string) []*x509.Certificate {
	var certs []*x509.Certificate
	seen := make(map[string]bool)
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil || c == nil {
			continue
		}
		key := string(c.Raw)
		if seen[key] {
			continue
		}
		seen[key] = true
		certs = append(certs, c)
	}
	return certs
}

// reselectLeafFromChain re-derives the true end-entity leaf from the combined
// set of certificates (leafPEM + chainPEM). It guards against upstream leaf
// selection that can mis-label a CA/root as the leaf when Keyfactor Command
// returns a chain that is not ordered leaf-first — e.g. the positional
// certificates[0] in api.UnpackPEM, or pkcs12.DecodeChain's last-cert fallback.
//
// The leaf is the certificate whose Subject is not the Issuer of any other cert
// in the set (i.e. nothing in the set is signed by it). This is order-
// independent and matches the go-client's findLeafCert logic for the P7B path.
//
// If a unique leaf cannot be determined (fewer than two certs, all self-signed,
// or the selected leaf already matches the input) the inputs are returned
// unchanged to avoid needless reordering churn.
func reselectLeafFromChain(ctx context.Context, leafPEM, chainPEM string) (string, string) {
	certs := parseAllCerts(leafPEM + chainPEM)
	if len(certs) < 2 {
		return leafPEM, chainPEM
	}

	issuers := make(map[string]bool, len(certs))
	for _, c := range certs {
		issuers[string(c.RawIssuer)] = true
	}

	var leaf *x509.Certificate
	var chain []*x509.Certificate
	for _, c := range certs {
		if leaf == nil && !issuers[string(c.RawSubject)] {
			leaf = c
			continue
		}
		chain = append(chain, c)
	}
	if leaf == nil {
		// Cannot distinguish a leaf (e.g. all certs are self-signed) — leave as-is.
		return leafPEM, chainPEM
	}

	newLeafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	if normalizePEMLineEndings(newLeafPEM) == normalizePEMLineEndings(leafPEM) {
		// Upstream already selected the correct leaf; keep original chain.
		return leafPEM, chainPEM
	}

	tflog.Warn(ctx, fmt.Sprintf(
		"Re-selected leaf certificate from chain: upstream returned a non-leaf (CN now %q, IsCA=%v). "+
			"This guards against non-leaf-first chains from Keyfactor Command.",
		leaf.Subject.CommonName, leaf.IsCA,
	))
	return normalizePEMLineEndings(newLeafPEM), normalizePEMLineEndings(encodeCertificateChain(ctx, chain, 0))
}

func parseLeafCert(ctx context.Context, leafPEM string) (*x509.Certificate, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	// check if is in base64 format and decode if so
	decoded, decodeErr := base64.StdEncoding.DecodeString(leafPEM)
	if decodeErr == nil && len(decoded) > 0 {
		leafPEM, decodeErr = decodeToPEM(leafPEM)
		if decodeErr == nil {
			leaf, err := x509.ParseCertificate(
				decoded,
			)
			if err == nil && leaf != nil {
				tflog.Debug(ctx, "Leaf certificate was base64-encoded DER, successfully decoded.")
				return leaf, diags
			}
		}
	}

	block, extra := pem.Decode([]byte(leafPEM))
	if block == nil && extra == nil {
		diags.AddError(
			"PEM Decoding Failed",
			"Failed to decode the PEM-encoded certificate.",
		)
		return nil, diags
	} else if block == nil {
		tflog.Warn(
			ctx,
			"Certificate PEM is missing a block header, and contains extra data. Attempting to decode the extra data.",
		)
		block, _ = pem.Decode(extra)
	}
	if block == nil {
		diags.AddError(
			"PEM Decoding Failed",
			"Failed to decode the PEM-encoded certificate.",
		)
		return nil, diags
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		diags.AddError(
			"Certificate Parsing Failed",
			fmt.Sprintf("Failed to parse the certificate: %s", err.Error()),
		)
		return nil, diags
	} else if leaf == nil {
		diags.AddError(
			"Certificate Parsing Error",
			"Failed to parse the certificate",
		)
		return nil, diags
	}
	return leaf, diags
}

func forceIfTrue(ctx context.Context, state attr.Value, config attr.Value, path path.Path) (bool, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	planVal, err := config.ToTerraformValue(ctx)
	if err != nil {
		diags.AddError(
			"Value conversion error",
			"Unable to convert value to bool",
		)
	}

	var forceRenewal bool
	convErr := planVal.As(&forceRenewal)
	if convErr != nil {
		diags.AddError(
			"Value conversion error",
			"Unable to convert value to bool",
		)
		return false, diags
	}

	if forceRenewal {
		return true, diags
	}

	return false, diags
}

// The v1 APIClient exposes a method to query security claims by type and value. To retrieve a unique security claim from Command
// it is required to also find a claim with the matching authentication scheme, which is not queryable via the QueryString parameter. That must be done as a separate
// operation from the API call. This function will query the security claims by type and value, then filter the results by the authentication scheme to return a unique claim if it exists.
func getSecurityClaimByTypeAndValueAndScheme(
	ctx context.Context,
	apiClient *keyfactor.APIClient,
	claimType string,
	claimValue string,
	authenticationScheme string,
) (*kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse, error) {
	tflog.Debug(
		ctx,
		fmt.Sprintf(
			"Getting security claim from remote source. ClaimType: %s, ClaimValue: %s, AuthenticationScheme: %s",
			claimType,
			claimValue,
			authenticationScheme,
		),
	)

	claimTypeEnum, err := kfv1.ParseCSSCMSCoreEnumsClaimType(claimType)
	if err != nil {
		return nil, err
	}

	tflog.Debug(ctx, fmt.Sprintf("Claim type %s has been parsed to %d", claimType, *claimTypeEnum))

	api := apiClient.V1.SecurityClaimsApi
	req := api.
		NewGetSecurityClaimsRequest(ctx).
		QueryString(fmt.Sprintf("((ClaimValue -eq \"%s\" and ClaimType -eq %d))", claimValue, *claimTypeEnum))

	response, _, err := api.GetSecurityClaimsExecute(req)

	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("No security claim found with claimType %s and claimValue %s", claimType, claimValue)
	}

	var result *kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse

	for _, claim := range response {
		if claim.Provider != nil && claim.Provider.AuthenticationScheme.Get() != nil && *claim.Provider.AuthenticationScheme.Get() == authenticationScheme {
			result = &claim
			break
		}
	}

	if result == nil {
		return nil, fmt.Errorf(
			"No security claim found with claimType %s and claimValue %s and authenticationScheme %s",
			claimType,
			claimValue,
			authenticationScheme,
		)
	}

	return result, nil
}

// The v2 APIClient exposes a method to query a role by name.  This function will query the security roles and filter security roles by name.
func getSecurityRoleByName(
	ctx context.Context,
	apiClient *keyfactor.APIClient,
	roleName string,
) (*kfv2.SecuritySecurityRolesSecurityRoleQueryResponse, error) {
	tflog.Debug(ctx, fmt.Sprintf("Getting security role from remote source. Role Name: %s", roleName))

	api := apiClient.V2.SecurityRolesApi
	req := api.
		NewGetSecurityRolesRequest(ctx).
		QueryString(fmt.Sprintf("((Name -eq \"%s\"))", roleName))

	response, _, err := req.Execute()

	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("No security role found with name %s", roleName)
	}

	// Command should not allow multiple security roles with the same name. Not going to code logic around multiple results.

	return &response[0], nil
}

// Queries security permissions by name and returns the first matching permission set.
func getSecurityPermissionSetByName(
	ctx context.Context,
	apiClient *keyfactor.APIClient,
	permissionSetName string,
) (*kfv1.PermissionSetsPermissionSetResponse, error) {
	tflog.Debug(
		ctx,
		fmt.Sprintf("Getting permission set ID by name from remote source. Permission set name: %s", permissionSetName),
	)

	api := apiClient.V1.PermissionSetApi
	var model *kfv1.PermissionSetsPermissionSetResponse
	pageNumber := 1
	for model == nil {
		tflog.Debug(ctx, fmt.Sprintf("Querying permission set page %d", pageNumber))
		permissionSets, _, err := api.NewGetPermissionSetsRequest(ctx).ReturnLimit(50).PageReturned(int32(pageNumber)).Execute()

		if err != nil {
			return nil, fmt.Errorf("failed to query permission sets: %w", err)
		}

		if len(permissionSets) == 0 {
			return nil, fmt.Errorf("no permissions were found with name %s", permissionSetName)
		}

		pageNumber++

		for _, permission := range permissionSets {
			// Check if the permission set name matches the requested name
			if permission.Name.Get() != nil && *permission.Name.Get() == permissionSetName {
				tflog.Debug(ctx, fmt.Sprintf("Found permission set with name: %s", permissionSetName))
				model = &permission
				break
			}
		}
	}

	tflog.Debug(ctx, fmt.Sprintf("Found permission set with matching name %s. ID: %s", permissionSetName, *model.Id))

	return model, nil
}

// Returns a pointer to the input object
func ptr[T any](v T) *T {
	return &v
}

// Converts a pointer to a string to a types.String object.
// If the pointer is nil, it returns a types.String with Null set to true.
func getStringType(value *string) types.String {
	if value == nil {
		return types.String{Value: "", Null: true}
	}
	return types.String{Value: *value}
}

// derefOrEmpty dereferences a *string, returning "" for a nil pointer. Use
// this wherever code needs a plain Go string from an SDK-nullable field and
// has no use for the Null flag -- e.g. building an SDK request DTO with a
// plain (non-nullable) string field. A raw `*value` on a field the server
// can legitimately return as null (Name/Description/PermissionSetId on a
// security role response, for example) panics the whole provider process.
func derefOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// Gets Terraform plan for a given resource type. If there's an error retrieving the state, an error is appended to diagnostics.
func getPlan[T any](ctx context.Context, plan *tfsdk.Plan, diagnostics *diag.Diagnostics) (*T, bool) {
	var result T
	diags := plan.Get(ctx, &result)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return nil, false
	}
	return &result, true
}

// Gets Terraform state for a given resource type. If there's an error retrieving the state, an error is appended to diagnostics.
func getState[T any](ctx context.Context, state *tfsdk.State, diagnostics *diag.Diagnostics) (*T, bool) {
	var result T
	diags := state.Get(ctx, &result)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return nil, false
	}
	return &result, true
}

// Gets a data source from the config. If there's an error retrieving the configuration, an error is appended to diagnostics.
func getDataSource[T any](ctx context.Context, config *tfsdk.Config, diagnostics *diag.Diagnostics) (*T, bool) {
	var result T
	diags := config.Get(ctx, &result)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return nil, false
	}
	return &result, true
}

// Updates Terraform state with provided result type. If there's an error, it appends to diagnostics.
func updateState[T any](ctx context.Context, state *tfsdk.State, diagnostics *diag.Diagnostics, result T) bool {
	diags := state.Set(ctx, result)
	diagnostics.Append(diags...)
	return diagnostics.HasError()
}

// Determines if the provider has been configured. If not, adds an error to the diagnostics.
func checkIfProviderIsConfigured(provider provider, diagnostics *diag.Diagnostics) bool {
	if !provider.configured {
		diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return false
	}
	return true
}

func getResourceIdFromTerraformState(state *terraform.State, resourcePath string) (string, error) {
	// Use the known resource path to construct the import ID
	rs, ok := state.RootModule().Resources[resourcePath]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return rs.Primary.Attributes["id"], nil
}

// stringContains
// checks if a string slice contains a specific string.
func stringContains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

// convertStringArrayToTerraform converts a slice of strings to a slice of Terraform attr.Value objects.
func convertStringArrayToTerraform(options []string) []attr.Value {
	var output []attr.Value
	for _, option := range options {
		output = append(output, types.String{Value: option})
	}
	return output
}

// convertIntArrayToTerraform converts a slice of integers (int, int32, int64) to a slice of Terraform attr.Value objects.
func convertIntArrayToTerraform(lengths any) []attr.Value {
	var result []attr.Value
	if lengths != nil {
		switch v := lengths.(type) {
		case []int:
			for _, length := range v {
				result = append(result, types.Int64{Value: int64(length)})
			}
		case []int32:
			for _, length := range v {
				result = append(result, types.Int64{Value: int64(length)})
			}
		case []int64:
			for _, length := range v {
				result = append(result, types.Int64{Value: length})
			}
		}
	}
	return result
}

// normalizeSerialNumber converts a serial number to a canonical uppercase hex format.
// It handles both hex strings (from the Keyfactor API) and decimal strings (from big.Int.String()).
func normalizeSerialNumber(sn string) string {
	if sn == "" || sn == "<nil>" {
		return ""
	}

	// Strip any separators like colons or spaces
	cleaned := strings.ReplaceAll(strings.ReplaceAll(sn, ":", ""), " ", "")

	// Check if the string contains any hex letter characters (a-f, A-F).
	// If it does, it's unambiguously a hex string.
	hasHexLetters := strings.ContainsAny(cleaned, "abcdefABCDEF")

	if hasHexLetters {
		// Validate it's actually valid hex
		if _, err := hex.DecodeString(cleaned); err == nil && len(cleaned)%2 == 0 {
			return strings.ToUpper(cleaned)
		}
	}

	// Try to parse as decimal (big.Int.String() output or digit-only serial)
	n := new(big.Int)
	if _, ok := n.SetString(cleaned, 10); ok {
		return strings.ToUpper(fmt.Sprintf("%X", n))
	}

	// Fallback for hex strings with odd length or other edge cases
	if _, err := hex.DecodeString(cleaned); err == nil {
		return strings.ToUpper(cleaned)
	}

	// Last resort: return uppercased as-is
	return strings.ToUpper(sn)
}

// normalizeThumbprint normalizes a certificate thumbprint to lowercase hex.
func normalizeThumbprint(tp string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(tp, ":", ""), " ", ""))
}

// lookupContainerNameByID resolves a certificate store container/application
// name from its numeric ID. Uses the by-ID endpoint (single record fetch) so
// it works for newly-created containers that haven't appeared on the first
// page of the paginated list endpoint yet. Returns "" when containerId is 0.
//
// The Keyfactor Command API and the SDK wrapping it do not expose a
// structured "not found" sentinel distinct from other errors (a 404 is
// collapsed into a plain error string alongside network/permission/5xx
// failures — see keyfactor-go-client's client.go response handling), so this
// function cannot definitively tell "the container was deleted" apart from
// "the lookup failed for an unrelated, possibly transient reason." Given that
// ambiguity, an erroring by-ID lookup is NOT treated as proof the container is
// gone: it is retried once against the paginated list endpoint (a second,
// independent code path) before giving up. Only if both lookups fail does the
// function fall back to hint (e.g. the previously-resolved name from state).
//
// This matters because callers write the returned value into
// container_name/application_name state via syncApplicationAndContainerName.
// A single transient failure with an empty hint (the case on the very first
// Read() after an out-of-band container assignment, when state never held a
// name to fall back to — see GH issue #175) would otherwise permanently null
// out the name fields even though container_id correctly reflects a real
// assignment. Note that nulling the *name* fields here is a cosmetic
// annoyance, not data loss on its own — Update()'s containerId resolution
// (resolveContainerAssignmentForUpdate) is the load-bearing safeguard against
// actually clearing the assignment server-side; this function only reduces
// how often the cosmetic drift happens.
func lookupContainerNameByID(ctx context.Context, client *api.Client, containerId int, hint string) string {
	if containerId == 0 {
		return ""
	}
	if client == nil {
		return hint
	}

	container, err := client.GetStoreContainer(containerId)
	if err == nil && container != nil && container.Name != "" {
		return container.Name
	}
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to resolve container name for ID %d via by-ID lookup: %s — retrying via the list endpoint before falling back to hint %q", containerId, err.Error(), hint))
	}

	if containers, listErr := client.GetStoreContainers(); listErr == nil && containers != nil {
		for _, c := range *containers {
			if c.Id != nil && *c.Id == containerId && c.Name != "" {
				return c.Name
			}
		}
	} else if listErr != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to resolve container name for ID %d via list-endpoint fallback: %s — falling back to hint %q", containerId, listErr.Error(), hint))
	}

	if hint == "" {
		tflog.Warn(ctx, fmt.Sprintf("Could not resolve a name for container ID %d and no prior state value is available; container_name/application_name will read as null this cycle even though container_id (%d) is real. The underlying container/application assignment itself is not affected by this.", containerId, containerId))
	}
	return hint
}
