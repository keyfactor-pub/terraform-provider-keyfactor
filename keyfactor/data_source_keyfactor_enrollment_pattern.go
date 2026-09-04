package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// allowedEnrollmentTypesPtrToTfInt64 converts the legacy keyfactor-go-client
// v3 API model's *int AllowedEnrollmentTypes field to types.Int64, guarding
// against a nil pointer the same way every other pointer field in
// dataSourceEnrollmentPattern.Read is already guarded (pattern.Template,
// pattern.AssociatedRoles, pattern.CertificateAuthorities, pattern.Regexes,
// pattern.MetadataFields, pattern.Defaults, pattern.EnrollmentFields,
// pattern.Policies). AllowedEnrollmentTypes is nil whenever Command omits
// the key from the response -- a real, reachable case, since the
// corresponding resource attribute (allowed_enrollment_types) is
// Optional+Computed, i.e. explicitly designed to be left unset. Without this
// guard, dereferencing the nil pointer panics on every `terraform plan`/
// `refresh` against such a pattern.
func allowedEnrollmentTypesPtrToTfInt64(v *int) types.Int64 {
	if v == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(*v), Null: isNullId(*v)}
}

// enrollmentPatternCandidate is the minimal (ID, Name) shape
// enrollmentPatternResolveIdentifier needs from each pattern returned by
// GetEnrollmentPatterns, factored out so the resolver can be unit tested
// without depending on the full legacy v3 API response type.
type enrollmentPatternCandidate struct {
	ID   int
	Name string
}

// enrollmentPatternResolveIdentifier resolves the user-supplied `identifier`
// attribute (documented as accepting either the pattern's name or its
// internal ID) against every candidate pattern at once, using name-or-ID
// semantics:
//
//   - An exact NAME match wins deterministically.
//   - A canonical ID-string match (fmt.Sprint(id) == identifier) is the
//     fallback -- deliberately NOT strconv.Atoi-based, so "007" never
//     matches ID 7 (only the literal string "7" does).
//   - If a genuine name match exists for one pattern AND a genuine
//     canonical-ID match exists for a DIFFERENT pattern, that is
//     ambiguous: return an error identifying both candidates rather than
//     silently picking one.
//
// This replaces two earlier, narrower designs, in order:
//  1. A plain "name == identifier OR id == identifier" OR,
//     with no priority between them, letting "first match wins" list
//     order silently resolve to the wrong pattern when both a name match
//     and a different ID match existed.
//  2. A strconv.Atoi-gated ID-only-or-name-only priority:
//     if identifier parses as an integer, match ONLY on ID, otherwise
//     match ONLY on name. That over-corrected: a pattern literally named
//     "2025" became unreachable (or worse, silently resolved to a
//     DIFFERENT pattern whose ID happens to be 2025) purely because its
//     name looks numeric, and "007" would resolve by parsed value to ID
//     7 even though no pattern is literally named "007" is being asked
//     for by ID at all.
//
// Returns the resolved candidate's index into candidates, or -1 with a
// descriptive error if identifier matches no candidate or is ambiguous
// between two different ones.
func enrollmentPatternResolveIdentifier(identifier string, candidates []enrollmentPatternCandidate) (int, error) {
	nameMatch := -1
	idMatch := -1
	for i, c := range candidates {
		if nameMatch == -1 && c.Name == identifier {
			nameMatch = i
		}
		if idMatch == -1 && fmt.Sprint(c.ID) == identifier {
			idMatch = i
		}
	}

	switch {
	case nameMatch == -1 && idMatch == -1:
		return -1, fmt.Errorf("could not find enrollment pattern with name or ID: %s", identifier)
	case nameMatch != -1 && idMatch != -1 && nameMatch != idMatch:
		return -1, fmt.Errorf(
			"identifier %q is ambiguous: it matches pattern %q (ID %d) by name, and pattern %q (ID %d) by ID; "+
				"rename one of them, or use the internal ID of the one you intend to look up",
			identifier, candidates[nameMatch].Name, candidates[nameMatch].ID, candidates[idMatch].Name, candidates[idMatch].ID,
		)
	case nameMatch != -1:
		return nameMatch, nil
	default:
		return idMatch, nil
	}
}

type dataSourceEnrollmentPatternType struct{}

func (r dataSourceEnrollmentPatternType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "The name or internal ID (integer) of the enrollment pattern to look up. An exact name match takes precedence; otherwise this value is matched against the pattern's internal ID as a decimal string (so \"007\" never matches ID 7). A value that matches a different pattern by name than by ID returns an error rather than silently picking one.",
			},
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the ID of the enrollment pattern in Keyfactor Command.",
			},
			"name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the Keyfactor Command reference name of the enrollment pattern.",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the Keyfactor Command description of the enrollment pattern.",
			},
			"template": {
				Type: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"id":                   types.Int64Type,
						"template_name":        types.StringType,
						"common_name":          types.StringType,
						"configuration_tenant": types.StringType,
						"requires_approval":    types.BoolType,
						"friendly_name":        types.StringType,
					},
				},
				Computed:    true,
				Description: "An object containing information for the template associated with the enrollment pattern.",
			},
			"template_default": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean indicating whether this enrollment pattern is the default pattern for the associated template (true) or not (false). A certificate template can have only one default enrollment pattern, which is required for the template to be used for enrollment. If no other enrollment pattern for the template exists or is marked as default, this option will automatically be enabled when a new pattern is created.",
			},
			"use_ad_permissions": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean indicating whether Active Directory permissions should be used for certificate enrollment authorization (true) or whether Keyfactor Command security roles should be used (false). If set to false, at least one value must be provided for AssociatedRoles.",
			},
			"associated_roles": {
				Type: types.ListType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":   types.Int64Type,
							"name": types.StringType,
						},
					},
				},
				Computed:    true,
				Description: "An array of objects indicating the security roles associated with the enrollment pattern. Only users holding ones of these roles will be able to use the enrollment pattern if UseADPermissions is false.",
			},
			"certificate_authorities": {
				Type: types.ListType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":                   types.Int64Type,
							"logical_name":         types.StringType,
							"host_name":            types.StringType,
							"configuration_tenant": types.StringType,
						},
					},
				},
				Computed: true,
				Description: "An array of objects indicating the certificate authorities to which the enrollment" +
					" pattern is restricted, if applicable (see the RestrictCAs parameter).",
			},
			"allowed_enrollment_types": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the type of enrollment allowed for the enrollment pattern. Setting these options causes the enrollment pattern to appear in dropdowns in the corresponding section of the Management Portal. In the case of CSR Enrollment and PFX Enrollment, the enrollment patterns only appear in dropdowns on the enrollment pages if they are available for enrollment from a CA also configured for enrollment within Keyfactor Command. See HTTPS CAs - Enrollment Section or DCOM CAs - Enrollment Section for more information.",
			},
			"regexes": {
				Type: types.ListType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"subject_part":   types.StringType,
							"regex":          types.StringType,
							"error":          types.StringType,
							"case_sensitive": types.BoolType,
						},
					},
				},
				Computed:    true,
				Description: "An array of objects containing regular expressions specific to an individual enrollment pattern, used to validate the subject data. Regular expressions defined on an enrollment pattern apply to enrollments made with that enrollment pattern only. Regular expressions defined for enrollment patterns take precedence over system-wide regular expressions.",
			},
			"metadata_fields": {
				Type: types.ListType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"metadata_id":    types.Int64Type,
							"default_value":  types.StringType,
							"validation":     types.StringType,
							"enrollment":     types.Int64Type,
							"message":        types.StringType,
							"case_sensitive": types.BoolType,
						},
					},
				},
				Computed:    true,
				Description: "An array of objects containing metadata field settings specific to an individual enrollment pattern.",
				MarkdownDescription: `
An array of objects containing metadata field settings specific to an individual enrollment pattern. These metadata field configurations can override global metadata field configurations in these possible ways:

- Configuration on the metadata field of required, optional or hidden.
- The default value for the metadata field.
- A regular expression defined for the field (string fields only) against which entered data will be validated along with its associated message.
- For fields of data type multiple choice, the list of values that appear in multiple choice dropdowns.

Metadata field settings defined on an enrollment pattern apply to enrollments made with that enrollment pattern only and take precedence over global-level metadata field settings.
`,
			},
			"restrict_cas": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean indicating whether the enrollment pattern should be restricted to use with a specified list of certificate authorities (true) or not (false). If set to true, at least one CA must be configured using the CertificateAuthorities parameter.",
			},
			"policies": {
				Type: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"allow_key_reuse":                     types.BoolType,
						"allow_wildcards":                     types.BoolType,
						"rfc_enforcement":                     types.BoolType,
						"certificate_owner_role":              types.Int64Type,
						"default_certificate_owner_role_id":   types.Int64Type,
						"default_certificate_owner_role_name": types.StringType,
						"default_certificate_owner_override":  types.BoolType,
						"primary_key_algorithms": types.ListType{
							ElemType: types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"name":        types.StringType,
									"bit_lengths": types.ListType{ElemType: types.Int64Type},
									"curves":      types.ListType{ElemType: types.StringType},
								},
							},
						},
						"alternative_key_algorithms": types.ListType{
							ElemType: types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"name":        types.StringType,
									"bit_lengths": types.ListType{ElemType: types.Int64Type},
									"curves":      types.ListType{ElemType: types.StringType},
								},
							},
						},
					},
				},
				Computed:    true,
				Description: "An object containing the individual policy settings for the enrollment pattern. Policies defined on an enrollment pattern apply to enrollments made with that enrollment pattern only and take precedence over system-wide policies. For more information about system-wide enrollment pattern policies, see GET Enrollment Patterns Settings.",
			},
			"defaults": {
				Type: types.ListType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"subject_part": types.StringType,
							"value":        types.StringType,
						},
					},
				},
				Computed: true,
				Description: "An array of objects containing default subject settings specific to an individual" +
					" enrollment pattern. Default subjects defined on an enrollment pattern apply to enrollments made with that enrollment pattern only and take precedence over system-wide default subject settings. For more information about system-wide defaults, see GET Enrollment Patterns Settings",
			},
			"enrollment_fields": {
				Type: types.ListType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":               types.Int64Type,
							"name":             types.StringType,
							"default_value":    types.StringType,
							"validation":       types.StringType,
							"enrollment":       types.Int64Type,
							"message":          types.StringType,
							"options":          types.ListType{ElemType: types.StringType},
							"depends_on":       types.StringType,
							"depends_on_value": types.StringType,
							"data_type":        types.Int64Type,
							"hint":             types.StringType,
						},
					},
				},
				Computed:    true,
				Description: "List of enrollment fields for the enrollment pattern.",
				MarkdownDescription: `
An object containing custom enrollment fields. These are configured for each enrollment pattern to allow you to submit custom fields with CSR enrollments and PFX enrollments, supplying custom request attributes to the CA during the enrollment process. This functionality offers benefits such as:

- Preventing users from requesting invalid certificates, based on your specific certificate requirements per enrollment pattern.
- Providing additional information to the CA with the CSR.

Once created for the enrollment pattern, these values are shown in Keyfactor Command on the PFX and CSR enrollment pages in the Additional Enrollment Fields section. The fields are mandatory during enrollment. The data will appear on the CA / Issued Certificates attribute tab for certificates enrolled with an enrollment pattern configured with Keyfactor Command enrollment fields.

**Note:** These are not metadata fields, so they are not stored in the Keyfactor Command database, but simply passed through to the CA. The CA in turn could, via a gateway or policy module, use this data to perform required actions.
`,
			},
		},
		MarkdownDescription: `
Reads an existing enrollment pattern from Keyfactor Command using the "/EnrollmentPatterns" API.

~> **Note:** The enrollment pattern can be identified by its name or internal ID. An exact name match takes precedence; otherwise ` + "`identifier`" + ` is matched against the pattern's internal ID as a decimal string (so ` + "`\"007\"`" + ` never matches ID 7). A value that matches a different pattern by name than by ID returns an error.

Enrollment patterns in Keyfactor Command provide a flexible way to streamline certificate enrollment by defining default values, policies, and access configurations for specific certificate templates and certificate authorities. This functionality helps reduce duplication of templates at the CA level while meeting diverse business requirements.

~> **Important:** Enrollment Patterns are only available in Keyfactor Command v25.0+

For full information on enrollment patterns view the [product documentation](https://software.keyfactor.com/Core-OnPrem/v25.3/Content/ReferenceGuide/Enrollment-Pattern-Operations.htm?Highlight=enrollment%20pattern)
`,
	}, nil
}

func (r dataSourceEnrollmentPatternType) NewDataSource(ctx context.Context, p tfsdk.Provider) (
	tfsdk.DataSource,
	diag.Diagnostics,
) {
	return dataSourceEnrollmentPattern{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceEnrollmentPattern struct {
	p provider
}

func (r dataSourceEnrollmentPattern) Read(
	ctx context.Context,
	request tfsdk.ReadDataSourceRequest,
	response *tfsdk.ReadDataSourceResponse,
) {
	var state CertificateEnrollmentPattern
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on enrollment pattern data source")
	patternName := state.Identifier.Value
	tflog.SetField(ctx, "pattern_name", patternName)

	enrollmentPatterns, err := r.p.client.GetEnrollmentPatterns()

	if err != nil {
		response.Diagnostics.AddError(
			"Error listing enrollment patterns from Keyfactor.",
			"Error reading enrollment patterns: "+err.Error(),
		)
		return
	}

	var result CertificateEnrollmentPattern
	found := false

	ctx = tflog.SetField(ctx, "pattern_identifier", patternName)
	tflog.Debug(ctx, "Searching for enrollment pattern by name or ID")

	// Resolve identifier against ALL candidates up
	// front, using name-or-ID semantics (see
	// enrollmentPatternResolveIdentifier's doc comment) -- an exact name
	// match wins deterministically; a canonical ID-string match
	// (fmt.Sprint(id) == identifier, so "007" never matches ID 7) is the
	// fallback; a genuine match on BOTH for two DIFFERENT patterns is an
	// error, not a silent pick. This replaces the previous strict
	// ID-only-or-name-only priority, which made a pattern
	// named e.g. "2025" unreachable (or worse, silently resolved to a
	// different pattern with ID 2025) purely because its name happened to
	// look numeric.
	candidates := make([]enrollmentPatternCandidate, len(enrollmentPatterns))
	for i, p := range enrollmentPatterns {
		candidates[i] = enrollmentPatternCandidate{ID: p.ID, Name: p.Name}
	}
	matchedIdx, resolveErr := enrollmentPatternResolveIdentifier(patternName, candidates)
	if resolveErr != nil {
		response.Diagnostics.AddError("Enrollment pattern not found", resolveErr.Error())
		return
	}

	for i, pattern := range enrollmentPatterns {
		tflog.Debug(ctx, fmt.Sprintf("Checking enrollment pattern: ID=%d, Name=%q", pattern.ID, pattern.Name))
		if i == matchedIdx {
			tflog.Info(ctx, fmt.Sprintf("Found enrollment pattern with name: %q", patternName))

			// Map the enrollment pattern data to the result
			result = CertificateEnrollmentPattern{
				Identifier:  state.Identifier,
				ID:          types.Int64{Value: int64(pattern.ID)},
				Name:        types.String{Value: pattern.Name},
				Description: types.String{Value: pattern.Description},
			}

			if pattern.Template != nil {
				tflog.Debug(
					ctx, fmt.Sprintf(
						"Enrollment pattern %q has template ID: %d", patternName,
						pattern.Template.Id,
					),
				)
				patternTemplate := *pattern.Template
				result.Template = &EnrollmentPatternTemplate{
					Id: types.Int64{
						Value: int64(patternTemplate.Id),
						Null:  isNullId(patternTemplate.Id),
					},
					TemplateName: types.String{
						Value: patternTemplate.TemplateName,
						Null:  isNullString(patternTemplate.TemplateName),
					},
					CommonName: types.String{
						Value: patternTemplate.CommonName,
						Null:  isNullString(patternTemplate.CommonName),
					},
					ConfigurationTenant: types.String{
						Value: patternTemplate.ConfigurationTenant,
						Null:  isNullString(patternTemplate.ConfigurationTenant),
					},
					RequiresApproval: types.Bool{
						Value: patternTemplate.RequiresApproval,
					},
					FriendlyName: types.String{
						Value: patternTemplate.FriendlyName,
						Null:  isNullString(patternTemplate.FriendlyName),
					},
				}
			}

			result.TemplateDefault = types.Bool{Value: pattern.TemplateDefault}
			result.UseADPermissions = types.Bool{Value: pattern.UseADPermissions}
			result.AllowedEnrollmentTypes = allowedEnrollmentTypesPtrToTfInt64(pattern.AllowedEnrollmentTypes)
			result.RestrictCAs = types.Bool{Value: pattern.RestrictCAs}

			// Associated Roles
			result.AssociatedRoles = &[]EnrollmentPatternAssociatedRole{}
			if pattern.AssociatedRoles != nil && len(pattern.AssociatedRoles) > 0 {
				tflog.Debug(ctx, "Handling associated roles")
				var assocRoles []EnrollmentPatternAssociatedRole
				for _, role := range pattern.AssociatedRoles {
					assocRoles = append(
						assocRoles, EnrollmentPatternAssociatedRole{
							Id: types.Int64{
								Value: int64(role.Id),
								Null:  isNullId(role.Id),
							},
							Name: types.String{
								Value: role.Name,
								Null:  isNullString(role.Name),
							},
						},
					)
				}
				result.AssociatedRoles = &assocRoles
			}

			// Certificate Authorities
			result.CertificateAuthorities = &[]EnrollmentPatternCA{}
			if pattern.CertificateAuthorities != nil && len(pattern.CertificateAuthorities) > 0 {
				tflog.Debug(ctx, "Handling certificate authorities")
				var cas []EnrollmentPatternCA
				for _, ca := range pattern.CertificateAuthorities {
					cas = append(
						cas, EnrollmentPatternCA{
							Id: types.Int64{
								Value: int64(ca.Id),
								Null:  isNullId(ca.Id),
							},
							LogicalName: types.String{
								Value: ca.LogicalName,
								Null:  isNullString(ca.LogicalName),
							},
							HostName: types.String{
								Value: ca.HostName,
								Null:  isNullString(ca.HostName),
							},
							ConfigurationTenant: types.String{
								Value: ca.ConfigurationTenant,
								Null:  isNullString(ca.ConfigurationTenant),
							},
						},
					)
				}
				result.CertificateAuthorities = &cas
			}

			// Regexes
			result.Regexes = &[]EnrollmentPatternRegexes{}
			if pattern.Regexes != nil && len(pattern.Regexes) > 0 {
				tflog.Debug(ctx, "Handling regexes")
				var regexes []EnrollmentPatternRegexes
				for _, regex := range pattern.Regexes {
					regexes = append(
						regexes, EnrollmentPatternRegexes{
							SubjectPart: types.String{
								Value: regex.SubjectPart,
								Null:  isNullString(regex.SubjectPart),
							},
							Regex: types.String{
								Value: regex.Regex,
								Null:  isNullString(regex.Regex),
							},
							Error: types.String{
								Value: regex.Error,
								Null:  isNullString(regex.Error),
							},
							CaseSensitive: types.Bool{
								Value: regex.CaseSensitive,
							},
						},
					)
				}
				result.Regexes = &regexes
			}

			// Metadata Fields
			result.MetadataFields = &[]EnrollmentPatternMetadataField{}
			if pattern.MetadataFields != nil && len(pattern.MetadataFields) > 0 {
				tflog.Debug(ctx, "Handling metadata fields")
				var metadataFields []EnrollmentPatternMetadataField
				for _, field := range pattern.MetadataFields {
					metadataFields = append(
						metadataFields, EnrollmentPatternMetadataField{
							MetadataId: types.Int64{
								Value: int64(field.MetadataId),
								Null:  isNullId(field.MetadataId),
							},
							DefaultValue: types.String{
								Value: field.DefaultValue,
								Null:  isNullString(field.DefaultValue),
							},
							Validation: types.String{
								Value: field.Validation,
								Null:  isNullString(field.Validation),
							},
							Enrollment: types.Int64{
								Value: int64(field.Enrollment),
								Null:  isNullId(field.Enrollment),
							},
							Message: types.String{
								Value: field.Message,
								Null:  isNullString(field.Message),
							},
							CaseSensitive: types.Bool{
								Value: field.CaseSensitive,
							},
						},
					)
				}
				result.MetadataFields = &metadataFields
			}

			// Defaults
			result.Defaults = &[]EnrollmentPatternDefault{}
			if pattern.Defaults != nil && len(pattern.Defaults) > 0 {
				tflog.Debug(ctx, "Handling defaults")
				var epDefaults []EnrollmentPatternDefault
				for _, def := range pattern.Defaults {
					epDefaults = append(
						epDefaults, EnrollmentPatternDefault{
							SubjectPart: types.String{
								Value: def.SubjectPart,
								Null:  isNullString(def.SubjectPart),
							},
							Value: types.String{
								Value: def.Value,
								Null:  isNullString(def.Value),
							},
						},
					)
				}
				result.Defaults = &epDefaults
			}

			// Enrollment Fields
			result.EnrollmentFields = &[]EnrollmentPatternField{}
			if pattern.EnrollmentFields != nil && len(pattern.EnrollmentFields) > 0 {
				tflog.Debug(ctx, "Handling enrollment fields")
				var erFields []EnrollmentPatternField
				for _, field := range pattern.EnrollmentFields {
					erFields = append(
						erFields, EnrollmentPatternField{
							Id: types.Int64{
								Value: int64(field.Id),
								Null:  isNullId(field.Id),
							},
							Name: types.String{
								Value: field.Name,
								Null:  isNullString(field.Name),
							},
							DefaultValue: types.String{
								Value: field.DefaultValue,
								Null:  isNullString(field.DefaultValue),
							},
							Validation: types.String{
								Value: field.Validation,
								Null:  isNullString(field.Validation),
							},
							Enrollment: types.Int64{
								Value: int64(field.Enrollment),
								Null:  isNullId(field.Enrollment),
							},
							Message: types.String{
								Value: field.Message,
								Null:  isNullString(field.Message),
							},
							Options: types.List{
								ElemType: types.StringType,
								Elems:    convertStringArrayToTerraform(field.Options),
								Null:     len(field.Options) == 0,
							},
							DependsOn: types.String{
								Value: field.DependsOn,
								Null:  isNullString(field.DependsOn),
							},
							DependsOnValue: types.String{
								Value: field.DependsOnValue,
								Null:  isNullString(field.DependsOnValue),
							},
							DataType: types.Int64{
								Value: int64(field.DataType),
								Null:  isNullId(field.DataType),
							},
							Hint: types.String{
								Value: field.Hint,
								Null:  isNullString(field.Hint),
							},
						},
					)
				}
				result.EnrollmentFields = &erFields
			}

			// Policies
			result.Policies = &EnrollmentPatternPolicyResponse{}
			if pattern.Policies != nil {
				tflog.Debug(ctx, "Handling policies")
				var policies = EnrollmentPatternPolicyResponse{
					AllowKeyReuse:  types.Bool{Value: pattern.Policies.AllowKeyReuse},
					AllowWildcards: types.Bool{Value: pattern.Policies.AllowWildcards},
					RFCEnforcement: types.Bool{Value: pattern.Policies.RFCEnforcement},
					CertificateOwnerRole: types.Int64{
						Value: int64(pattern.Policies.CertificateOwnerRole),
						Null:  isNullId(pattern.Policies.CertificateOwnerRole),
					},
					DefaultCertificateOwnerOverride: types.Bool{Value: pattern.Policies.DefaultCertificateOwnerOverride},
					DefaultCertificateOwnerRoleId: types.Int64{
						Value: int64(pattern.Policies.DefaultCertificateOwnerRoleId),
						Null:  isNullId(pattern.Policies.DefaultCertificateOwnerRoleId),
					},
					DefaultCertificateOwnerRoleName: types.String{
						Value: pattern.Policies.DefaultCertificateOwnerRoleName,
						Null:  isNullString(pattern.Policies.DefaultCertificateOwnerRoleName),
					},
					PrimaryKeyAlgorithms:     []EnrollmentPatternsAlgorithmsAlgorithmData{},
					AlternativeKeyAlgorithms: []EnrollmentPatternsAlgorithmsAlgorithmData{},
				}
				if pattern.Policies.PrimaryKeyAlgorithms != nil && len(pattern.Policies.PrimaryKeyAlgorithms) > 0 {
					for _, algo := range pattern.Policies.PrimaryKeyAlgorithms {
						keyAlgo := EnrollmentPatternsAlgorithmsAlgorithmData{
							Name: types.String{
								Value: algo.Name,
								Null:  isNullString(algo.Name),
							},
							BitLengths: types.List{
								ElemType: types.Int64Type,
								Elems:    convertIntArrayToTerraform(algo.BitLengths),
								Null:     len(algo.BitLengths) == 0,
							},
							CurveName: types.List{
								ElemType: types.StringType,
								Elems:    convertStringArrayToTerraform(algo.Curves),
								Null:     len(algo.Curves) == 0,
							},
						}
						policies.PrimaryKeyAlgorithms = append(
							policies.PrimaryKeyAlgorithms, keyAlgo,
						)
					}
				}
				if pattern.Policies.AlternativeKeyAlgorithms != nil && len(pattern.Policies.AlternativeKeyAlgorithms) > 0 {
					for _, algo := range pattern.Policies.AlternativeKeyAlgorithms {
						altAlgo := EnrollmentPatternsAlgorithmsAlgorithmData{
							Name: types.String{
								Value: algo.Name,
								Null:  isNullString(algo.Name),
							},
							BitLengths: types.List{
								ElemType: types.Int64Type,
								Elems:    convertIntArrayToTerraform(algo.BitLengths),
								Null:     len(algo.BitLengths) == 0,
							},
							CurveName: types.List{
								ElemType: types.StringType,
								Elems:    convertStringArrayToTerraform(algo.Curves),
								Null:     len(algo.Curves) == 0,
							},
						}
						policies.AlternativeKeyAlgorithms = append(
							policies.AlternativeKeyAlgorithms, altAlgo,
						)
					}
				}
				result.Policies = &policies
			}

			tflog.Debug(ctx, "Completed mapping enrollment pattern data")
			found = true
			break
		}
	}
	if !found {
		// Defensive only: enrollmentPatternResolveIdentifier already
		// returned a descriptive "not found"/ambiguous error above (and
		// this function returned before reaching here) for every case
		// that function can detect. This should be unreachable in
		// practice -- it would only trip if matchedIdx pointed outside
		// enrollmentPatterns, which resolveErr == nil rules out.
		response.Diagnostics.AddError(
			"Enrollment pattern not found",
			fmt.Sprintf("Could not find enrollment pattern with identifier: %s", patternName),
		)
		return
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
