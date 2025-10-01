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

type dataSourceEnrollmentPatternType struct{}

func (r dataSourceEnrollmentPatternType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "The name or internal ID (integer) of the enrollment pattern to look up.",
			},
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the ID of the enrollment pattern in Keyfactor Command.",
			},
			"name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the name of the enrollment pattern.",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the description of the enrollment pattern.",
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
				Description: "Template configuration for the enrollment pattern.",
			},
			"template_default": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A boolean indicating whether this is the default template for the enrollment pattern.",
			},
			"use_ad_permissions": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A boolean indicating whether to use Active Directory permissions.",
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
				Description: "List of roles associated with this enrollment pattern.",
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
				Computed:    true,
				Description: "List of certificate authorities associated with this enrollment pattern.",
			},
			"allowed_enrollment_types": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the type of enrollment allowed for the enrollment pattern.",
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
				Description: "List of regular expressions for the enrollment pattern.",
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
				Description: "List of metadata fields for the enrollment pattern.",
			},
			"restrict_cas": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A boolean indicating whether to restrict certificate authorities.",
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
				Description: "Policy configuration for the enrollment pattern.",
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
				Computed:    true,
				Description: "List of default values for the enrollment pattern.",
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
			},
		},
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
	for _, pattern := range enrollmentPatterns {
		tflog.Debug(ctx, fmt.Sprintf("Checking enrollment pattern: ID=%d, Name=%s", pattern.ID, pattern.Name))
		// Check if the current pattern matches the requested name or ID
		if pattern.Name == patternName || fmt.Sprint(pattern.ID) == patternName {
			tflog.Info(ctx, fmt.Sprintf("Found enrollment pattern with name: %s", patternName))

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
						"Enrollment pattern %s has template ID: %d", patternName,
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
			result.AllowedEnrollmentTypes = types.Int64{
				Value: int64(*pattern.AllowedEnrollmentTypes),
				Null:  isNullId(*pattern.AllowedEnrollmentTypes),
			}
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
							},
							CurveName: types.List{
								ElemType: types.StringType,
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
		response.Diagnostics.AddError(
			"Enrollment pattern not found",
			fmt.Sprintf("Could not find enrollment pattern with name: %s", patternName),
		)
		return
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
