package keyfactor

import (
	"context"
	"fmt"
	"strings"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// allowedEnrollmentTypesPtrToTfInt64 converts the SDK
// *CSSCMSCoreEnumsEnrollmentType AllowedEnrollmentTypes field to types.Int64,
// guarding against a nil pointer the same way every other pointer field in
// dataSourceEnrollmentPattern.Read is already guarded. AllowedEnrollmentTypes
// is nil whenever Command omits the key from the response -- a real, reachable
// case, since the corresponding resource attribute (allowed_enrollment_types)
// is Optional+Computed, i.e. explicitly designed to be left unset. Without
// this guard, dereferencing the nil pointer panics on every `terraform plan`/
// `refresh` against such a pattern.
func allowedEnrollmentTypesPtrToTfInt64(v *kfv1.CSSCMSCoreEnumsEnrollmentType) types.Int64 {
	return enumPtrToTfInt64(v)
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

// enrollmentPatternSelectByTemplateShortName validates the count of patterns
// returned by a server-side template_short_name QueryString filter and returns
// a descriptive error when the count is not exactly 1.
//
// templateDefaultFilter reflects the user's template_default config value:
//
//   - nil  — template_default was omitted; no TemplateDefault filter was applied.
//   - *true  — TemplateDefault -eq "true" was applied (user wants default patterns).
//   - *false — TemplateDefault -eq "false" was applied (user wants non-default patterns).
//
// Error messages are tailored to each case so the guidance never contradicts
// the user's explicit intent (e.g. a user who set template_default=false is
// not told to "set template_default=true").
func enrollmentPatternSelectByTemplateShortName(count int, templateShortName string, templateDefaultFilter *bool) error {
	switch {
	case count == 1:
		return nil

	case count == 0 && templateDefaultFilter != nil && !*templateDefaultFilter:
		// User explicitly asked for non-default patterns and got none.
		return fmt.Errorf(
			"no non-default enrollment patterns found for template short name %q; "+
				"try omitting template_default or set template_default = true to select the default pattern",
			templateShortName,
		)

	case count == 0 && templateDefaultFilter != nil && *templateDefaultFilter:
		// User explicitly asked for default patterns and got none.
		return fmt.Errorf(
			"no default enrollment pattern found for template short name %q; "+
				"the template may exist but have no pattern marked as default — "+
				"try omitting template_default to find any pattern for the template",
			templateShortName,
		)

	case count == 0:
		// No filter applied; nothing found at all.
		return fmt.Errorf(
			"no enrollment pattern found for template short name %q; "+
				"ensure the template name is correct and at least one enrollment pattern references it",
			templateShortName,
		)

	case templateDefaultFilter != nil && *templateDefaultFilter:
		// User asked for default patterns; got multiple (unexpected).
		return fmt.Errorf(
			"found %d default enrollment patterns for template short name %q; "+
				"this is unexpected — use identifier with the specific pattern name",
			count, templateShortName,
		)

	case templateDefaultFilter != nil && !*templateDefaultFilter:
		// User asked for non-default patterns; got multiple.
		return fmt.Errorf(
			"found %d non-default enrollment patterns for template short name %q; "+
				"use identifier with the specific pattern name",
			count, templateShortName,
		)

	default:
		// No filter applied; got multiple.
		return fmt.Errorf(
			"found %d enrollment patterns for template short name %q; "+
				"set template_default = true to select the default pattern for the template, "+
				"or use identifier with the specific pattern name",
			count, templateShortName,
		)
	}
}

type dataSourceEnrollmentPatternType struct{}

func (r dataSourceEnrollmentPatternType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:     types.StringType,
				Optional: true,
				Validators: []tfsdk.AttributeValidator{
					atLeastOneOfValidator{otherAttr: "template_short_name"},
				},
				Description: "The name or internal ID (integer) of the enrollment pattern to look up. " +
					"An exact name match takes precedence; otherwise this value is matched against the pattern's " +
					"internal ID as a decimal string (so \"007\" never matches ID 7). A value that matches a " +
					"different pattern by name than by ID returns an error rather than silently picking one. " +
					"Mutually exclusive with template_short_name.",
			},
			"template_short_name": {
				Type:     types.StringType,
				Optional: true,
				Validators: []tfsdk.AttributeValidator{
					conflictsWithAttrValidator{
						otherAttr: "identifier",
						message:   "Use either identifier or template_short_name, not both.",
					},
				},
				Description: "The template short name (AD common name) to filter enrollment patterns by. " +
					"Mutually exclusive with identifier. When multiple patterns match, set " +
					"template_default = true to select the default pattern for the template.",
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
				Type:     types.BoolType,
				Optional: true,
				Computed: true,
				Validators: []tfsdk.AttributeValidator{
					conflictsWithAttrValidator{
						otherAttr: "identifier",
						message:   "template_default is a filter that only applies when template_short_name is set.",
					},
				},
				Description: "A Boolean indicating whether this enrollment pattern is the default pattern for " +
					"the associated template (true) or not (false). A certificate template can have only one " +
					"default enrollment pattern, which is required for the template to be used for enrollment. " +
					"If no other enrollment pattern for the template exists or is marked as default, this option " +
					"will automatically be enabled when a new pattern is created. " +
					"When set in configuration, only valid alongside template_short_name: setting " +
					"template_default = true filters to the default pattern for the given template short name.",
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

Enrollment patterns can be looked up in two ways:

- By ` + "`identifier`" + ` (name or numeric ID): an exact name match takes precedence; otherwise ` + "`identifier`" + ` is matched against the pattern's internal ID as a decimal string (so ` + "`\"007\"`" + ` never matches ID 7). A value that matches a different pattern by name than by ID returns an error.
- By ` + "`template_short_name`" + ` (AD common name): performs a server-side query for enrollment patterns associated with the given template short name. If multiple patterns match, set ` + "`template_default = true`" + ` to select the default pattern for the template, or use ` + "`identifier`" + ` with the specific pattern name.

` + "`identifier`" + ` and ` + "`template_short_name`" + ` are mutually exclusive — exactly one must be set.

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

	// Validate mutually exclusive lookup keys.
	identifierSet := !state.Identifier.Null && !state.Identifier.Unknown && state.Identifier.Value != ""
	templateShortNameSet := !state.TemplateShortName.Null && !state.TemplateShortName.Unknown && state.TemplateShortName.Value != ""

	if !identifierSet && !templateShortNameSet {
		response.Diagnostics.AddError(
			"Missing required attribute",
			"Exactly one of 'identifier' or 'template_short_name' must be set.",
		)
		return
	}
	if identifierSet && templateShortNameSet {
		response.Diagnostics.AddError(
			"Conflicting attributes",
			"'identifier' and 'template_short_name' are mutually exclusive; set exactly one.",
		)
		return
	}

	// template_default is only meaningful alongside template_short_name.
	templateDefaultSet := !state.TemplateDefault.Null && !state.TemplateDefault.Unknown
	if templateDefaultSet && identifierSet {
		response.Diagnostics.AddError(
			"Invalid attribute combination",
			"'template_default' is only valid when 'template_short_name' is set; it cannot be used with 'identifier'.",
		)
		return
	}

	// Fetch the target pattern via the appropriate lookup path.
	var targetPattern kfv1.EnrollmentPatternsEnrollmentPatternResponse

	if identifierSet {
		patternName := state.Identifier.Value
		ctx = tflog.SetField(ctx, "pattern_identifier", patternName)
		tflog.Debug(ctx, "Searching for enrollment pattern by name or ID")

		// TODO: the API does not support server-side filtering by name in the
		// identifier (name-or-ID) path, so we fetch all patterns client-side and
		// resolve. The cap is set high enough to avoid silently missing patterns
		// in large deployments. If pagination is added to the API, switch to it.
		enrollmentPatterns, _, err := r.p.sdkClient.V1.EnrollmentPatternApi.
			NewGetEnrollmentPatternsRequest(ctx).
			ReturnLimit(10000).
			Execute()
		if err != nil {
			response.Diagnostics.AddError(
				"Error listing enrollment patterns from Keyfactor.",
				"Error reading enrollment patterns: "+err.Error(),
			)
			return
		}
		if len(enrollmentPatterns) == 10000 {
			response.Diagnostics.AddWarning(
				"Enrollment pattern list may be truncated.",
				"The server returned exactly 10000 enrollment patterns, which is the maximum page size. "+
					"Some patterns may not be visible. Contact your administrator to reduce the number of patterns or use the ID-based identifier instead.",
			)
		}

		// Resolve identifier against all candidates using name-or-ID semantics
		// (see enrollmentPatternResolveIdentifier's doc comment). An exact name
		// match wins deterministically; a canonical ID-string match is the
		// fallback; a genuine match on both for two different patterns is an
		// error rather than a silent pick.
		candidates := make([]enrollmentPatternCandidate, len(enrollmentPatterns))
		for i, p := range enrollmentPatterns {
			candidates[i] = enrollmentPatternCandidate{ID: int(p.GetId()), Name: p.GetName()}
		}
		matchedIdx, resolveErr := enrollmentPatternResolveIdentifier(patternName, candidates)
		if resolveErr != nil {
			response.Diagnostics.AddError("Enrollment pattern not found", resolveErr.Error())
			return
		}
		targetPattern = enrollmentPatterns[matchedIdx]
	} else {
		// template_short_name path: server-side QueryString filter.
		templateShortName := state.TemplateShortName.Value
		ctx = tflog.SetField(ctx, "template_short_name", templateShortName)
		tflog.Debug(ctx, "Searching for enrollment pattern by template short name")

		// F6+F1: escape backslashes first, then double quotes, to prevent
		// QueryString injection. Backslashes must be escaped first so the
		// quote-escape backslashes themselves are not double-escaped.
		//   foo\  → foo\\ (backslash escape)
		//   foo"  → foo\" (quote escape)
		//   foo\" → foo\\" (backslash escapes first, then quote)
		escapedShortName := strings.ReplaceAll(templateShortName, `\`, `\\`)
		escapedShortName = strings.ReplaceAll(escapedShortName, `"`, `\"`)
		queryStr := fmt.Sprintf("TemplateShortName -eq \"%s\"", escapedShortName)

		// templateDefaultFilterPtr mirrors the user's template_default config:
		//   nil    — omitted in config; no TemplateDefault filter applied
		//   *true  — user set template_default = true; filter for defaults
		//   *false — user set template_default = false; filter for non-defaults
		// This pointer is passed to enrollmentPatternSelectByTemplateShortName so
		// the error message reflects the user's actual intent rather than
		// assuming they did not filter.
		var templateDefaultFilterPtr *bool
		if templateDefaultSet {
			val := state.TemplateDefault.Value
			templateDefaultFilterPtr = &val
			if val {
				queryStr += " AND TemplateDefault -eq \"true\""
			} else {
				queryStr += " AND TemplateDefault -eq \"false\""
			}
		}

		enrollmentPatterns, _, err := r.p.sdkClient.V1.EnrollmentPatternApi.
			NewGetEnrollmentPatternsRequest(ctx).
			QueryString(queryStr).
			ReturnLimit(500).
			Execute()
		if err != nil {
			response.Diagnostics.AddError(
				"Error listing enrollment patterns from Keyfactor.",
				"Error reading enrollment patterns: "+err.Error(),
			)
			return
		}

		if selectErr := enrollmentPatternSelectByTemplateShortName(
			len(enrollmentPatterns), templateShortName, templateDefaultFilterPtr,
		); selectErr != nil {
			response.Diagnostics.AddError("Enrollment pattern lookup failed", selectErr.Error())
			return
		}
		targetPattern = enrollmentPatterns[0]
	}

	// Map the found pattern to state. Identifier and TemplateShortName are
	// preserved from the config so write-only filter attributes round-trip
	// correctly (null when not used, user value when used).
	result := CertificateEnrollmentPattern{
		Identifier:        state.Identifier,
		TemplateShortName: state.TemplateShortName,
		ID:                types.Int64{Value: int64(targetPattern.GetId())},
		Name:              nullableStringToTfString(targetPattern.Name),
		Description:       nullableStringToTfString(targetPattern.Description),
	}

	if targetPattern.Template != nil {
		tflog.Debug(
			ctx, fmt.Sprintf(
				"Enrollment pattern %q has template ID: %d", targetPattern.GetName(),
				targetPattern.Template.GetId(),
			),
		)
		tmpl := targetPattern.Template
		result.Template = &EnrollmentPatternTemplate{
			Id:                  int32PtrToTfInt64(tmpl.Id),
			TemplateName:        nullableStringToTfString(tmpl.TemplateName),
			CommonName:          nullableStringToTfString(tmpl.CommonName),
			ConfigurationTenant: nullableStringToTfString(tmpl.ConfigurationTenant),
			RequiresApproval:    boolPtrToTfBool(tmpl.RequiresApproval),
			FriendlyName:        nullableStringToTfString(tmpl.FriendlyName),
		}
	}

	result.TemplateDefault = boolPtrToTfBool(targetPattern.TemplateDefault)
	result.UseADPermissions = boolPtrToTfBool(targetPattern.UseADPermissions)
	result.AllowedEnrollmentTypes = allowedEnrollmentTypesPtrToTfInt64(targetPattern.AllowedEnrollmentTypes)
	result.RestrictCAs = boolPtrToTfBool(targetPattern.RestrictCAs)

	// Associated Roles
	result.AssociatedRoles = &[]EnrollmentPatternAssociatedRole{}
	if len(targetPattern.AssociatedRoles) > 0 {
		tflog.Debug(ctx, "Handling associated roles")
		var assocRoles []EnrollmentPatternAssociatedRole
		for _, role := range targetPattern.AssociatedRoles {
			assocRoles = append(
				assocRoles, EnrollmentPatternAssociatedRole{
					Id:   int32PtrToTfInt64(role.Id),
					Name: nullableStringToTfString(role.Name),
				},
			)
		}
		result.AssociatedRoles = &assocRoles
	}

	// Certificate Authorities
	result.CertificateAuthorities = &[]EnrollmentPatternCA{}
	if len(targetPattern.CertificateAuthorities) > 0 {
		tflog.Debug(ctx, "Handling certificate authorities")
		var cas []EnrollmentPatternCA
		for _, ca := range targetPattern.CertificateAuthorities {
			cas = append(
				cas, EnrollmentPatternCA{
					Id:                  int32PtrToTfInt64(ca.Id),
					LogicalName:         nullableStringToTfString(ca.LogicalName),
					HostName:            nullableStringToTfString(ca.HostName),
					ConfigurationTenant: nullableStringToTfString(ca.ConfigurationTenant),
				},
			)
		}
		result.CertificateAuthorities = &cas
	}

	// Regexes
	result.Regexes = &[]EnrollmentPatternRegexes{}
	if len(targetPattern.Regexes) > 0 {
		tflog.Debug(ctx, "Handling regexes")
		var regexes []EnrollmentPatternRegexes
		for _, regex := range targetPattern.Regexes {
			regexes = append(
				regexes, EnrollmentPatternRegexes{
					SubjectPart:   nullableStringToTfString(regex.SubjectPart),
					Regex:         nullableStringToTfString(regex.Regex),
					Error:         nullableStringToTfString(regex.Error),
					CaseSensitive: boolPtrToTfBool(regex.CaseSensitive),
				},
			)
		}
		result.Regexes = &regexes
	}

	// Metadata Fields
	result.MetadataFields = &[]EnrollmentPatternMetadataField{}
	if len(targetPattern.MetadataFields) > 0 {
		tflog.Debug(ctx, "Handling metadata fields")
		var metadataFields []EnrollmentPatternMetadataField
		for _, field := range targetPattern.MetadataFields {
			metadataFields = append(
				metadataFields, EnrollmentPatternMetadataField{
					MetadataId:    int32PtrToTfInt64(field.MetadataId),
					DefaultValue:  nullableStringToTfString(field.DefaultValue),
					Validation:    nullableStringToTfString(field.Validation),
					Enrollment:    enumPtrToTfInt64(field.Enrollment),
					Message:       nullableStringToTfString(field.Message),
					CaseSensitive: boolPtrToTfBool(field.CaseSensitive),
				},
			)
		}
		result.MetadataFields = &metadataFields
	}

	// Defaults
	result.Defaults = &[]EnrollmentPatternDefault{}
	if len(targetPattern.Defaults) > 0 {
		tflog.Debug(ctx, "Handling defaults")
		var epDefaults []EnrollmentPatternDefault
		for _, def := range targetPattern.Defaults {
			epDefaults = append(
				epDefaults, EnrollmentPatternDefault{
					SubjectPart: nullableStringToTfString(def.SubjectPart),
					Value:       nullableStringToTfString(def.Value),
				},
			)
		}
		result.Defaults = &epDefaults
	}

	// Enrollment Fields
	// The SDK's EnrollmentPatternsEnrollmentPatternFieldResponse only
	// carries Name, DataType, and Options -- the remaining fields
	// (Id, DefaultValue, Validation, Enrollment, Message, DependsOn,
	// DependsOnValue, Hint) are not returned by the listing endpoint
	// and are set to Null here.
	result.EnrollmentFields = &[]EnrollmentPatternField{}
	if len(targetPattern.EnrollmentFields) > 0 {
		tflog.Debug(ctx, "Handling enrollment fields")
		var erFields []EnrollmentPatternField
		for _, field := range targetPattern.EnrollmentFields {
			var optList types.List
			if field.Options == nil {
				optList = types.List{ElemType: types.StringType, Null: true}
			} else {
				optList = types.List{
					ElemType: types.StringType,
					Elems:    convertStringArrayToTerraform(field.Options),
				}
			}
			erFields = append(
				erFields, EnrollmentPatternField{
					Id:             types.Int64{Null: true},
					Name:           nullableStringToTfString(field.Name),
					DefaultValue:   types.String{Null: true},
					Validation:     types.String{Null: true},
					Enrollment:     types.Int64{Null: true},
					Message:        types.String{Null: true},
					Options:        optList,
					DependsOn:      types.String{Null: true},
					DependsOnValue: types.String{Null: true},
					DataType:       enumPtrToTfInt64(field.DataType),
					Hint:           types.String{Null: true},
				},
			)
		}
		result.EnrollmentFields = &erFields
	}

	// Policies
	result.Policies = &EnrollmentPatternPolicyResponse{}
	if targetPattern.Policies != nil {
		tflog.Debug(ctx, "Handling policies")
		pol := targetPattern.Policies
		policies := EnrollmentPatternPolicyResponse{
			AllowKeyReuse:                   nullableBoolToTfBool(pol.AllowKeyReuse),
			AllowWildcards:                  nullableBoolToTfBool(pol.AllowWildcards),
			RFCEnforcement:                  nullableBoolToTfBool(pol.RFCEnforcement),
			CertificateOwnerRole:            enumPtrToTfInt64(pol.CertificateOwnerRole),
			DefaultCertificateOwnerOverride: boolPtrToTfBool(pol.DefaultCertificateOwnerOverride),
			DefaultCertificateOwnerRoleId:   nullableInt32ToTfInt64(pol.DefaultCertificateOwnerRoleId),
			DefaultCertificateOwnerRoleName: nullableStringToTfString(pol.DefaultCertificateOwnerRoleName),
			PrimaryKeyAlgorithms:            []EnrollmentPatternsAlgorithmsAlgorithmData{},
			AlternativeKeyAlgorithms:        []EnrollmentPatternsAlgorithmsAlgorithmData{},
		}
		if len(pol.PrimaryKeyAlgorithms) > 0 {
			for _, algo := range pol.PrimaryKeyAlgorithms {
				policies.PrimaryKeyAlgorithms = append(
					policies.PrimaryKeyAlgorithms, sdkAlgorithmDataToTf(algo),
				)
			}
		}
		if len(pol.AlternativeKeyAlgorithms) > 0 {
			for _, algo := range pol.AlternativeKeyAlgorithms {
				policies.AlternativeKeyAlgorithms = append(
					policies.AlternativeKeyAlgorithms, sdkAlgorithmDataToTf(algo),
				)
			}
		}
		result.Policies = &policies
	}

	tflog.Debug(ctx, "Completed mapping enrollment pattern data")

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

// sdkAlgorithmDataToTf converts a single SDK AlgorithmDataResponse entry
// (from the Policies.PrimaryKeyAlgorithms or AlternativeKeyAlgorithms slice)
// into the data source's EnrollmentPatternsAlgorithmsAlgorithmData TF type.
func sdkAlgorithmDataToTf(algo kfv1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse) EnrollmentPatternsAlgorithmsAlgorithmData {
	entry := EnrollmentPatternsAlgorithmsAlgorithmData{
		Name: nullableStringToTfString(algo.Name),
	}
	if algo.BitLengths == nil {
		entry.BitLengths = types.List{ElemType: types.Int64Type, Null: true}
	} else {
		entry.BitLengths = types.List{
			ElemType: types.Int64Type,
			Elems:    convertIntArrayToTerraform(algo.BitLengths),
		}
	}
	if algo.Curves == nil {
		entry.CurveName = types.List{ElemType: types.StringType, Null: true}
	} else {
		entry.CurveName = types.List{
			ElemType: types.StringType,
			Elems:    convertStringArrayToTerraform(algo.Curves),
		}
	}
	return entry
}
