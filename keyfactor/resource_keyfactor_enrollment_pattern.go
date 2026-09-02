package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

// enrollmentPatternAlgorithmSchema returns the schema for a single entry of
// policies.primary_key_algorithms / policies.alternative_key_algorithms. This
// shape (name-keyed list of {name, bit_lengths, curves}) is deliberately kept
// identical to what data_source_keyfactor_enrollment_pattern.go exposes for
// the same server field -- the SDK v25 EnrollmentPatternsEnrollmentPattern-
// PolicyResponse/-Request already return/accept PrimaryKeyAlgorithms and
// AlternativeKeyAlgorithms as a flat []AlgorithmData{Name,BitLengths,Curves}
// list (unlike the pre-v25 per-algorithm-type KeyInfo{RSA,ECDSA,Ed448,
// Ed25519} shape templatePolicySchema's key_info still models), so no
// conversion between a fixed struct and a name-keyed list is needed here.
func enrollmentPatternAlgorithmSchema() map[string]tfsdk.Attribute {
	return map[string]tfsdk.Attribute{
		"name": {
			Type:        types.StringType,
			Required:    true,
			Description: "Algorithm name, e.g. RSA, ECDSA, Ed448, Ed25519.",
		},
		"bit_lengths": {
			Type:          types.ListType{ElemType: types.Int64Type},
			Optional:      true,
			Computed:      true,
			Description:   "Allowed key bit lengths for this algorithm.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"curves": {
			Type:          types.ListType{ElemType: types.StringType},
			Optional:      true,
			Computed:      true,
			Description:   "Allowed curve names for this algorithm (ECDSA/Ed448/Ed25519 only).",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
	}
}

// enrollmentPatternPolicySchema mirrors the "policies" object exposed by
// data_source_keyfactor_enrollment_pattern.go, with individually
// Optional+Computed subfields (rather than the data source's single flat
// Computed ObjectType) so this resource can actually write policy settings.
func enrollmentPatternPolicySchema() map[string]tfsdk.Attribute {
	return map[string]tfsdk.Attribute{
		"allow_key_reuse": {
			Type:          types.BoolType,
			Optional:      true,
			Computed:      true,
			Description:   "Whether certificate key reuse is allowed.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"allow_wildcards": {
			Type:          types.BoolType,
			Optional:      true,
			Computed:      true,
			Description:   "Whether wildcard SANs are allowed.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"rfc_enforcement": {
			Type:          types.BoolType,
			Optional:      true,
			Computed:      true,
			Description:   "Whether RFC 2818 compliance (require DNS SAN) should be enforced.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"certificate_owner_role": {
			Type:          types.Int64Type,
			Optional:      true,
			Computed:      true,
			Description:   "Certificate owner role: 0=None, 1=Requester, 2=Specified.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"default_certificate_owner_role_id": {
			Type:          types.Int64Type,
			Optional:      true,
			Computed:      true,
			Description:   "ID of the security role that should be set as the owner of the cert during import of new certificates.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"default_certificate_owner_role_name": {
			Type:          types.StringType,
			Computed:      true,
			Description:   "Name of the security role that should be set as the owner of the cert during import of new certificates. Read-only, derived from default_certificate_owner_role_id.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"default_certificate_owner_override": {
			Type:          types.BoolType,
			Optional:      true,
			Computed:      true,
			Description:   "Whether the given default_certificate_owner_role_id/name override the global setting.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"primary_key_algorithms": {
			Optional:      true,
			Computed:      true,
			Description:   "Primary (required) key algorithm constraints for enrollment.",
			PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			Attributes:    tfsdk.ListNestedAttributes(enrollmentPatternAlgorithmSchema()),
		},
		"alternative_key_algorithms": {
			Optional:      true,
			Computed:      true,
			Description:   "Alternative (optional) key algorithm constraints for enrollment.",
			PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			Attributes:    tfsdk.ListNestedAttributes(enrollmentPatternAlgorithmSchema()),
		},
	}
}

// ---------------------------------------------------------------------------
// Resource type
// ---------------------------------------------------------------------------

type resourceEnrollmentPatternType struct{}

func (r resourceEnrollmentPatternType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		MarkdownDescription: `
Manages a Keyfactor Command enrollment pattern using the "/EnrollmentPatterns" API.

Enrollment patterns provide a flexible way to streamline certificate enrollment by defining default values, policies, and access configurations for specific certificate templates and certificate authorities. This functionality helps reduce duplication of templates at the CA level while meeting diverse business requirements.

~> **Important:** Enrollment Patterns are only available in Keyfactor Command v25.0+

~> **Note:** ` + "`associated_role_names`, `certificate_authority_ids`" + ` are write-only: Keyfactor Command does not echo these back in the same shape they were submitted (it expands them into ` + "`associated_roles`/`certificate_authorities`" + `), so the provider preserves the last-known value from state instead of clearing it on refresh.

For full information on enrollment patterns view the [product documentation](https://software.keyfactor.com/Core-OnPrem/v25.3/Content/ReferenceGuide/Enrollment-Pattern-Operations.htm?Highlight=enrollment%20pattern)
`,
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "The server-assigned ID of the enrollment pattern.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "The reference name of the enrollment pattern.",
			},
			"description": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A description of the enrollment pattern.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			"template_id": {
				Type:          types.Int64Type,
				Required:      true,
				Description:   "The ID of the certificate template this enrollment pattern is associated with. Immutable -- changing this value forces recreation of the enrollment pattern.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"template": {
				Computed:      true,
				Description:   "The certificate template associated with the enrollment pattern (read-only, expanded from template_id).",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.SingleNestedAttributes(
					map[string]tfsdk.Attribute{
						"id":                   {Type: types.Int64Type, Computed: true},
						"template_name":        {Type: types.StringType, Computed: true},
						"common_name":          {Type: types.StringType, Computed: true},
						"configuration_tenant": {Type: types.StringType, Computed: true},
						"requires_approval":    {Type: types.BoolType, Computed: true},
						"friendly_name":        {Type: types.StringType, Computed: true},
					},
				),
			},

			"template_default": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether this enrollment pattern is the default pattern for the associated template. A certificate template can have only one default enrollment pattern, which is required for the template to be used for enrollment. If no other enrollment pattern for the template exists or is marked as default, this option is automatically enabled when a new pattern is created.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"use_ad_permissions": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether Active Directory permissions should be used for certificate enrollment authorization (true) or whether Keyfactor Command security roles should be used (false). If false, at least one value must be provided for associated_role_names.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			"associated_role_names": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				Computed:      true,
				Description:   "Names of the security roles associated with the enrollment pattern. Only users holding one of these roles will be able to use the enrollment pattern if use_ad_permissions is false. Write-only: not returned by the server in this shape (see associated_roles); the provider preserves the last-known value from state on refresh.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"associated_roles": {
				Computed:      true,
				Description:   "The security roles associated with the enrollment pattern (read-only, expanded from associated_role_names).",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"id":   {Type: types.Int64Type, Computed: true},
						"name": {Type: types.StringType, Computed: true},
					},
				),
			},

			"certificate_authority_ids": {
				Type:          types.ListType{ElemType: types.Int64Type},
				Optional:      true,
				Computed:      true,
				Description:   "IDs of the certificate authorities to which the enrollment pattern is restricted, if applicable (see restrict_cas). Write-only: not returned by the server in this shape (see certificate_authorities); the provider preserves the last-known value from state on refresh.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"certificate_authorities": {
				Computed:      true,
				Description:   "The certificate authorities to which the enrollment pattern is restricted (read-only, expanded from certificate_authority_ids).",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"id":                   {Type: types.Int64Type, Computed: true},
						"logical_name":         {Type: types.StringType, Computed: true},
						"host_name":            {Type: types.StringType, Computed: true},
						"configuration_tenant": {Type: types.StringType, Computed: true},
					},
				),
			},

			"allowed_enrollment_types": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Bitmask of enrollment types allowed for the enrollment pattern: 1=CSR, 2=PFX, 3=both.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			"regexes": {
				Optional:      true,
				Computed:      true,
				Description:   "Regular expressions specific to this enrollment pattern, used to validate subject data. Regular expressions defined here take precedence over system-wide regular expressions.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"subject_part": {Type: types.StringType, Required: true},
						"regex": {
							Type:          types.StringType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"error": {
							Type:          types.StringType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"case_sensitive": {
							Type:          types.BoolType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
					},
				),
			},
			"metadata_fields": {
				Optional:      true,
				Computed:      true,
				Description:   "Metadata field settings specific to this enrollment pattern. These take precedence over global-level metadata field settings.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"metadata_id": {Type: types.Int64Type, Required: true, Description: "ID of the metadata field definition."},
						"default_value": {
							Type:          types.StringType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"validation": {
							Type:          types.StringType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"enrollment": {
							Type:          types.Int64Type,
							Optional:      true,
							Computed:      true,
							Description:   "Enrollment requirement: 0=None, 1=Optional, 2=Required.",
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"message": {
							Type:          types.StringType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"case_sensitive": {
							Type:          types.BoolType,
							Optional:      true,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
					},
				),
			},

			"restrict_cas": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether the enrollment pattern should be restricted to the certificate authorities listed in certificate_authority_ids. If true, at least one CA must be configured.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			"policies": {
				Optional:      true,
				Computed:      true,
				Description:   "Individual policy settings for the enrollment pattern. Policies defined here take precedence over system-wide policies. Keyfactor Command requires a Policies object on every create/update; if this attribute is left undeclared, the provider still sends an empty policy object so server-side defaults apply.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes:    tfsdk.SingleNestedAttributes(enrollmentPatternPolicySchema()),
			},

			"defaults": {
				Optional:      true,
				Computed:      true,
				Description:   "Default subject values specific to this enrollment pattern. These take precedence over system-wide default subject settings.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"subject_part": {Type: types.StringType, Required: true},
						"value":        {Type: types.StringType, Required: true},
					},
				),
			},
			"enrollment_fields": {
				Optional:      true,
				Computed:      true,
				Description:   "Custom enrollment fields for CSR/PFX enrollment specific to this enrollment pattern. These are not metadata fields -- they are passed through to the CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"name":      {Type: types.StringType, Required: true},
						"data_type": {Type: types.Int64Type, Required: true, Description: "1=String, 2=MultiValue."},
						"options":   {Type: types.ListType{ElemType: types.StringType}, Optional: true},
					},
				),
			},

			"force_template_default": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Write-only directive: when true, forces this pattern to become the template's default even if another pattern currently holds that status. Not persisted -- must be re-declared on every apply where it is needed; always reads back as null.",
			},
		},
	}, nil
}

func (r resourceEnrollmentPatternType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceEnrollmentPattern{p: *(p.(*provider))}, nil
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

type resourceEnrollmentPattern struct {
	p provider
}

type EnrollmentPatternResourceTemplate struct {
	Id                  types.Int64  `tfsdk:"id"`
	TemplateName        types.String `tfsdk:"template_name"`
	CommonName          types.String `tfsdk:"common_name"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
	RequiresApproval    types.Bool   `tfsdk:"requires_approval"`
	FriendlyName        types.String `tfsdk:"friendly_name"`
}

type EnrollmentPatternResourceRole struct {
	Id   types.Int64  `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
}

type EnrollmentPatternResourceCA struct {
	Id                  types.Int64  `tfsdk:"id"`
	LogicalName         types.String `tfsdk:"logical_name"`
	HostName            types.String `tfsdk:"host_name"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
}

type EnrollmentPatternResourceRegex struct {
	SubjectPart   types.String `tfsdk:"subject_part"`
	Regex         types.String `tfsdk:"regex"`
	Error         types.String `tfsdk:"error"`
	CaseSensitive types.Bool   `tfsdk:"case_sensitive"`
}

type EnrollmentPatternResourceMetadataField struct {
	MetadataId    types.Int64  `tfsdk:"metadata_id"`
	DefaultValue  types.String `tfsdk:"default_value"`
	Validation    types.String `tfsdk:"validation"`
	Enrollment    types.Int64  `tfsdk:"enrollment"`
	Message       types.String `tfsdk:"message"`
	CaseSensitive types.Bool   `tfsdk:"case_sensitive"`
}

type EnrollmentPatternResourceAlgorithm struct {
	Name       types.String `tfsdk:"name"`
	BitLengths types.List   `tfsdk:"bit_lengths"`
	Curves     types.List   `tfsdk:"curves"`
}

type EnrollmentPatternResourcePolicy struct {
	AllowKeyReuse                   types.Bool                           `tfsdk:"allow_key_reuse"`
	AllowWildcards                  types.Bool                           `tfsdk:"allow_wildcards"`
	RFCEnforcement                  types.Bool                           `tfsdk:"rfc_enforcement"`
	CertificateOwnerRole            types.Int64                          `tfsdk:"certificate_owner_role"`
	DefaultCertificateOwnerRoleId   types.Int64                          `tfsdk:"default_certificate_owner_role_id"`
	DefaultCertificateOwnerRoleName types.String                         `tfsdk:"default_certificate_owner_role_name"`
	DefaultCertificateOwnerOverride types.Bool                           `tfsdk:"default_certificate_owner_override"`
	PrimaryKeyAlgorithms            []EnrollmentPatternResourceAlgorithm `tfsdk:"primary_key_algorithms"`
	AlternativeKeyAlgorithms        []EnrollmentPatternResourceAlgorithm `tfsdk:"alternative_key_algorithms"`
}

type EnrollmentPatternResourceDefault struct {
	SubjectPart types.String `tfsdk:"subject_part"`
	Value       types.String `tfsdk:"value"`
}

type EnrollmentPatternResourceField struct {
	Name     types.String `tfsdk:"name"`
	DataType types.Int64  `tfsdk:"data_type"`
	Options  types.List   `tfsdk:"options"`
}

// KeyfactorEnrollmentPatternState is the Terraform state model for
// keyfactor_enrollment_pattern.
//
// AssociatedRoleNames and CertificateAuthorityIds are write-only from the
// server's perspective: Create/Update/GetById (all three share the same
// EnrollmentPatternsEnrollmentPatternResponse shape) only ever expand these
// into AssociatedRoles/CertificateAuthorities objects, never echo back the
// plain name/ID list that was submitted. Read/Import must therefore preserve
// these from the prior Terraform state rather than hardcode them null on
// every un-declared apply, or the provider would either wipe them on refresh
// or (for Optional+Computed with useStateOrNullModifier) hit "provider
// produced inconsistent result after apply" -- see
// KeyfactorCertificateCollectionState's Query field for the same pattern.
type KeyfactorEnrollmentPatternState struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`

	TemplateId types.Int64                        `tfsdk:"template_id"`
	Template   *EnrollmentPatternResourceTemplate `tfsdk:"template"`

	TemplateDefault  types.Bool `tfsdk:"template_default"`
	UseADPermissions types.Bool `tfsdk:"use_ad_permissions"`

	AssociatedRoleNames types.List                      `tfsdk:"associated_role_names"`
	AssociatedRoles     []EnrollmentPatternResourceRole `tfsdk:"associated_roles"`

	CertificateAuthorityIds types.List                    `tfsdk:"certificate_authority_ids"`
	CertificateAuthorities  []EnrollmentPatternResourceCA `tfsdk:"certificate_authorities"`

	AllowedEnrollmentTypes types.Int64 `tfsdk:"allowed_enrollment_types"`

	Regexes        []EnrollmentPatternResourceRegex         `tfsdk:"regexes"`
	MetadataFields []EnrollmentPatternResourceMetadataField `tfsdk:"metadata_fields"`

	RestrictCAs types.Bool `tfsdk:"restrict_cas"`

	Policies *EnrollmentPatternResourcePolicy `tfsdk:"policies"`

	Defaults         []EnrollmentPatternResourceDefault `tfsdk:"defaults"`
	EnrollmentFields []EnrollmentPatternResourceField   `tfsdk:"enrollment_fields"`

	ForceTemplateDefault types.Bool `tfsdk:"force_template_default"`
}

// ---------------------------------------------------------------------------
// Small conversion helpers local to this resource
// ---------------------------------------------------------------------------

// enumPtrToTfInt64 converts any int32-backed enum pointer (e.g.
// *CSSCMSCoreEnumsMetadataTypeEnrollment, *CSSCMSCoreEnumsTemplateEnrollment-
// FieldType, *CSSCMSCoreEnumsTemplateCertificateOwnerRole) to types.Int64,
// mapping nil (server field omitted) to Null so a subsequent write does not
// silently send the zero value of the enum.
func enumPtrToTfInt64[T ~int32](v *T) types.Int64 {
	if v == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(*v)}
}

// tfListToStringSlice extracts a []string from a types.List, returning nil
// when the list is null/unknown so callers can distinguish "nothing to send"
// from "send an explicit empty list."
func tfListToStringSlice(ctx context.Context, l types.List) []string {
	if l.Null || l.Unknown {
		return nil
	}
	var result []string
	l.ElementsAs(ctx, &result, false)
	if result == nil {
		result = []string{}
	}
	return result
}

// tfListToInt32Slice extracts a []int32 from a types.List of Int64 elements,
// returning nil when the list is null/unknown.
func tfListToInt32Slice(ctx context.Context, l types.List) []int32 {
	if l.Null || l.Unknown {
		return nil
	}
	var vals []int64
	l.ElementsAs(ctx, &vals, false)
	result := make([]int32, len(vals))
	for i, v := range vals {
		result[i] = int32(v)
	}
	return result
}

// ---------------------------------------------------------------------------
// Response -> State conversion
// ---------------------------------------------------------------------------

func enrollmentPatternTemplateResponseToState(t *v1.EnrollmentPatternsEnrollmentPatternTemplateResponse) *EnrollmentPatternResourceTemplate {
	if t == nil {
		return nil
	}
	return &EnrollmentPatternResourceTemplate{
		Id:                  int32PtrToTfInt64(t.Id),
		TemplateName:        nullableStringToTfString(t.TemplateName),
		CommonName:          nullableStringToTfString(t.CommonName),
		ConfigurationTenant: nullableStringToTfString(t.ConfigurationTenant),
		RequiresApproval:    boolPtrToTfBool(t.RequiresApproval),
		FriendlyName:        nullableStringToTfString(t.FriendlyName),
	}
}

func enrollmentPatternAssociatedRolesToState(roles []v1.EnrollmentPatternsEnrollmentPatternAssociatedRoleResponse) []EnrollmentPatternResourceRole {
	var result []EnrollmentPatternResourceRole
	for _, role := range roles {
		result = append(
			result, EnrollmentPatternResourceRole{
				Id:   int32PtrToTfInt64(role.Id),
				Name: nullableStringToTfString(role.Name),
			},
		)
	}
	return result
}

func enrollmentPatternCAsToState(cas []v1.EnrollmentPatternsEnrollmentPatternCAResponse) []EnrollmentPatternResourceCA {
	var result []EnrollmentPatternResourceCA
	for _, ca := range cas {
		result = append(
			result, EnrollmentPatternResourceCA{
				Id:                  int32PtrToTfInt64(ca.Id),
				LogicalName:         nullableStringToTfString(ca.LogicalName),
				HostName:            nullableStringToTfString(ca.HostName),
				ConfigurationTenant: nullableStringToTfString(ca.ConfigurationTenant),
			},
		)
	}
	return result
}

func enrollmentPatternRegexesToState(regexes []v1.EnrollmentPatternsEnrollmentPatternRegexesResponse) []EnrollmentPatternResourceRegex {
	var result []EnrollmentPatternResourceRegex
	for _, rx := range regexes {
		result = append(
			result, EnrollmentPatternResourceRegex{
				SubjectPart:   nullableStringToTfString(rx.SubjectPart),
				Regex:         nullableStringToTfString(rx.Regex),
				Error:         nullableStringToTfString(rx.Error),
				CaseSensitive: boolPtrToTfBool(rx.CaseSensitive),
			},
		)
	}
	return result
}

func enrollmentPatternMetadataFieldsToState(fields []v1.EnrollmentPatternsEnrollmentPatternMetadataFieldResponse) []EnrollmentPatternResourceMetadataField {
	var result []EnrollmentPatternResourceMetadataField
	for _, f := range fields {
		result = append(
			result, EnrollmentPatternResourceMetadataField{
				MetadataId:    int32PtrToTfInt64(f.MetadataId),
				DefaultValue:  nullableStringToTfString(f.DefaultValue),
				Validation:    nullableStringToTfString(f.Validation),
				Enrollment:    enumPtrToTfInt64(f.Enrollment),
				Message:       nullableStringToTfString(f.Message),
				CaseSensitive: boolPtrToTfBool(f.CaseSensitive),
			},
		)
	}
	return result
}

func enrollmentPatternDefaultsToState(defaults []v1.EnrollmentPatternsEnrollmentPatternDefaultResponse) []EnrollmentPatternResourceDefault {
	var result []EnrollmentPatternResourceDefault
	for _, d := range defaults {
		result = append(
			result, EnrollmentPatternResourceDefault{
				SubjectPart: nullableStringToTfString(d.SubjectPart),
				Value:       nullableStringToTfString(d.Value),
			},
		)
	}
	return result
}

func enrollmentPatternFieldsToState(fields []v1.EnrollmentPatternsEnrollmentPatternFieldResponse) []EnrollmentPatternResourceField {
	var result []EnrollmentPatternResourceField
	for _, f := range fields {
		entry := EnrollmentPatternResourceField{
			Name:     nullableStringToTfString(f.Name),
			DataType: enumPtrToTfInt64(f.DataType),
		}
		if len(f.Options) > 0 {
			entry.Options = stringSliceToTfList(f.Options)
		} else {
			entry.Options = types.List{Null: true, ElemType: types.StringType}
		}
		result = append(result, entry)
	}
	return result
}

func algorithmDataResponseToResourceEntry(a v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse) EnrollmentPatternResourceAlgorithm {
	entry := EnrollmentPatternResourceAlgorithm{
		Name: nullableStringToTfString(a.Name),
	}
	if len(a.BitLengths) > 0 {
		entry.BitLengths = types.List{ElemType: types.Int64Type, Elems: convertIntArrayToTerraform(a.BitLengths)}
	} else {
		entry.BitLengths = types.List{Null: true, ElemType: types.Int64Type}
	}
	if len(a.Curves) > 0 {
		entry.Curves = stringSliceToTfList(a.Curves)
	} else {
		entry.Curves = types.List{Null: true, ElemType: types.StringType}
	}
	return entry
}

func enrollmentPatternPolicyResponseToState(p *v1.EnrollmentPatternsEnrollmentPatternPolicyResponse) *EnrollmentPatternResourcePolicy {
	if p == nil {
		return nil
	}
	pol := &EnrollmentPatternResourcePolicy{
		AllowKeyReuse:                   nullableBoolToTfBool(p.AllowKeyReuse),
		AllowWildcards:                  nullableBoolToTfBool(p.AllowWildcards),
		RFCEnforcement:                  nullableBoolToTfBool(p.RFCEnforcement),
		CertificateOwnerRole:            enumPtrToTfInt64(p.CertificateOwnerRole),
		DefaultCertificateOwnerRoleId:   nullableInt32ToTfInt64(p.DefaultCertificateOwnerRoleId),
		DefaultCertificateOwnerRoleName: nullableStringToTfString(p.DefaultCertificateOwnerRoleName),
		DefaultCertificateOwnerOverride: boolPtrToTfBool(p.DefaultCertificateOwnerOverride),
	}
	for _, algo := range p.PrimaryKeyAlgorithms {
		pol.PrimaryKeyAlgorithms = append(pol.PrimaryKeyAlgorithms, algorithmDataResponseToResourceEntry(algo))
	}
	for _, algo := range p.AlternativeKeyAlgorithms {
		pol.AlternativeKeyAlgorithms = append(pol.AlternativeKeyAlgorithms, algorithmDataResponseToResourceEntry(algo))
	}
	return pol
}

// enrollmentPatternResponseToState maps the shared Create/Update/GetById
// response shape (EnrollmentPatternsEnrollmentPatternResponse) onto Terraform
// state. Callers are responsible for re-applying the write-only fields
// (AssociatedRoleNames, CertificateAuthorityIds, ForceTemplateDefault) this
// function cannot populate from any response -- see
// KeyfactorEnrollmentPatternState's doc comment.
func enrollmentPatternResponseToState(resp *v1.EnrollmentPatternsEnrollmentPatternResponse) KeyfactorEnrollmentPatternState {
	state := KeyfactorEnrollmentPatternState{}

	if resp.Id != nil {
		state.ID = types.Int64{Value: int64(*resp.Id)}
	} else {
		state.ID = types.Int64{Null: true}
	}
	state.Name = nullableStringToTfString(resp.Name)
	state.Description = nullableStringToTfString(resp.Description)

	state.Template = enrollmentPatternTemplateResponseToState(resp.Template)
	if resp.Template != nil && resp.Template.Id != nil {
		state.TemplateId = types.Int64{Value: int64(*resp.Template.Id)}
	} else {
		state.TemplateId = types.Int64{Null: true}
	}

	state.TemplateDefault = boolPtrToTfBool(resp.TemplateDefault)
	state.UseADPermissions = boolPtrToTfBool(resp.UseADPermissions)

	state.AssociatedRoles = enrollmentPatternAssociatedRolesToState(resp.AssociatedRoles)
	state.CertificateAuthorities = enrollmentPatternCAsToState(resp.CertificateAuthorities)

	state.AllowedEnrollmentTypes = enrollmentTypePtrToTfInt64(resp.AllowedEnrollmentTypes)

	state.Regexes = enrollmentPatternRegexesToState(resp.Regexes)
	state.MetadataFields = enrollmentPatternMetadataFieldsToState(resp.MetadataFields)

	state.RestrictCAs = boolPtrToTfBool(resp.RestrictCAs)

	state.Policies = enrollmentPatternPolicyResponseToState(resp.Policies)

	state.Defaults = enrollmentPatternDefaultsToState(resp.Defaults)
	state.EnrollmentFields = enrollmentPatternFieldsToState(resp.EnrollmentFields)

	return state
}

// ---------------------------------------------------------------------------
// State -> Request conversion
// ---------------------------------------------------------------------------

// buildEnrollmentPatternPolicyRequest is always called, even when plan is
// nil, because Command 25.5.x rejects Create/Update requests that omit
// Policies entirely (error 0xA0F00003) -- see EnrollmentPatternsEnrollment-
// PatternCreateRequest.Policies, which has no `omitempty` tag and is a value
// (not pointer) field, so a zero-value struct still serializes as `{}`.
func buildEnrollmentPatternPolicyRequest(ctx context.Context, p *EnrollmentPatternResourcePolicy) v1.EnrollmentPatternsEnrollmentPatternPolicyRequest {
	req := v1.EnrollmentPatternsEnrollmentPatternPolicyRequest{}
	if p == nil {
		return req
	}
	if !p.AllowKeyReuse.Null && !p.AllowKeyReuse.Unknown {
		req.SetAllowKeyReuse(p.AllowKeyReuse.Value)
	}
	if !p.AllowWildcards.Null && !p.AllowWildcards.Unknown {
		req.SetAllowWildcards(p.AllowWildcards.Value)
	}
	if !p.RFCEnforcement.Null && !p.RFCEnforcement.Unknown {
		req.SetRFCEnforcement(p.RFCEnforcement.Value)
	}
	if !p.CertificateOwnerRole.Null && !p.CertificateOwnerRole.Unknown {
		role := v1.CSSCMSCoreEnumsTemplateCertificateOwnerRole(int32(p.CertificateOwnerRole.Value))
		req.CertificateOwnerRole = &role
	}
	if !p.DefaultCertificateOwnerRoleId.Null && !p.DefaultCertificateOwnerRoleId.Unknown {
		req.SetDefaultCertificateOwnerRoleId(int32(p.DefaultCertificateOwnerRoleId.Value))
	}
	// default_certificate_owner_role_name is Computed-only (server-derived);
	// there is no plan-side value to send.
	if !p.DefaultCertificateOwnerOverride.Null && !p.DefaultCertificateOwnerOverride.Unknown {
		req.SetDefaultCertificateOwnerOverride(p.DefaultCertificateOwnerOverride.Value)
	}
	if len(p.PrimaryKeyAlgorithms) > 0 {
		req.SetPrimaryKeyAlgorithms(buildAlgorithmDataRequestV2List(ctx, p.PrimaryKeyAlgorithms))
	}
	if len(p.AlternativeKeyAlgorithms) > 0 {
		req.SetAlternativeKeyAlgorithms(buildAlgorithmDataRequestV2List(ctx, p.AlternativeKeyAlgorithms))
	}
	return req
}

func buildAlgorithmDataRequestV2List(ctx context.Context, algos []EnrollmentPatternResourceAlgorithm) []v1.EnrollmentPatternsAlgorithmsAlgorithmDataRequestV2 {
	var result []v1.EnrollmentPatternsAlgorithmsAlgorithmDataRequestV2
	for _, a := range algos {
		entry := v1.EnrollmentPatternsAlgorithmsAlgorithmDataRequestV2{Name: a.Name.Value}
		if !a.BitLengths.Null && !a.BitLengths.Unknown {
			var lengths []int64
			a.BitLengths.ElementsAs(ctx, &lengths, false)
			for _, l := range lengths {
				entry.BitLengths = append(entry.BitLengths, int32(l))
			}
		}
		if !a.Curves.Null && !a.Curves.Unknown {
			var curves []string
			a.Curves.ElementsAs(ctx, &curves, false)
			entry.Curves = curves
		}
		result = append(result, entry)
	}
	return result
}

func buildEnrollmentPatternRegexesRequest(plan []EnrollmentPatternResourceRegex) []v1.EnrollmentPatternsEnrollmentPatternRegexesRequest {
	var result []v1.EnrollmentPatternsEnrollmentPatternRegexesRequest
	for _, rx := range plan {
		entry := v1.EnrollmentPatternsEnrollmentPatternRegexesRequest{}
		entry.SetSubjectPart(rx.SubjectPart.Value)
		if !rx.Regex.Null && !rx.Regex.Unknown {
			entry.SetRegex(rx.Regex.Value)
		}
		if !rx.Error.Null && !rx.Error.Unknown {
			entry.SetError(rx.Error.Value)
		}
		if !rx.CaseSensitive.Null && !rx.CaseSensitive.Unknown {
			entry.SetCaseSensitive(rx.CaseSensitive.Value)
		}
		result = append(result, entry)
	}
	return result
}

func buildEnrollmentPatternMetadataFieldsRequest(plan []EnrollmentPatternResourceMetadataField) []v1.EnrollmentPatternsEnrollmentPatternMetadataFieldRequest {
	var result []v1.EnrollmentPatternsEnrollmentPatternMetadataFieldRequest
	for _, mf := range plan {
		entry := v1.EnrollmentPatternsEnrollmentPatternMetadataFieldRequest{}
		entry.SetMetadataId(int32(mf.MetadataId.Value))
		if !mf.DefaultValue.Null && !mf.DefaultValue.Unknown {
			entry.SetDefaultValue(mf.DefaultValue.Value)
		}
		if !mf.Validation.Null && !mf.Validation.Unknown {
			entry.SetValidation(mf.Validation.Value)
		}
		if !mf.Enrollment.Null && !mf.Enrollment.Unknown {
			entry.SetEnrollment(v1.CSSCMSCoreEnumsMetadataTypeEnrollment(int32(mf.Enrollment.Value)))
		}
		if !mf.Message.Null && !mf.Message.Unknown {
			entry.SetMessage(mf.Message.Value)
		}
		if !mf.CaseSensitive.Null && !mf.CaseSensitive.Unknown {
			entry.SetCaseSensitive(mf.CaseSensitive.Value)
		}
		result = append(result, entry)
	}
	return result
}

func buildEnrollmentPatternDefaultsRequest(plan []EnrollmentPatternResourceDefault) []v1.EnrollmentPatternsEnrollmentPatternDefaultRequest {
	var result []v1.EnrollmentPatternsEnrollmentPatternDefaultRequest
	for _, d := range plan {
		entry := v1.EnrollmentPatternsEnrollmentPatternDefaultRequest{}
		entry.SetSubjectPart(d.SubjectPart.Value)
		entry.SetValue(d.Value.Value)
		result = append(result, entry)
	}
	return result
}

func buildEnrollmentPatternFieldsRequest(ctx context.Context, plan []EnrollmentPatternResourceField) []v1.EnrollmentPatternsEnrollmentPatternFieldRequest {
	var result []v1.EnrollmentPatternsEnrollmentPatternFieldRequest
	for _, f := range plan {
		entry := v1.EnrollmentPatternsEnrollmentPatternFieldRequest{}
		entry.SetName(f.Name.Value)
		if !f.DataType.Null && !f.DataType.Unknown {
			entry.SetDataType(int32(f.DataType.Value))
		}
		if !f.Options.Null && !f.Options.Unknown {
			var opts []string
			f.Options.ElementsAs(ctx, &opts, false)
			entry.SetOptions(opts)
		}
		result = append(result, entry)
	}
	return result
}

// buildEnrollmentPatternCreateRequest builds the POST /EnrollmentPatterns
// body. template_id/name/policies are always sent (Template and Name are
// required scalar fields on the SDK struct; Policies per the "always send
// Policies" note on buildEnrollmentPatternPolicyRequest).
func buildEnrollmentPatternCreateRequest(ctx context.Context, plan KeyfactorEnrollmentPatternState) v1.EnrollmentPatternsEnrollmentPatternCreateRequest {
	req := *v1.NewEnrollmentPatternsEnrollmentPatternCreateRequest(
		int32(plan.TemplateId.Value), plan.Name.Value, buildEnrollmentPatternPolicyRequest(ctx, plan.Policies),
	)

	if !plan.Description.Null && !plan.Description.Unknown {
		req.SetDescription(plan.Description.Value)
	}
	if !plan.TemplateDefault.Null && !plan.TemplateDefault.Unknown {
		req.SetTemplateDefault(plan.TemplateDefault.Value)
	}
	if !plan.UseADPermissions.Null && !plan.UseADPermissions.Unknown {
		req.SetUseADPermissions(plan.UseADPermissions.Value)
	}
	if roles := tfListToStringSlice(ctx, plan.AssociatedRoleNames); roles != nil {
		req.SetAssociatedRoles(roles)
	}
	if caIds := tfListToInt32Slice(ctx, plan.CertificateAuthorityIds); caIds != nil {
		req.SetCertificateAuthorities(caIds)
	}
	if !plan.AllowedEnrollmentTypes.Null && !plan.AllowedEnrollmentTypes.Unknown {
		req.SetAllowedEnrollmentTypes(int32(plan.AllowedEnrollmentTypes.Value))
	}
	if len(plan.Regexes) > 0 {
		req.SetRegexes(buildEnrollmentPatternRegexesRequest(plan.Regexes))
	}
	if len(plan.MetadataFields) > 0 {
		req.SetMetadataFields(buildEnrollmentPatternMetadataFieldsRequest(plan.MetadataFields))
	}
	if !plan.RestrictCAs.Null && !plan.RestrictCAs.Unknown {
		req.SetRestrictCAs(plan.RestrictCAs.Value)
	}
	if len(plan.Defaults) > 0 {
		req.SetDefaults(buildEnrollmentPatternDefaultsRequest(plan.Defaults))
	}
	if len(plan.EnrollmentFields) > 0 {
		req.SetEnrollmentFields(buildEnrollmentPatternFieldsRequest(ctx, plan.EnrollmentFields))
	}
	return req
}

// buildEnrollmentPatternUpdateRequest builds the PUT /EnrollmentPatterns/{id}
// body. There is no Template field -- the template is immutable after create
// (enforced by template_id's RequiresReplace plan modifier).
func buildEnrollmentPatternUpdateRequest(ctx context.Context, plan KeyfactorEnrollmentPatternState) v1.EnrollmentPatternsEnrollmentPatternRequest {
	req := *v1.NewEnrollmentPatternsEnrollmentPatternRequest(
		plan.Name.Value, buildEnrollmentPatternPolicyRequest(ctx, plan.Policies),
	)

	if !plan.Description.Null && !plan.Description.Unknown {
		req.SetDescription(plan.Description.Value)
	}
	if !plan.TemplateDefault.Null && !plan.TemplateDefault.Unknown {
		req.SetTemplateDefault(plan.TemplateDefault.Value)
	}
	if !plan.UseADPermissions.Null && !plan.UseADPermissions.Unknown {
		req.SetUseADPermissions(plan.UseADPermissions.Value)
	}
	if roles := tfListToStringSlice(ctx, plan.AssociatedRoleNames); roles != nil {
		req.SetAssociatedRoles(roles)
	}
	if caIds := tfListToInt32Slice(ctx, plan.CertificateAuthorityIds); caIds != nil {
		req.SetCertificateAuthorities(caIds)
	}
	if !plan.AllowedEnrollmentTypes.Null && !plan.AllowedEnrollmentTypes.Unknown {
		req.SetAllowedEnrollmentTypes(int32(plan.AllowedEnrollmentTypes.Value))
	}
	if len(plan.Regexes) > 0 {
		req.SetRegexes(buildEnrollmentPatternRegexesRequest(plan.Regexes))
	}
	if len(plan.MetadataFields) > 0 {
		req.SetMetadataFields(buildEnrollmentPatternMetadataFieldsRequest(plan.MetadataFields))
	}
	if !plan.RestrictCAs.Null && !plan.RestrictCAs.Unknown {
		req.SetRestrictCAs(plan.RestrictCAs.Value)
	}
	if len(plan.Defaults) > 0 {
		req.SetDefaults(buildEnrollmentPatternDefaultsRequest(plan.Defaults))
	}
	if len(plan.EnrollmentFields) > 0 {
		req.SetEnrollmentFields(buildEnrollmentPatternFieldsRequest(ctx, plan.EnrollmentFields))
	}
	return req
}

// preserveUndeclaredEnrollmentPatternFields extends the same read-modify-
// write pattern used by preserveUndeclaredTemplateFields (resource_keyfactor_
// certificate_template.go, #195) to this resource: PUT /EnrollmentPatterns/
// {id} is a full-replace endpoint, so any Optional+Computed field left
// Null/Unknown on plan would otherwise be omitted from the request and
// cleared server-side instead of left unchanged. current must come from a
// GET performed immediately before the update (see Update()).
//
// AssociatedRoleNames/CertificateAuthorityIds are NOT handled here -- unlike
// every other field, no response (including this fresh GET) ever echoes them
// back in their write shape, so there is no "current server value" to fall
// back to. Update() falls back to its own prior Terraform state for those
// two instead, exactly as certificate_collection's Query field does.
func preserveUndeclaredEnrollmentPatternFields(
	plan *KeyfactorEnrollmentPatternState,
	current *v1.EnrollmentPatternsEnrollmentPatternResponse,
) {
	if current == nil {
		return
	}
	c := enrollmentPatternResponseToState(current)

	if plan.Description.Null || plan.Description.Unknown {
		plan.Description = c.Description
	}
	if plan.TemplateDefault.Null || plan.TemplateDefault.Unknown {
		plan.TemplateDefault = c.TemplateDefault
	}
	if plan.UseADPermissions.Null || plan.UseADPermissions.Unknown {
		plan.UseADPermissions = c.UseADPermissions
	}
	if plan.AllowedEnrollmentTypes.Null || plan.AllowedEnrollmentTypes.Unknown {
		plan.AllowedEnrollmentTypes = c.AllowedEnrollmentTypes
	}
	if plan.RestrictCAs.Null || plan.RestrictCAs.Unknown {
		plan.RestrictCAs = c.RestrictCAs
	}
	if plan.Regexes == nil {
		plan.Regexes = c.Regexes
	}
	if plan.MetadataFields == nil {
		plan.MetadataFields = c.MetadataFields
	}
	if plan.Defaults == nil {
		plan.Defaults = c.Defaults
	}
	if plan.EnrollmentFields == nil {
		plan.EnrollmentFields = c.EnrollmentFields
	}

	if plan.Policies == nil {
		plan.Policies = c.Policies
	} else if c.Policies != nil {
		pp, cp := plan.Policies, c.Policies
		if pp.AllowKeyReuse.Null || pp.AllowKeyReuse.Unknown {
			pp.AllowKeyReuse = cp.AllowKeyReuse
		}
		if pp.AllowWildcards.Null || pp.AllowWildcards.Unknown {
			pp.AllowWildcards = cp.AllowWildcards
		}
		if pp.RFCEnforcement.Null || pp.RFCEnforcement.Unknown {
			pp.RFCEnforcement = cp.RFCEnforcement
		}
		if pp.CertificateOwnerRole.Null || pp.CertificateOwnerRole.Unknown {
			pp.CertificateOwnerRole = cp.CertificateOwnerRole
		}
		if pp.DefaultCertificateOwnerRoleId.Null || pp.DefaultCertificateOwnerRoleId.Unknown {
			pp.DefaultCertificateOwnerRoleId = cp.DefaultCertificateOwnerRoleId
		}
		if pp.DefaultCertificateOwnerOverride.Null || pp.DefaultCertificateOwnerOverride.Unknown {
			pp.DefaultCertificateOwnerOverride = cp.DefaultCertificateOwnerOverride
		}
		if pp.PrimaryKeyAlgorithms == nil {
			pp.PrimaryKeyAlgorithms = cp.PrimaryKeyAlgorithms
		}
		if pp.AlternativeKeyAlgorithms == nil {
			pp.AlternativeKeyAlgorithms = cp.AlternativeKeyAlgorithms
		}
		// Always server-derived; never plan-settable.
		pp.DefaultCertificateOwnerRoleName = cp.DefaultCertificateOwnerRoleName
	}
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r resourceEnrollmentPattern) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceEnrollmentPattern.Create")

	var plan KeyfactorEnrollmentPatternState
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	if plan.TemplateId.Null || plan.TemplateId.Unknown {
		response.Diagnostics.AddError(
			"Missing template_id.",
			"template_id is required to create an enrollment pattern.",
		)
		return
	}

	body := buildEnrollmentPatternCreateRequest(ctx, plan)

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	LogFunctionCall(ctx, "EnrollmentPatternApi.CreateEnrollmentPatterns")
	req := patternApi.NewCreateEnrollmentPatternsRequest(ctx).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		EnrollmentPatternsEnrollmentPatternCreateRequest(body)
	if !plan.ForceTemplateDefault.Null && !plan.ForceTemplateDefault.Unknown {
		req = req.ForceTemplateDefault(plan.ForceTemplateDefault.Value)
	}
	resp, httpResp, err := req.Execute()
	LogFunctionReturned(ctx, "EnrollmentPatternApi.CreateEnrollmentPatterns")
	if err != nil {
		respBody := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error creating enrollment pattern.",
			fmt.Sprintf("Could not create enrollment pattern %q: %s. Details: %s", plan.Name.Value, err.Error(), respBody),
		)
		return
	}

	newState := enrollmentPatternResponseToState(resp)
	newState.AssociatedRoleNames = plan.AssociatedRoleNames
	newState.CertificateAuthorityIds = plan.CertificateAuthorityIds
	newState.ForceTemplateDefault = types.Bool{Null: true}

	tflog.Debug(ctx, fmt.Sprintf("Created enrollment pattern ID %d", newState.ID.Value))

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceEnrollmentPattern.Create")
}

func (r resourceEnrollmentPattern) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceEnrollmentPattern.Read")

	var state KeyfactorEnrollmentPatternState
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading enrollment pattern ID %d", state.ID.Value))

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	LogFunctionCall(ctx, "EnrollmentPatternApi.GetEnrollmentPatternsById")
	resp, httpResp, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, int32(state.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	LogFunctionReturned(ctx, "EnrollmentPatternApi.GetEnrollmentPatternsById")
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %d not found, removing from state", state.ID.Value))
			response.State.RemoveResource(ctx)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading enrollment pattern.",
			fmt.Sprintf("Could not read enrollment pattern %d: %s. Details: %s", state.ID.Value, err.Error(), body),
		)
		return
	}

	newState := enrollmentPatternResponseToState(resp)

	// GetById never returns AssociatedRoleNames/CertificateAuthorityIds in
	// their write shape -- preserve from the prior state (see
	// KeyfactorEnrollmentPatternState's doc comment). force_template_default
	// is a one-shot directive, not a persisted setting -- always null.
	newState.AssociatedRoleNames = state.AssociatedRoleNames
	newState.CertificateAuthorityIds = state.CertificateAuthorityIds
	newState.ForceTemplateDefault = types.Bool{Null: true}

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceEnrollmentPattern.Read")
}

func (r resourceEnrollmentPattern) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceEnrollmentPattern.Update")

	var plan KeyfactorEnrollmentPatternState
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var state KeyfactorEnrollmentPatternState
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// CONFIG (not plan) is the reliable signal for "did the user actually
	// declare this attribute" -- see preserveUndeclaredTemplateFields's
	// discussion of the same distinction in resource_keyfactor_certificate_
	// template.go.
	var config KeyfactorEnrollmentPatternState
	diags = request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	if plan.ID.Value == 0 {
		plan.ID = state.ID
	}

	tflog.Info(ctx, fmt.Sprintf("Updating enrollment pattern ID %d", plan.ID.Value))

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	// Fresh GET immediately before update -- PUT /EnrollmentPatterns/{id} is a
	// full-replace endpoint; see preserveUndeclaredEnrollmentPatternFields.
	LogFunctionCall(ctx, "EnrollmentPatternApi.GetEnrollmentPatternsById (pre-update)")
	current, httpResp, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, int32(plan.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	LogFunctionReturned(ctx, "EnrollmentPatternApi.GetEnrollmentPatternsById (pre-update)")
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading enrollment pattern before update.",
			fmt.Sprintf(
				"Could not read enrollment pattern %d to preserve its current field values: %s. Details: %s",
				plan.ID.Value, err.Error(), body,
			),
		)
		return
	}
	preserveUndeclaredEnrollmentPatternFields(&plan, current)

	// associated_role_names / certificate_authority_ids have no server-side
	// source of truth at all (see KeyfactorEnrollmentPatternState's doc
	// comment) -- fall back to this resource's own prior state, not the
	// fresh GET, when config leaves them undeclared.
	if config.AssociatedRoleNames.Null {
		plan.AssociatedRoleNames = state.AssociatedRoleNames
	}
	if config.CertificateAuthorityIds.Null {
		plan.CertificateAuthorityIds = state.CertificateAuthorityIds
	}

	updateBody := buildEnrollmentPatternUpdateRequest(ctx, plan)

	LogFunctionCall(ctx, "EnrollmentPatternApi.UpdateEnrollmentPatternsById")
	req := patternApi.NewUpdateEnrollmentPatternsByIdRequest(ctx, int32(plan.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		EnrollmentPatternsEnrollmentPatternRequest(updateBody)
	if !plan.ForceTemplateDefault.Null && !plan.ForceTemplateDefault.Unknown {
		req = req.ForceTemplateDefault(plan.ForceTemplateDefault.Value)
	}
	resp, httpResp, err := req.Execute()
	LogFunctionReturned(ctx, "EnrollmentPatternApi.UpdateEnrollmentPatternsById")
	if err != nil {
		respBody := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error updating enrollment pattern.",
			fmt.Sprintf("Could not update enrollment pattern %d: %s. Details: %s", plan.ID.Value, err.Error(), respBody),
		)
		return
	}

	newState := enrollmentPatternResponseToState(resp)
	newState.AssociatedRoleNames = plan.AssociatedRoleNames
	newState.CertificateAuthorityIds = plan.CertificateAuthorityIds
	newState.ForceTemplateDefault = types.Bool{Null: true}

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceEnrollmentPattern.Update")
}

func (r resourceEnrollmentPattern) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceEnrollmentPattern.Delete")

	var state KeyfactorEnrollmentPatternState
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting enrollment pattern ID %d", state.ID.Value))

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	LogFunctionCall(ctx, "EnrollmentPatternApi.DeleteEnrollmentPatternsById")
	httpResp, err := patternApi.NewDeleteEnrollmentPatternsByIdRequest(ctx, int32(state.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	LogFunctionReturned(ctx, "EnrollmentPatternApi.DeleteEnrollmentPatternsById")
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %d already deleted", state.ID.Value))
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error deleting enrollment pattern.",
			fmt.Sprintf("Could not delete enrollment pattern %d: %s. Details: %s", state.ID.Value, err.Error(), body),
		)
		return
	}

	LogFunctionExit(ctx, "resourceEnrollmentPattern.Delete")
}

func (r resourceEnrollmentPattern) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("ImportState called on enrollment pattern with ID %q", request.ID))

	id, err := strconv.Atoi(request.ID)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid enrollment pattern ID.",
			fmt.Sprintf("Import ID must be an integer, got %q: %s", request.ID, err.Error()),
		)
		return
	}

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	resp, httpResp, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, int32(id)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			response.Diagnostics.AddError(
				"Enrollment pattern not found.",
				fmt.Sprintf("Could not find enrollment pattern %d to import: %s", id, err.Error()),
			)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error importing enrollment pattern.",
			fmt.Sprintf("Could not read enrollment pattern %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	// GetById never returns AssociatedRoleNames/CertificateAuthorityIds in
	// their write shape, so an imported pattern starts with these null in
	// state -- the next apply will need them re-declared in configuration if
	// the user wants Terraform to manage them going forward (same caveat as
	// certificate_collection's Query field on import).
	newState := enrollmentPatternResponseToState(resp)
	newState.ForceTemplateDefault = types.Bool{Null: true}

	diags := response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
}
