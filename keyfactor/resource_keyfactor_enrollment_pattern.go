package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
			// template/associated_roles/certificate_authorities are read-only
			// (server-derived, nothing for a user to set), but MUST declare
			// Optional in addition to Computed, matching every other nested
			// attribute in this schema (policies, regexes, metadata_fields,
			// defaults, enrollment_fields all already do). Reproduced live
			// against kfclab: a Computed-only (no Optional) nested attribute
			// with no prior Terraform state (first create) plans to an
			// explicit Null -- not "(known after apply)" -- so when Create()'s
			// real API response later populates it with actual data, Terraform
			// rejects the apply with "Provider produced inconsistent result
			// after apply: .template: was null, but now <object>" (same for
			// .associated_roles). Adding Optional makes this attribute plan
			// exactly like every sibling Optional+Computed attribute here:
			// "(known after apply)" pre-apply, resolved to the real value
			// post-apply -- no user-facing behavior changes since nothing
			// about Create()/Update() ever reads these fields from the plan.
			"template": {
				Optional:      true,
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
			// Optional required alongside Computed -- see the comment on
			// "template" above.
			"associated_roles": {
				Optional:      true,
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
			// Optional required alongside Computed -- see the comment on
			// "template" above.
			"certificate_authorities": {
				Optional:      true,
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
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Write-only directive: when true, forces this pattern to become the template's default even if another pattern currently holds that status. Not persisted -- must be re-declared on every apply where it is needed; always reads back as null.",
				PlanModifiers: []tfsdk.AttributePlanModifier{alwaysUnknownModifier{}},
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
// Audit logging (PR #210 full-review finding F5)
// ---------------------------------------------------------------------------

// tfBoolLogString/tfInt64LogString/tfStringLogString/tfListLogString render a
// tfsdk attr.Value as a short human-readable string for audit-log lines,
// distinguishing null/unknown from an actual value rather than printing the
// struct's internal representation.
//
// tfStringLogString/tfListLogString %q-escape the actual value (bool/int64
// values need no escaping, since they can't contain control characters).
// This matches the rest of the codebase's established convention for
// logging user/server-controlled strings -- see e.g.
// resource_keyfactor_certificate_authority.go's and resource_keyfactor_
// security_identity.go's %q-escaped log lines -- and closes the CWE-117
// log-injection shape this file's audit-log diffs previously left open: an
// embedded "\n" in, say, an associated_role_names entry or a certificate
// collection query would otherwise forge a second, visually-separate log
// line under this repo's TF_LOG=DEBUG plaintext logging path (PR #210
// full-review finding FIX-6).
func tfBoolLogString(v types.Bool) string {
	if v.Unknown {
		return "(unknown)"
	}
	if v.Null {
		return "(null)"
	}
	return strconv.FormatBool(v.Value)
}

func tfInt64LogString(v types.Int64) string {
	if v.Unknown {
		return "(unknown)"
	}
	if v.Null {
		return "(null)"
	}
	return strconv.FormatInt(v.Value, 10)
}

func tfStringLogString(v types.String) string {
	if v.Unknown {
		return "(unknown)"
	}
	if v.Null {
		return "(null)"
	}
	return fmt.Sprintf("%q", v.Value)
}

func tfListLogString(ctx context.Context, l types.List) string {
	if l.Unknown {
		return "(unknown)"
	}
	if l.Null {
		return "(null)"
	}
	var vals []string
	l.ElementsAs(ctx, &vals, false)
	if vals == nil {
		// ElementsAs above only succeeds directly for []string; for a list
		// of a different element type, fall back to formatting the raw
		// attr.Value elements so this still produces a readable, non-empty
		// log line instead of silently reporting "[]" for a populated
		// non-string list.
		for _, e := range l.Elems {
			vals = append(vals, fmt.Sprintf("%v", e))
		}
	}
	quoted := make([]string, len(vals))
	for i, v := range vals {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

// algorithmListLogString renders a []EnrollmentPatternResourceAlgorithm (the
// raw Go slice type backing policies.primary_key_algorithms/alternative_key_
// algorithms -- see EnrollmentPatternResourcePolicy) as a short human-
// readable string for audit-log lines, mirroring tfListLogString's null vs.
// value distinction for the types.List-backed fields logged alongside it: a
// nil slice (this resource's "undeclared" sentinel for these two fields --
// see buildEnrollmentPatternPolicyRequest's doc comment for the same
// nil-vs-non-nil-empty distinction) logs as "(null)"; a non-nil (even
// zero-length) slice renders each entry's name/bit_lengths/curves, %q-
// escaped via tfStringLogString/tfListLogString for the same CWE-117 reason
// those helpers exist.
func algorithmListLogString(ctx context.Context, algos []EnrollmentPatternResourceAlgorithm) string {
	if algos == nil {
		return "(null)"
	}
	entries := make([]string, 0, len(algos))
	for _, a := range algos {
		entries = append(
			entries, fmt.Sprintf(
				"{name:%s,bit_lengths:%s,curves:%s}",
				tfStringLogString(a.Name), tfListLogString(ctx, a.BitLengths), tfListLogString(ctx, a.Curves),
			),
		)
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// regexListLogString renders a []EnrollmentPatternResourceRegex (the raw Go
// slice type backing the top-level regexes attribute) as a short human-
// readable string for audit-log lines, mirroring algorithmListLogString's
// null vs. value distinction and %q-escaping convention: a nil slice
// (undeclared regexes -- see buildEnrollmentPatternRegexesRequest's doc
// comment for the same nil-vs-non-nil-empty distinction) logs as "(null)"; a
// non-nil (even zero-length) slice renders each entry's subject_part/regex/
// error/case_sensitive, %q-escaped via tfStringLogString/tfBoolLogString for
// the same CWE-117 reason those helpers exist. PR #210 full-review round 4
// finding FIX-K.
func regexListLogString(regexes []EnrollmentPatternResourceRegex) string {
	if regexes == nil {
		return "(null)"
	}
	entries := make([]string, 0, len(regexes))
	for _, rx := range regexes {
		entries = append(
			entries, fmt.Sprintf(
				"{subject_part:%s,regex:%s,error:%s,case_sensitive:%s}",
				tfStringLogString(rx.SubjectPart), tfStringLogString(rx.Regex), tfStringLogString(rx.Error),
				tfBoolLogString(rx.CaseSensitive),
			),
		)
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// metadataFieldListLogString renders a []EnrollmentPatternResourceMetadataField
// (the raw Go slice type backing the top-level metadata_fields attribute) as
// a short human-readable string for audit-log lines, mirroring
// regexListLogString's null vs. value distinction and %q-escaping
// convention: a nil slice (undeclared metadata_fields -- see
// buildEnrollmentPatternMetadataFieldsRequest's doc comment for the same
// nil-vs-non-nil-empty distinction) logs as "(null)"; a non-nil (even
// zero-length) slice renders each entry's metadata_id/default_value/
// validation/enrollment/message/case_sensitive, %q-escaped via
// tfStringLogString/tfInt64LogString/tfBoolLogString for the same CWE-117
// reason those helpers exist. metadata_fields[].enrollment gates
// required/optional/hidden status for enrollment metadata (e.g. a mandatory
// "Change Ticket Number" field), so its default_value/enrollment/validation
// settings are exactly the kind of "how strictly enrollment is validated"
// control already tracked here for regexes/policies.rfc_enforcement. See PR
// #210 full-review round 5 finding FIX-M.
func metadataFieldListLogString(fields []EnrollmentPatternResourceMetadataField) string {
	if fields == nil {
		return "(null)"
	}
	entries := make([]string, 0, len(fields))
	for _, f := range fields {
		entries = append(
			entries, fmt.Sprintf(
				"{metadata_id:%s,default_value:%s,validation:%s,enrollment:%s,message:%s,case_sensitive:%s}",
				tfInt64LogString(f.MetadataId), tfStringLogString(f.DefaultValue), tfStringLogString(f.Validation),
				tfInt64LogString(f.Enrollment), tfStringLogString(f.Message), tfBoolLogString(f.CaseSensitive),
			),
		)
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// defaultListLogString renders a []EnrollmentPatternResourceDefault (the raw
// Go slice type backing the top-level defaults attribute) as a short
// human-readable string for audit-log lines -- see
// metadataFieldListLogString's doc comment for the same null-vs-value and
// %q-escaping rationale. defaults pre-fills subject content for certificates
// issued through this pattern, affecting the accuracy of what gets issued
// (processing-integrity relevant), so it belongs in the same audit trail as
// the other subject/validation-affecting fields. See PR #210 full-review
// round 5 finding FIX-M.
func defaultListLogString(defaults []EnrollmentPatternResourceDefault) string {
	if defaults == nil {
		return "(null)"
	}
	entries := make([]string, 0, len(defaults))
	for _, d := range defaults {
		entries = append(
			entries, fmt.Sprintf(
				"{subject_part:%s,value:%s}",
				tfStringLogString(d.SubjectPart), tfStringLogString(d.Value),
			),
		)
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// enrollmentFieldListLogString renders a []EnrollmentPatternResourceField
// (the raw Go slice type backing the top-level enrollment_fields attribute)
// as a short human-readable string for audit-log lines -- see
// metadataFieldListLogString's doc comment for the same null-vs-value and
// %q-escaping rationale. enrollment_fields is CA-passthrough data that ends
// up in issued certificates, so like defaults it affects the accuracy of
// what gets issued. See PR #210 full-review round 5 finding FIX-M.
func enrollmentFieldListLogString(ctx context.Context, fields []EnrollmentPatternResourceField) string {
	if fields == nil {
		return "(null)"
	}
	entries := make([]string, 0, len(fields))
	for _, f := range fields {
		entries = append(
			entries, fmt.Sprintf(
				"{name:%s,data_type:%s,options:%s}",
				tfStringLogString(f.Name), tfInt64LogString(f.DataType), tfListLogString(ctx, f.Options),
			),
		)
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// enrollmentPatternPolicyRelevantFieldChanges compares the prior Terraform
// state against the final Update() plan (after preserveUndeclaredEnrollment-
// PatternFields and the associated_role_names/certificate_authority_ids
// fallback have run -- i.e. exactly what is about to be sent to Command) and
// returns one human-readable "field: old -> new" description per changed
// policy-relevant field. Covers the fields this resource can change that
// matter for a compliance audit trail: the reference name of the pattern
// itself (name), which template's default enrollment pattern this is
// (template_default -- see the same-named schema attribute's description:
// "a certificate template can have only one default enrollment pattern,
// which is required for the template to be used for enrollment"), the
// authorization model governing enrollment (use_ad_permissions,
// restrict_cas) and who it grants access to (associated_role_names,
// certificate_authority_ids), which enrollment methods -- and thus
// key-custody model -- are permitted (allowed_enrollment_types: 1=CSR,
// 2=PFX/server-generated key, 3=both), how strictly enrollment is validated
// (regexes, metadata_fields, policies.rfc_enforcement,
// policies.allow_wildcards, policies.allow_key_reuse), the cryptographic
// strength allowed (policies.primary_key_algorithms,
// policies.alternative_key_algorithms), the subject content and CA
// passthrough data that ends up in issued certificates (defaults,
// enrollment_fields -- processing-integrity relevant even though neither is
// a classic access-control gate), and who owns the resulting certificates
// (policies.certificate_owner_role,
// policies.default_certificate_owner_role_id/name,
// policies.default_certificate_owner_override), plus the one-shot
// force_template_default directive. Deliberately a pure function (no
// tflog/side effects) so it can be unit tested directly; Update() emits one
// tflog.Info per returned entry.
//
// template_id is deliberately NOT compared here: it is RequiresReplace
// (immutable -- see its schema attribute), so it can never differ between
// prior and updated on a genuine Update() call; a "change" to template_id
// is actually a destroy+create, already visible in Terraform's own plan
// output, and is instead reported on the Create side by
// enrollmentPatternCreationAuditFields below. See PR #210 full-review round
// 4 finding FIX-J.
//
// policies.default_certificate_owner_role_name is deliberately NOT compared
// here: both `prior`/`updated` at the point this function runs (see
// Update()) are still derived from state/GET responses taken BEFORE the PUT
// that actually applies this update, so this field structurally cannot
// reflect a same-apply change to policies.default_certificate_owner_role_id
// (the id line above already reports that). Update() separately calls
// enrollmentPatternOwnerRoleNameChange, sourced from the actual PUT
// response, after the update has been applied. See PR #210 full-review
// round 5 finding FIX-O.
func enrollmentPatternPolicyRelevantFieldChanges(
	ctx context.Context,
	prior, updated KeyfactorEnrollmentPatternState,
) []string {
	var changes []string

	appendIfChanged := func(name, oldVal, newVal string) {
		if oldVal != newVal {
			changes = append(changes, fmt.Sprintf("%s: %s -> %s", name, oldVal, newVal))
		}
	}

	appendIfChanged("name", tfStringLogString(prior.Name), tfStringLogString(updated.Name))
	appendIfChanged("template_default", tfBoolLogString(prior.TemplateDefault), tfBoolLogString(updated.TemplateDefault))
	appendIfChanged("use_ad_permissions", tfBoolLogString(prior.UseADPermissions), tfBoolLogString(updated.UseADPermissions))
	appendIfChanged("associated_role_names", tfListLogString(ctx, prior.AssociatedRoleNames), tfListLogString(ctx, updated.AssociatedRoleNames))
	appendIfChanged("restrict_cas", tfBoolLogString(prior.RestrictCAs), tfBoolLogString(updated.RestrictCAs))
	appendIfChanged("certificate_authority_ids", tfListLogString(ctx, prior.CertificateAuthorityIds), tfListLogString(ctx, updated.CertificateAuthorityIds))
	appendIfChanged("allowed_enrollment_types", tfInt64LogString(prior.AllowedEnrollmentTypes), tfInt64LogString(updated.AllowedEnrollmentTypes))
	appendIfChanged("regexes", regexListLogString(prior.Regexes), regexListLogString(updated.Regexes))
	appendIfChanged(
		"metadata_fields",
		metadataFieldListLogString(prior.MetadataFields), metadataFieldListLogString(updated.MetadataFields),
	)
	appendIfChanged("defaults", defaultListLogString(prior.Defaults), defaultListLogString(updated.Defaults))
	appendIfChanged(
		"enrollment_fields",
		enrollmentFieldListLogString(ctx, prior.EnrollmentFields), enrollmentFieldListLogString(ctx, updated.EnrollmentFields),
	)
	// force_template_default is a one-shot, write-only directive: every CRUD
	// path in this file unconditionally resets it to Null in the persisted
	// state (see alwaysUnknownModifier's doc comment), so `prior` here is
	// ALWAYS Null by construction, regardless of what actually happened on
	// any previous apply -- it is never a real signal. A naive
	// appendIfChanged("force_template_default", ...) comparison against that
	// always-Null baseline would report a false-positive "changed" entry
	// (null -> false) on every single Update() where a user declares
	// force_template_default = false in config and leaves it there, forever
	// -- even though the directive was never actually invoked (only a
	// genuinely true value triggers the ForceTemplateDefault API call at
	// the Update() call site -- false is sent as a no-op equivalent to
	// leaving it unset). Report a change only when the directive is
	// genuinely being invoked this apply (a known, true value on the
	// updated/plan side) -- that is the only case that has any real,
	// auditable effect. See PR #210 full-review round 4 finding FIX-L.
	if !updated.ForceTemplateDefault.Null && !updated.ForceTemplateDefault.Unknown && updated.ForceTemplateDefault.Value {
		changes = append(
			changes, fmt.Sprintf(
				"force_template_default: %s -> %s",
				tfBoolLogString(prior.ForceTemplateDefault), tfBoolLogString(updated.ForceTemplateDefault),
			),
		)
	}

	if prior.Policies != nil || updated.Policies != nil {
		// When either side's Policies pointer is nil (server/plan omitted the
		// policies key entirely), fall back to an explicitly Null-flagged
		// zero value rather than Go's implicit struct zero value. A bare
		// `var o EnrollmentPatternResourcePolicy` zero-value produces
		// types.Bool{Null: false, Value: false} / types.Int64{Null: false,
		// Value: 0} / types.String{Null: false, Value: ""} for every
		// subfield -- none of which are actually flagged Null -- so
		// tfBoolLogString/tfInt64LogString/tfStringLogString would render
		// "false"/"0"/"" instead of the accurate "(null)", misrepresenting a
		// genuinely-absent prior/updated value as a concrete one. See PR
		// #210 full-review round 5 finding FIX-N.
		o, n := enrollmentPatternNullPolicy(), enrollmentPatternNullPolicy()
		if prior.Policies != nil {
			o = *prior.Policies
		}
		if updated.Policies != nil {
			n = *updated.Policies
		}
		appendIfChanged("policies.rfc_enforcement", tfBoolLogString(o.RFCEnforcement), tfBoolLogString(n.RFCEnforcement))
		appendIfChanged("policies.allow_wildcards", tfBoolLogString(o.AllowWildcards), tfBoolLogString(n.AllowWildcards))
		appendIfChanged("policies.allow_key_reuse", tfBoolLogString(o.AllowKeyReuse), tfBoolLogString(n.AllowKeyReuse))
		appendIfChanged("policies.certificate_owner_role", tfInt64LogString(o.CertificateOwnerRole), tfInt64LogString(n.CertificateOwnerRole))
		appendIfChanged(
			"policies.default_certificate_owner_role_id",
			tfInt64LogString(o.DefaultCertificateOwnerRoleId), tfInt64LogString(n.DefaultCertificateOwnerRoleId),
		)
		// policies.default_certificate_owner_role_name is intentionally not
		// compared here -- see this function's doc comment (FIX-O).
		appendIfChanged(
			"policies.default_certificate_owner_override",
			tfBoolLogString(o.DefaultCertificateOwnerOverride), tfBoolLogString(n.DefaultCertificateOwnerOverride),
		)
		appendIfChanged(
			"policies.primary_key_algorithms",
			algorithmListLogString(ctx, o.PrimaryKeyAlgorithms), algorithmListLogString(ctx, n.PrimaryKeyAlgorithms),
		)
		appendIfChanged(
			"policies.alternative_key_algorithms",
			algorithmListLogString(ctx, o.AlternativeKeyAlgorithms), algorithmListLogString(ctx, n.AlternativeKeyAlgorithms),
		)
	}

	return changes
}

// enrollmentPatternNullPolicy returns a zero-value EnrollmentPatternResourcePolicy
// with every scalar subfield explicitly flagged Null, for use as a diff-side
// fallback when the source *EnrollmentPatternResourcePolicy is itself nil --
// see enrollmentPatternPolicyRelevantFieldChanges's doc comment on the
// resulting bare Go zero-value pitfall (PR #210 full-review round 5 finding
// FIX-N).
func enrollmentPatternNullPolicy() EnrollmentPatternResourcePolicy {
	return EnrollmentPatternResourcePolicy{
		AllowKeyReuse:                   types.Bool{Null: true},
		AllowWildcards:                  types.Bool{Null: true},
		RFCEnforcement:                  types.Bool{Null: true},
		CertificateOwnerRole:            types.Int64{Null: true},
		DefaultCertificateOwnerRoleId:   types.Int64{Null: true},
		DefaultCertificateOwnerRoleName: types.String{Null: true},
		DefaultCertificateOwnerOverride: types.Bool{Null: true},
	}
}

// enrollmentPatternOwnerRoleNameChange reports a
// "policies.default_certificate_owner_role_name: old -> new" audit line, or
// "" when unchanged. Unlike every other field compared by
// enrollmentPatternPolicyRelevantFieldChanges, this one is NOT safe to
// compare using the prior-state/pre-update-GET-derived `prior`/`updated`
// values that function receives: both sides of that comparison are resolved
// BEFORE the update PUT actually applies (see
// preserveUndeclaredEnrollmentPatternFields's unconditional
// `pp.DefaultCertificateOwnerRoleName = cp.DefaultCertificateOwnerRoleName`,
// sourced from a GET taken immediately before the PUT), so a same-apply
// change to policies.default_certificate_owner_role_id would render this
// field as unchanged even though the name resolves differently once the PUT
// takes effect. Call this instead with `actual` sourced from the Update PUT
// response itself (already fetched by Update() -- no extra API call needed),
// which reflects the genuinely-applied result. See PR #210 full-review round
// 5 finding FIX-O.
func enrollmentPatternOwnerRoleNameChange(prior, actual *EnrollmentPatternResourcePolicy) string {
	oldName := types.String{Null: true}
	if prior != nil {
		oldName = prior.DefaultCertificateOwnerRoleName
	}
	newName := types.String{Null: true}
	if actual != nil {
		newName = actual.DefaultCertificateOwnerRoleName
	}
	oldStr, newStr := tfStringLogString(oldName), tfStringLogString(newName)
	if oldStr == newStr {
		return ""
	}
	return fmt.Sprintf("policies.default_certificate_owner_role_name: %s -> %s", oldStr, newStr)
}

// enrollmentPatternCreationAuditFields renders the same access-control-
// relevant fields enrollmentPatternPolicyRelevantFieldChanges audits on
// every subsequent Update() -- the reference name of the pattern (name) and
// which template it is immutably associated with (template_id -- see
// enrollmentPatternPolicyRelevantFieldChanges's doc comment for why
// template_id is Create-only), which template's default enrollment pattern
// this is (template_default), the authorization model governing enrollment
// (use_ad_permissions, restrict_cas) and who it grants access to
// (associated_role_names, certificate_authority_ids), which enrollment
// methods -- and thus key-custody model -- are permitted
// (allowed_enrollment_types: 1=CSR, 2=PFX/server-generated key, 3=both), how
// strictly enrollment is validated (regexes, metadata_fields,
// policies.rfc_enforcement, policies.allow_wildcards,
// policies.allow_key_reuse), the cryptographic strength allowed
// (policies.primary_key_algorithms, policies.alternative_key_algorithms),
// the subject content and CA passthrough data that ends up in issued
// certificates (defaults, enrollment_fields), who owns the resulting
// certificates (policies.certificate_owner_role, policies.default_
// certificate_owner_role_id/name, policies.default_certificate_owner_
// override), and the one-shot force_template_default directive -- as one
// "field: value" string per field, for Create()'s audit-log line.
//
// Unlike enrollmentPatternPolicyRelevantFieldChanges, Create() has no
// pre-update GET to worry about: `created` here is derived directly from the
// Create response itself, so policies.default_certificate_owner_role_name is
// already the genuinely-resolved value and is reported normally (no FIX-O
// suppression needed on this path).
//
// force_template_default is passed in separately (submittedForceTemplate-
// Default), rather than read off `created`, because by the time Create()
// builds its audit log, created.ForceTemplateDefault has already been
// force-reset to Null (it is never persisted server-side -- see the comment
// above every CRUD path's `ForceTemplateDefault = types.Bool{Null: true}`
// assignment). Reading it off `created` would always render "(null)"
// regardless of what was actually sent to Command on this create -- the
// caller must pass the plan value that was actually used to build the
// create request, before that reset. See PR #210 full-review round 2
// finding FIX-B.
//
// Create() has no prior Terraform state to diff against (the resource
// doesn't exist yet), so unlike enrollmentPatternPolicyRelevantFieldChanges
// this simply reports what was set rather than an old -> new pair --
// diffing against a synthetic zero-value KeyfactorEnrollmentPatternState
// would render misleading "old" values (e.g. a Go zero-value types.Int64{}
// prints as "0" via tfInt64LogString, not "(null)", since it isn't actually
// flagged Null). Previously Create() logged nothing beyond the bare numeric
// ID (see the tflog call below in Create()), leaving an asymmetric audit
// trail: full field detail for every Update(), none for the initial grant
// of enrollment/CA access -- a gap a SOC2 auditor reconstructing "who was
// granted access to what, and when" would flag (PR #210 full-review finding
// FIX-8). Pure function so it can be unit tested directly, matching
// enrollmentPatternPolicyRelevantFieldChanges.
func enrollmentPatternCreationAuditFields(
	ctx context.Context,
	created KeyfactorEnrollmentPatternState,
	submittedForceTemplateDefault types.Bool,
) []string {
	var fields []string
	add := func(name, val string) {
		fields = append(fields, fmt.Sprintf("%s: %s", name, val))
	}

	add("name", tfStringLogString(created.Name))
	add("template_id", tfInt64LogString(created.TemplateId))
	add("template_default", tfBoolLogString(created.TemplateDefault))
	add("use_ad_permissions", tfBoolLogString(created.UseADPermissions))
	add("associated_role_names", tfListLogString(ctx, created.AssociatedRoleNames))
	add("restrict_cas", tfBoolLogString(created.RestrictCAs))
	add("certificate_authority_ids", tfListLogString(ctx, created.CertificateAuthorityIds))
	add("allowed_enrollment_types", tfInt64LogString(created.AllowedEnrollmentTypes))
	add("regexes", regexListLogString(created.Regexes))
	add("metadata_fields", metadataFieldListLogString(created.MetadataFields))
	add("defaults", defaultListLogString(created.Defaults))
	add("enrollment_fields", enrollmentFieldListLogString(ctx, created.EnrollmentFields))
	add("force_template_default", tfBoolLogString(submittedForceTemplateDefault))

	if created.Policies != nil {
		p := created.Policies
		add("policies.rfc_enforcement", tfBoolLogString(p.RFCEnforcement))
		add("policies.allow_wildcards", tfBoolLogString(p.AllowWildcards))
		add("policies.allow_key_reuse", tfBoolLogString(p.AllowKeyReuse))
		add("policies.certificate_owner_role", tfInt64LogString(p.CertificateOwnerRole))
		add("policies.default_certificate_owner_role_id", tfInt64LogString(p.DefaultCertificateOwnerRoleId))
		add("policies.default_certificate_owner_role_name", tfStringLogString(p.DefaultCertificateOwnerRoleName))
		add("policies.default_certificate_owner_override", tfBoolLogString(p.DefaultCertificateOwnerOverride))
		add("policies.primary_key_algorithms", algorithmListLogString(ctx, p.PrimaryKeyAlgorithms))
		add("policies.alternative_key_algorithms", algorithmListLogString(ctx, p.AlternativeKeyAlgorithms))
	}

	return fields
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

// enrollmentPatternAssociatedRolesToState converts the server's
// AssociatedRoles response into state. AssociatedRoles is a plain
// (non-nullable-wrapper) []T on EnrollmentPatternsEnrollmentPatternResponse
// (`json:"AssociatedRoles,omitempty"`), so it is Go-nil only when the
// server's JSON omits the key entirely; an explicit `[]` decodes to a
// non-nil, zero-length slice. Building the result by appending onto a
// nil-initialized Go slice (the bug -- fixed here) collapses that
// non-nil-but-empty case back to nil regardless, which the framework's
// reflection layer encodes as a null list -- clobbering a known non-null
// empty-list plan value and crashing the apply with "Provider produced
// inconsistent result after apply." Mirrors the fix already applied to
// enrollmentPatternFieldsToState's Options/algorithmDataResponseToResourceEntry's
// BitLengths/Curves above, and the identical bug class fixed for
// certStoreTypeDefToState under GitHub issue #192.
func enrollmentPatternAssociatedRolesToState(roles []v1.EnrollmentPatternsEnrollmentPatternAssociatedRoleResponse) []EnrollmentPatternResourceRole {
	if roles == nil {
		return nil
	}
	result := make([]EnrollmentPatternResourceRole, 0, len(roles))
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

// enrollmentPatternCAsToState -- see enrollmentPatternAssociatedRolesToState's
// doc comment; identical nil-vs-non-nil-empty fix for CertificateAuthorities.
func enrollmentPatternCAsToState(cas []v1.EnrollmentPatternsEnrollmentPatternCAResponse) []EnrollmentPatternResourceCA {
	if cas == nil {
		return nil
	}
	result := make([]EnrollmentPatternResourceCA, 0, len(cas))
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

// enrollmentPatternRegexesToState -- see enrollmentPatternAssociatedRolesToState's
// doc comment; identical nil-vs-non-nil-empty fix for Regexes.
func enrollmentPatternRegexesToState(regexes []v1.EnrollmentPatternsEnrollmentPatternRegexesResponse) []EnrollmentPatternResourceRegex {
	if regexes == nil {
		return nil
	}
	result := make([]EnrollmentPatternResourceRegex, 0, len(regexes))
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

// enrollmentPatternMetadataFieldsToState -- see enrollmentPatternAssociatedRolesToState's
// doc comment; identical nil-vs-non-nil-empty fix for MetadataFields.
func enrollmentPatternMetadataFieldsToState(fields []v1.EnrollmentPatternsEnrollmentPatternMetadataFieldResponse) []EnrollmentPatternResourceMetadataField {
	if fields == nil {
		return nil
	}
	result := make([]EnrollmentPatternResourceMetadataField, 0, len(fields))
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

// enrollmentPatternDefaultsToState -- see enrollmentPatternAssociatedRolesToState's
// doc comment; identical nil-vs-non-nil-empty fix for Defaults.
func enrollmentPatternDefaultsToState(defaults []v1.EnrollmentPatternsEnrollmentPatternDefaultResponse) []EnrollmentPatternResourceDefault {
	if defaults == nil {
		return nil
	}
	result := make([]EnrollmentPatternResourceDefault, 0, len(defaults))
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

// enrollmentPatternFieldsToState converts the server's EnrollmentFields
// response into state. f.Options is a plain (non-nullable-wrapper) []string
// on the SDK response model: encoding/json only leaves it Go-nil when the
// server's JSON response omits the "Options" key entirely or sends an
// explicit `null` -- both of which mean "no value," matching a Null plan for
// an undeclared `options`. Any other case (including an explicit `[]`) comes
// back as a non-nil, possibly zero-length slice, which only happens when the
// config actually declared `options = [...]` (including `options = []`) and
// the server echoed it back. Collapsing that non-nil-but-empty case to Null
// unconditionally (the bug -- fixed here) clobbers a known non-null
// empty-list plan value with Null and crashes the apply with "Provider
// produced inconsistent result after apply" -- see
// TestUnitEnrollmentPatternFieldsToStatePreservesEmptyOptions.
func enrollmentPatternFieldsToState(fields []v1.EnrollmentPatternsEnrollmentPatternFieldResponse) []EnrollmentPatternResourceField {
	// EnrollmentFields itself (the outer slice, as opposed to each entry's
	// nested Options handled above) is subject to the identical nil-vs-
	// non-nil-empty bug -- see enrollmentPatternAssociatedRolesToState's doc
	// comment.
	if fields == nil {
		return nil
	}
	result := make([]EnrollmentPatternResourceField, 0, len(fields))
	for _, f := range fields {
		entry := EnrollmentPatternResourceField{
			Name:     nullableStringToTfString(f.Name),
			DataType: enumPtrToTfInt64(f.DataType),
		}
		if f.Options == nil {
			entry.Options = types.List{Null: true, ElemType: types.StringType}
		} else {
			entry.Options = stringSliceToTfList(f.Options)
		}
		result = append(result, entry)
	}
	return result
}

// algorithmDataResponseToResourceEntry converts a single PrimaryKeyAlgorithms/
// AlternativeKeyAlgorithms entry from the server response into state.
// a.BitLengths/a.Curves are plain (non-nullable-wrapper) slices on the SDK
// response model -- same nil-vs-non-nil-empty distinction as
// enrollmentPatternFieldsToState's Options handling above. primary_key_
// algorithms/alternative_key_algorithms are Optional+Computed with
// tfsdk.UseStateForUnknown(), which only substitutes the prior state when the
// PLAN value is Unknown; an explicitly-declared `curves = []` (legitimate for
// an RSA entry, which has no curves) is a known, non-null plan value that
// UseStateForUnknown never touches, so collapsing a non-nil-but-empty
// response slice to Null unconditionally (the bug -- fixed here) still
// crashes the apply with "Provider produced inconsistent result after
// apply" for that case -- see
// TestUnitAlgorithmDataResponseToResourceEntryPreservesEmptyBitLengthsAndCurves.
func algorithmDataResponseToResourceEntry(a v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse) EnrollmentPatternResourceAlgorithm {
	entry := EnrollmentPatternResourceAlgorithm{
		Name: nullableStringToTfString(a.Name),
	}
	if a.BitLengths == nil {
		entry.BitLengths = types.List{Null: true, ElemType: types.Int64Type}
	} else {
		entry.BitLengths = types.List{ElemType: types.Int64Type, Elems: convertIntArrayToTerraform(a.BitLengths)}
	}
	if a.Curves == nil {
		entry.Curves = types.List{Null: true, ElemType: types.StringType}
	} else {
		entry.Curves = stringSliceToTfList(a.Curves)
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
	// PrimaryKeyAlgorithms/AlternativeKeyAlgorithms themselves (the outer
	// slices, as opposed to each entry's nested BitLengths/Curves handled by
	// algorithmDataResponseToResourceEntry above) are subject to the
	// identical nil-vs-non-nil-empty bug -- see
	// enrollmentPatternAssociatedRolesToState's doc comment. Appending onto
	// a nil-initialized pol.PrimaryKeyAlgorithms/AlternativeKeyAlgorithms
	// (the bug -- fixed here) would collapse a non-nil-but-empty response
	// (`primary_key_algorithms = []`) back to nil/Null.
	if p.PrimaryKeyAlgorithms != nil {
		pol.PrimaryKeyAlgorithms = make([]EnrollmentPatternResourceAlgorithm, 0, len(p.PrimaryKeyAlgorithms))
		for _, algo := range p.PrimaryKeyAlgorithms {
			pol.PrimaryKeyAlgorithms = append(pol.PrimaryKeyAlgorithms, algorithmDataResponseToResourceEntry(algo))
		}
	}
	if p.AlternativeKeyAlgorithms != nil {
		pol.AlternativeKeyAlgorithms = make([]EnrollmentPatternResourceAlgorithm, 0, len(p.AlternativeKeyAlgorithms))
		for _, algo := range p.AlternativeKeyAlgorithms {
			pol.AlternativeKeyAlgorithms = append(pol.AlternativeKeyAlgorithms, algorithmDataResponseToResourceEntry(algo))
		}
	}
	return pol
}

// alwaysUnknownModifier plans its attribute as Unknown only when the config
// actually declares a definite `true` (or is itself still Unknown, e.g.
// chained from a not-yet-applied resource) -- i.e. only when the directive
// is genuinely being invoked this apply. Every other case (undeclared/Null
// config, or an explicit `false`) plans a stable Null.
//
// force_template_default is a one-shot, write-only directive: every CRUD
// path in this file unconditionally resolves it to Null in the final state
// (it is never persisted server-side, so there is nothing else it could
// resolve to). Without any modifier, a non-Computed attribute's planned
// value is exactly whatever the config declares -- e.g. `true`. Terraform
// Core then rejects the apply with "Provider produced inconsistent result
// after apply" the moment the final state (Null) disagrees with that
// planned value, which happens on literally the field's only real use case
// (declaring force_template_default = true). Marking the attribute Computed
// and planning it Unknown for that one case sidesteps the comparison
// entirely: Core accepts any final value -- including Null -- for an
// attribute whose planned value was Unknown.
//
// An earlier version of this modifier planned Unknown UNCONDITIONALLY,
// regardless of config/state. That over-applied to the overwhelmingly
// common case where force_template_default is never declared (or is
// declared false, which the request-building code below treats as
// equivalent to unset -- see Create()/Update()'s `!plan.ForceTemplateDefault
// .Null && !plan.ForceTemplateDefault.Unknown` guard before sending it):
// every subsequent `terraform plan` -- even with zero declared changes --
// reported `force_template_default = null -> (known after apply)`,
// forever, breaking a clean drift-check. Planning a stable Null for the
// undeclared/false case (mirroring useStateOrNullModifier's style) fixes
// that while still resolving to Unknown -- and thus still tolerating the
// always-Null final state -- for the one case that matters. This has no
// effect on whether the directive is actually honored: every CRUD path
// decodes the real value from Config (not Plan) to build the API request
// (see the comment above Create()'s request.Config.Get call), so the
// modifier only changes what Core expects to see afterward, not what gets
// sent to Command. See PR #210 full-review finding FIX-1 (original
// modifier) and round 2 finding FIX-A (perpetual-diff fix).
type alwaysUnknownModifier struct{}

func (m alwaysUnknownModifier) Description(_ context.Context) string {
	return "Plans this attribute as unknown when config declares (or may yet resolve to) true, so its final value is free to differ from the declared config value (including resolving to null); otherwise plans a stable null."
}

func (m alwaysUnknownModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m alwaysUnknownModifier) Modify(_ context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if cfg, ok := req.AttributeConfig.(types.Bool); ok {
		// Config not yet known (e.g. chained from a resource not yet
		// applied this run) -- it could still resolve to true, so stay
		// Unknown rather than risk a stable-Null plan that later disagrees
		// with a genuinely-true final config.
		if cfg.Unknown {
			resp.AttributePlan = types.Bool{Unknown: true}
			return
		}
		if !cfg.Null && cfg.Value {
			resp.AttributePlan = types.Bool{Unknown: true}
			return
		}
	}
	resp.AttributePlan = types.Bool{Null: true}
}

// resolveUnknownListToNull resolves an Unknown types.List to Null, leaving
// every other value (Null or known) untouched.
//
// Used for write-only list attributes (associated_role_names,
// certificate_authority_ids -- see KeyfactorEnrollmentPatternState's doc
// comment) whose Create-time plan value can legitimately still be Unknown
// when left undeclared in config: useStateOrNullModifier only carries a
// value forward from PRIOR state, and on Create there is no prior state at
// all (fwserver's StateGetAttributeValue returns a Go nil, not a typed Null,
// for every attribute when the whole state is nil), so the modifier's
// "nothing to carry forward" guard leaves the plan exactly as the
// framework's default Computed handling set it: Unknown. For most
// Optional+Computed fields that's fine -- Create()'s API response fills in
// the real value afterward. But these two fields are write-only: Command
// never echoes them back in any response, so there is no source of truth to
// resolve the Unknown plan value to except Null. Passing Unknown straight
// into response.State.Set makes the framework reject the whole Create with
// "Value Conversion Error: unhandled unknown value" -- reproduced live
// against kfclab via terraform/enrollment_pattern_demo (config that leaves
// certificate_authority_ids undeclared).
func resolveUnknownListToNull(l types.List) types.List {
	if l.Unknown {
		return types.List{Null: true, ElemType: l.ElemType}
	}
	return l
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
	// nil vs non-nil-empty matters here: the generated request models'
	// ToMap()/MarshalJSON() (see model_enrollment_patterns_enrollment_
	// pattern_policy_request.go) include a list field in the request body
	// whenever it is non-nil -- even zero-length -- and omit it only when
	// it is Go-nil. That means a non-nil empty slice IS how this SDK
	// expresses "explicitly clear this list back to empty" (unlike a
	// struct's own `encoding/json:"...,omitempty"` tag, which these
	// generated types don't actually rely on for marshaling). Gating on
	// `len(p.X) > 0` (the bug -- fixed here) treated a plan-declared empty
	// list (`primary_key_algorithms = []`) identically to an undeclared
	// one, silently omitting the field from the request instead of
	// clearing it server-side -- see PR #210 full-review finding F2 and
	// TestUnitBuildEnrollmentPatternPolicyRequestPreservesEmptyAlgorithmLists.
	if p.PrimaryKeyAlgorithms != nil {
		req.SetPrimaryKeyAlgorithms(buildAlgorithmDataRequestV2List(ctx, p.PrimaryKeyAlgorithms))
	}
	if p.AlternativeKeyAlgorithms != nil {
		req.SetAlternativeKeyAlgorithms(buildAlgorithmDataRequestV2List(ctx, p.AlternativeKeyAlgorithms))
	}
	return req
}

// buildAlgorithmDataRequestV2List preserves the nil-vs-non-nil-empty
// distinction of its input: a non-nil algos (even zero-length) must produce
// a non-nil result, or buildEnrollmentPatternPolicyRequest's `!= nil` gate
// above would be defeated by this function silently collapsing it back to
// nil (the same append-onto-nil-slice bug already fixed for the response
// conversion helpers above).
func buildAlgorithmDataRequestV2List(ctx context.Context, algos []EnrollmentPatternResourceAlgorithm) []v1.EnrollmentPatternsAlgorithmsAlgorithmDataRequestV2 {
	if algos == nil {
		return nil
	}
	result := make([]v1.EnrollmentPatternsAlgorithmsAlgorithmDataRequestV2, 0, len(algos))
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

// buildEnrollmentPatternRegexesRequest preserves the nil-vs-non-nil-empty
// distinction of its input -- see buildAlgorithmDataRequestV2List's doc
// comment; a non-nil plan (even zero-length) must produce a non-nil result
// so the request models' ToMap() includes an explicit `"Regexes": []`
// instead of omitting the field.
func buildEnrollmentPatternRegexesRequest(plan []EnrollmentPatternResourceRegex) []v1.EnrollmentPatternsEnrollmentPatternRegexesRequest {
	if plan == nil {
		return nil
	}
	result := make([]v1.EnrollmentPatternsEnrollmentPatternRegexesRequest, 0, len(plan))
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

// buildEnrollmentPatternMetadataFieldsRequest -- see
// buildEnrollmentPatternRegexesRequest's doc comment; identical
// nil-vs-non-nil-empty preservation for MetadataFields.
func buildEnrollmentPatternMetadataFieldsRequest(plan []EnrollmentPatternResourceMetadataField) []v1.EnrollmentPatternsEnrollmentPatternMetadataFieldRequest {
	if plan == nil {
		return nil
	}
	result := make([]v1.EnrollmentPatternsEnrollmentPatternMetadataFieldRequest, 0, len(plan))
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

// buildEnrollmentPatternDefaultsRequest -- see
// buildEnrollmentPatternRegexesRequest's doc comment; identical
// nil-vs-non-nil-empty preservation for Defaults.
func buildEnrollmentPatternDefaultsRequest(plan []EnrollmentPatternResourceDefault) []v1.EnrollmentPatternsEnrollmentPatternDefaultRequest {
	if plan == nil {
		return nil
	}
	result := make([]v1.EnrollmentPatternsEnrollmentPatternDefaultRequest, 0, len(plan))
	for _, d := range plan {
		entry := v1.EnrollmentPatternsEnrollmentPatternDefaultRequest{}
		entry.SetSubjectPart(d.SubjectPart.Value)
		entry.SetValue(d.Value.Value)
		result = append(result, entry)
	}
	return result
}

// buildEnrollmentPatternFieldsRequest -- see
// buildEnrollmentPatternRegexesRequest's doc comment; identical
// nil-vs-non-nil-empty preservation for EnrollmentFields.
func buildEnrollmentPatternFieldsRequest(ctx context.Context, plan []EnrollmentPatternResourceField) []v1.EnrollmentPatternsEnrollmentPatternFieldRequest {
	if plan == nil {
		return nil
	}
	result := make([]v1.EnrollmentPatternsEnrollmentPatternFieldRequest, 0, len(plan))
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
	// nil vs non-nil-empty (NOT len > 0) is the deliberate gate here -- see
	// buildEnrollmentPatternPolicyRequest's doc comment above for why: the
	// request models' ToMap() sends an explicit `[]` for any non-nil list,
	// so a plan-declared empty list (e.g. `regexes = []`) must reach
	// SetRegexes with a non-nil empty slice to actually clear the field
	// server-side, rather than being gated out and silently leaving the
	// prior value in place.
	if plan.Regexes != nil {
		req.SetRegexes(buildEnrollmentPatternRegexesRequest(plan.Regexes))
	}
	if plan.MetadataFields != nil {
		req.SetMetadataFields(buildEnrollmentPatternMetadataFieldsRequest(plan.MetadataFields))
	}
	if !plan.RestrictCAs.Null && !plan.RestrictCAs.Unknown {
		req.SetRestrictCAs(plan.RestrictCAs.Value)
	}
	if plan.Defaults != nil {
		req.SetDefaults(buildEnrollmentPatternDefaultsRequest(plan.Defaults))
	}
	if plan.EnrollmentFields != nil {
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
	// nil vs non-nil-empty (NOT len > 0) is the deliberate gate here -- see
	// buildEnrollmentPatternPolicyRequest's doc comment above for why: the
	// request models' ToMap() sends an explicit `[]` for any non-nil list,
	// so a plan-declared empty list (e.g. `regexes = []`) must reach
	// SetRegexes with a non-nil empty slice to actually clear the field
	// server-side, rather than being gated out and silently leaving the
	// prior value in place.
	if plan.Regexes != nil {
		req.SetRegexes(buildEnrollmentPatternRegexesRequest(plan.Regexes))
	}
	if plan.MetadataFields != nil {
		req.SetMetadataFields(buildEnrollmentPatternMetadataFieldsRequest(plan.MetadataFields))
	}
	if !plan.RestrictCAs.Null && !plan.RestrictCAs.Unknown {
		req.SetRestrictCAs(plan.RestrictCAs.Value)
	}
	if plan.Defaults != nil {
		req.SetDefaults(buildEnrollmentPatternDefaultsRequest(plan.Defaults))
	}
	if plan.EnrollmentFields != nil {
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
// Config validation
// ---------------------------------------------------------------------------

// ValidateConfig rejects config-time constraint violations before plan/apply
// ever runs -- see validateEnrollmentPatternConfigConstraints for the checks
// performed. Follows the same pattern as resourceCertificateAuthority.
// ValidateConfig (resource_keyfactor_certificate_authority.go).
func (r resourceEnrollmentPattern) ValidateConfig(
	ctx context.Context,
	request tfsdk.ValidateResourceConfigRequest,
	response *tfsdk.ValidateResourceConfigResponse,
) {
	LogFunctionEntry(ctx, "resourceEnrollmentPattern.ValidateConfig")

	var config KeyfactorEnrollmentPatternState
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	response.Diagnostics.Append(validateEnrollmentPatternConfigConstraints(config)...)

	LogFunctionExit(ctx, "resourceEnrollmentPattern.ValidateConfig")
}

// validateEnrollmentPatternConfigConstraints enforces two cross-field
// constraints that this resource's own schema descriptions document but,
// until now, nothing actually checked (PR #210 full-review round 2 findings
// F3/F4):
//
//  1. restrict_cas's description states "If true, at least one CA must be
//     configured" -- reject restrict_cas=true paired with an empty/undeclared
//     certificate_authority_ids.
//  2. use_ad_permissions's description states "If false, at least one value
//     must be provided for associated_role_names" -- reject
//     use_ad_permissions=false paired with an empty/undeclared
//     associated_role_names.
//
// A third, softer case is also flagged (as a warning, not an error):
// certificate_authority_ids declared non-empty while restrict_cas is
// explicitly false. Per restrict_cas's own description, the CA restriction
// only applies "if applicable (see restrict_cas)" -- i.e. only when
// restrict_cas is true -- so declaring certificate_authority_ids without
// restrict_cas=true is very likely a config mistake (the list is silently
// inert). This is deliberately a warning rather than a hard error: unlike
// the two required-value checks above, there is no live-lab confirmation
// that Command itself rejects or even meaningfully ignores this combination,
// and forcing an error here risks rejecting an otherwise legitimate config
// that stages certificate_authority_ids ahead of a later restrict_cas=true
// change.
//
// A null/unknown value for any attribute involved is never an error (or
// warning): ValidateConfig only ever sees Config, which cannot resolve a
// value that isn't known yet (e.g. a value chained from another
// not-yet-applied resource). Only explicitly configured, known values are
// checked. Factored out of ValidateConfig so it can be unit tested directly
// against a KeyfactorEnrollmentPatternState value.
func validateEnrollmentPatternConfigConstraints(cfg KeyfactorEnrollmentPatternState) diag.Diagnostics {
	var diags diag.Diagnostics

	restrictCAsKnown := !cfg.RestrictCAs.Null && !cfg.RestrictCAs.Unknown
	caIdsKnown := !cfg.CertificateAuthorityIds.Null && !cfg.CertificateAuthorityIds.Unknown
	caIdsDeclaredNonEmpty := caIdsKnown && len(cfg.CertificateAuthorityIds.Elems) > 0
	caIdsEmpty := cfg.CertificateAuthorityIds.Null || (caIdsKnown && len(cfg.CertificateAuthorityIds.Elems) == 0)

	if restrictCAsKnown && cfg.RestrictCAs.Value && caIdsEmpty {
		diags.AddAttributeError(
			path.Root("certificate_authority_ids"),
			"Missing certificate authorities for restrict_cas",
			"restrict_cas is set to true, which requires at least one entry in certificate_authority_ids.",
		)
	}

	if restrictCAsKnown && !cfg.RestrictCAs.Value && caIdsDeclaredNonEmpty {
		diags.AddAttributeWarning(
			path.Root("certificate_authority_ids"),
			"certificate_authority_ids has no effect",
			"certificate_authority_ids is declared, but restrict_cas is explicitly false, so the enrollment "+
				"pattern is not restricted to these certificate authorities. Set restrict_cas = true to enforce "+
				"this restriction, or remove certificate_authority_ids if it is not needed.",
		)
	}

	useADKnown := !cfg.UseADPermissions.Null && !cfg.UseADPermissions.Unknown
	if useADKnown && !cfg.UseADPermissions.Value {
		rolesKnown := !cfg.AssociatedRoleNames.Null && !cfg.AssociatedRoleNames.Unknown
		rolesEmpty := cfg.AssociatedRoleNames.Null || (rolesKnown && len(cfg.AssociatedRoleNames.Elems) == 0)
		if rolesEmpty {
			diags.AddAttributeError(
				path.Root("associated_role_names"),
				"Missing associated roles for use_ad_permissions = false",
				"use_ad_permissions is set to false, which requires at least one entry in associated_role_names.",
			)
		}
	}

	return diags
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

	// Decode from Config, not Plan. On Create there is no prior resource
	// state at all, so every Computed-only/Optional+Computed attribute this
	// schema derives entirely from the server response (template,
	// associated_roles, certificate_authorities, and Policies' nested
	// primary_key_algorithms/alternative_key_algorithms) is planned Unknown
	// by the framework's default Computed handling -- correctly so, since
	// Create()'s response below is what actually fills them in. But several
	// of these fields are backed by raw Go slice/struct types in
	// KeyfactorEnrollmentPatternState (not attr.Value types like
	// types.List), which cannot represent an Unknown tftypes value at all:
	// decoding request.Plan (which legitimately contains Unknown for them)
	// through the framework's reflection-based Get panics^Wfails with
	// "Value Conversion Error: unhandled unknown value" before this
	// function's own logic ever runs -- reproduced live against kfclab
	// (terraform/enrollment_pattern_demo, "policies = {}" left with its
	// primary_key_algorithms/alternative_key_algorithms sub-fields
	// undeclared). Config never contains this problem for these attributes:
	// they are Computed-only or Optional+Computed-and-undeclared, so Config
	// -- which reflects only what the user actually wrote in HCL, never the
	// framework's own "known after apply" placeholders -- always resolves
	// them to Null, which every one of these raw Go types can decode fine.
	// (Config CAN still be Unknown for a genuinely Optional attribute whose
	// value chains from another not-yet-applied resource; that pre-existing,
	// unrelated edge case is unchanged by this fix.) Update() is unaffected:
	// it always has prior state, so useStateOrNullModifier already carries
	// these fields forward as a known value instead of leaving them Unknown.
	var plan KeyfactorEnrollmentPatternState
	diags := request.Config.Get(ctx, &plan)
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
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error creating enrollment pattern.",
			fmt.Sprintf("creating enrollment pattern %q", plan.Name.Value),
		)...)
		return
	}

	newState := enrollmentPatternResponseToState(resp)
	// On Create there is no prior Terraform state at all, so
	// useStateOrNullModifier's Computed handling (see
	// resource_keyfactor_certificate_template.go) has nothing to carry
	// forward and correctly leaves an undeclared associated_role_names /
	// certificate_authority_ids Unknown in the plan -- that's the right
	// behavior for Optional+Computed fields in general (it lets other
	// resources fill the real value from the API response). But these two
	// fields are write-only: Command never echoes them back, so there is
	// no response-derived value either, and copying the still-Unknown plan
	// value straight into final state below makes the framework reject the
	// whole Create with "Value Conversion Error: unhandled unknown value".
	// Resolve to Null explicitly -- the only value actually available when
	// the field was never declared on first apply.
	newState.AssociatedRoleNames = resolveUnknownListToNull(plan.AssociatedRoleNames)
	newState.CertificateAuthorityIds = resolveUnknownListToNull(plan.CertificateAuthorityIds)
	newState.ForceTemplateDefault = types.Bool{Null: true}

	tflog.Debug(ctx, fmt.Sprintf("Created enrollment pattern ID %d", newState.ID.Value))
	// Field-level audit logging for the access-control-relevant fields set
	// on this initial create -- see enrollmentPatternCreationAuditFields's
	// doc comment (PR #210 full-review finding FIX-8). Info level matches
	// the level already used for the equivalent Update() diff logging
	// below (these fields -- role names, CA ids, policy enum settings --
	// are not free-text search content, unlike certificate_collection's
	// query field; see FIX-7).
	for _, field := range enrollmentPatternCreationAuditFields(ctx, newState, plan.ForceTemplateDefault) {
		tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %d field set on create: %s", newState.ID.Value, field))
	}

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
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error reading enrollment pattern.",
			fmt.Sprintf("reading enrollment pattern %d", state.ID.Value),
		)...)
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

	// Decode from Config, not Plan -- mirrors Create()'s handling (see the
	// comment above Create()'s request.Config.Get call). Several fields
	// (Template, AssociatedRoles, CertificateAuthorities, Policies'
	// PrimaryKeyAlgorithms/AlternativeKeyAlgorithms) are backed by raw Go
	// slice/struct types that cannot represent an Unknown tftypes value.
	// On Update() these are normally carried forward from prior state by
	// useStateOrNullModifier, but that modifier leaves the plan genuinely
	// Unknown whenever the attribute's OWN config value is itself Unknown
	// -- e.g. primary_key_algorithms chaining a value from another
	// resource not yet applied in the same run. Decoding request.Plan in
	// that case crashes with "Value Conversion Error: unhandled unknown
	// value" (PR #210 full-review finding FIX-3). Config never has this
	// problem for these attributes: they are Computed-only or left
	// undeclared, both of which Config always resolves to Null. Since plan
	// is now sourced from Config, it also doubles as the reliable "did the
	// user actually declare this attribute" signal (see
	// preserveUndeclaredTemplateFields's discussion of the same
	// distinction in resource_keyfactor_certificate_template.go), so the
	// previously-separate `config` decode is no longer needed.
	var plan KeyfactorEnrollmentPatternState
	diags := request.Config.Get(ctx, &plan)
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

	// Config never populates id -- it's computed-only, never written by a
	// user -- so always fall back to prior state for it.
	plan.ID = state.ID

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
	if current == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error reading enrollment pattern before update.",
			fmt.Sprintf("reading enrollment pattern %d to preserve its current field values", plan.ID.Value),
		)...)
		return
	}
	preserveUndeclaredEnrollmentPatternFields(&plan, current)

	// associated_role_names / certificate_authority_ids have no server-side
	// source of truth at all (see KeyfactorEnrollmentPatternState's doc
	// comment) -- fall back to this resource's own prior state, not the
	// fresh GET, when config leaves them undeclared (Null) OR when config
	// is Unknown (e.g. `associated_role_names =
	// [keyfactor_security_role.my_role.name]` where that role is created
	// in the same apply -- PR #210 full-review finding FIX-4). Without the
	// Unknown check, plan.AssociatedRoleNames/CertificateAuthorityIds would
	// stay Unknown all the way into newState below, and a final state must
	// never contain an Unknown value.
	if plan.AssociatedRoleNames.Null || plan.AssociatedRoleNames.Unknown {
		plan.AssociatedRoleNames = state.AssociatedRoleNames
	}
	if plan.CertificateAuthorityIds.Null || plan.CertificateAuthorityIds.Unknown {
		plan.CertificateAuthorityIds = state.CertificateAuthorityIds
	}

	// Audit-log old (prior state) vs new (final plan, post preservation)
	// values for policy-relevant fields before the API call actually
	// applies them -- PR #210 full-review finding F5. state is the
	// unmodified prior Terraform state; plan at this point already
	// reflects preserveUndeclaredEnrollmentPatternFields and the
	// associated_role_names/certificate_authority_ids fallback above, i.e.
	// exactly what buildEnrollmentPatternUpdateRequest is about to send.
	for _, change := range enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan) {
		tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %d field change on update: %s", plan.ID.Value, change))
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
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error updating enrollment pattern.",
			fmt.Sprintf("updating enrollment pattern %d", plan.ID.Value),
		)...)
		return
	}

	newState := enrollmentPatternResponseToState(resp)
	newState.AssociatedRoleNames = plan.AssociatedRoleNames
	newState.CertificateAuthorityIds = plan.CertificateAuthorityIds
	newState.ForceTemplateDefault = types.Bool{Null: true}

	// policies.default_certificate_owner_role_name can only be audited
	// accurately AFTER the update has actually been applied -- see
	// enrollmentPatternOwnerRoleNameChange's doc comment (PR #210 full-review
	// round 5 finding FIX-O). newState.Policies here is derived from `resp`,
	// the PUT response itself, so this reuses data already fetched rather
	// than issuing an extra GET.
	if change := enrollmentPatternOwnerRoleNameChange(state.Policies, newState.Policies); change != "" {
		tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %d field change on update: %s", plan.ID.Value, change))
	}

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
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error importing enrollment pattern.",
			fmt.Sprintf("reading enrollment pattern %d to import", id),
		)...)
		return
	}

	// GetById never returns AssociatedRoleNames/CertificateAuthorityIds in
	// their write shape, so an imported pattern starts with these null in
	// state -- the next apply will need them re-declared in configuration if
	// the user wants Terraform to manage them going forward (same caveat as
	// certificate_collection's Query field on import).
	//
	// enrollmentPatternResponseToState never touches these two fields, so
	// without the explicit assignment below they are left at Go's zero
	// value for types.List -- {Null: false, Unknown: false, ElemType: nil}.
	// That is NOT a valid "Null" list: response.State.Set's encoder requires
	// ElemType to be set even for a null value, and errors with "cannot
	// convert List to tftypes.Value if ElemType field is not set" --
	// reproduced live against kfclab (terraform/enrollment_pattern_demo's
	// `terraform import`).
	newState := enrollmentPatternResponseToState(resp)
	newState.AssociatedRoleNames = types.List{Null: true, ElemType: types.StringType}
	newState.CertificateAuthorityIds = types.List{Null: true, ElemType: types.Int64Type}
	newState.ForceTemplateDefault = types.Bool{Null: true}

	diags := response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
}
