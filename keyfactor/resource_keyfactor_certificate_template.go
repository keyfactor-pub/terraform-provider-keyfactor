package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ---------------------------------------------------------------------------
// Plan modifiers
// ---------------------------------------------------------------------------

// useStateOrNullModifier is like UseStateForUnknown but also replaces Unknown
// with null when the prior state is null. This is necessary for read-only list
// attributes backed by Go slice types (which cannot hold Unknown values): if
// the resource has no data for the list, the state is null and
// UseStateForUnknown would leave the plan Unknown, causing a type conversion
// error when the framework tries to deserialize the plan into the Go struct.
type useStateOrNullModifier struct{}

func (m useStateOrNullModifier) Description(_ context.Context) string {
	return "Uses prior state value if known; resolves to null when state is null."
}

func (m useStateOrNullModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m useStateOrNullModifier) Modify(_ context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	if req.AttributeConfig.IsUnknown() {
		return
	}
	// When state is unknown, we have nothing useful — leave plan as-is.
	if req.AttributeState.IsUnknown() {
		return
	}
	// Whether state is null or has a value, use the state (null → null, known → known).
	resp.AttributePlan = req.AttributeState
}

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

func templatePolicySchema() map[string]tfsdk.Attribute {
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
			Description:   "Whether RFC enforcement (require DNS SAN) is enabled.",
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
			Description:   "ID of the default certificate owner role.",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"default_certificate_owner_role_name": {
			Type:          types.StringType,
			Computed:      true,
			Description:   "Name of the default certificate owner role (read-only).",
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
		"key_info": {
			Optional:    true,
			Computed:    true,
			Description: "Key algorithm constraints for enrollment policy.",
			Attributes: tfsdk.SingleNestedAttributes(
				map[string]tfsdk.Attribute{
					"rsa": {
						Optional:    true,
						Computed:    true,
						Description: "RSA key constraints.",
						Attributes: tfsdk.SingleNestedAttributes(
							map[string]tfsdk.Attribute{
								"bit_lengths": {
									Type:          types.ListType{ElemType: types.Int64Type},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed RSA bit lengths.",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
								"curves": {
									Type:          types.ListType{ElemType: types.StringType},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed curves (unused for RSA).",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
							},
						),
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
					},
					"ecdsa": {
						Optional:    true,
						Computed:    true,
						Description: "ECDSA key constraints.",
						Attributes: tfsdk.SingleNestedAttributes(
							map[string]tfsdk.Attribute{
								"bit_lengths": {
									Type:          types.ListType{ElemType: types.Int64Type},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed ECDSA bit lengths.",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
								"curves": {
									Type:          types.ListType{ElemType: types.StringType},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed ECDSA curve OIDs.",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
							},
						),
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
					},
					"ed448": {
						Optional:    true,
						Computed:    true,
						Description: "Ed448 key constraints.",
						Attributes: tfsdk.SingleNestedAttributes(
							map[string]tfsdk.Attribute{
								"bit_lengths": {
									Type:          types.ListType{ElemType: types.Int64Type},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed Ed448 bit lengths.",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
								"curves": {
									Type:          types.ListType{ElemType: types.StringType},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed curves (unused for Ed448).",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
							},
						),
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
					},
					"ed25519": {
						Optional:    true,
						Computed:    true,
						Description: "Ed25519 key constraints.",
						Attributes: tfsdk.SingleNestedAttributes(
							map[string]tfsdk.Attribute{
								"bit_lengths": {
									Type:          types.ListType{ElemType: types.Int64Type},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed Ed25519 bit lengths.",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
								"curves": {
									Type:          types.ListType{ElemType: types.StringType},
									Optional:      true,
									Computed:      true,
									Description:   "Allowed curves (unused for Ed25519).",
									PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
								},
							},
						),
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
					},
				},
			),
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
		},
	}
}

// ---------------------------------------------------------------------------
// Resource type
// ---------------------------------------------------------------------------

type resourceCertificateTemplateType struct{}

func (r resourceCertificateTemplateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Description: "Manages a Keyfactor Command Certificate Template. Templates are created/deleted by importing from the CA — this resource only manages template settings (Update + Import). Setting `allowed_enrollment_types=0` effectively disables enrollment for the template.",
		Attributes: map[string]tfsdk.Attribute{
			// Identity
			"id": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Integer ID of the certificate template.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// Read-only (from CA/AD)
			"common_name": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Short name (common name) of the template as defined in the CA. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"template_name": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Display name of the template as defined in the CA. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"display_name": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Display name field from the server. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"oid": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "OID of the template. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_size": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Minimum key size from the CA. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_type": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Key type from the CA (e.g. RSA, ECC). Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_types": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Human-readable list of all supported key types. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"forest_root": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Forest root the template belongs to. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"configuration_tenant": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Configuration tenant. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_archival": {
				Type:          types.BoolType,
				Computed:      true,
				Description:   "Whether key archival is configured on the template. Read-only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// Writable fields
			"friendly_name": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Friendly name for the template. Deprecated in Command v25+.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_retention": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Key retention policy: 0=None, 1=SettingDriven, 2=Always, 3=Never.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_retention_days": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Number of days to retain private keys.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allowed_enrollment_types": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Bitmask of allowed enrollment types: 0=none (disabled), 1=PFX, 2=CSR, 3=both. Setting to 0 effectively disables the template. Deprecated in Command v25+ (use enrollment patterns).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"use_allowed_requesters": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to restrict enrollment to specific requesters. Deprecated in Command v25+ (use keyfactor_template_role_binding instead).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allowed_requesters": {
				Type:        types.ListType{ElemType: types.StringType},
				Optional:    true,
				Description: "List of security roles allowed to enroll. Deprecated in Command v25+ (use keyfactor_template_role_binding instead).",
			},
			"requires_approval": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether certificate enrollments require approval.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allow_one_click_renewals": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether one-click renewals are allowed.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_usage": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Key usage bitmask.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// Nested writable: template_policy
			"template_policy": {
				Optional:      true,
				Computed:      true,
				Description:   "Enrollment policy settings for the template.",
				Attributes:    tfsdk.SingleNestedAttributes(templatePolicySchema()),
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},

			// Nested writable lists
			"template_regexes": {
				Optional:    true,
				Description: "Subject field regex validation rules. Deprecated in Command v25+.",
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"subject_part": {
							Type:     types.StringType,
							Required: true,
						},
						"regex": {
							Type:     types.StringType,
							Required: true,
						},
						"error": {
							Type:     types.StringType,
							Optional: true,
							Computed: true,
						},
						"case_sensitive": {
							Type:     types.BoolType,
							Optional: true,
							Computed: true,
						},
					},
				),
			},
			"template_defaults": {
				Optional:    true,
				Description: "Default values for subject fields. Deprecated in Command v25+.",
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"subject_part": {
							Type:     types.StringType,
							Required: true,
						},
						"value": {
							Type:     types.StringType,
							Required: true,
						},
					},
				),
			},
			"enrollment_fields": {
				Optional:    true,
				Description: "Custom enrollment fields for CSR/PFX enrollment. Deprecated in Command v25+.",
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"id": {
							Type:          types.Int64Type,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"name": {
							Type:     types.StringType,
							Required: true,
						},
						"data_type": {
							Type:        types.Int64Type,
							Required:    true,
							Description: "1=String, 2=MultiValue.",
						},
						"options": {
							Type:     types.ListType{ElemType: types.StringType},
							Optional: true,
						},
					},
				),
			},
			"metadata_fields": {
				Optional:    true,
				Description: "Metadata field associations for this template.",
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"id": {
							Type:          types.Int64Type,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"metadata_id": {
							Type:        types.Int64Type,
							Required:    true,
							Description: "ID of the metadata field definition.",
						},
						"default_value": {
							Type:     types.StringType,
							Optional: true,
							Computed: true,
						},
						"validation": {
							Type:     types.StringType,
							Optional: true,
							Computed: true,
						},
						"enrollment": {
							Type:          types.Int64Type,
							Optional:      true,
							Computed:      true,
							Description:   "Enrollment requirement: 0=None, 1=Optional, 2=Required.",
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
						},
						"message": {
							Type:     types.StringType,
							Optional: true,
							Computed: true,
						},
						"case_sensitive": {
							Type:     types.BoolType,
							Optional: true,
							Computed: true,
						},
					},
				),
			},

			// Read-only nested lists
			"extended_key_usages": {
				Computed:      true,
				Description:   "Extended key usages defined on the template (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"id": {
							Type:     types.Int64Type,
							Computed: true,
						},
						"oid": {
							Type:     types.StringType,
							Computed: true,
						},
						"display_name": {
							Type:     types.StringType,
							Computed: true,
						},
					},
				),
			},
			"key_algorithms": {
				Computed:      true,
				Description:   "Supported key algorithms reported by the CA (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"algorithm": {
							Type:     types.StringType,
							Computed: true,
						},
						"bit_lengths": {
							Type:     types.ListType{ElemType: types.Int64Type},
							Computed: true,
						},
						"curves": {
							Type:     types.ListType{ElemType: types.StringType},
							Computed: true,
						},
					},
				),
			},

			// v25+ fields
			"manageability": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Manageability level (Command v25+, read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"certificate_cleanup_enabled": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether expired certificate cleanup is enabled (Command v25+).",
			},
			"time_after_expiration": {
				Type:        types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "Time after expiration before cleanup eligibility (Command v25+).",
			},
			"time_after_expiration_units": {
				Type:        types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "Units for time_after_expiration: 0=Days, 1=Weeks, 2=Months (Command v25+).",
			},
			"delete_with_archived_key": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether to delete certificates with archived keys during cleanup (Command v25+).",
			},
		},
	}, nil
}

func (r resourceCertificateTemplateType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCertificateTemplate{p: *(p.(*provider))}, nil
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

type resourceCertificateTemplate struct {
	p provider
}

type TemplateKeyAlgorithmEntry struct {
	Algorithm  types.String `tfsdk:"algorithm"`
	BitLengths types.List   `tfsdk:"bit_lengths"`
	Curves     types.List   `tfsdk:"curves"`
}

type TemplateEKUEntry struct {
	ID          types.Int64  `tfsdk:"id"`
	OID         types.String `tfsdk:"oid"`
	DisplayName types.String `tfsdk:"display_name"`
}

type TemplateRegexEntry struct {
	SubjectPart   types.String `tfsdk:"subject_part"`
	Regex         types.String `tfsdk:"regex"`
	Error         types.String `tfsdk:"error"`
	CaseSensitive types.Bool   `tfsdk:"case_sensitive"`
}

type TemplateDefaultEntry struct {
	SubjectPart types.String `tfsdk:"subject_part"`
	Value       types.String `tfsdk:"value"`
}

type TemplateEnrollmentFieldEntry struct {
	ID       types.Int64  `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	DataType types.Int64  `tfsdk:"data_type"`
	Options  types.List   `tfsdk:"options"`
}

type TemplateMetadataFieldEntry struct {
	ID            types.Int64  `tfsdk:"id"`
	MetadataID    types.Int64  `tfsdk:"metadata_id"`
	DefaultValue  types.String `tfsdk:"default_value"`
	Validation    types.String `tfsdk:"validation"`
	Enrollment    types.Int64  `tfsdk:"enrollment"`
	Message       types.String `tfsdk:"message"`
	CaseSensitive types.Bool   `tfsdk:"case_sensitive"`
}

type TemplateKeyInfoAlgorithm struct {
	BitLengths types.List `tfsdk:"bit_lengths"`
	Curves     types.List `tfsdk:"curves"`
}

type TemplateKeyInfo struct {
	RSA     *TemplateKeyInfoAlgorithm `tfsdk:"rsa"`
	ECDSA   *TemplateKeyInfoAlgorithm `tfsdk:"ecdsa"`
	Ed448   *TemplateKeyInfoAlgorithm `tfsdk:"ed448"`
	Ed25519 *TemplateKeyInfoAlgorithm `tfsdk:"ed25519"`
}

type TemplatePolicyState struct {
	AllowKeyReuse                   types.Bool       `tfsdk:"allow_key_reuse"`
	AllowWildcards                  types.Bool       `tfsdk:"allow_wildcards"`
	RFCEnforcement                  types.Bool       `tfsdk:"rfc_enforcement"`
	CertificateOwnerRole            types.Int64      `tfsdk:"certificate_owner_role"`
	DefaultCertificateOwnerRoleID   types.Int64      `tfsdk:"default_certificate_owner_role_id"`
	DefaultCertificateOwnerRoleName types.String     `tfsdk:"default_certificate_owner_role_name"`
	KeyInfo                         *TemplateKeyInfo `tfsdk:"key_info"`
}

type KeyfactorCertificateTemplateState struct {
	// Identity
	ID types.Int64 `tfsdk:"id"`

	// Read-only from CA
	CommonName          types.String `tfsdk:"common_name"`
	TemplateName        types.String `tfsdk:"template_name"`
	DisplayName         types.String `tfsdk:"display_name"`
	OID                 types.String `tfsdk:"oid"`
	KeySize             types.String `tfsdk:"key_size"`
	KeyType             types.String `tfsdk:"key_type"`
	KeyTypes            types.String `tfsdk:"key_types"`
	ForestRoot          types.String `tfsdk:"forest_root"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
	KeyArchival         types.Bool   `tfsdk:"key_archival"`

	// Writable
	FriendlyName           types.String `tfsdk:"friendly_name"`
	KeyRetention           types.Int64  `tfsdk:"key_retention"`
	KeyRetentionDays       types.Int64  `tfsdk:"key_retention_days"`
	AllowedEnrollmentTypes types.Int64  `tfsdk:"allowed_enrollment_types"`
	UseAllowedRequesters   types.Bool   `tfsdk:"use_allowed_requesters"`
	AllowedRequesters      types.List   `tfsdk:"allowed_requesters"`
	RequiresApproval       types.Bool   `tfsdk:"requires_approval"`
	AllowOneClickRenewals  types.Bool   `tfsdk:"allow_one_click_renewals"`
	KeyUsage               types.Int64  `tfsdk:"key_usage"`

	// Nested writable
	TemplatePolicy   *TemplatePolicyState           `tfsdk:"template_policy"`
	TemplateRegexes  []TemplateRegexEntry           `tfsdk:"template_regexes"`
	TemplateDefaults []TemplateDefaultEntry         `tfsdk:"template_defaults"`
	EnrollmentFields []TemplateEnrollmentFieldEntry `tfsdk:"enrollment_fields"`
	MetadataFields   []TemplateMetadataFieldEntry   `tfsdk:"metadata_fields"`

	// Read-only nested
	ExtendedKeyUsages []TemplateEKUEntry          `tfsdk:"extended_key_usages"`
	KeyAlgorithms     []TemplateKeyAlgorithmEntry `tfsdk:"key_algorithms"`

	// v25+ read-only
	Manageability             types.Int64 `tfsdk:"manageability"`
	CertificateCleanupEnabled types.Bool  `tfsdk:"certificate_cleanup_enabled"`
	TimeAfterExpiration       types.Int64 `tfsdk:"time_after_expiration"`
	TimeAfterExpirationUnits  types.Int64 `tfsdk:"time_after_expiration_units"`
	DeleteWithArchivedKey     types.Bool  `tfsdk:"delete_with_archived_key"`
}

// ---------------------------------------------------------------------------
// Response → State conversion
// ---------------------------------------------------------------------------

func templateResponseToState(resp *v1.TemplatesTemplateRetrievalResponse) KeyfactorCertificateTemplateState {
	state := KeyfactorCertificateTemplateState{
		ID:                     types.Int64{Value: int64(resp.GetId())},
		CommonName:             types.String{Value: resp.GetCommonName()},
		TemplateName:           types.String{Value: resp.GetTemplateName()},
		DisplayName:            types.String{Value: resp.GetDisplayName()},
		OID:                    types.String{Value: resp.GetOid()},
		KeySize:                types.String{Value: resp.GetKeySize()},
		KeyType:                types.String{Value: resp.GetKeyType()},
		KeyTypes:               types.String{Value: resp.GetKeyTypes()},
		ForestRoot:             types.String{Value: resp.GetForestRoot()},
		ConfigurationTenant:    types.String{Value: resp.GetConfigurationTenant()},
		KeyArchival:            types.Bool{Value: resp.GetKeyArchival()},
		FriendlyName:           types.String{Value: resp.GetFriendlyName()},
		KeyRetentionDays:       nullableInt32ToTfInt64(resp.KeyRetentionDays),
		AllowedEnrollmentTypes: types.Int64{Value: int64(resp.GetAllowedEnrollmentTypes())},
		UseAllowedRequesters:   types.Bool{Value: resp.GetUseAllowedRequesters()},
		RequiresApproval:       types.Bool{Value: resp.GetRequiresApproval()},
		AllowOneClickRenewals:  types.Bool{Value: resp.GetAllowOneClickRenewals()},
		KeyUsage:               types.Int64{Value: int64(resp.GetKeyUsage())},
	}

	// Manageability (v25+)
	if resp.Manageability.IsSet() && resp.Manageability.Get() != nil {
		state.Manageability = types.Int64{Value: int64(resp.GetManageability())}
	} else {
		state.Manageability = types.Int64{Null: true}
	}

	// CertificateCleanupEnabled
	if resp.CertificateCleanupEnabled.IsSet() {
		state.CertificateCleanupEnabled = types.Bool{Value: resp.GetCertificateCleanupEnabled()}
	} else {
		state.CertificateCleanupEnabled = types.Bool{Null: true}
	}
	// TimeAfterExpiration
	if resp.TimeAfterExpiration.IsSet() {
		state.TimeAfterExpiration = types.Int64{Value: int64(resp.GetTimeAfterExpiration())}
	} else {
		state.TimeAfterExpiration = types.Int64{Null: true}
	}
	// TimeAfterExpirationUnits
	if resp.TimeAfterExpirationUnits != nil {
		state.TimeAfterExpirationUnits = types.Int64{Value: int64(*resp.TimeAfterExpirationUnits)}
	} else {
		state.TimeAfterExpirationUnits = types.Int64{Null: true}
	}
	// DeleteWithArchivedKey
	if resp.DeleteWithArchivedKey.IsSet() {
		state.DeleteWithArchivedKey = types.Bool{Value: resp.GetDeleteWithArchivedKey()}
	} else {
		state.DeleteWithArchivedKey = types.Bool{Null: true}
	}

	// KeyRetention enum → int
	if resp.KeyRetention != nil {
		state.KeyRetention = types.Int64{Value: int64(*resp.KeyRetention)}
	} else {
		state.KeyRetention = types.Int64{Null: true}
	}

	// AllowedRequesters
	if len(resp.AllowedRequesters) > 0 {
		state.AllowedRequesters = stringSliceToTfList(resp.AllowedRequesters)
	} else {
		state.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}
	}

	// TemplatePolicy
	if resp.TemplatePolicy != nil {
		p := resp.TemplatePolicy
		pol := &TemplatePolicyState{}
		if p.AllowKeyReuse.Get() != nil {
			pol.AllowKeyReuse = types.Bool{Value: *p.AllowKeyReuse.Get()}
		} else {
			pol.AllowKeyReuse = types.Bool{Null: true}
		}
		if p.AllowWildcards.Get() != nil {
			pol.AllowWildcards = types.Bool{Value: *p.AllowWildcards.Get()}
		} else {
			pol.AllowWildcards = types.Bool{Null: true}
		}
		if p.RFCEnforcement.Get() != nil {
			pol.RFCEnforcement = types.Bool{Value: *p.RFCEnforcement.Get()}
		} else {
			pol.RFCEnforcement = types.Bool{Null: true}
		}
		if p.CertificateOwnerRole != nil {
			pol.CertificateOwnerRole = types.Int64{Value: int64(*p.CertificateOwnerRole)}
		} else {
			pol.CertificateOwnerRole = types.Int64{Null: true}
		}
		pol.DefaultCertificateOwnerRoleID = nullableInt32ToTfInt64(p.DefaultCertificateOwnerRoleId)
		pol.DefaultCertificateOwnerRoleName = nullableStringToTfString(p.DefaultCertificateOwnerRoleName)

		if p.KeyInfo != nil {
			pol.KeyInfo = algorithmDataToKeyInfo(p.KeyInfo)
		}
		state.TemplatePolicy = pol
	}

	// TemplateRegexes
	for _, rx := range resp.TemplateRegexes {
		entry := TemplateRegexEntry{
			SubjectPart:   nullableStringToTfString(rx.SubjectPart),
			Regex:         nullableStringToTfString(rx.Regex),
			Error:         nullableStringToTfString(rx.Error),
			CaseSensitive: types.Bool{Value: rx.GetCaseSensitive()},
		}
		state.TemplateRegexes = append(state.TemplateRegexes, entry)
	}

	// TemplateDefaults
	for _, def := range resp.TemplateDefaults {
		state.TemplateDefaults = append(
			state.TemplateDefaults, TemplateDefaultEntry{
				SubjectPart: nullableStringToTfString(def.SubjectPart),
				Value:       nullableStringToTfString(def.Value),
			},
		)
	}

	// EnrollmentFields
	for _, ef := range resp.EnrollmentFields {
		entry := TemplateEnrollmentFieldEntry{
			ID:   types.Int64{Value: int64(ef.GetId())},
			Name: nullableStringToTfString(ef.Name),
		}
		if ef.DataType != nil {
			entry.DataType = types.Int64{Value: int64(*ef.DataType)}
		}
		if len(ef.Options) > 0 {
			entry.Options = stringSliceToTfList(ef.Options)
		} else {
			entry.Options = types.List{Null: true, ElemType: types.StringType}
		}
		state.EnrollmentFields = append(state.EnrollmentFields, entry)
	}

	// MetadataFields
	for _, mf := range resp.MetadataFields {
		entry := TemplateMetadataFieldEntry{
			ID:            types.Int64{Value: int64(mf.GetId())},
			MetadataID:    types.Int64{Value: int64(mf.GetMetadataId())},
			DefaultValue:  nullableStringToTfString(mf.DefaultValue),
			Validation:    nullableStringToTfString(mf.Validation),
			Message:       nullableStringToTfString(mf.Message),
			CaseSensitive: types.Bool{Value: mf.GetCaseSensitive()},
		}
		if mf.Enrollment != nil {
			entry.Enrollment = types.Int64{Value: int64(*mf.Enrollment)}
		}
		state.MetadataFields = append(state.MetadataFields, entry)
	}

	// ExtendedKeyUsages
	for _, eku := range resp.ExtendedKeyUsages {
		state.ExtendedKeyUsages = append(
			state.ExtendedKeyUsages, TemplateEKUEntry{
				ID:          types.Int64{Value: int64(eku.GetId())},
				OID:         nullableStringToTfString(eku.Oid),
				DisplayName: nullableStringToTfString(eku.DisplayName),
			},
		)
	}

	// KeyAlgorithms (from KeyAlgorithms.KeyInfo in the SDK struct)
	if resp.KeyAlgorithms != nil && resp.KeyAlgorithms.KeyInfo != nil {
		ki := resp.KeyAlgorithms.KeyInfo
		algEntries := map[string]*v1.CSSCMSDataModelModelsTemplatesAlgorithmsAlgorithmData{
			"RSA":     ki.RSA,
			"ECDSA":   ki.ECDSA,
			"Ed448":   ki.Ed448,
			"Ed25519": ki.Ed25519,
		}
		for _, name := range []string{"RSA", "ECDSA", "Ed448", "Ed25519"} {
			data := algEntries[name]
			if data == nil {
				continue
			}
			entry := TemplateKeyAlgorithmEntry{
				Algorithm: types.String{Value: name},
			}
			// bit_lengths
			if len(data.BitLengths) > 0 {
				elems := make([]attr.Value, len(data.BitLengths))
				for i, bl := range data.BitLengths {
					elems[i] = types.Int64{Value: int64(bl)}
				}
				entry.BitLengths = types.List{ElemType: types.Int64Type, Elems: elems}
			} else {
				entry.BitLengths = types.List{Null: true, ElemType: types.Int64Type}
			}
			// curves
			if len(data.Curves) > 0 {
				entry.Curves = stringSliceToTfList(data.Curves)
			} else {
				entry.Curves = types.List{Null: true, ElemType: types.StringType}
			}
			state.KeyAlgorithms = append(state.KeyAlgorithms, entry)
		}
	}

	return state
}

func algorithmDataToKeyInfo(ki *v1.CSSCMSDataModelModelsTemplatesAlgorithmsKeyInfo) *TemplateKeyInfo {
	result := &TemplateKeyInfo{}
	result.RSA = algorithmDataToEntry(ki.RSA)
	result.ECDSA = algorithmDataToEntry(ki.ECDSA)
	result.Ed448 = algorithmDataToEntry(ki.Ed448)
	result.Ed25519 = algorithmDataToEntry(ki.Ed25519)
	return result
}

func algorithmDataToEntry(data *v1.CSSCMSDataModelModelsTemplatesAlgorithmsAlgorithmData) *TemplateKeyInfoAlgorithm {
	if data == nil {
		return nil
	}
	entry := &TemplateKeyInfoAlgorithm{}
	if len(data.BitLengths) > 0 {
		elems := make([]attr.Value, len(data.BitLengths))
		for i, bl := range data.BitLengths {
			elems[i] = types.Int64{Value: int64(bl)}
		}
		entry.BitLengths = types.List{ElemType: types.Int64Type, Elems: elems}
	} else {
		entry.BitLengths = types.List{Null: true, ElemType: types.Int64Type}
	}
	if len(data.Curves) > 0 {
		entry.Curves = stringSliceToTfList(data.Curves)
	} else {
		entry.Curves = types.List{Null: true, ElemType: types.StringType}
	}
	return entry
}

// ---------------------------------------------------------------------------
// State → Update Request conversion
// ---------------------------------------------------------------------------

func buildTemplateUpdateRequest(
	ctx context.Context,
	plan KeyfactorCertificateTemplateState,
) v1.TemplatesTemplateUpdateRequest {
	id := int32(plan.ID.Value)
	req := v1.TemplatesTemplateUpdateRequest{Id: &id}

	if !plan.FriendlyName.Null && !plan.FriendlyName.Unknown {
		req.SetFriendlyName(plan.FriendlyName.Value)
	}
	if !plan.KeyRetention.Null && !plan.KeyRetention.Unknown {
		kr := v1.CSSCMSCoreEnumsKeyRetentionPolicy(int32(plan.KeyRetention.Value))
		req.KeyRetention = &kr
	}
	if !plan.KeyRetentionDays.Null && !plan.KeyRetentionDays.Unknown {
		req.SetKeyRetentionDays(int32(plan.KeyRetentionDays.Value))
	}
	if !plan.AllowedEnrollmentTypes.Null && !plan.AllowedEnrollmentTypes.Unknown {
		et := v1.CSSCMSCoreEnumsEnrollmentType(int32(plan.AllowedEnrollmentTypes.Value))
		req.AllowedEnrollmentTypes = &et
	}
	if !plan.UseAllowedRequesters.Null && !plan.UseAllowedRequesters.Unknown {
		v := plan.UseAllowedRequesters.Value
		req.UseAllowedRequesters = &v
	}
	if !plan.AllowedRequesters.Null && !plan.AllowedRequesters.Unknown {
		var requesters []string
		plan.AllowedRequesters.ElementsAs(ctx, &requesters, false)
		req.AllowedRequesters = requesters
	}
	if !plan.RequiresApproval.Null && !plan.RequiresApproval.Unknown {
		v := plan.RequiresApproval.Value
		req.RequiresApproval = &v
	}
	if !plan.AllowOneClickRenewals.Null && !plan.AllowOneClickRenewals.Unknown {
		v := plan.AllowOneClickRenewals.Value
		req.AllowOneClickRenewals = &v
	}
	if !plan.KeyUsage.Null && !plan.KeyUsage.Unknown {
		ku := int32(plan.KeyUsage.Value)
		req.KeyUsage = &ku
	}
	if !plan.CertificateCleanupEnabled.Null && !plan.CertificateCleanupEnabled.Unknown {
		req.SetCertificateCleanupEnabled(plan.CertificateCleanupEnabled.Value)
	}
	if !plan.TimeAfterExpiration.Null && !plan.TimeAfterExpiration.Unknown {
		req.SetTimeAfterExpiration(int32(plan.TimeAfterExpiration.Value))
	}
	if !plan.TimeAfterExpirationUnits.Null && !plan.TimeAfterExpirationUnits.Unknown {
		units := v1.CSSCMSDataModelEnumsCertificateCleanupTimeUnits(plan.TimeAfterExpirationUnits.Value)
		req.SetTimeAfterExpirationUnits(units)
	}
	if !plan.DeleteWithArchivedKey.Null && !plan.DeleteWithArchivedKey.Unknown {
		req.SetDeleteWithArchivedKey(plan.DeleteWithArchivedKey.Value)
	}

	// TemplatePolicy
	if plan.TemplatePolicy != nil {
		pol := &v1.TemplatesTemplatePolicyRequestModel{}
		p := plan.TemplatePolicy
		if !p.AllowKeyReuse.Null && !p.AllowKeyReuse.Unknown {
			pol.SetAllowKeyReuse(p.AllowKeyReuse.Value)
		}
		if !p.AllowWildcards.Null && !p.AllowWildcards.Unknown {
			pol.SetAllowWildcards(p.AllowWildcards.Value)
		}
		if !p.RFCEnforcement.Null && !p.RFCEnforcement.Unknown {
			pol.SetRFCEnforcement(p.RFCEnforcement.Value)
		}
		if !p.CertificateOwnerRole.Null && !p.CertificateOwnerRole.Unknown {
			role := v1.CSSCMSCoreEnumsTemplateCertificateOwnerRole(int32(p.CertificateOwnerRole.Value))
			pol.CertificateOwnerRole = &role
		}
		if !p.DefaultCertificateOwnerRoleID.Null && !p.DefaultCertificateOwnerRoleID.Unknown {
			pol.SetDefaultCertificateOwnerRoleId(int32(p.DefaultCertificateOwnerRoleID.Value))
		}
		if p.KeyInfo != nil {
			pol.KeyInfo = buildKeyInfoRequest(p.KeyInfo)
		}
		req.TemplatePolicy = pol
	}

	// TemplateRegexes
	if len(plan.TemplateRegexes) > 0 {
		var regexes []v1.TemplatesTemplateRegexRequestResponseModel
		for _, rx := range plan.TemplateRegexes {
			entry := v1.TemplatesTemplateRegexRequestResponseModel{}
			entry.SetSubjectPart(rx.SubjectPart.Value)
			entry.SetRegex(rx.Regex.Value)
			if !rx.Error.Null && !rx.Error.Unknown {
				entry.SetError(rx.Error.Value)
			}
			if !rx.CaseSensitive.Null && !rx.CaseSensitive.Unknown {
				v := rx.CaseSensitive.Value
				entry.CaseSensitive = &v
			}
			regexes = append(regexes, entry)
		}
		req.TemplateRegexes = regexes
	}

	// TemplateDefaults
	if len(plan.TemplateDefaults) > 0 {
		var defaults []v1.TemplatesTemplateDefaultRequestResponseModel
		for _, def := range plan.TemplateDefaults {
			entry := v1.TemplatesTemplateDefaultRequestResponseModel{}
			entry.SetSubjectPart(def.SubjectPart.Value)
			entry.SetValue(def.Value.Value)
			defaults = append(defaults, entry)
		}
		req.TemplateDefaults = defaults
	}

	// EnrollmentFields
	if len(plan.EnrollmentFields) > 0 {
		var fields []v1.TemplatesTemplateEnrollmentFieldRequestResponseModel
		for _, ef := range plan.EnrollmentFields {
			entry := v1.TemplatesTemplateEnrollmentFieldRequestResponseModel{}
			if !ef.ID.Null && !ef.ID.Unknown && ef.ID.Value != 0 {
				id32 := int32(ef.ID.Value)
				entry.Id = &id32
			}
			entry.SetName(ef.Name.Value)
			if !ef.DataType.Null && !ef.DataType.Unknown {
				dt := v1.CSSCMSCoreEnumsTemplateEnrollmentFieldType(int32(ef.DataType.Value))
				entry.DataType = &dt
			}
			if !ef.Options.Null && !ef.Options.Unknown {
				var opts []string
				ef.Options.ElementsAs(ctx, &opts, false)
				entry.Options = opts
			}
			fields = append(fields, entry)
		}
		req.EnrollmentFields = fields
	}

	// MetadataFields
	if len(plan.MetadataFields) > 0 {
		var fields []v1.TemplatesTemplateMetadataFieldRequestResponseModel
		for _, mf := range plan.MetadataFields {
			entry := v1.TemplatesTemplateMetadataFieldRequestResponseModel{}
			if !mf.ID.Null && !mf.ID.Unknown && mf.ID.Value != 0 {
				id32 := int32(mf.ID.Value)
				entry.Id = &id32
			}
			mid := int32(mf.MetadataID.Value)
			entry.MetadataId = &mid
			if !mf.DefaultValue.Null && !mf.DefaultValue.Unknown {
				entry.SetDefaultValue(mf.DefaultValue.Value)
			}
			if !mf.Validation.Null && !mf.Validation.Unknown {
				entry.SetValidation(mf.Validation.Value)
			}
			if !mf.Message.Null && !mf.Message.Unknown {
				entry.SetMessage(mf.Message.Value)
			}
			if !mf.CaseSensitive.Null && !mf.CaseSensitive.Unknown {
				v := mf.CaseSensitive.Value
				entry.CaseSensitive = &v
			}
			if !mf.Enrollment.Null && !mf.Enrollment.Unknown {
				en := v1.CSSCMSCoreEnumsMetadataTypeEnrollment(int32(mf.Enrollment.Value))
				entry.Enrollment = &en
			}
			fields = append(fields, entry)
		}
		req.MetadataFields = fields
	}

	return req
}

func buildKeyInfoRequest(ki *TemplateKeyInfo) *v1.CSSCMSDataModelModelsTemplatesAlgorithmsKeyInfo {
	result := &v1.CSSCMSDataModelModelsTemplatesAlgorithmsKeyInfo{}
	result.RSA = buildAlgorithmDataRequest(ki.RSA)
	result.ECDSA = buildAlgorithmDataRequest(ki.ECDSA)
	result.Ed448 = buildAlgorithmDataRequest(ki.Ed448)
	result.Ed25519 = buildAlgorithmDataRequest(ki.Ed25519)
	return result
}

func buildAlgorithmDataRequest(entry *TemplateKeyInfoAlgorithm) *v1.CSSCMSDataModelModelsTemplatesAlgorithmsAlgorithmData {
	if entry == nil {
		return nil
	}
	data := &v1.CSSCMSDataModelModelsTemplatesAlgorithmsAlgorithmData{}
	if !entry.BitLengths.Null && !entry.BitLengths.Unknown {
		var lengths []int64
		entry.BitLengths.ElementsAs(context.Background(), &lengths, false)
		for _, l := range lengths {
			data.BitLengths = append(data.BitLengths, int32(l))
		}
	}
	if !entry.Curves.Null && !entry.Curves.Unknown {
		var curves []string
		entry.Curves.ElementsAs(context.Background(), &curves, false)
		data.Curves = curves
	}
	return data
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r resourceCertificateTemplate) Create(
	_ context.Context,
	_ tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	response.Diagnostics.AddError(
		"Cannot create Certificate Template.",
		"Templates are created by importing them from the CA into Keyfactor Command. Use `terraform import keyfactor_certificate_template.<name> <id>` to bring an existing template under management.",
	)
}

func (r resourceCertificateTemplate) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateTemplate.Read")

	var state KeyfactorCertificateTemplateState
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading certificate template ID %d", state.ID.Value))

	templateAPI := r.p.sdkClient.V1.TemplateApi
	req := templateAPI.NewGetTemplatesByIdRequest(ctx, int32(state.ID.Value))
	resp, httpResp, err := req.Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("Template %d not found, removing from state", state.ID.Value))
			response.State.RemoveResource(ctx)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading certificate template.",
			fmt.Sprintf("Could not read template %d: %s. Details: %s", state.ID.Value, err.Error(), body),
		)
		return
	}

	newState := templateResponseToState(resp)
	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateTemplate.Read")
}

func (r resourceCertificateTemplate) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateTemplate.Update")

	var plan KeyfactorCertificateTemplateState
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var state KeyfactorCertificateTemplateState
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	// Carry ID from state (plan has it as Unknown during import)
	if plan.ID.Value == 0 {
		plan.ID = state.ID
	}

	tflog.Info(ctx, fmt.Sprintf("Updating certificate template ID %d", plan.ID.Value))

	updateReq := buildTemplateUpdateRequest(ctx, plan)
	templateAPI := r.p.sdkClient.V1.TemplateApi
	req := templateAPI.NewUpdateTemplatesRequest(ctx).TemplatesTemplateUpdateRequest(updateReq)
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error updating certificate template.",
			fmt.Sprintf("Could not update template %d: %s. Details: %s", plan.ID.Value, err.Error(), body),
		)
		return
	}

	newState := templateResponseToState(resp)
	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateTemplate.Update")
}

func (r resourceCertificateTemplate) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	// Templates cannot be deleted via API — just remove from state.
	tflog.Info(
		ctx,
		"Delete called on certificate template — removing from state only. Templates must be removed from the CA directly.",
	)
}

func (r resourceCertificateTemplate) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("ImportState called on certificate template with ID %q", request.ID))

	id, err := strconv.Atoi(request.ID)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid template ID.",
			fmt.Sprintf("Import ID must be an integer, got %q: %s", request.ID, err.Error()),
		)
		return
	}

	templateAPI := r.p.sdkClient.V1.TemplateApi
	req := templateAPI.NewGetTemplatesByIdRequest(ctx, int32(id))
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error importing certificate template.",
			fmt.Sprintf("Could not read template %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	state := templateResponseToState(resp)
	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
}
