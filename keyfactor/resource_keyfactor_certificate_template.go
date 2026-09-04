package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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

// displayNameFollowsFriendlyNameModifier resolves display_name's plan the way
// tfsdk.UseStateForUnknown would (prior state value carried forward) EXCEPT
// when friendly_name is itself changing this apply. display_name is a
// Computed, read-only field that Command derives from friendly_name (the
// server mirrors a configured friendly_name back as display_name once one is
// set) -- pinning display_name to the prior state's value with a plain
// UseStateForUnknown modifier is only safe when friendly_name is NOT
// changing. When friendly_name IS changing, display_name must be left
// Unknown so Update()'s response can populate the new server-derived value
// without the framework rejecting it as "Provider produced inconsistent
// result after apply" (the stale prior value would otherwise be pinned as
// the "planned" value, which the real post-apply value legitimately no
// longer matches). See dev-harness Gap B / GH issue #195 follow-up.
type displayNameFollowsFriendlyNameModifier struct{}

func (m displayNameFollowsFriendlyNameModifier) Description(_ context.Context) string {
	return "Uses the prior state value unless friendly_name is changing this apply, in which case display_name is left unknown so it can be recomputed from the server's response."
}

func (m displayNameFollowsFriendlyNameModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m displayNameFollowsFriendlyNameModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	if req.AttributeState.IsNull() {
		return
	}
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	if req.AttributeConfig.IsUnknown() {
		return
	}

	var friendlyConfig, friendlyState types.String
	if diags := req.Config.GetAttribute(ctx, path.Root("friendly_name"), &friendlyConfig); diags.HasError() {
		return
	}
	if diags := req.State.GetAttribute(ctx, path.Root("friendly_name"), &friendlyState); diags.HasError() {
		return
	}

	switch {
	case friendlyConfig.Unknown:
		// Cannot yet tell whether friendly_name is changing (it depends on
		// another not-yet-known value) -- be conservative and leave
		// display_name unknown.
		return
	case friendlyConfig.Null:
		// friendly_name undeclared: it will resolve to the prior state value
		// via its own UseStateForUnknown modifier, so it is NOT changing.
		resp.AttributePlan = req.AttributeState
	case !friendlyState.Null && friendlyConfig.Value == friendlyState.Value:
		// friendly_name explicitly re-declared with its current value: not
		// changing.
		resp.AttributePlan = req.AttributeState
	default:
		// friendly_name is changing (newly declared, or declared with a
		// value different from current state) -- leave display_name Unknown
		// so the server's post-update response is free to set the new
		// mirrored value.
	}
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
				Description:   "Display name field from the server. Read-only. Mirrors friendly_name once one is configured, so it may legitimately change whenever friendly_name changes.",
				PlanModifiers: []tfsdk.AttributePlanModifier{displayNameFollowsFriendlyNameModifier{}},
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
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				Computed:      true,
				Description:   "List of security roles allowed to enroll. Deprecated in Command v25+ (use keyfactor_template_role_binding instead). Computed because Update() preserves the server's current value when this attribute is left undeclared (see preserveUndeclaredTemplateFields) -- an undeclared value is not necessarily null.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
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
				Optional:      true,
				Computed:      true,
				Description:   "Subject field regex validation rules. Deprecated in Command v25+. Computed because Update() preserves the server's current value when this attribute is left undeclared (see preserveUndeclaredTemplateFields) -- an undeclared value is not necessarily null.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
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
				Optional:      true,
				Computed:      true,
				Description:   "Default values for subject fields. Deprecated in Command v25+. Computed because Update() preserves the server's current value when this attribute is left undeclared (see preserveUndeclaredTemplateFields) -- an undeclared value is not necessarily null.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
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
				Optional:      true,
				Computed:      true,
				Description:   "Custom enrollment fields for CSR/PFX enrollment. Deprecated in Command v25+. Computed because Update() preserves the server's current value when this attribute is left undeclared (see preserveUndeclaredTemplateFields) -- an undeclared value is not necessarily null.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
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
				Optional:      true,
				Computed:      true,
				Description:   "Metadata field associations for this template. Computed because Update() preserves the server's current value when this attribute is left undeclared (see preserveUndeclaredTemplateFields) -- an undeclared value is not necessarily null.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
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

// preserveUndeclaredTemplateFields extends the #195 read-modify-write
// pattern -- originally scoped to AllowedRequesters/UseAllowedRequesters
// only (formerly its own preserveAllowedRequesters helper, folded in here
// since templateResponseToState already computes the identical
// AllowedRequesters/UseAllowedRequesters conversion as `c`) -- to every
// other writable field TemplatesTemplateUpdateRequest can represent. PUT
// /Templates is a full-replace endpoint: buildTemplateUpdateRequest skips
// any plan field left Null/Unknown (or, for the native-Go-slice/pointer
// nested fields, nil/empty), and Command then clears that field
// server-side rather than leaving it unchanged. Before this fix, an update
// that only declared (say) friendly_name silently reset every OTHER
// undeclared Optional field on the template -- observed live: key_retention
// "FromIssuance" -> "None" and allow_one_click_renewals true -> false
// (dev-harness certificate_template_demo finding, completes #195). This
// mirrors the same systematic sweep already applied to
// keyfactor_template_role_binding's buildTemplateRoleBindingUpdateArg (#190).
//
// current must come from a GET performed immediately before this update
// (see Update()), not this resource's own prior Terraform state -- state
// can be stale because keyfactor_template_role_binding mutates some of
// these same server-side fields (TemplatePolicy, AllowedRequesters) out-of-
// band via its own PUT calls. current may be nil if Update() decided no
// preservation GET was needed; that is a no-op here.
//
// TemplatePolicy and the TemplateRegexes/TemplateDefaults/EnrollmentFields/
// MetadataFields collections are native Go pointer/slice types rather than
// types.List/types.Object. Unlike TemplatePolicy (a pointer, where nil really
// is the only "unset" representation available), the four slice fields CAN
// distinguish "declared empty" from "undeclared": the plugin framework's
// reflection layer (internal/reflect/slice.go, BuildValue) decodes a null
// list into a nil Go slice but a known (possibly zero-length) list into a
// non-nil slice via reflect.MakeSlice -- so `plan.X == nil` means undeclared
// (or explicitly null) while a non-nil `plan.X` with len 0 means the config
// declared `x = []` and intends a clear. The checks below key off nil-ness,
// not len(), for exactly that reason: a `len(plan.X) == 0` check cannot tell
// those two cases apart and would silently refill a declared-empty list from
// the server, so the clear the user asked for would never actually happen
// (see full-review round 2 finding #1).
//
// Every field TemplatesTemplateUpdateRequest can represent is covered here.
// KeyType is the one further field GetTemplateResponse (the OLDER client
// used by keyfactor_template_role_binding) can represent that this resource
// cannot preserve -- but that's immaterial here: this resource's own schema
// has no key_type write path (key_type is Computed/read-only, sourced from
// the CA, and TemplatesTemplateUpdateRequest has no matching writable
// field), so there is nothing for this function to omit.
func preserveUndeclaredTemplateFields(plan *KeyfactorCertificateTemplateState, config *KeyfactorCertificateTemplateState, current *v1.TemplatesTemplateRetrievalResponse) {
	if current == nil {
		return
	}
	c := templateResponseToState(current)

	// allowed_requesters / use_allowed_requesters are the two fields
	// keyfactor_template_role_binding mutates out-of-band via its own PUT
	// calls (addAllowedRequesterToTemplate / removeRoleFromTemplate), so
	// whether the fresh GET (`c`) should win over plan must key on whether
	// CONFIG actually declares the attribute -- NOT on plan null-ness, unlike
	// every other field below.
	//
	// Why plan null-ness is the wrong signal here (full-review round 5
	// [HIGH]): allowed_requesters is Optional+Computed with
	// useStateOrNullModifier, so when config leaves it undeclared, its plan
	// value isn't Null -- MarkComputedNilsAsUnknown marks it Unknown
	// (whenever ANY other attribute on this resource changes), and
	// useStateOrNullModifier then pins that Unknown to the PRIOR STATE's
	// list. That prior state can itself already be stale: a
	// keyfactor_template_role_binding destroy runs its removeRoleFromTemplate
	// PUT (clearing the role server-side) BEFORE this template's own Update
	// runs, in the same apply. Keying off "plan is non-null" then
	// (wrongly) reads as "config declared this list" and skips the fresh
	// GET, so buildTemplateUpdateRequest re-PUTs the stale, just-revoked
	// role list with UseAllowedRequesters=true -- silently re-granting an
	// enrollment permission the user just removed, with no diff and no
	// error, forever (the next Read just re-absorbs the re-granted role
	// back into state).
	//
	// Keying off CONFIG instead: when config does not declare
	// allowed_requesters, the fresh GET's value always wins over plan,
	// regardless of whether plan happens to be null, unknown, or a known
	// (possibly stale) list. This is a no-op change for every apply where no
	// concurrent binding mutation happened (plan and the fresh GET already
	// agree there), and it never re-grants a revoked role. Its one trade-off:
	// in the exact binding-destroy-during-this-apply interleaving above, the
	// fresh GET's value can legitimately disagree with the KNOWN (pinned)
	// value Terraform core already recorded during planning, which surfaces
	// as a one-time "Provider produced inconsistent result after apply"
	// error on that apply. There is no plan-time fix available for that: the
	// binding resource's Delete that invalidates the pinned plan value runs
	// AFTER planning, so no plan modifier can see it coming. A loud, one-time
	// error that self-corrects on retry is the deliberate trade-off versus a
	// silent, permanent privilege re-grant.
	if config == nil || config.AllowedRequesters.Null {
		plan.AllowedRequesters = c.AllowedRequesters
	}
	if config == nil || config.UseAllowedRequesters.Null {
		plan.UseAllowedRequesters = c.UseAllowedRequesters
	}
	if plan.FriendlyName.Null || plan.FriendlyName.Unknown {
		plan.FriendlyName = c.FriendlyName
	}
	if plan.KeyRetention.Null || plan.KeyRetention.Unknown {
		plan.KeyRetention = c.KeyRetention
	}
	if plan.KeyRetentionDays.Null || plan.KeyRetentionDays.Unknown {
		plan.KeyRetentionDays = c.KeyRetentionDays
	}
	if plan.AllowedEnrollmentTypes.Null || plan.AllowedEnrollmentTypes.Unknown {
		plan.AllowedEnrollmentTypes = c.AllowedEnrollmentTypes
	}
	if plan.RequiresApproval.Null || plan.RequiresApproval.Unknown {
		plan.RequiresApproval = c.RequiresApproval
	}
	if plan.AllowOneClickRenewals.Null || plan.AllowOneClickRenewals.Unknown {
		plan.AllowOneClickRenewals = c.AllowOneClickRenewals
	}
	if plan.KeyUsage.Null || plan.KeyUsage.Unknown {
		plan.KeyUsage = c.KeyUsage
	}
	if plan.CertificateCleanupEnabled.Null || plan.CertificateCleanupEnabled.Unknown {
		plan.CertificateCleanupEnabled = c.CertificateCleanupEnabled
	}
	if plan.TimeAfterExpiration.Null || plan.TimeAfterExpiration.Unknown {
		plan.TimeAfterExpiration = c.TimeAfterExpiration
	}
	if plan.TimeAfterExpirationUnits.Null || plan.TimeAfterExpirationUnits.Unknown {
		plan.TimeAfterExpirationUnits = c.TimeAfterExpirationUnits
	}
	if plan.DeleteWithArchivedKey.Null || plan.DeleteWithArchivedKey.Unknown {
		plan.DeleteWithArchivedKey = c.DeleteWithArchivedKey
	}

	if plan.TemplatePolicy == nil {
		plan.TemplatePolicy = c.TemplatePolicy
	} else if c.TemplatePolicy != nil {
		pp, cp := plan.TemplatePolicy, c.TemplatePolicy
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
		if pp.DefaultCertificateOwnerRoleID.Null || pp.DefaultCertificateOwnerRoleID.Unknown {
			pp.DefaultCertificateOwnerRoleID = cp.DefaultCertificateOwnerRoleID
		}
		if pp.KeyInfo == nil {
			pp.KeyInfo = cp.KeyInfo
		}
	}

	if plan.TemplateRegexes == nil {
		plan.TemplateRegexes = c.TemplateRegexes
	}
	if plan.TemplateDefaults == nil {
		plan.TemplateDefaults = c.TemplateDefaults
	}
	if plan.EnrollmentFields == nil {
		plan.EnrollmentFields = c.EnrollmentFields
	}
	if plan.MetadataFields == nil {
		plan.MetadataFields = c.MetadataFields
	}
}

// preserveTfListEmptyVsNull is the types.List analog of
// preserveListEmptyVsNull (see resource_keyfactor_certificate_store_type.go,
// issue #192) for Optional+Computed list attributes backed by types.List --
// here, allowed_requesters -- rather than a native Go slice.
//
// templateResponseToState maps AllowedRequesters to a known list only when
// the server returns a non-empty array; an empty/absent array always becomes
// types.List{Null: true} (see its "AllowedRequesters" comment), regardless
// of whether the user declared `allowed_requesters = []` (a real "clear the
// list" intent, which the PUT above did carry out) or left the attribute
// undeclared. Left alone, a declared-empty plan value (known, 0 elements)
// disagrees with that always-null response shape and Terraform core rejects
// the apply with "Provider produced inconsistent result after apply" --
// permanently, since the next Read reproduces the same null vs. the user's
// still-declared [] on every subsequent plan (full-review round 2 finding
// #1b).
//
// target is only ever Null or a non-empty known list coming out of
// templateResponseToState, never a known empty list -- so it is enough to
// key off target.Null and reference's null-ness alone: reference (the plan
// in Update, or prior state in Read) faithfully preserves "declared empty"
// vs. "undeclared" because the reflection layer encodes them differently (a
// non-nil empty Go slice underlies a known empty list -- see
// preserveUndeclaredTemplateFields's doc comment). A populated target is left
// untouched -- there both shapes already agree with any non-null reference.
func preserveTfListEmptyVsNull(target *types.List, reference types.List) {
	if !target.Null {
		return
	}
	if reference.Null || reference.Unknown {
		return
	}
	*target = types.List{Elems: []attr.Value{}, ElemType: target.ElemType}
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

	// Reconcile the null-vs-empty shape of the writable collections against
	// prior state rather than trusting the server response's shape alone --
	// see preserveTfListEmptyVsNull/preserveListEmptyVsNull's doc comments
	// (full-review round 2 finding #1b) for why templateResponseToState
	// cannot, by itself, tell "declared empty" apart from "undeclared" once
	// the server reports zero entries.
	preserveTfListEmptyVsNull(&newState.AllowedRequesters, state.AllowedRequesters)
	preserveListEmptyVsNull(&newState.TemplateRegexes, state.TemplateRegexes)
	preserveListEmptyVsNull(&newState.TemplateDefaults, state.TemplateDefaults)
	preserveListEmptyVsNull(&newState.EnrollmentFields, state.EnrollmentFields)
	preserveListEmptyVsNull(&newState.MetadataFields, state.MetadataFields)

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
	// CONFIG (not plan, not state) is the only reliable signal for "did the
	// user actually declare this attribute" -- see preserveUndeclaredTemplateFields's
	// allowed_requesters/use_allowed_requesters handling below and full-review
	// round 5 [HIGH]: an Optional+Computed attribute's plan value can be a
	// known, non-null, but STALE value (pinned from prior state by a plan
	// modifier) even when config never declared it at all.
	var config KeyfactorCertificateTemplateState
	diags = request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	// Carry ID from state (plan has it as Unknown during import)
	if plan.ID.Value == 0 {
		plan.ID = state.ID
	}

	tflog.Info(ctx, fmt.Sprintf("Updating certificate template ID %d", plan.ID.Value))

	templateAPI := r.p.sdkClient.V1.TemplateApi

	// PUT /Templates is a full-replace endpoint, and buildTemplateUpdateRequest
	// skips any plan field left Null/Unknown -- Command then clears that field
	// server-side rather than leaving it unchanged. A config that leaves a
	// writable field undeclared therefore does NOT mean "leave unchanged";
	// this resource's own prior Terraform state isn't a safe substitute either,
	// since keyfactor_template_role_binding mutates allowed_requesters/
	// use_allowed_requesters out-of-band via its own PUT calls, so state here
	// can already be stale. Read-modify-write against a fresh GET immediately
	// before this update -- the same "fetch current, then carry forward what
	// this apply doesn't intend to change" pattern used by
	// addAllowedRequesterToTemplate/removeRoleFromTemplate (#190) -- is what
	// actually reflects the current server value. Fixes #195; extended by
	// preserveUndeclaredTemplateFields (see its doc comment) to every other
	// writable field, not just allowed_requesters.
	//
	// This fetch used to be gated behind templateUpdateNeedsPreservationFetch,
	// skipped only when every writable field was already declared on plan.
	// That gate's field roster had already drifted from
	// preserveUndeclaredTemplateFields's own logic (the gate only checked
	// plan.TemplatePolicy == nil, but preserveUndeclaredTemplateFields also
	// fills nested-null template_policy fields when TemplatePolicy itself is
	// non-nil) -- a plan fully declared except for one nested template_policy
	// field would skip the fetch and silently lose that field, the same #195
	// bug class the gate existed to prevent. The fetch is now unconditional:
	// one extra cheap GET in the (rare, for a resource with this many optional
	// fields) fully-declared case, in exchange for removing that drift hazard
	// entirely -- preserveUndeclaredTemplateFields is already a no-op when
	// every field is declared, so this is otherwise behavior-identical.
	getReq := templateAPI.NewGetTemplatesByIdRequest(ctx, int32(plan.ID.Value))
	current, httpResp, err := getReq.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading certificate template before update.",
			fmt.Sprintf(
				"Could not read template %d to preserve its current field values: %s. Details: %s",
				plan.ID.Value, err.Error(), body,
			),
		)
		return
	}
	preserveUndeclaredTemplateFields(&plan, &config, current)

	updateReq := buildTemplateUpdateRequest(ctx, plan)
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

	// Reconcile the null-vs-empty shape of the writable collections against
	// plan rather than trusting the server response's shape alone -- a
	// declared `x = []` (a real clear, sent above) must read back as a known
	// empty list to match the plan's known-empty value, not collapse to null
	// the way an always-empty-on-clear server response otherwise would. See
	// preserveTfListEmptyVsNull/preserveListEmptyVsNull's doc comments
	// (full-review round 2 finding #1b).
	preserveTfListEmptyVsNull(&newState.AllowedRequesters, plan.AllowedRequesters)
	preserveListEmptyVsNull(&newState.TemplateRegexes, plan.TemplateRegexes)
	preserveListEmptyVsNull(&newState.TemplateDefaults, plan.TemplateDefaults)
	preserveListEmptyVsNull(&newState.EnrollmentFields, plan.EnrollmentFields)
	preserveListEmptyVsNull(&newState.MetadataFields, plan.MetadataFields)

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
