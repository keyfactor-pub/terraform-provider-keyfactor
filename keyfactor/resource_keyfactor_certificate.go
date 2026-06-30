package keyfactor

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Plan modifier instance used in the schema:
// PlanModifiers: []tfsdk.AttributePlanModifier{ replaceIfNotAfterWithinRenewalDays },
var replaceIfNotAfterWithinRenewalDays tfsdk.AttributePlanModifier = renewEligibleReplaceOnExpiryWindow{}

// Custom plan modifier for renewal eligibility window
type renewEligibleReplaceOnExpiryWindow struct{}

func (m renewEligibleReplaceOnExpiryWindow) Description(ctx context.Context) string {
	return "Require replace when time until not_after is within or exceeds renew_days."
}

func (m renewEligibleReplaceOnExpiryWindow) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m renewEligibleReplaceOnExpiryWindow) Modify(
	ctx context.Context,
	req tfsdk.ModifyAttributePlanRequest,
	resp *tfsdk.ModifyAttributePlanResponse,
) {
	// Need existing state to evaluate current certificate expiry
	if req.State.Raw.IsNull() {
		return
	}

	// Read not_after (RFC3339) from state
	var notAfter types.String
	if diags := req.State.GetAttribute(ctx, path.Root("not_after"), &notAfter); diags.HasError() {
		return
	}
	if notAfter.Unknown || notAfter.Null || notAfter.Value == "" {
		return
	}

	// Read renew_days from plan; if unknown/null, fallback to state
	var renewDays types.Int64
	if diags := req.Plan.GetAttribute(
		ctx,
		path.Root("renewal_config").AtName("renew_days"),
		&renewDays,
	); diags.HasError() {
		// ignore and fallback to state below
	}
	if renewDays.Unknown || renewDays.Null || renewDays.Value <= 0 {
		_ = req.State.GetAttribute(ctx, path.Root("renewal_config").AtName("renew_days"), &renewDays)
	}
	if renewDays.Unknown || renewDays.Null || renewDays.Value <= 0 {
		return
	}

	// Parse not_after and compute time remaining
	na, err := time.Parse(time.RFC3339, notAfter.Value)
	if err != nil {
		return
	}
	timeRemaining := time.Until(na)
	renewWindow := time.Duration(renewDays.Value) * 24 * time.Hour

	// Force replacement if within or past the renewal window
	if timeRemaining <= renewWindow {
		resp.RequiresReplace = true
	}
}

// privateKeyPlanModifier handles plan modifications for the private_key attribute.
//
// Normal case (state non-null): preserves the state value (same as UseStateForUnknown).
//
// Post-import case (state null, key_password in config): returns Unknown so the
// Update function is free to attempt key recovery with the provided key_password
// without triggering a "provider produced inconsistent result" error.
//
// No-recovery case (state null, no key_password): resolves to null (same as
// useStateOrNullModifier), suppressing spurious "(known after apply)" noise.
type privateKeyPlanModifier struct{}

func (m privateKeyPlanModifier) Description(_ context.Context) string {
	return "Preserves prior private_key state; enables recovery after import when key_password is set."
}

func (m privateKeyPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m privateKeyPlanModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	// Only act when the plan value is Unknown (Computed, not supplied in config).
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	if req.AttributeConfig.IsUnknown() || req.AttributeState.IsUnknown() {
		return
	}

	var config CommandCertificate
	var state CommandCertificate
	configOk := !req.Config.Get(ctx, &config).HasError()
	stateOk := !req.State.Get(ctx, &state).HasError()

	// When certificate_format is changing, leave Unknown so the Update function
	// can populate (or clear) private_key as appropriate for the new format.
	if configOk && stateOk {
		if effectiveCertificateFormat(config.CertificateFormat.Value) != effectiveCertificateFormat(state.CertificateFormat.Value) {
			return // leave Unknown — format is changing
		}
	}

	// State has a known value — preserve it.
	if !req.AttributeState.IsNull() {
		resp.AttributePlan = req.AttributeState
		return
	}
	// State is null (e.g. first plan after import). If key_password is set in
	// the config, recovery is possible in Update — leave plan as Unknown.
	if configOk {
		if !config.KeyPassword.IsNull() && !config.KeyPassword.Unknown && config.KeyPassword.Value != "" {
			return // leave plan Unknown — Update will attempt recovery
		}
	}
	// Also allow recovery if enrollment_password is already in state (prior
	// enrollment with auto-generated password).
	if stateOk {
		if !state.EnrollmentPassword.IsNull() && state.EnrollmentPassword.Value != "" {
			return // leave plan Unknown — Update can use enrollment_password
		}
	}
	// No recovery path available — resolve to null.
	resp.AttributePlan = req.AttributeState
}

// formatDependentModifier is a plan modifier for format-specific output fields
// (certificate_pem, certificate_chain, ca_certificate, pfx, jks, zip).
//
// When certificate_format is stable (not changing), it behaves like
// useStateOrNullModifier: preserves the prior state value to suppress
// spurious "(known after apply)" noise.
//
// When certificate_format is changing (e.g. PEM → PFX), it leaves the plan
// Unknown so the Update function is free to populate the correct field for
// the new format without triggering a "provider produced inconsistent result"
// error.
type formatDependentModifier struct{}

func (m formatDependentModifier) Description(_ context.Context) string {
	return "Preserves state for stable certificate_format; leaves Unknown when format is changing."
}

func (m formatDependentModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m formatDependentModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	if req.AttributeConfig.IsUnknown() || req.AttributeState.IsUnknown() {
		return
	}
	// When certificate_format is changing, leave Unknown so the provider can
	// return the value appropriate for the new format.
	var config CommandCertificate
	var state CommandCertificate
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		return
	}
	if diags := req.State.Get(ctx, &state); diags.HasError() {
		return
	}
	if effectiveCertificateFormat(config.CertificateFormat.Value) != effectiveCertificateFormat(state.CertificateFormat.Value) {
		return // leave Unknown — format is changing, value will differ
	}
	// Format is stable — preserve state (or null if state is null).
	resp.AttributePlan = req.AttributeState
}

type resourceCommandCertificateType struct{}

func (r resourceCommandCertificateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Read-only alias of `identifier` for Terraform framework compatibility.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"csr": {
				Type:          types.StringType,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{RequiresReplaceIfPreviouslySet()},
				Description:   "Base-64 encoded certificate signing request (CSR)",
			},
			"key_password": {
				Type:     types.StringType,
				Optional: true,
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Sensitive:   true,
				Description: "Password used to recover the private key from Keyfactor Command. NOTE: If no value is provided a random password will be generated for key recovery. This value is not stored and does not encrypt the private key in Terraform state. Also note that if a password is provided it must meet any password complexity requirements enforced by the CA template or creation will fail. Auto-generated passwords will be of length 32 and contain a minimum of 4 of the following: uppercase, lowercase, numeric, and special characters.",
			},
			"common_name": {
				Type:     types.StringType,
				Computed: false,
				//Required:      true,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject common name (CN) of the certificate.",
			},
			"locality": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject locality (L) of the certificate",
			},
			"organization": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject organization (O) of the certificate",
			},
			"state": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject state (ST) of the certificate",
			},
			"country": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject country of the certificate",
			},
			"organizational_unit": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject organizational unit (OU) of the certificate",
			},
			"certificate_authority": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown(), tfsdk.RequiresReplace()},
				Description:   "Name of the certificate authority to use for enrollment. Optional when using a certificate template or enrollment pattern — Command will automatically select a CA associated with the template or pattern. Required when enrolling against a standalone CA. Example: \"MYCA\\\\My Issuing CA\"",
			},
			"certificate_template": {
				Type:          types.StringType,
				Required:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{RequiresReplaceIfPreviouslySet()},
				Description:   "A string that sets the name of the certificate template that should be used to issue the certificate. The template short name should be used. See also EnrollmentPatternId.\n\nOne of either the Template or the EnrollmentPatternId is required unless the enrollment is being done against a standalone CA. If both the Template and EnrollmentPatternId are provided, the settings from the enrollment pattern take precedence. If both are specified, the enrollment will fail if the Template does not match the one defined by the specified enrollment pattern.\n\nImportant:  The template must be configured with at least one enrollment pattern in order to be used for enrollment (see POST Enrollment Patterns).\nNote:  This parameter is considered deprecated as for Keyfactor Command v25.1.0 and may be removed in a future release.",
				Validators: []tfsdk.AttributeValidator{
					atLeastOneOfValidator{otherAttr: "certificate_enrollment_pattern"},
				},
			},
			"certificate_enrollment_pattern": {
				Type:          types.StringType,
				Required:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{RequiresReplaceIfPreviouslySet()},
				Description: "Either the `name` or internal `ID` (" +
					"integer) indicating the enrollment pattern to use when" +
					" requesting the certificate. If this value is not provided, the default enrollment pattern defined for the template provided in the request (see the Template parameter) will be used.\n\nOne of either the Template or the EnrollmentPatternId is required unless the enrollment is being done against a standalone CA. If both the Template and EnrollmentPatternId are provided, the settings from the enrollment pattern take precedence. If both are specified, the enrollment will fail if the Template does not match the one defined by the specified enrollment pattern. IMPORTANT: Requires Keyfactor Command v25.1.0+",
				Validators: []tfsdk.AttributeValidator{
					atLeastOneOfValidator{otherAttr: "certificate_template"},
				},
			},
			"dns_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description: "List of DNS names to use as subjects of the certificate. " +
					"NOTE: This field **does not work with CSR enrollments**, " +
					"all SANs should be included in the CSR. " +
					"Additional SANs added by the CA during enrollment **will" +
					" not** be reflected in this field",
			},
			"uri_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description: "List of URIs to use as subjects of the certificate. " +
					"NOTE: This field **does not work with CSR enrollments**, " +
					"all SANs should be included in the CSR. " +
					"Additional SANs added by the CA during enrollment **will" +
					" not** be reflected in this field",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"ip_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description: "List of DNS names to use as subjects of the certificate. " +
					"NOTE: This field **does not work with CSR enrollments**, " +
					"all SANs should be included in the CSR. " +
					"Additional SANs added by the CA during enrollment **will" +
					" not** be reflected in this field",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"certificate_format": {
				Type:     types.StringType,
				Optional: true,
				Description: "Optional: The output format to return the enrolled certificate in. " +
					"Valid PFX enrollment options are: `PEM, PFX, JKS, " +
					"Zip`. Valid CSR enrollment options are `PEM, DER`. Defaults to: `PEM`",
				//Validators: []tfsdk.AttributeValidator{},
			},
			"metadata": {
				Type: types.MapType{
					ElemType: types.StringType,
				},
				Optional:      true,
				Computed:      true,
				Description:   "Metadata key-value pairs to be attached to certificate. Set to null or an empty map to clear all metadata on the server. Changes are applied in-place (no certificate replacement).",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"serial_number": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Serial number of newly enrolled certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"issuer_dn": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Issuer distinguished name that signed the certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"thumbprint": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Thumbprint of newly enrolled certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"not_before": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Not Before date of enrolled certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"not_after": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Not After date of enrolled certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"identifier": {
				Type:     types.StringType,
				Required: false,
				Computed: true,
				Description: "Keyfactor certificate identifier. This can be any of the following values: thumbprint, CN, " +
					"or Keyfactor Command Certificate ID. If using CN to lookup the last issued certificate, the CN must " +
					"be an exact match and if multiple certificates are returned the certificate that was most recently " +
					"issued will be returned. ",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"collection_id": {
				Type:     types.Int64Type,
				Computed: false,
				Optional: true,
				Description: "Optional certificate collection ID. This is required if enrollment permissions have been " +
					"granted at the collection level. NOTE: This will *not* assign the cert to the specified collection ID; " +
					"assignment is based the collection's associated query. For more information on collection permissions see " +
					"the Keyfactor Command docs: https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/CertificatePermissions.htm?Highlight=collection%20permissions",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"owner_role_name": {
				Type:     types.StringType,
				Optional: true,
				Description: "Optional owner role name. " +
					"This is required if the certificate template being used requires an owner role to be set during" +
					" enrollment. Only compatible with Keyfactor Command versions v12.3.0 and later.",
				MarkdownDescription: `
A string containing the name of the security role assigned as the certificate owner. This name must match the existing name of the security role.

Expanded Change Owner Permission: A user who holds the Certificates > Expanded Change Owner permission can set the certificate owner to any role within the permission sets they are a member of. This permission setting overrides the Certificates > Collections > Change Owner permission (both Global and Collection-level) if both are set.

Collections > Change Owner Permission:

Global or Collection Level—No Default Value: A user who holds only the Certificates > Collections > Change Owner permission at either the Global or Collection level can set the certificate owner to any role they belong to if there is not a default value populated from the enrollment pattern or existing certificate on a renewal.
Global or Collection Level—Default Value: A user who holds only the Certificates > Collections > Change Owner permission at either the Global or Collection level can change the default certificate owner to any role they belong to. If the default value populated from the enrollment pattern or existing certificate on a renewal is not a role held by the acting user, the this value will not be populated in the Certificate Owner Role field. The user will still be allowed to add a new owner value.
Note:  To assign a certificate owner, one of OwnerRoleId or OwnerRoleName is required, not both. A certificate owner is required if the enrollment pattern or system-wide settings Certificate Owner Role policy has been configured as Required.

> [!IMPORTANT]
> Only compatible with Keyfactor Command versions v12.3.0 and later.
`,
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"certificate_id": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Keyfactor Command certificate ID.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"command_request_id": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Keyfactor request ID.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"certificate_pem": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "PEM formatted certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{formatDependentModifier{}},
			},
			"ca_certificate": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "PEM formatted CA certificate",
				PlanModifiers: []tfsdk.AttributePlanModifier{formatDependentModifier{}},
			},
			"certificate_chain": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "PEM formatted full certificate chain",
				PlanModifiers: []tfsdk.AttributePlanModifier{formatDependentModifier{}},
			},
			"private_key": {
				Type:          types.StringType,
				Computed:      true,
				Sensitive:     true,
				Description:   "PEM formatted PKCS#1 private key imported if cert_template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.",
				PlanModifiers: []tfsdk.AttributePlanModifier{privateKeyPlanModifier{}},
			},
			"enrollment_password": {
				Type:      types.StringType,
				Computed:  true,
				Sensitive: true,
				Description: "The password used during certificate issuance. Also used to unlock PFX/PKCS12 and JKS" +
					" keystores. Only returned if the certificate template has KeyRetention set to a value other than" +
					" None. Will use `key_password` value if specified else will generate a random password of length" +
					fmt.Sprintf("%d", DEFAULT_PFX_PASSWORD_LEN) + " with a minimum of " + fmt.Sprintf(
					"%d",
					DEFAULT_PFX_PASSWORD_UPPER_COUNT,
				) +
					" uppercase, " + fmt.Sprintf("%d", DEFAULT_PFX_PASSWORD_NUMBER_COUNT) + " numeric, and " +
					fmt.Sprintf("%d", DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT) + " special characters." +
					" Review this provider's schema docs for more details: https://registry.terraform." +
					"io/providers/keyfactor-pub/keyfactor/latest/docs#schema",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"jks": {
				Type:          types.StringType,
				Computed:      true,
				Sensitive:     true,
				Description:   "Base64 encoded JKS keystore containing the certificate, private key (if available), and certificate chain. Only returned if the certificate template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.",
				PlanModifiers: []tfsdk.AttributePlanModifier{formatDependentModifier{}},
			},
			"pfx": {
				Type:          types.StringType,
				Computed:      true,
				Sensitive:     true,
				Description:   "Base64 encoded PFX keystore containing the certificate, private key (if available), and certificate chain. Only returned if the certificate template has KeyRetention set to a value other than None.",
				PlanModifiers: []tfsdk.AttributePlanModifier{formatDependentModifier{}},
			},
			"zip": {
				Type:          types.StringType,
				Computed:      true,
				Sensitive:     true,
				Description:   "Base64 encoded ZIP archive containing the certificate, private key (if available), and certificate chain in PEM and DER formats. Only returned if the certificate template has KeyRetention set to a value other than None.",
				PlanModifiers: []tfsdk.AttributePlanModifier{formatDependentModifier{}},
			},
			"use_cn_as_friendly_name": {
				Type:     types.BoolType,
				Computed: false,
				Description: "Only applicable for PFX enrollments. Use the common name as the friendly name for the" +
					" certificate. Defaults to `true`. " +
					"NOTE: Keyfactor Command must be configured to `allow custom friendly name` for this to work" +
					" under `Application Settings > Enrollment > PFX`.",
				Optional: true,
			},
			"friendly_name": {
				Type:     types.StringType,
				Computed: false,
				Description: "Only applicable for PFX enrollments. A friendly name for the certificate. " +
					"If not provided, " +
					"the common name will be used unless `use_cn_as_friendly_name` is set to `false`.",
				Optional: true,
			},
			"is_expired": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the certificate is expired. When true, Terraform will plan a certificate replacement on the next apply.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.UseStateForUnknown(),
					tfsdk.RequiresReplaceIf(
						func(_ context.Context, stateVal attr.Value, _ attr.Value, _ path.Path) (bool, diag.Diagnostics) {
							b, ok := stateVal.(types.Bool)
							return ok && b.Value, nil
						},
						"Certificate is expired and must be re-enrolled.",
						"Certificate is expired and must be re-enrolled.",
					),
				},
			},
			"is_revoked": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the certificate is revoked. When true, Terraform will plan a certificate replacement on the next apply.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.UseStateForUnknown(),
					tfsdk.RequiresReplaceIf(
						func(_ context.Context, stateVal attr.Value, _ attr.Value, _ path.Path) (bool, diag.Diagnostics) {
							b, ok := stateVal.(types.Bool)
							return ok && b.Value, nil
						},
						"Certificate is revoked and must be re-enrolled.",
						"Certificate is revoked and must be re-enrolled.",
					),
				},
			},
			"is_pending_revocation": {
				Type:          types.BoolType,
				Computed:      true,
				Description:   "Whether the certificate is pending revocation",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"revocation_effective_date": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "The effective date of the certificate revocation",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"revoke_on_destroy": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Whether to revoke the certificate on resource `destroy`. IMPORTANT: If set to `false` the certificate will not be revoked on `destroy`ing operations. This means the certificate will need to be revoked outside of Terraform. Defaults to `true`.",
			},
			"expiry_warn_days": {
				Type:     types.Int64Type,
				Optional: true,
				Description: fmt.Sprintf(
					"Number of days before expiry to warn about the certificate. "+
						"Defaults to %d days.", DEFAULT_EXPIRY_WARNING_DAYS,
				),
			},
			"renewal_config": {
				Attributes: tfsdk.SingleNestedAttributes(
					map[string]tfsdk.Attribute{
						"force_renewal": {
							Type:        types.BoolType,
							Description: "Will force certificate to be renewed",
							Optional:    true,
							PlanModifiers: []tfsdk.AttributePlanModifier{
								tfsdk.RequiresReplaceIf(
									// The conditional function
									func(
										ctx context.Context,
										state attr.Value,
										config attr.Value,
										path path.Path,
									) (bool, diag.Diagnostics) {
										tflog.Debug(ctx, "Checking if 'force_renewal' is set to true")
										if state == nil {
											tflog.Debug(ctx, "State is nil, returning false for 'force_renewal'")
											return false, nil
										}
										forceRenewal, ok := config.(types.Bool)
										if ok && forceRenewal.Value {
											tflog.Debug(
												ctx, "force_renewal is true, "+
													"this resource will be forced to replace",
											)
											return true, nil
										}
										return false, nil
									},
									"Triggers resource replacement when 'force_renewal' is set to true.",
									`
Triggers replacement of resource when true.

> [!IMPORTANT] 
> This field will automatically be set to "true" when the certificate is eligible for renewal. If you do not wish to 
> auto renew the certificate, you must explicitly set this to "false".

`,
								),
							},
						},
						"renew_days": {
							Type:        types.Int64Type,
							Required:    true,
							Description: "The number of days before the certificate expires to trigger renewal.",
							//PlanModifiers:,
						},
						"renew_eligible": {
							Type:     types.BoolType,
							Computed: true,
							Description: "Calculated value indicating whether the certificate is eligible for renewal" +
								" based on `renew_days`, current date, and certificate expiry date.",
							PlanModifiers: []tfsdk.AttributePlanModifier{
								replaceIfNotAfterWithinRenewalDays,
							},
						},
						"revoke_on_renew": {
							Type:        types.BoolType,
							Optional:    true,
							Description: "Whether the existing certificate should be revoked on renewal.",
						},
					},
				),
				Optional: true,
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				//PlanModifiers: []tfsdk.AttributePlanModifier{
				//	tfsdk.RequiresReplaceIf(
				//		// The conditional function
				//		func(
				//			ctx context.Context,
				//			state attr.Value,
				//			plan attr.Value,
				//			path path.Path,
				//		) (bool, diag.Diagnostics) {
				//			tflog.Debug(ctx, "Checking if 'renew_eligible' is set to true")
				//			if state == nil {
				//				tflog.Debug(
				//					ctx,
				//					"State does not contain `renewal_config`, returning false for plan modifier",
				//				)
				//				return false, nil
				//			}
				//			if plan == nil {
				//				tflog.Debug(
				//					ctx,
				//					"Plan does not contain `renewal_config`, returning false for plan modifier",
				//				)
				//				return false, nil
				//			}
				//			stateRenewConfig, stateRenewConfigOk := state.(types.Object)
				//			if !stateRenewConfigOk {
				//				tflog.Debug(
				//					ctx,
				//					"State `renewal_config` is not an Object, returning false for plan modifier",
				//				)
				//				return false, nil
				//			}
				//
				//			tflog.Debug(ctx, "Parsing plan `renewal_config`")
				//			planObj, planRenewConfigOk := plan.(types.Object)
				//			if !planRenewConfigOk {
				//				tflog.Debug(
				//					ctx,
				//					"Plan `renewal_config` is not an Object, returning false for plan modifier",
				//				)
				//				return false, nil
				//			} else if planObj.IsNull() {
				//				tflog.Debug(ctx, "`renewal_config` is null in plan, returning false for plan modifier")
				//				return false, nil
				//			}
				//
				//			tflog.Debug(ctx, "Parsing plan `force_renewal`")
				//			planForceRenewalAttr, planForceRenewalOk := planObj.Attrs["force_renewal"]
				//			if planForceRenewalOk {
				//				tflog.Debug(ctx, "`force_renewal` is set in plan, checking value")
				//				if planForceRenewalAttr.Type(ctx) == types.BoolType && planForceRenewalAttr.(types.Bool).Value {
				//					tflog.Debug(
				//						ctx,
				//						"`force_renewal` is true in plan, returning true for plan modifier",
				//					)
				//					return true, nil
				//				}
				//			}
				//
				//			tflog.Debug(ctx, "Parsing state `renewal_config`")
				//			stateForceRenewalAttr, stateRenewConfigOk := stateRenewConfig.Attrs["force_renewal"]
				//			if stateRenewConfigOk {
				//				tflog.Debug(ctx, "`force_renewal` is set in state, checking value")
				//				if stateForceRenewalAttr.Type(ctx) == types.BoolType && stateForceRenewalAttr.(types.Bool).Value {
				//					tflog.Debug(ctx, "`force_renewal` is true in state, checking plan value is false")
				//					if planForceRenewalAttr != nil && !planForceRenewalAttr.IsNull() &&
				//						!planForceRenewalAttr.(types.Bool).Value {
				//						tflog.Debug(
				//							ctx, "force_renewal is true in state and false in plan, "+
				//								"plan value takes precedence, returning false plan modifier",
				//						)
				//						return false, nil
				//					}
				//					tflog.Debug(ctx, "`force_renewal` is true, returning true for plan modifier")
				//					return true, nil
				//				}
				//			}
				//
				//			tflog.Debug(ctx, "Parsing state `renew_eligible`")
				//			renewEligibleAttr, stateRenewEligibleOk := stateRenewConfig.Attrs["renew_eligible"]
				//			if stateRenewEligibleOk {
				//				tflog.Debug(ctx, "`renew_eligible` is set in state, checking value")
				//				if renewEligibleAttr.Type(ctx) == types.BoolType && renewEligibleAttr.(types.Bool).Value {
				//					tflog.Debug(ctx, "renew_eligible is true, returning true for plan modifier")
				//					return true, nil
				//				}
				//			}
				//			tflog.Debug(ctx, "No conditions met for plan modifier, returning false")
				//			return false, nil
				//		},
				//		"Triggers resource replacement when 'renew_eligible' or `force_renewal` are"+
				//			" calculated or set to `true`.",
				//		"Triggers resource replacement when 'renew_eligible' or `force_renewal` are"+
				//			" set to `true`.",
				//	),
				//},
				Computed: false,
				Description: "Configuration for certificate renewal. " +
					"IMPORTANT: This does not deploy the updated certificate to associated certificate store" +
					" locations/endpoints. " +
					"To deploy the updated certificate you must define a `keyfactor_certificate_deployment` resource" +
					" or deploy via the Command UI.",
				MarkdownDescription: `Configuration for certificate renewal.
> [!IMPORTANT]
> This does not deploy the updated certificate to associated certificate store locations. To deploy the updated
> certificate you must define a "keyfactor_certificate_deployment" Terraform resource that references this
> certificate or deploy via the Command UI.
`,
			},
			"key_type": {
				Type:     types.StringType,
				Optional: true,
				Computed: true,
				Description: "Key algorithm for PFX enrollment: RSA, ECC, Ed25519, Ed448. " +
					"If omitted, the CA/template default is used. " +
					"Populated from the issued certificate on read. " +
					"Cannot be set when `csr` is also set.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown(), RequiresReplaceIfPreviouslySet()},
				Validators: []tfsdk.AttributeValidator{
					conflictsWithAttrValidator{otherAttr: "csr"},
				},
			},
			"key_size": {
				Type:     types.Int64Type,
				Optional: true,
				Computed: true,
				Description: "Key size in bits for PFX enrollment (e.g. 2048, 4096 for RSA; 256, 384, 521 for ECC). " +
					"If omitted, the CA/template default is used. " +
					"Populated from the issued certificate on read. " +
					"Cannot be set when `csr` is also set.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown(), RequiresReplaceIfPreviouslySet()},
				Validators: []tfsdk.AttributeValidator{
					conflictsWithAttrValidator{otherAttr: "csr"},
				},
			},
			"curve": {
				Type:     types.StringType,
				Optional: true,
				Computed: true,
				Description: "ECC curve name for PFX enrollment (e.g. P-256, P-384, P-521). " +
					"Only relevant when key_type=ECC. " +
					"Populated from the issued certificate on read. " +
					"Cannot be set when `csr` is also set.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}, RequiresReplaceIfPreviouslySet()},
				Validators: []tfsdk.AttributeValidator{
					conflictsWithAttrValidator{otherAttr: "csr"},
				},
			},
		},
		Description: "Manages a certificate in Keyfactor Command using the `/Enrollment` and `/Certificates` APIs",
	}, nil
}

func (r resourceCommandCertificateType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCommandCertificate{
		p: *(p.(*provider)),
	}, nil
}

type resourceCommandCertificate struct {
	p provider
}

func (r resourceCommandCertificate) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	tflog.Info(ctx, "Create called on certificate resource")
	tflog.Debug(ctx, "Checking provider configuration")
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan CommandCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	certificateId := plan.ID.Value
	collectionId := plan.CollectionId.Value
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "collection_id", collectionId)
	tflog.Info(ctx, "Create called on certificate resource")

	//sans := plan.SANs
	//metadata := plan.Metadata.Elems
	csr := plan.CSR.Value
	// If CSR and CommonName are both set, or neither are set, error
	if (plan.CSR.IsNull() && plan.CommonName.IsNull()) || (!plan.CSR.IsNull() && !plan.CommonName.IsNull()) || (csr == "" && plan.CommonName.IsNull()) {
		tflog.Error(ctx, "Invalid resource definition, CSR and CN are both null")
		response.Diagnostics.AddError(
			ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
			"You must provide either a CSR or a CN to create a certificate.",
		)
		return
	}
	if !plan.CSR.IsNull() && csr != "" { //Enroll CSR
		tflog.Debug(ctx, "Calling enrollCSR()")
		result, csrErr := r.enrollCSR(ctx, csr, &plan)
		if csrErr != nil && len(csrErr) > 0 {
			response.Diagnostics.Append(csrErr...)
			if csrErr.HasError() {
				return
			}

		}

		tflog.Debug(ctx, "Setting state")
		result.syncTfId()
		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}

		return
	} else { //Enroll PFX
		tflog.Debug(ctx, "Calling enrollPFXV2()")
		result, pfxErr := r.enrollPFXV2(ctx, &plan)
		if pfxErr.HasError() {
			response.Diagnostics.Append(pfxErr...)
			return
		}

		if result == nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				"empty response returned from Keyfactor Command after PFX enrollment",
			)
			return
		}

		tflog.Debug(ctx, "Setting state")
		result.syncTfId()
		diags = response.State.Set(ctx, *result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}
	}

}

// preserveWriteOnlyEnrollmentFieldsFromState copies the write-only enrollment
// parameters from the prior Terraform state into the result struct that the
// Read path returns. The Keyfactor Command server does not echo these fields
// back on certificate GET responses, so if Read returned null/zero for them
// after Create the framework would surface "Provider produced inconsistent
// result after apply" because Create wrote the plan values into state.
//
// Fields preserved:
//   - collection_id: server has no concept of collection context on a stored
//     certificate; only meaningful at enrollment / lookup time.
//   - friendly_name: write-only enrollment parameter (CustomFriendlyName).
//   - use_cn_as_friendly_name: write-only enrollment parameter; the server
//     does not store this flag separately from the resolved friendly name.
//
// This helper exists primarily as a stable, directly-testable seam so a unit
// test can validate the fix for the "inconsistent result after apply"
// regression that existed in v2.8.0, without needing a full VCR cassette
// round-trip through Read.
func preserveWriteOnlyEnrollmentFieldsFromState(state CommandCertificate, result *CommandCertificate) {
	if result == nil {
		return
	}
	result.CollectionId = state.CollectionId
	result.FriendlyName = state.FriendlyName
	result.UseCNAsFriendlyName = state.UseCNAsFriendlyName
}

func (r resourceCommandCertificate) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state CommandCertificate
	tflog.Info(ctx, "Read called on CommandCertificate resource")
	if response == nil {
		tflog.Warn(ctx, "nil ReadResourceResponse")
	}

	tflog.Debug(ctx, "Reading state file")
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading state file")
		return
	}

	// Determine certificate ID type and resolve CN or thumbprint
	certificateID, idTypeErr := strconv.Atoi(state.ID.Value)
	if idTypeErr != nil {
		certificateID = UNKNOWN_CERTIFICATE_ID
	}
	collectionIdInt := int(state.CollectionId.Value)

	thumbprint, commonName := determineCertificateIdType(state.ID.Value)
	logInitialCertificateFields(ctx, certificateID, commonName, thumbprint, collectionIdInt)

	// Prepare args for API call
	apiArgs := prepareCertificateContextArgs(certificateID, collectionIdInt, thumbprint, commonName)

	// Fetch certificate context
	certGetResp, apiErr := r.p.client.GetCertificateContext(apiArgs)
	if hasAPIErrors(ctx, apiErr, state.ID.Value, &response.Diagnostics) {
		tflog.Warn(ctx, fmt.Sprintf("Failed to retrieve certificate from GET /Certificates/%d", certificateID))
	}

	certificateFormat := state.CertificateFormat.Value
	if certificateFormat == "" {
		certificateFormat = DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT
	}
	// Attempt to recover or download certificate from Command
	leafPEM, chainPEM, pKeyPEM, rawData, rDiags := recoverOrDownloadCertificate(
		ctx,
		certificateID,
		collectionIdInt,
		state.KeyPassword.Value,
		r.p.client,
		certificateFormat,
	)

	// If the configured format (e.g. "STORE"→PEM) doesn't return the private key,
	// do a secondary PFX recovery attempt so that private_key stays populated in
	// state and drift-check doesn't report "changed outside Terraform".
	if pKeyPEM == "" && certGetResp != nil && certGetResp.HasPrivateKey {
		recoverPwd := state.KeyPassword.Value
		if recoverPwd == "" {
			recoverPwd = state.EnrollmentPassword.Value
		}
		// RecoverCertificate requires a non-empty password (it encrypts the PFX
		// response with it). Generate one if neither stored password is available.
		if recoverPwd == "" {
			recoverPwd = generatePassword(PFXPasswordLength, PFXPasswordSpecialChars, PFXPasswordDigits, PFXPasswordUpperCases)
		}
		pKeyPEM, _, _, _, _ = recoverPrivateKeyFromKeyfactorCommand(
			ctx, certificateID, collectionIdInt, recoverPwd, r.p.client, "PFX",
		)
	}

	// Handle leaf PEM encoding for certificates without private keys
	if certGetResp != nil && leafPEM == "" {
		leafPEM, _ = encodeCertificate(ctx, certGetResp.ContentBytes, certificateID)
	} else if rawData != nil && leafPEM == "" {
		leafPEM, _ = encodeCertificate(ctx, rawData, certificateID)
	}

	if leafPEM == "" {
		response.Diagnostics.Append(rDiags...)
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to retrieve certificate '%s' from Keyfactor Command. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}

	// Guard against upstream paths returning a CA/root as the leaf when Command
	// sends a non-leaf-first chain (e.g. UnpackPEM's certificates[0] or
	// DecodeChain's last-cert fallback). Re-select the true leaf from leaf+chain.
	leafPEM, chainPEM = reselectLeafFromChain(ctx, leafPEM, chainPEM)

	leaf, lDiags := parseLeafCert(
		ctx,
		leafPEM,
	)
	response.Diagnostics.Append(lDiags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error parsing certificate")
		return
	} else if leaf == nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to parse certificate '%s' from Keyfactor Command. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}

	notBeforeStr := leaf.NotBefore.UTC().Format(time.RFC3339)
	notAfterStr := leaf.NotAfter.UTC().Format(time.RFC3339)
	sn := normalizeSerialNumber(leaf.SerialNumber.String())
	issuerDN := leaf.Issuer.String()
	tp, _ := api.GetCertificateThumbprint(leaf)
	tp = normalizeThumbprint(tp)
	fullChain := chainPEM
	if !strings.Contains(fullChain, leafPEM) {
		fullChain = leafPEM + chainPEM
	}

	caName := state.CertificateAuthority.Value
	templateName := state.CertificateTemplate.Value
	metadata := state.Metadata

	cn, l, s, c, o, ou := parseSubjectToTfState(*leaf)
	var warningDays int
	if state.ExpiryWarningDays.Null || state.ExpiryWarningDays.Unknown || state.ExpiryWarningDays.Value <= 0 {
		warningDays = DEFAULT_EXPIRY_WARNING_DAYS
	} else {
		warningDays = int(state.ExpiryWarningDays.Value)
	}

	var (
		revoked bool
		expired bool
		//expiring bool
		cDiags diag.Diagnostics
	)
	tflog.Debug(ctx, "Calling checkCertDiags()")
	revoked, _, expired, cDiags = checkCertDiags(ctx, certGetResp, warningDays, leaf)
	response.Diagnostics.Append(cDiags...)
	if certGetResp != nil {
		// Preserve the user's original certificate_authority value when the server
		// returns a fully-qualified name (e.g. "hostname\\LogicalName") but the user
		// specified only the logical name.  This prevents spurious plan drift on
		// an attribute that carries RequiresReplace semantics.
		remoteCaName := certGetResp.CertificateAuthorityName
		if remoteCaName != "" {
			if caName == "" {
				// caName empty (e.g., enrollment-pattern enrollment with no
				// user-supplied certificate_authority): populate from server so
				// the resource reflects which CA actually issued the cert.
				caName = remoteCaName
			} else if remoteCaName != caName {
				// Check if the remote CA name ends with the state value (logical name match)
				if !strings.HasSuffix(remoteCaName, "\\"+caName) && !strings.HasSuffix(remoteCaName, "\\\\"+caName) {
					caName = remoteCaName
				} else {
					tflog.Debug(
						ctx,
						fmt.Sprintf(
							"Preserving user-supplied certificate_authority %q (remote returned %q)",
							caName,
							remoteCaName,
						),
					)
				}
			}
		}
		certificateID = certGetResp.Id
		//templateName = certGetResp.TemplateName
		metadata = flattenMetadata(certGetResp.Metadata)
	}

	renewalConfig := state.RenewalConfig
	if state.RenewalConfig != nil {
		tflog.Debug(ctx, "RenewalConfig is not nil, checking renewal eligibility")
		renewalConfig = &CertificateAutoRenewConfig{
			ForceRenewal: state.RenewalConfig.ForceRenewal,
			RenewDays:    state.RenewalConfig.RenewDays,
			//RenewEligible: types.Bool{
			//	Value: renewEligible,
			//},
			RevokeOnRenew: state.RenewalConfig.RevokeOnRenew,
		}
		if state.RenewalConfig.RenewDays.Value != 0 {
			ctx = tflog.SetField(ctx, "renew_days", state.RenewalConfig.RenewDays.Value)
			tflog.Info(ctx, "Checking if certificate is eligible for renewal.")
			renewDays := int(state.RenewalConfig.RenewDays.Value)
			renewEligible, _, _ := isExpiring(ctx, leaf, renewDays)
			renewalConfig.RenewEligible = types.Bool{
				Unknown: false,
				Null:    false,
				Value:   renewEligible,
			}
			if renewEligible {
				tflog.Debug(ctx, "Certificate is eligible for renewal, setting `force_renewal` to true")
				renewalConfig.ForceRenewal = types.Bool{
					Unknown: false,
					Null:    false,
					Value:   true, // Force this to true to trigger plan modifier replacement on next run
				}

				if !state.CommonName.IsNull() {
					diags.AddWarning(
						"Certificate renewal eligible",
						fmt.Sprintf(
							"Certificate with common name '%s'(%s) is eligible for renewal, "+
								"please run `terraform apply` to renew it.",
							state.CommonName.Value, state.ID.Value,
						),
					)
				} else {

					diags.AddWarning(
						"Certificate renewal eligible",
						fmt.Sprintf(
							"Certificate '%s' is eligible for renewal, please run `terraform apply` to renew it.",
							state.ID.Value,
						),
					)

				}

			}
		} else {
			renewalConfig.RenewEligible = state.RenewalConfig.RenewEligible
		}
	}

	if !state.CSR.IsNull() {
		// Check if DNSSANs, IPSANs, and URISANs are empty and set them to null if they are
		if len(state.DNSSANs.Elems) != 0 {
			diags.AddWarning(
				"`dns_sans` are set but not used in CSR enrollment.",
				"The `dns_sans` field is not used in CSR enrollment, "+
					"they will be ignored. Please include the SANs in the CSR instead.",
			)
		}
		if len(state.IPSANs.Elems) != 0 {
			diags.AddWarning(
				"`ip_sans` are set but not used in CSR enrollment.",
				"The `ip_sans` field is not used in CSR enrollment, "+
					"they will be ignored. Please include the SANs in the CSR instead.",
			)
		}

		if len(state.URISANs.Elems) != 0 {
			diags.AddWarning(
				"`uri_sans` are set but not used in CSR enrollment.",
				"The `uri_sans` field is not used in CSR enrollment, "+
					"they will be ignored. Please include the SANs in the CSR instead.",
			)
		}
	}

	enrollmentPatternId := certGetResp.EnrollmentPatternId
	enrollmentPatternIdStr := fmt.Sprintf("%d", enrollmentPatternId)

	var enrollmentPatternName string

	if state.EnrollmentPattern.Value != enrollmentPatternIdStr {
		enrollmentPatternResp, epnErr := r.p.client.GetEnrollmentPattern(enrollmentPatternId)
		if epnErr != nil {
			tflog.Warn(ctx, fmt.Sprintf("Failed to retrieve enrollment pattern name for ID %d", enrollmentPatternId))
			if !state.EnrollmentPattern.Unknown && !state.EnrollmentPattern.Null {
				enrollmentPatternName = state.EnrollmentPattern.Value
			}
		} else {
			enrollmentPatternNamePtr := enrollmentPatternResp.Name
			if enrollmentPatternNamePtr != "" {
				enrollmentPatternName = enrollmentPatternNamePtr
			} else {
				enrollmentPatternName = fmt.Sprintf("%d", enrollmentPatternId)
			}
		}
	} else {
		enrollmentPatternName = state.EnrollmentPattern.Value
	}

	var ownerRoleName string
	if certGetResp != nil && certGetResp.OwnerRoleName != "" {
		ownerRoleName = certGetResp.OwnerRoleName
	}
	tflog.Debug(ctx, "Creating state object for certificate.")
	result := CommandCertificate{
		ID:                 state.ID,
		CSR:                state.CSR,
		CommonName:         cn,
		Locality:           l,
		State:              s,
		Country:            c,
		Organization:       o,
		OrganizationalUnit: ou,
		DNSSANs:            state.DNSSANs,
		IPSANs:             state.IPSANs,
		URISANs:            state.URISANs,
		SerialNumber:       types.String{Value: sn, Null: isNullString(sn)},
		IssuerDN:           types.String{Value: issuerDN, Null: isNullString(issuerDN)},
		Thumbprint:         types.String{Value: tp, Null: isNullString(tp)},
		//PEM:                types.String{Value: leafPEM, Null: isNullString(leafPEM) || certificateFormat == "PEM"},
		//PEMCACert:          types.String{Value: chainPEM, Null: isNullString(chainPEM) || certificateFormat == "PEM"},
		//PEMChain:           types.String{Value: fullChain, Null: isNullString(fullChain) || certificateFormat == "PEM"},
		//PrivateKey:         types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM) || certificateFormat == "PEM"},
		PEM:                types.String{Null: true},
		PEMCACert:          types.String{Null: true},
		PEMChain:           types.String{Null: true},
		PrivateKey:         types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)},
		PFX:                types.String{Null: true},
		JKS:                types.String{Null: true},
		Zip:                types.String{Null: true},
		KeyPassword:        state.KeyPassword,
		EnrollmentPassword: state.EnrollmentPassword,
		CertificateAuthority: types.String{
			Value: caName,
			Null:  isNullString(caName),
		},
		CertificateFormat: state.CertificateFormat,
		//CertificateTemplate: types.String{Value: templateName, Null: isNullString(templateName)},
		Metadata:          metadata,
		CertificateId:     types.Int64{Value: int64(certificateID), Null: isNullId(certificateID)},
		ExpiryWarningDays: state.ExpiryWarningDays,
		IsExpired: types.Bool{
			Value: expired,
		},
		IsRevoked: types.Bool{
			Value: revoked,
		},
		IsPendingRevocation: types.Bool{
			Value: certGetResp != nil && strings.Contains(strings.ToLower(certGetResp.CertStateString), "pending"),
		},
		RenewalConfig: renewalConfig,
		OwnerRoleName: types.String{
			Value: ownerRoleName,
			Null:  isNullString(ownerRoleName),
		},
		EnrollmentPattern:   state.EnrollmentPattern,   // This may be mutated below
		CertificateTemplate: state.CertificateTemplate, // This may be mutated below
		NotBefore: types.String{
			Value: notBeforeStr,
			Null:  isNullString(notBeforeStr),
		},
		NotAfter: types.String{
			Value: notAfterStr,
			Null:  isNullString(notAfterStr),
		},
		RevocationEffDate: state.RevocationEffDate,
		RevokeOnDestroy:   state.RevokeOnDestroy,
		KeyType:           state.KeyType,
		KeySize:           state.KeySize,
		Curve:             state.Curve,
	}

	// Preserve write-only enrollment fields (collection_id, friendly_name,
	// use_cn_as_friendly_name) that the server does not return on GET. Without
	// this, Create -> Read produces "Provider produced inconsistent result
	// after apply" because the plan value would be replaced by null.
	preserveWriteOnlyEnrollmentFieldsFromState(state, &result)

	if certGetResp != nil {
		if certGetResp.RevocationEffDate != "" {
			result.RevocationEffDate = types.String{
				Value: certGetResp.RevocationEffDate,
				Null:  isNullString(certGetResp.RevocationEffDate),
			}
		}
		if certGetResp.KeyAlgorithm != "" {
			result.KeyType = types.String{Value: normalizeKeyAlgorithm(certGetResp.KeyAlgorithm)}
		}
		if certGetResp.KeySizeInBits > 0 {
			result.KeySize = types.Int64{Value: int64(certGetResp.KeySizeInBits)}
		}
		if certGetResp.Curve != "" {
			result.Curve = types.String{Value: curveOIDToName(certGetResp.Curve)}
		}

	}

	// handle template name + enrollment pattern sets
	// Both may be set (enrollment pattern takes precedence per API docs).
	// Update state values if the server returned different names.
	if !state.EnrollmentPattern.Null && !state.EnrollmentPattern.Unknown {
		if state.EnrollmentPattern.Value != enrollmentPatternName {
			result.EnrollmentPattern = types.String{
				Value: enrollmentPatternName,
				Null:  isNullString(enrollmentPatternName),
			}
			tflog.Debug(
				ctx,
				fmt.Sprintf(
					"Setting enrollment pattern name to '%s' from fetched value",
					enrollmentPatternName,
				),
			)
		}
	}
	if !state.CertificateTemplate.Null && !state.CertificateTemplate.Unknown {
		if state.CertificateTemplate.Value != templateName {
			result.CertificateTemplate = types.String{
				Value: templateName,
				Null:  isNullString(templateName),
			}
			tflog.Debug(
				ctx,
				fmt.Sprintf("Setting template name to '%s' from fetched value", templateName),
			)
		}
	}
	// If only template is set (no enrollment pattern), null out enrollment pattern
	// to avoid forcing a replacement on next run.
	if !state.CertificateTemplate.Null && (state.EnrollmentPattern.Null || state.EnrollmentPattern.Unknown) {
		result.EnrollmentPattern = types.String{
			Null: true,
		}
	}

	if !state.CSR.IsNull() {
		// CSR cert in normal operation: preserve subject fields from state.
		// (The CN/SANs live in the CSR, not the config, so we must not let
		// the cert parse overwrite what was there.)
		result.CommonName = state.CommonName
		result.Locality = state.Locality
		result.State = state.State
		result.Country = state.Country
		result.Organization = state.Organization
		result.OrganizationalUnit = state.OrganizationalUnit
	} else if certGetResp != nil && !certGetResp.HasPrivateKey {
		// CSR cert after import: CSR is null in state (it was never stored
		// during import), but the cert has no server-side private key, so
		// this must be a CSR-enrolled cert.  The Terraform config will not
		// set common_name / SANs (they are embedded in the CSR), so preserve
		// nulls to avoid RequiresReplace drift on every post-import plan.
		result.CommonName = state.CommonName
		result.Locality = state.Locality
		result.State = state.State
		result.Country = state.Country
		result.Organization = state.Organization
		result.OrganizationalUnit = state.OrganizationalUnit
	}

	switch certificateFormat {
	case "PEM":
		result.PEM = types.String{Value: leafPEM, Null: isNullString(leafPEM)}
		result.PEMCACert = types.String{Value: chainPEM, Null: isNullString(chainPEM)}
		result.PEMChain = types.String{Value: fullChain, Null: isNullString(fullChain)}
		result.PrivateKey = types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)}
	case "JKS":
		if rawData != nil {
			result.JKS = types.String{Value: *rawData, Null: isNullString(*rawData)}
		}
	case "PFX":
		if rawData != nil {
			result.PFX = types.String{Value: *rawData, Null: isNullString(*rawData)}
		}
	case "ZIP":
		if rawData != nil {
			result.Zip = types.String{Value: *rawData, Null: isNullString(*rawData)}
		}
	default:
		// should never happen due to validation
		tflog.Warn(ctx, fmt.Sprintf("Unknown certificate format '%s'", certificateFormat))
		result.PEM = types.String{Value: leafPEM, Null: isNullString(leafPEM)}
		result.PEMCACert = types.String{Value: chainPEM, Null: isNullString(chainPEM)}
		result.PEMChain = types.String{Value: fullChain, Null: isNullString(fullChain)}
		result.PrivateKey = types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)}
	}

	// ca_certificate is public issuer information that never changes for a given
	// certificate. If the format-specific download path did not populate it (e.g.
	// STORE/PFX/JKS/ZIP formats, or when key_password is absent after import),
	// fall back to the prior state value so it doesn't oscillate on every plan.
	if result.PEMCACert.IsNull() && !state.PEMCACert.IsNull() {
		result.PEMCACert = state.PEMCACert
	}

	// Set state
	tflog.Debug(ctx, "Setting state")
	result.syncTfId()
	sDiags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(sDiags...)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCommandCertificate) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	tflog.Info(ctx, "Update called on certificate resource")
	// Get plan values
	var plan CommandCertificate
	tflog.Debug(ctx, "Reading plan file")
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading plan file")
		return
	}

	// Get current state
	var state CommandCertificate
	tflog.Debug(ctx, "Reading state file")
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Debug(ctx, "Error reading state file")
		return
	}

	csr := plan.CSR.Value

	if (plan.CSR.IsNull() && plan.CommonName.IsNull()) || (!plan.CSR.IsNull() && !plan.CommonName.IsNull()) || (csr == "" && plan.CommonName.IsNull()) {
		tflog.Error(
			ctx,
			"Invalid certificate resource definition, must provide either a CSR or a CN to create a certificate",
		)
		response.Diagnostics.AddError(
			ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
			"You must provide either a CSR or a CN to create a certificate.",
		)
		return
	}

	// Use plan.CollectionId so that when the user changes collection_id in config,
	// the API call uses the new value (collection context is a permission hint, not
	// a resource-identity field).
	collectionIdInt := int(plan.CollectionId.Value)

	thumbprint, commonName := determineCertificateIdType(state.ID.Value)
	certificateID := int(state.CertificateId.Value)
	logInitialCertificateFields(ctx, certificateID, commonName, thumbprint, collectionIdInt)

	// Prepare args for API call
	apiArgs := prepareCertificateContextArgs(certificateID, collectionIdInt, thumbprint, commonName)

	var (
		revoked bool
		expired bool
		//expiring bool
		cDiags diag.Diagnostics
	)

	var warningDays int
	if plan.ExpiryWarningDays.Null || plan.ExpiryWarningDays.Unknown || plan.ExpiryWarningDays.Value <= 0 {
		warningDays = DEFAULT_EXPIRY_WARNING_DAYS
	} else {
		warningDays = int(plan.ExpiryWarningDays.Value)
	}

	// Fetch certificate context
	certGetResp, apiErr := r.p.client.GetCertificateContext(apiArgs)
	if hasAPIErrors(ctx, apiErr, state.ID.Value, &response.Diagnostics) {
		// GetCertificateContext returns (nil, err) on failure; hasAPIErrors has
		// already appended an error diagnostic. We MUST return here, otherwise
		// the certGetResp.ContentBytes dereference below panics with a nil
		// pointer (SIGSEGV). The Read path was hardened with certGetResp != nil
		// guards in v2.9.0; this aligns Update with that behavior.
		tflog.Error(ctx, fmt.Sprintf("Failed to retrieve certificate from GET /Certificates/%d", certificateID))
		return
	}
	if certGetResp == nil {
		// Defensive: GET returned no error but a nil response. Returning here
		// prevents a nil-pointer dereference on certGetResp.ContentBytes below.
		tflog.Error(ctx, fmt.Sprintf("GET /Certificates/%d returned a nil response", certificateID))
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Could not retrieve certificate '%s' from Keyfactor Command during update: "+
					"the API returned an empty response.", state.ID.Value,
			),
		)
		return
	}

	leaf, lDiags := parseLeafCert(
		ctx,
		certGetResp.ContentBytes,
	)
	if lDiags.HasError() {
		//this should never happen unless state has been manually manipulated
		response.Diagnostics.Append(lDiags...)
		return
	}

	tflog.Debug(ctx, "Calling checkCertDiags()")
	revoked, _, expired, cDiags = checkCertDiags(ctx, certGetResp, warningDays, leaf)
	response.Diagnostics.Append(cDiags...)
	//if certGetResp != nil {
	//	caName = certGetResp.CertificateAuthorityName
	//	certificateID = certGetResp.Id
	//	//templateName = certGetResp.TemplateName
	//	metadata = flattenMetadata(certGetResp.Metadata)
	//}

	renewalConfig := plan.RenewalConfig
	if plan.RenewalConfig != nil {
		renewalConfig = &CertificateAutoRenewConfig{
			ForceRenewal: plan.RenewalConfig.ForceRenewal,
			RenewDays:    plan.RenewalConfig.RenewDays,
			//RenewEligible: types.Bool{
			//	Value: renewEligible,
			//},
			RevokeOnRenew: plan.RenewalConfig.RevokeOnRenew,
		}
		if plan.RenewalConfig.RenewDays.Value != 0 {
			ctx = tflog.SetField(ctx, "renew_days", plan.RenewalConfig.RenewDays.Value)
			tflog.Info(ctx, "Checking if certificate is eligible for renewal.")
			renewDays := int(plan.RenewalConfig.RenewDays.Value)
			renewEligible, _, _ := isExpiring(ctx, leaf, renewDays)
			renewalConfig.RenewEligible = types.Bool{
				Unknown: false,
				Null:    false,
				Value:   renewEligible,
			}
		}
	}

	// Check if ownerrolename has changed
	if plan.OwnerRoleName.Value != state.OwnerRoleName.Value {
		tflog.Debug(ctx, "OwnerRoleName has changed, updating certificate owner role.")
		// Check if rolename is an integer ID or string name
		ownerInt, convErr := strconv.Atoi(plan.OwnerRoleName.Value)
		ownerRequest := &api.OwnerRequest{}
		if convErr != nil {
			ownerRequest.NewRoleName = &plan.OwnerRoleName.Value
		} else {
			ownerRequest.NewRoleId = &ownerInt
		}

		oErr := r.p.client.ChangeCertificateOwnerRole(certificateID, ownerRequest)
		if oErr != nil {
			response.Diagnostics.AddError(
				"Certificate owner update error.",
				fmt.Sprintf(
					"Could not update cert '%s''s owner role to %s on Keyfactor: "+oErr.Error(),
					state.ID.Value, plan.OwnerRoleName.Value,
				),
			)
			return
		}
	}

	if csr != "" {
		tflog.Debug(ctx, "Creating certificate from CSR.")

		var dnsSANs []string
		var ipSANs []string
		var uriSANs []string
		var planMetadata map[string]string
		var stateMetadata map[string]string
		diags = state.DNSSANs.ElementsAs(ctx, &dnsSANs, true)
		diags = state.IPSANs.ElementsAs(ctx, &ipSANs, true)
		diags = state.URISANs.ElementsAs(ctx, &uriSANs, true)
		diags = plan.Metadata.ElementsAs(ctx, &planMetadata, false)
		diags = state.Metadata.ElementsAs(ctx, &stateMetadata, false)

		//diags = request.Plan.Get(ctx, &metadata)

		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}

		certificateIdInt, cIdErr := strconv.Atoi(state.ID.Value)
		if cIdErr != nil {
			certificateIdInt = int(state.CertificateId.Value)
		}

		sans := append(dnsSANs, ipSANs...)
		sans = append(sans, uriSANs...)

		tflog.Debug(ctx, fmt.Sprintf("Creating certificate with SANs: %s", sans))
		metaInterface := make(map[string]interface{})
		for k, v := range planMetadata {
			metaInterface[k] = v
		}
		if !plan.Metadata.Equal(state.Metadata) {
			tflog.Debug(ctx, "Metadata is updated. Attempting to update metadata on Keyfactor.")

			err := r.p.client.UpdateMetadata(
				&api.UpdateMetadataArgs{
					CertID:   certificateIdInt,
					Metadata: metaInterface,
				},
			)
			if err != nil {
				response.Diagnostics.AddError(
					"Certificate metadata update error.",
					fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value),
				)
				return
			}
		}

		// Set state
		var result = CommandCertificate{
			ID:                   types.String{Value: state.ID.Value},
			CSR:                  plan.CSR,
			CommonName:           plan.CommonName,
			Locality:             plan.Locality,
			State:                plan.State,
			Country:              plan.Country,
			Organization:         plan.Organization,
			OrganizationalUnit:   plan.OrganizationalUnit,
			DNSSANs:              plan.DNSSANs,
			IPSANs:               plan.IPSANs,
			URISANs:              plan.URISANs,
			SerialNumber:         state.SerialNumber,
			IssuerDN:             state.IssuerDN,
			Thumbprint:           state.Thumbprint,
			PEM:                  state.PEM,
			PEMCACert:            state.PEMCACert,
			PEMChain:             state.PEMChain,
			PrivateKey:           state.PrivateKey,
			KeyPassword:          plan.KeyPassword,
			EnrollmentPassword:   state.EnrollmentPassword,
			CertificateId:        state.CertificateId,
			CertificateAuthority: knownStringFromPlan(plan.CertificateAuthority),
			CertificateTemplate:  plan.CertificateTemplate,
			Metadata:             knownMetadataFromPlan(plan.Metadata),
			UseCNAsFriendlyName:  state.UseCNAsFriendlyName,
			FriendlyName:         state.FriendlyName,
			CollectionId:         plan.CollectionId,
			ExpiryWarningDays:    plan.ExpiryWarningDays,
			IsExpired: types.Bool{
				Value: expired,
			},
			IsRevoked: types.Bool{
				Value: revoked,
			},
			IsPendingRevocation: types.Bool{
				Value: certGetResp != nil && strings.Contains(strings.ToLower(certGetResp.CertStateString), "pending"),
			},
			RenewalConfig: renewalConfig,

			CertificateFormat: plan.CertificateFormat,
			EnrollmentPattern: plan.EnrollmentPattern,
			OwnerRoleName:     plan.OwnerRoleName,
			PFX:               state.PFX,
			JKS:               state.JKS,
			Zip:               state.Zip,
			NotBefore:         state.NotBefore,
			NotAfter:          state.NotAfter,
			RevocationEffDate: state.RevocationEffDate,
			RevokeOnDestroy:   plan.RevokeOnDestroy,
			KeyType:           state.KeyType,
			KeySize:           state.KeySize,
			Curve:             state.Curve,
		}

		if (certGetResp != nil) && (certGetResp.RevocationEffDate != "") {
			result.RevocationEffDate = types.String{
				Value: certGetResp.RevocationEffDate,
				Null:  isNullString(certGetResp.RevocationEffDate),
			}
		}

		if !state.CSR.IsNull() {
			result.CommonName = state.CommonName
			result.Locality = state.Locality
			result.State = state.State
			result.Country = state.Country
			result.Organization = state.Organization
			result.OrganizationalUnit = state.OrganizationalUnit

		}

		// Set state
		tflog.Debug(ctx, "Setting state")
		result.syncTfId()
		diags = response.State.Set(ctx, &result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	} else {
		//check if metadata is updated
		var planMetadata map[string]string
		var stateMetadata map[string]string
		tflog.Debug(ctx, "Reading metadata from state and plan")
		diags = plan.Metadata.ElementsAs(ctx, &planMetadata, false)
		tflog.Debug(ctx, "Reading metadata from state and plan")
		diags = state.Metadata.ElementsAs(ctx, &stateMetadata, false)

		if !plan.Metadata.Equal(state.Metadata) {
			tflog.Debug(ctx, "Metadata is updated. Attempting to update metadata on Keyfactor.")

			// Convert map[string]string to map[string]interface{}
			planMetadataInterface := make(map[string]interface{})
			for k, v := range planMetadata {
				tflog.Trace(ctx, fmt.Sprintf("Setting metadata key %s to value %s", k, v))
				planMetadataInterface[k] = v
			}
			tflog.Info(
				ctx,
				fmt.Sprintf("Updating metadata for certificate '%s' on Keyfactor Command.", state.ID.Value),
			)
			err := r.p.client.UpdateMetadata(
				&api.UpdateMetadataArgs{
					CertID:   int(state.CertificateId.Value),
					Metadata: planMetadataInterface,
				},
			)
			if err != nil {
				response.Diagnostics.AddError(
					"Certificate metadata update error.",
					fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value),
				)
				return
			}
		}

		// Set state
		tflog.Debug(ctx, "Updating CommandCertificate state object")
		var result = CommandCertificate{
			ID:                   state.ID,
			CSR:                  state.CSR,
			CommonName:           state.CommonName,
			Locality:             state.Locality,
			State:                state.State,
			Country:              state.Country,
			Organization:         state.Organization,
			OrganizationalUnit:   state.OrganizationalUnit,
			DNSSANs:              state.DNSSANs,
			IPSANs:               state.IPSANs,
			URISANs:              state.URISANs,
			SerialNumber:         state.SerialNumber,
			IssuerDN:             state.IssuerDN,
			Thumbprint:           state.Thumbprint,
			PEM:                  state.PEM,
			PEMCACert:            state.PEMCACert,
			PEMChain:             state.PEMChain,
			PrivateKey:           state.PrivateKey,
			KeyPassword:          plan.KeyPassword,
			EnrollmentPassword:   state.EnrollmentPassword,
			CertificateId:        state.CertificateId,
			CertificateAuthority: state.CertificateAuthority,
			CertificateTemplate:  plan.CertificateTemplate,
			Metadata:             knownMetadataFromPlan(plan.Metadata),
			UseCNAsFriendlyName:  state.UseCNAsFriendlyName,
			FriendlyName:         state.FriendlyName,
			CollectionId:         plan.CollectionId,
			ExpiryWarningDays:    plan.ExpiryWarningDays,
			IsExpired: types.Bool{
				Value: expired,
			},
			IsRevoked: types.Bool{
				Value: revoked,
			},
			IsPendingRevocation: types.Bool{
				Value: certGetResp != nil && strings.Contains(strings.ToLower(certGetResp.CertStateString), "pending"),
			},
			RenewalConfig: renewalConfig,

			CertificateFormat: plan.CertificateFormat,
			EnrollmentPattern: plan.EnrollmentPattern,
			OwnerRoleName:     plan.OwnerRoleName,
			PFX:               state.PFX,
			JKS:               state.JKS,
			Zip:               state.Zip,
			NotBefore:         state.NotBefore,
			NotAfter:          state.NotAfter,
			RevocationEffDate: state.RevocationEffDate,
			RevokeOnDestroy:   plan.RevokeOnDestroy,
			KeyType:           state.KeyType,
			KeySize:           state.KeySize,
			Curve:             state.Curve,
		}

		if (certGetResp != nil) && (certGetResp.RevocationEffDate != "") {
			result.RevocationEffDate = types.String{
				Value: certGetResp.RevocationEffDate,
				Null:  isNullString(certGetResp.RevocationEffDate),
			}
		}

		// If the effective certificate_format changed, re-download in the new
		// format so that format-specific state fields (PEM, PFX, JKS, Zip) are
		// refreshed without forcing resource recreation. (Fixes #150)
		//
		// Normalize: "" and "STORE" both produce PEM output in Read, so they
		// are effectively equivalent and don't require a re-download.
		effectivePlanFmt := effectiveCertificateFormat(plan.CertificateFormat.Value)
		effectiveStateFmt := effectiveCertificateFormat(state.CertificateFormat.Value)
		if effectivePlanFmt != effectiveStateFmt {
			tflog.Info(
				ctx, fmt.Sprintf(
					"certificate_format changed from %q to %q (effective: %q → %q), re-downloading certificate.",
					state.CertificateFormat.Value, plan.CertificateFormat.Value,
					effectiveStateFmt, effectivePlanFmt,
				),
			)
			dlLeafPEM, dlChainPEM, dlPKeyPEM, dlRawData, dlDiags := recoverOrDownloadCertificate(
				ctx,
				int(state.CertificateId.Value),
				int(plan.CollectionId.Value),
				plan.KeyPassword.Value,
				r.p.client,
				effectivePlanFmt,
			)
			if dlDiags.HasError() {
				response.Diagnostics.Append(dlDiags...)
			} else {
				// Clear all format-specific fields
				result.PEM = types.String{Null: true}
				result.PEMCACert = types.String{Null: true}
				result.PEMChain = types.String{Null: true}
				result.PrivateKey = types.String{Null: true}
				result.PFX = types.String{Null: true}
				result.JKS = types.String{Null: true}
				result.Zip = types.String{Null: true}

				switch effectivePlanFmt {
				case "PEM":
					dlFullChain := dlChainPEM
					if !strings.Contains(dlFullChain, dlLeafPEM) {
						dlFullChain = dlLeafPEM + dlChainPEM
					}
					result.PEM = types.String{Value: dlLeafPEM, Null: isNullString(dlLeafPEM)}
					result.PEMCACert = types.String{Value: dlChainPEM, Null: isNullString(dlChainPEM)}
					result.PEMChain = types.String{Value: dlFullChain, Null: isNullString(dlFullChain)}
					result.PrivateKey = types.String{Value: dlPKeyPEM, Null: isNullString(dlPKeyPEM)}
				case "JKS":
					if dlRawData != nil {
						result.JKS = types.String{Value: *dlRawData, Null: isNullString(*dlRawData)}
					}
				case "PFX":
					if dlRawData != nil {
						result.PFX = types.String{Value: *dlRawData, Null: isNullString(*dlRawData)}
					}
				case "ZIP":
					if dlRawData != nil {
						result.Zip = types.String{Value: *dlRawData, Null: isNullString(*dlRawData)}
					}
				}
			}
		}

		// Post-import private key recovery.
		//
		// privateKeyPlanModifier leaves plan.PrivateKey as Unknown when
		// state.PrivateKey is null and key_password is in the config.  That
		// signals here to attempt key recovery so that the private key is
		// populated on the first reconcile apply after import.
		//
		// If recovery fails (e.g. key is not archived in Command) we simply
		// store null — the plan was Unknown so either outcome is valid and no
		// "inconsistent result" error is raised.
		// Only attempt key recovery when the effective format is PEM — for PFX/JKS/ZIP
		// the private key is embedded in the binary blob; private_key must stay null.
		if plan.PrivateKey.Unknown && certGetResp != nil && certGetResp.HasPrivateKey &&
			effectivePlanFmt == "PEM" {
			recoverPassword := plan.KeyPassword.Value
			if recoverPassword == "" {
				recoverPassword = state.EnrollmentPassword.Value
			}
			if recoverPassword != "" {
				tflog.Debug(ctx, fmt.Sprintf(
					"Attempting post-import private key recovery for certificate %v",
					state.CertificateId.Value,
				))
				pKeyPEM, _, _, _, rDiags := recoverPrivateKeyFromKeyfactorCommand(
					ctx,
					int(state.CertificateId.Value),
					int(plan.CollectionId.Value),
					recoverPassword,
					r.p.client,
					"PFX",
				)
				if !rDiags.HasError() && pKeyPEM != "" {
					tflog.Debug(ctx, "Post-import private key recovery succeeded.")
					result.PrivateKey = types.String{Value: pKeyPEM}
				} else {
					tflog.Debug(ctx, "Post-import private key recovery failed; private_key remains null.")
					result.PrivateKey = types.String{Null: true}
				}
			} else {
				result.PrivateKey = types.String{Null: true}
			}
		}

		result.syncTfId()
		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}
	}
}

func (r resourceCommandCertificate) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on certificate resource")
	var state CommandCertificate
	tflog.Debug(ctx, "Reading state file")
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading state file")
		return
	}

	// Get order ID from state
	certificateId := state.ID.Value
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)

	if certificateId == "" {
		tflog.Warn(ctx, "Certificate ID is empty, removing empty certificate from state.")
		response.Diagnostics.AddWarning(
			"Certificate ID is empty.",
			"Delete called on empty ID. Removing empty certificate from state.",
		)
		response.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "Parsing certificate ID")
	certificateIdInt, cIdErr := strconv.Atoi(state.ID.Value)
	tflog.Debug(ctx, "Parsing certificate CN")
	certificateCN := state.CommonName.Value
	tflog.Debug(ctx, "Parsing certificate thumbprint")
	certificateThumbprint := state.Thumbprint.Value
	if cIdErr != nil {
		if certificateThumbprint == "" && certificateCN == "" {
			tflog.Error(ctx, "Invalid Certificate ID")
			response.Diagnostics.AddError(
				"Invalid Certificate ID",
				"Certificate ID is not an integer, unable to call revoke API.",
			)
		}
		return
	}

	collectionID := state.CollectionId.Value
	collectionIdInt := int(collectionID)

	ctx = tflog.SetField(ctx, "collection_id", collectionID)
	ctx = tflog.SetField(ctx, "certificate_id", certificateIdInt)
	ctx = tflog.SetField(ctx, "certificate_cn", certificateCN)
	ctx = tflog.SetField(ctx, "certificate_thumbprint", certificateThumbprint)

	if state.RenewalConfig != nil && !state.RenewalConfig.RevokeOnRenew.Null && !state.RenewalConfig.RevokeOnRenew.Value {
		// Remove resource from state without revocation
		tflog.Debug(ctx, "RevokeOnRenew is false, skipping revocation for certificate.")
		response.State.RemoveResource(ctx)
		tflog.Info(ctx, fmt.Sprintf("Certificate '%s' removed from state.", certificateId))
		return
	}

	if !state.RevokeOnDestroy.Null && !state.RevokeOnDestroy.Value {
		tflog.Debug(ctx, "RevokeOnDestroy is false, skipping revocation for certificate.")
		response.State.RemoveResource(ctx)
		tflog.Info(ctx, fmt.Sprintf("Certificate '%s' removed from state.", certificateId))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Revoking certificate %v on Keyfactor Command", certificateId))

	tflog.Debug(ctx, "Creating RevokeCertArgs")
	revokeArgs := &api.RevokeCertArgs{
		CertificateIds: []int{certificateIdInt}, // Certificate ID expects array of integers
		Reason:         5,                       // reason = 5 means Cessation of Operation
		Comment:        "Terraform destroy called on provider with associated cert ID",
	}

	if collectionIdInt > 0 {
		tflog.Debug(ctx, "Setting collection ID on API request")
		revokeArgs.CollectionId = collectionIdInt
	}

	tflog.Debug(ctx, "Calling RevokeCert")
	err := kfClient.RevokeCert(revokeArgs)
	if err != nil {

		if strings.Contains(err.Error(), "has previously been revoked") { // EJBCA specific?
			response.Diagnostics.AddWarning(
				"Certificate previously revoked",
				fmt.Sprintf("%s", err.Error()),
			)
		} else {
			tflog.Error(ctx, fmt.Sprintf("Error revoking certificate '%d' on Keyfactor Command", certificateIdInt))
			response.Diagnostics.AddError(
				"Certificate revocation error.",
				fmt.Sprintf("Keyfactor Command could not revoke cert '%s' : "+err.Error(), state.ID.Value),
			)
			return
		}
	}

	// Remove resource from state
	tflog.Debug(ctx, "Removing certificate from state")
	response.State.RemoveResource(ctx)
	tflog.Info(ctx, fmt.Sprintf("Certificate '%s' removed from state.", certificateId))
}

func (r resourceCommandCertificate) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on certificate resource")
	var state CommandCertificate
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate resource")
	certificateId := request.ID
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)

	certificateIdInt, _ := strconv.Atoi(certificateId)

	// Prepare args for API call
	// Use of collection_id to import is not currently supported
	apiArgs := prepareCertificateContextArgs(certificateIdInt, 0, request.ID, request.ID)

	// Fetch certificate context
	certGetResp, apiErr := r.p.client.GetCertificateContext(apiArgs)
	if hasAPIErrors(ctx, apiErr, state.ID.Value, &response.Diagnostics) {
		tflog.Warn(ctx, fmt.Sprintf("Failed to retrieve certificate from GET /Certificates/%s", state.ID.Value))
	}

	tflog.Info(ctx, fmt.Sprintf("Attempting to retrieve certificate '%s' from Keyfactor Command.", state.ID.Value))

	var (
		leafPEM          string
		chainPEM         string
		pKeyPEM          string
		rawData          *string
		importRecoverPwd string
	)

	// CSR-enrolled certificates have no server-side private key.  Attempting
	// PFX recovery for those certs always fails, so use the PEM download path
	// directly.  For PFX-enrolled certs (HasPrivateKey==true) we still attempt
	// recovery so that the private_key attribute is populated in state.
	if certGetResp != nil && !certGetResp.HasPrivateKey {
		tflog.Debug(ctx, "Certificate has no server-side private key (CSR enrollment); using PEM download path")
		leafPEM, chainPEM, _, _ = downloadCertificateFromKeyfactorCommand(ctx, certificateIdInt, 0, r.p.client)
	} else {
		tflog.Debug(ctx, "Calling recoverOrDownloadCertificate")
		var rDiags diag.Diagnostics
		// Generate a one-time password for import recovery. RecoverCertificate
		// uses this to encrypt the PFX response (it is NOT the original enrollment
		// password). Any non-empty password works. We store it as EnrollmentPassword
		// so that subsequent Read calls can re-recover the key without a reconcile apply.
		importRecoverPwd = generatePassword(PFXPasswordLength, PFXPasswordSpecialChars, PFXPasswordDigits, PFXPasswordUpperCases)
		leafPEM, chainPEM, pKeyPEM, rawData, rDiags = recoverOrDownloadCertificate(
			ctx,
			certificateIdInt,
			int(state.CollectionId.Value),
			importRecoverPwd,
			r.p.client,
			"PFX",
		)

		if rDiags.HasError() {
			tflog.Error(ctx, fmt.Sprintf("Error retrieving certificate '%s' from Keyfactor Command.", certificateId))
			response.Diagnostics.Append(rDiags...)
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command", certificateId),
			)
			return
		}

		// PFX download without the user-supplied key_password returns the encrypted
		// blob but cannot extract the chain cert.  Fetch it separately so that
		// ca_certificate is populated in the imported state and does not show as
		// "(known after apply)" on every subsequent plan.
		if chainPEM == "" {
			_, chainPEM, _, _ = downloadCertificateFromKeyfactorCommand(ctx, certificateIdInt, 0, r.p.client)
		}
	}
	_ = rawData

	var (
		ownerRoleName string
		requestId     int
	)

	// Handle leaf PEM encoding for certificates without private keys
	if certGetResp != nil && leafPEM == "" {
		ownerRoleName = certGetResp.OwnerRoleName
		requestId = certGetResp.CertRequestId
		leafPEM, _ = encodeCertificate(ctx, certGetResp.ContentBytes, certGetResp.Id)
	} else if rawData != nil && leafPEM == "" {
		leafPEM, _ = encodeCertificate(ctx, rawData, certGetResp.Id)
	}

	if leafPEM == "" {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to retrieve certificate '%s' from Keyfactor Command. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}

	// Guard against upstream paths returning a CA/root as the leaf (see Read).
	leafPEM, chainPEM = reselectLeafFromChain(ctx, leafPEM, chainPEM)

	leaf, lDiags := parseLeafCert(ctx, leafPEM)
	response.Diagnostics.Append(lDiags...)
	if response.Diagnostics.HasError() || leaf == nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to parse certificate '%s' during import. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}
	sn := normalizeSerialNumber(leaf.SerialNumber.String())
	issuerDN := leaf.Issuer.String()
	tp, _ := api.GetCertificateThumbprint(leaf)
	tp = normalizeThumbprint(tp)
	fullChain := chainPEM
	if !strings.Contains(fullChain, leafPEM) {
		fullChain = leafPEM + chainPEM
	}

	caName := state.CertificateAuthority.Value
	templateName := state.CertificateTemplate.Value
	metadata := state.Metadata
	if certGetResp != nil {
		// Info that can only be retrieved with `Read Certificates` permissions
		remoteCaName := certGetResp.CertificateAuthorityName
		if remoteCaName != "" {
			if caName == "" {
				// caName is empty (import path or enrollment-pattern create with
				// no user-supplied certificate_authority): extract the logical
				// name from the server-returned CA path.  Handles Windows
				// "HOST\\LogicalName" and EJBCA URL format
				// "http://ejbca.../ejbca\\LogicalName" so that state stores the
				// short logical name and matches the typical user-supplied
				// certificate_authority value without causing drift.
				if idx := strings.LastIndex(remoteCaName, "\\"); idx >= 0 {
					caName = remoteCaName[idx+1:]
				} else {
					caName = remoteCaName
				}
			} else if remoteCaName != caName {
				if !strings.HasSuffix(remoteCaName, "\\"+caName) && !strings.HasSuffix(remoteCaName, "\\\\"+caName) {
					caName = remoteCaName
				} else {
					tflog.Debug(
						ctx,
						fmt.Sprintf(
							"Preserving user-supplied certificate_authority %q (remote returned %q)",
							caName,
							remoteCaName,
						),
					)
				}
			}
		}
		certificateIdInt = certGetResp.Id
		// Do not update templateName from server during import: certificate_template
		// and certificate_enrollment_pattern are write-only enrollment parameters
		// that cannot be recovered from the certificate record.  Leaving templateName
		// as "" stores null in state; users should add lifecycle.ignore_changes for
		// these attributes after importing certs enrolled via enrollment patterns.
		// templateName = certGetResp.TemplateName
		metadata = flattenMetadata(certGetResp.Metadata)
		revoked := isRevoked(certGetResp)
		if revoked {
			response.Diagnostics.AddWarning(
				"Certificate revoked",
				fmt.Sprintf("Certificate '%s' is revoked", state.ID.Value),
			)
		}
	}

	cn, l, s, c, o, ou := parseSubjectToTfState(*leaf)

	tflog.Debug(ctx, "Creating CommandCertificate object")
	var result = CommandCertificate{
		ID:                 types.String{Value: certificateId},
		CSR:                types.String{Null: true}, // write-only; not recoverable from server
		CommonName:         cn,
		Locality:           l,
		State:              s,
		Country:            c,
		Organization:       o,
		OrganizationalUnit: ou,
		DNSSANs:            DNSSANStoTerraform(leaf.DNSNames, false),
		IPSANs:             IPSANStoTerraform(leaf.IPAddresses, false),
		URISANs:            URISANStoTerraform(leaf.URIs, false),
		SerialNumber:       types.String{Value: sn, Null: isNullString(sn)},
		IssuerDN:           types.String{Value: issuerDN, Null: isNullString(issuerDN)},
		Thumbprint:         types.String{Value: tp, Null: isNullString(tp)},
		PEM:                types.String{Value: leafPEM, Null: isNullString(leafPEM)},
		PEMCACert:          types.String{Value: chainPEM, Null: isNullString(chainPEM)},
		PEMChain:           types.String{Value: fullChain, Null: isNullString(fullChain)},
		PrivateKey:         types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)},
		KeyPassword:        types.String{Null: true}, // write-only; not recoverable from server
		// Store the recovery password only when key recovery succeeded, enabling
		// subsequent Read calls to re-recover the private key without a reconcile apply.
		EnrollmentPassword: types.String{Value: importRecoverPwd, Null: isNullString(pKeyPEM)},
		CertificateAuthority: types.String{
			Value: caName,
			Null:  isNullString(caName),
		},
		CertificateTemplate: types.String{Value: templateName, Null: isNullString(templateName)},
		Metadata:            metadata,
		CertificateId:       types.Int64{Value: int64(certificateIdInt), Null: isNullId(certificateIdInt)},
		CollectionId:        state.CollectionId,
		FriendlyName:        state.FriendlyName,
		UseCNAsFriendlyName: state.UseCNAsFriendlyName,
		RequestId:           types.Int64{Value: int64(requestId), Null: isNullId(requestId)},
		ExpiryWarningDays:   types.Int64{Null: true},  // write-only; isNullId(0)==true means not set
		IsExpired:           types.Bool{Value: false}, // Set to false as we just enrolled the certificate
		IsRevoked:           types.Bool{Value: false}, // Set to false as we just enrolled the certificate
		IsPendingRevocation: types.Bool{Null: true},   // Set to false as we just enrolled the certificate
		RenewalConfig:       state.RenewalConfig,
		CertificateFormat:   types.String{Null: true}, // write-only; isNullString("")==true means not set
		OwnerRoleName:       types.String{Value: ownerRoleName, Null: isNullString(ownerRoleName)},
		EnrollmentPattern:   types.String{Null: true}, // write-only; not recoverable after import (like CertificateTemplate)
		NotBefore:           state.NotBefore,
		NotAfter:            state.NotAfter,
		RevocationEffDate:   state.RevocationEffDate,
		RevokeOnDestroy:     types.Bool{Null: true}, // write-only; false means not set
		KeyType:             state.KeyType,
		KeySize:             state.KeySize,
		Curve:               state.Curve,
	}

	// For CSR-enrolled certificates, subject fields (CN, SANs, locality, etc.)
	// are embedded in the CSR and are not set in the Terraform config.
	// Null them out so post-import plans show only in-place changes for
	// write-only enrollment params rather than triggering replacement.
	if certGetResp != nil && !certGetResp.HasPrivateKey {
		result.CommonName = types.String{Null: true}
		result.Locality = types.String{Null: true}
		result.State = types.String{Null: true}
		result.Country = types.String{Null: true}
		result.Organization = types.String{Null: true}
		result.OrganizationalUnit = types.String{Null: true}
		result.DNSSANs = DNSSANStoTerraform(nil, false)
		result.IPSANs = IPSANStoTerraform(nil, false)
		result.URISANs = URISANStoTerraform(nil, false)
	}

	if certGetResp != nil {
		if certGetResp.RevocationEffDate != "" {
			result.RevocationEffDate = types.String{
				Value: certGetResp.RevocationEffDate,
				Null:  isNullString(certGetResp.RevocationEffDate),
			}
		}
		if certGetResp.NotBefore != "" {
			result.NotBefore = types.String{
				Value: certGetResp.NotBefore,
				Null:  isNullString(certGetResp.NotBefore),
			}
		}
		if certGetResp.NotAfter != "" {
			result.NotAfter = types.String{
				Value: certGetResp.NotAfter,
				Null:  isNullString(certGetResp.NotAfter),
			}
		}
		if certGetResp.KeyAlgorithm != "" {
			result.KeyType = types.String{Value: normalizeKeyAlgorithm(certGetResp.KeyAlgorithm)}
		}
		if certGetResp.KeySizeInBits > 0 {
			result.KeySize = types.Int64{Value: int64(certGetResp.KeySizeInBits)}
		}
		if certGetResp.Curve != "" {
			result.Curve = types.String{Value: curveOIDToName(certGetResp.Curve)}
		}
	}

	// Set state
	tflog.Debug(ctx, "Setting state")
	result.syncTfId()
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error setting state")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Certificate '%s' imported into state.", certificateId))
}

func (r resourceCommandCertificate) CertLookupByRequestID(
	ctx context.Context,
	requestID int,
	collectionId int,
) (*api.GetCertificateResponse, error) {
	certArgs := &api.GetCertificateContextArgs{
		IncludeMetadata:      boolToPointer(true),
		IncludeLocations:     boolToPointer(true),
		IncludeHasPrivateKey: boolToPointer(true),
		CollectionId:         intToPointer(collectionId),
		Id:                   0,
		CommonName:           "",
		Thumbprint:           "",
		RequestId:            requestID,
	}
	certResp, err := r.p.client.GetCertificateContext(certArgs)
	if err != nil {
		return nil, err
	}
	return certResp, nil
}

func (r resourceCommandCertificate) WaitForPendingCert(
	ctx context.Context,
	enrollResponse *api.EnrollResponseV2,
	cn string,
	collectionId int,
) (*api.GetCertificateResponse, error) {
	tflog.Debug(ctx, "Enter WaitForPendingCert")
	sleepDuration := 1 * time.Second
	isPending := true
	ctx = tflog.SetField(ctx, "certificate_request_id", enrollResponse.CertificateInformation.KeyfactorRequestID)
	ctx = tflog.SetField(ctx, "common_name", cn)
	ctx = tflog.SetField(ctx, "sleep_duration", sleepDuration)
	ctx = tflog.SetField(ctx, "is_pending", isPending)
	tflog.Info(ctx, "Waiting for certificate request to be approved.")

	for i := 0; i < MAX_ITERATIONS; i++ {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Certificate %d for %s is pending approvals, waiting on approval.",
				enrollResponse.CertificateInformation.KeyfactorRequestID,
				cn,
			),
		)
		tflog.Debug(ctx, "Looking for a certificate with request ID on Keyfactor Command")
		certResp, err := r.CertLookupByRequestID(
			ctx,
			enrollResponse.CertificateInformation.KeyfactorRequestID,
			collectionId,
		)
		if err != nil {
			tflog.Error(
				ctx,
				fmt.Sprintf(
					"Error looking up certificate with request ID %d on Keyfactor Command: "+err.Error(),
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			// increment sleep duration
			tflog.Debug(ctx, fmt.Sprintf("Sleeping for %v", sleepDuration))
			time.Sleep(sleepDuration)
			sleepDuration *= SLEEP_DURATION_MULTIPLIER
			if sleepDuration > MAX_WAIT_SECONDS*time.Second {
				sleepDuration = MAX_WAIT_SECONDS * time.Second
			}
			continue
		}
		if certResp != nil && certResp.CertRequestId == enrollResponse.CertificateInformation.KeyfactorRequestID {
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate '%s' found with request ID '%d' so approval must have occurred.",
					cn,
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			return certResp, nil
		}
		// increment sleep duration
		tflog.Debug(ctx, fmt.Sprintf("Sleeping for %v", sleepDuration))
		time.Sleep(sleepDuration)
		sleepDuration *= SLEEP_DURATION_MULTIPLIER
		if sleepDuration > MAX_WAIT_SECONDS*time.Second {
			sleepDuration = MAX_WAIT_SECONDS * time.Second
		}
	}
	tflog.Warn(
		ctx,
		fmt.Sprintf(
			"Certificate request '%d' for '%s' is still pending approvals after '%d' iterations",
			enrollResponse.CertificateInformation.KeyfactorRequestID,
			cn,
			MAX_ITERATIONS,
		),
	)
	return nil, fmt.Errorf(
		"certificate request '%d' for '%s' is still pending approvals, waiting on approval",
		enrollResponse.CertificateInformation.KeyfactorRequestID,
		cn,
	)
}

func (r resourceCommandCertificate) HandlePendingCert(
	ctx context.Context,
	enrollResponse *api.EnrollResponseV2,
	cn string,
	collectionId int,
) (*api.GetCertificateResponse, error) {
	tflog.Info(ctx, "Certificate is pending approval, waiting on approval.")
	tflog.Debug(ctx, "Enter HandlePendingCert")
	sleepDuration := 1 * time.Second
	isPending := true
	ctx = tflog.SetField(ctx, "certificate_id", enrollResponse.CertificateInformation.KeyfactorRequestID)
	ctx = tflog.SetField(ctx, "common_name", cn)
	ctx = tflog.SetField(ctx, "sleep_duration", sleepDuration)
	ctx = tflog.SetField(ctx, "is_pending", isPending)
	for i := 0; i < MAX_ITERATIONS; i++ {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Certificate %d for %s is pending approvals, waiting on approval.",
				enrollResponse.CertificateInformation.KeyfactorRequestID,
				cn,
			),
		)

		tflog.Debug(ctx, "Fetching pending certificates from Keyfactor Command")
		pendingCertsResponse, lpErr := r.p.client.ListPendingCertificates(nil) //todo: can I pass collection ID?

		tflog.Debug(ctx, "Fetching certificates pending external validation from Keyfactor Command")
		pendingExternalResponse, lpeErr := r.p.client.ListExternalValidationPendingCertificates(nil) //todo: can I pass collection ID?

		if lpErr != nil || lpeErr != nil {
			if lpErr != nil {
				return nil, fmt.Errorf(
					"Could not retrieve pending certificates from Keyfactor Command: %s",
					lpErr.Error(),
				)
			}
			return nil, fmt.Errorf("Could not retrieve pending certificates from Keyfactor Command: %s", lpeErr.Error())
		}

		if isPending {
			tflog.Debug(
				ctx,
				"Iterating through pending certificates from Keyfactor Command to check if certificate is still pending",
			)
			if len(pendingCertsResponse) > 0 || len(pendingExternalResponse) > 0 {
				tflog.Debug(
					ctx,
					"Iterating through certificates pending internal validation from Keyfactor Command",
				)
				for _, cert := range pendingCertsResponse {
					if cert.Id == enrollResponse.CertificateInformation.KeyfactorRequestID {
						tflog.Info(
							ctx,
							fmt.Sprintf(
								"Certificate %d for %s is pending approvals, waiting on approval for %ss.",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								cn,
								sleepDuration,
							),
						)
						tflog.Debug(ctx, fmt.Sprintf("Sleeping for %v", sleepDuration))
						time.Sleep(sleepDuration)
						sleepDuration *= SLEEP_DURATION_MULTIPLIER
						tflog.Debug(ctx, "Incrementing sleep duration for next loop")
						if sleepDuration > MAX_WAIT_SECONDS*time.Second {
							sleepDuration = MAX_WAIT_SECONDS * time.Second
						}
						isPending = true
						tflog.Debug(
							ctx,
							fmt.Sprintf(
								"Certificate %d is still pending approvals, sleeping for %v",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								sleepDuration,
							),
						)
						break
					}
					tflog.Debug(
						ctx,
						fmt.Sprintf(
							"Certificate %d is not pending internal approvals",
							enrollResponse.CertificateInformation.KeyfactorRequestID,
						),
					)
					isPending = false
				}
			} else {
				if i < MAX_APPROVAL_WAIT_LOOPS {
					tflog.Debug(
						ctx,
						"No pending certificates from Keyfactor Command checking if approval has occurred.",
					)
					approveResp, _ := r.CertLookupByRequestID(
						ctx,
						enrollResponse.CertificateInformation.KeyfactorRequestID,
						collectionId,
					) //todo: pass collection ID
					if approveResp != nil && approveResp.CertRequestId == enrollResponse.CertificateInformation.KeyfactorRequestID {
						tflog.Debug(ctx, "Certificate found so approval must have occurred.")
						return approveResp, nil
					}

					tflog.Debug(ctx, "Allowing time for Keyfactor Command to generate certificate approval.")
					tflog.Info(
						ctx,
						fmt.Sprintf(
							"No pending certificates from Keyfactor Command, will check again in %d seconds.",
							sleepDuration,
						),
					)
					time.Sleep(sleepDuration)
					sleepDuration *= SLEEP_DURATION_MULTIPLIER
					continue
				}
				tflog.Debug(
					ctx,
					"No pending certificates from Keyfactor Command so this approval or denial must have occurred.",
				)
				isPending = false
			}
			if !isPending {
				tflog.Debug(
					ctx,
					"Iterating through certificates pending external validation from Keyfactor Command",
				)
				for _, cert := range pendingExternalResponse {
					if cert.Id == enrollResponse.CertificateInformation.KeyfactorRequestID {
						tflog.Info(
							ctx,
							fmt.Sprintf(
								"Certificate %d for %s is pending approvals, waiting on approval for %ss.",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								cn,
								sleepDuration,
							),
						)
						time.Sleep(sleepDuration)
						sleepDuration *= SLEEP_DURATION_MULTIPLIER
						if sleepDuration > MAX_WAIT_SECONDS*time.Second {
							sleepDuration = MAX_WAIT_SECONDS * time.Second
						}
						isPending = true
						tflog.Debug(
							ctx,
							fmt.Sprintf(
								"Certificate %d is still pending approvals, sleeping for %v",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								sleepDuration,
							),
						)
						break
					}
					tflog.Debug(
						ctx,
						fmt.Sprintf(
							"Certificate %d is not pending external approvals",
							enrollResponse.CertificateInformation.KeyfactorRequestID,
						),
					)
					isPending = false
				}
			}
		}
		if !isPending {
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate %d is not pending approvals, checking if it was denied",
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			deniedCertsResponse, _ := r.p.client.ListDeniedCertificates(nil)
			for _, cert := range deniedCertsResponse {
				if cert.Id == enrollResponse.CertificateInformation.KeyfactorRequestID {
					errMsg := fmt.Sprintf(
						"Certificate request '%d' for %s was denied ",
						enrollResponse.CertificateInformation.KeyfactorRequestID,
						cn,
					)
					tflog.Error(ctx, errMsg)
					return nil, fmt.Errorf("%s", errMsg)
				}
			}
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate %d is not pending approvals, checking if it was approved",
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			time.Sleep(MAX_WAIT_SECONDS * time.Second) // Allow command to generate cert
			break
		}
	}
	// Look up certificate by certjficate request ID and return the most recently issued certificate
	certResponse, gErr := r.CertLookupByRequestID(
		ctx,
		enrollResponse.CertificateInformation.KeyfactorRequestID,
		collectionId,
	)
	if gErr != nil {
		return nil, gErr
	}
	return certResponse, nil
}

func (r resourceCommandCertificate) enrollPFXV2(ctx context.Context, plan *CommandCertificate) (
	*CommandCertificate,
	diag.Diagnostics,
) {

	var (
		autoPassword   string
		lookupPassword string
		pKeyPEM        string
		leafPEM        string
		chainPEM       string
		pChain         []string
		//rawData        *string
	)

	collectionId := plan.CollectionId.Value
	collectionIdInt := int(collectionId)

	tflog.Info(ctx, "Resource is PFX certificate enrollment.")
	diags := diag.Diagnostics{}
	if plan.KeyPassword.Value == "" {
		tflog.Debug(ctx, "No password provided, generating random enrollment password.")

		autoPassword = generatePassword(
			PFXPasswordLength,
			PFXPasswordSpecialChars,
			PFXPasswordDigits,
			PFXPasswordUpperCases,
		)
		lookupPassword = autoPassword
	} else {
		tflog.Debug(ctx, "Password provided, using provided password as enrollment password.")
		lookupPassword = plan.KeyPassword.Value
	}

	useCNAsFriendlyName := true // Defaults to true for backwards compatability
	if !plan.UseCNAsFriendlyName.Null {
		useCNAsFriendlyName = plan.UseCNAsFriendlyName.Value
	}

	var friendlyName = plan.FriendlyName.Value
	if friendlyName == "" && useCNAsFriendlyName {
		friendlyName = plan.CommonName.Value
	}

	dnsSANs, ipSANs, uriSANs, dnsSANsDiags := r.parseSans(ctx, plan)
	if dnsSANsDiags.HasError() {
		diags.Append(dnsSANsDiags...)
	}

	metadata, metadataErr := r.parseMetadata(ctx, plan)
	if metadataErr != nil {
		diags.Append(metadataErr...)
	}

	certificateFormat := DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT
	if !plan.CertificateFormat.IsNull() {
		certificateFormat = strings.ToUpper(fmt.Sprintf("%s", plan.CertificateFormat.Value))
		//check if certificate format is valid by seeing if it's in the list of valid formats
		if !stringContains(VALID_CERTIFICATE_FORMATS, certificateFormat) {
			diags.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"Invalid certificate format '%s'. Valid formats are: %s",
					certificateFormat,
					strings.Join(VALID_CERTIFICATE_FORMATS, ", "),
				),
			)
			return nil, diags
		} else if certificateFormat == "PEM" {
			tflog.Warn(
				ctx, "PEM format selected for PFX enrollment. "+
					"But Golang can't decrypt the response so force PFX and decode later.",
			)
			certificateFormat = DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT
		}
	}
	ctx = tflog.SetField(ctx, "certificate_format", certificateFormat)

	var enrollmentPatternId int
	if !plan.EnrollmentPattern.IsNull() {
		// try to convert string to int
		var erpErr error
		var convErr error

		enrollmentPatternId, convErr = strconv.Atoi(plan.EnrollmentPattern.Value)
		if convErr != nil {
			tflog.Debug(ctx, "Enrollment pattern is not an integer, looking up by name.")
			enrollmentPatternId, erpErr = r.LookupEnrollmentPatternIDByName(
				ctx,
				plan.EnrollmentPattern.Value,
			) // API PERMISSIONS: Enrollment Pattern - READ
			if erpErr != nil {
				diags.AddError(
					ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
					fmt.Sprintf(
						"Could not find enrollment pattern '%s' on Keyfactor: %s",
						plan.EnrollmentPattern.Value,
						erpErr.Error(),
					),
				)
				return nil, diags
			}
		}

	} else if !plan.CertificateTemplate.IsNull() && plan.CertificateTemplate.Value != "" {
		// No enrollment pattern specified but a template was given.  On v25+
		// Command servers require an enrollment pattern — look up the default
		// one for this template. On pre-v25 servers this returns (0, nil) and
		// enrollment proceeds with the template name alone.
		var epErr error
		enrollmentPatternId, epErr = r.LookupEnrollmentPatternIDByTemplateName(
			ctx,
			plan.CertificateTemplate.Value,
		)
		if epErr != nil {
			diags.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"Could not look up enrollment pattern for template '%s': %s",
					plan.CertificateTemplate.Value,
					epErr.Error(),
				),
			)
			return nil, diags
		}
	}

	// When an enrollment pattern is used, do not also send the Template name.
	// On v25+ EJBCA, sending both causes the API to validate that the template
	// name matches the pattern's linked template exactly (by short name), which
	// fails when the user supplied the display name.  The enrollment pattern
	// already encodes the template; omitting Template is safe per the API docs.
	enrollTemplate := plan.CertificateTemplate.Value
	if enrollmentPatternId > 0 {
		enrollTemplate = ""
	}

	tflog.Debug(ctx, "Creating API request.")
	PFXArgs := &api.EnrollPFXFctArgsV2{
		CustomFriendlyName:          friendlyName,
		Password:                    lookupPassword,
		PopulateMissingValuesFromAD: false, //TODO: Add support for this
		CertificateAuthority:        plan.CertificateAuthority.Value,
		Template:                    enrollTemplate,
		IncludeChain:                true,              //TODO: Add support for this
		CertFormat:                  certificateFormat, // Get certificate from data source
		EnrollmentPatternId:         enrollmentPatternId,
		OwnerRoleName:               plan.OwnerRoleName.Value,
		SANs: &api.SANs{
			IP4: ipSANs,
			IP6: nil, //TODO: ipv6 SANs support
			DNS: dnsSANs,
			URI: uriSANs,
		},
		Metadata: metadata,
		Subject: &api.CertificateSubject{
			SubjectCommonName:         plan.CommonName.Value,
			SubjectLocality:           plan.Locality.Value,
			SubjectOrganization:       plan.Organization.Value,
			SubjectCountry:            plan.Country.Value,
			SubjectOrganizationalUnit: plan.OrganizationalUnit.Value,
			SubjectState:              plan.State.Value,
		},
	}
	if !plan.KeyType.Null && !plan.KeyType.Unknown && plan.KeyType.Value != "" {
		// Normalize "ECDSA" → "ECC" — the Command API only accepts "ECC".
		kt := plan.KeyType.Value
		if strings.EqualFold(kt, "ECDSA") {
			kt = "ECC"
		}
		PFXArgs.KeyType = kt

		// The Command API requires KeyLength alongside KeyType for all algorithms.
		// For Ed25519/Ed448 the size is fixed; for ECC derive it from key_size or
		// curve; for RSA use key_size directly.
		switch {
		case strings.EqualFold(kt, "Ed25519"):
			PFXArgs.KeyLength = 255
		case strings.EqualFold(kt, "Ed448"):
			PFXArgs.KeyLength = 448
		case strings.EqualFold(kt, "ECC"):
			if !plan.KeySize.Null && !plan.KeySize.Unknown && plan.KeySize.Value > 0 {
				PFXArgs.KeyLength = int(plan.KeySize.Value)
			} else if !plan.Curve.Null && !plan.Curve.Unknown && plan.Curve.Value != "" {
				PFXArgs.KeyLength = curveNameToKeyLength(plan.Curve.Value)
			}
		default: // RSA and any future types
			if !plan.KeySize.Null && !plan.KeySize.Unknown && plan.KeySize.Value > 0 {
				PFXArgs.KeyLength = int(plan.KeySize.Value)
			}
		}
	}
	if !plan.Curve.Null && !plan.Curve.Unknown && plan.Curve.Value != "" {
		// Curve OID alongside KeyLength further constrains the exact curve for ECC.
		PFXArgs.Curve = curveNameToOID(plan.Curve.Value)
	}
	tflog.Debug(ctx, "API PFXArgs created.")

	//convert PFX args to JSON string
	tflog.Debug(ctx, "Converting PFXArgs to JSON.")
	jsonData, err := json.Marshal(PFXArgs)
	if err != nil {
		tflog.Error(ctx, "Error converting PFXArgs to JSON.")
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			"Could not convert PFXArgs to JSON: "+err.Error(),
		)
		return nil, diags
	}
	ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))

	tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))
	tflog.Debug(ctx, fmt.Sprintf("Creating PFX certificate %s on Keyfactor.", PFXArgs.Subject.SubjectCommonName))
	tflog.Debug(ctx, "Calling EnrollPFXV2.")
	enrollResponse, err := r.p.client.EnrollPFXV2(PFXArgs)
	if err != nil {
		tflog.Error(ctx, "No response from Keyfactor Command after PFX enrollment.")
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			fmt.Sprintf(
				"Could not create certificate %s on Keyfactor: "+err.Error(),
				PFXArgs.Subject.SubjectCommonName,
			),
		)
		return nil, diags
	}
	enrolledId := enrollResponse.CertificateInformation.KeyfactorID
	ctx = tflog.SetField(ctx, "enrolled_id", enrolledId)
	enrolledThumbprint := enrollResponse.CertificateInformation.Thumbprint
	ctx = tflog.SetField(ctx, "enrolled_thumbprint", enrolledThumbprint)
	enrolledSerialNumber := enrollResponse.CertificateInformation.SerialNumber
	ctx = tflog.SetField(ctx, "enrolled_serial_number", enrolledSerialNumber)
	enrolledIssuerDN := enrollResponse.CertificateInformation.IssuerDN
	ctx = tflog.SetField(ctx, "enrolled_issuer_dn", enrolledIssuerDN)
	// check if request is pending approvals
	if enrollResponse.CertificateInformation.RequestDisposition == "PENDING" {
		// call HandlePendingCert
		tflog.Debug(ctx, fmt.Sprintf("Certificate %s is pending approval.", PFXArgs.Subject.SubjectCommonName))
		tflog.Debug(
			ctx,
			fmt.Sprintf("Calling HandlePendingCert for certificate %s.", PFXArgs.Subject.SubjectCommonName),
		)
		approvedCert, pErr := r.HandlePendingCert(
			ctx,
			enrollResponse,
			PFXArgs.Subject.SubjectCommonName,
			int(collectionId),
		)
		ERROR_PENDING_CERTS_PERMISSIONS := "does not have any of the required permissions: Alerts - Read"
		if pErr != nil {
			//check if error contains 401
			if strings.Contains(pErr.Error(), "401") || strings.Contains(
				pErr.Error(),
				ERROR_PENDING_CERTS_PERMISSIONS,
			) {
				tflog.Warn(ctx, "Unauthorized to list pending certificate requests.")
				waitResp, waitErr := r.WaitForPendingCert(
					ctx,
					enrollResponse,
					plan.CommonName.Value,
					int(collectionId),
				)
				if waitErr != nil {
					tflog.Error(
						ctx,
						fmt.Sprintf("Error handling pending certificate %s.", PFXArgs.Subject.SubjectCommonName),
					)
					diags.AddError(
						ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
						fmt.Sprintf(
							"Could not create certificate '%s' on Keyfactor Command: "+pErr.Error(),
							PFXArgs.Subject.SubjectCommonName,
						),
					)
					return nil, diags
				}
				approvedCert = waitResp
			} else {
				tflog.Error(
					ctx,
					fmt.Sprintf("Error handling pending certificate %s.", PFXArgs.Subject.SubjectCommonName),
				)
				diags.AddError(
					ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
					fmt.Sprintf(
						"Could not create certificate '%s' on Keyfactor Command: "+pErr.Error(),
						PFXArgs.Subject.SubjectCommonName,
					),
				)
				return nil, diags
			}
		}
		if approvedCert == nil {
			tflog.Error(
				ctx,
				fmt.Sprintf("Certificate '%s' is pending approval.", PFXArgs.Subject.SubjectCommonName),
			)
			diags.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"No response recieved on create certificate '%s' on Keyfactor Command: "+pErr.Error(),
					PFXArgs.Subject.SubjectCommonName,
				),
			)
			return nil, diags
		}

		enrolledId = approvedCert.Id
		ctx = tflog.SetField(ctx, "enrolled_id", enrolledId)
		enrolledThumbprint = approvedCert.Thumbprint
		ctx = tflog.SetField(ctx, "enrolled_thumbprint", enrolledThumbprint)
		enrolledSerialNumber = approvedCert.SerialNumber
		ctx = tflog.SetField(ctx, "enrolled_serial_number", enrolledSerialNumber)
		enrolledIssuerDN = approvedCert.IssuerDN
		ctx = tflog.SetField(ctx, "enrolled_issuer_dn", enrolledIssuerDN)
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Certificate %s (%d) has been approved and created.",
				PFXArgs.Subject.SubjectCommonName,
				enrolledId,
			),
		)
	}

	// Set state
	tflog.Info(
		ctx,
		fmt.Sprintf("Setting state for certificate '%s'(%d).", PFXArgs.Subject.SubjectCommonName, enrolledId),
	)
	tflog.Debug(ctx, "Creating state object")

	if plan.RenewalConfig != nil {
		tflog.Debug(ctx, "RenewalConfig is not nil, setting renewal_eligible to false.")
		plan.RenewalConfig.RenewEligible = types.Bool{
			Unknown: false,
			Value:   false,
		} // Set to false as we just enrolled the certificate
	}

	var result = CommandCertificate{
		ID:                 types.String{Value: fmt.Sprintf("%v", enrolledId)},
		CSR:                plan.CSR,
		CommonName:         plan.CommonName,
		Organization:       plan.Organization,
		OrganizationalUnit: plan.OrganizationalUnit,
		Locality:           plan.Locality,
		State:              plan.State,
		Country:            plan.Country,
		DNSSANs:            plan.DNSSANs,
		IPSANs:             plan.IPSANs,
		URISANs:            plan.URISANs,
		SerialNumber:       types.String{Value: normalizeSerialNumber(enrolledSerialNumber)},
		IssuerDN:           types.String{Value: enrolledIssuerDN},
		Thumbprint:         types.String{Value: normalizeThumbprint(enrolledThumbprint)},
		//PEM:                  types.String{Value: leafPEM}, //This is set below depending out output format
		//PEMCACert:            types.String{Value: chainPEM}, //This is set below depending out output format
		//PEMChain:             types.String{Value: chainPEM}, //This is set below depending out output format
		//PrivateKey:           types.String{Value: pKeyPEM}, //This is set below depending out output format
		KeyPassword:          plan.KeyPassword,
		EnrollmentPassword:   types.String{Value: lookupPassword, Null: isNullString(lookupPassword)},
		CertificateAuthority: knownStringFromPlan(plan.CertificateAuthority),
		CertificateTemplate:  plan.CertificateTemplate,
		CertificateId:        types.Int64{Value: int64(enrolledId)},
		RequestId:            types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)},
		Metadata:             knownMetadataFromPlan(plan.Metadata),
		CollectionId:         plan.CollectionId,
		FriendlyName:         plan.FriendlyName,
		UseCNAsFriendlyName:  plan.UseCNAsFriendlyName,
		ExpiryWarningDays:    plan.ExpiryWarningDays,
		IsExpired:            types.Bool{Value: false}, // Set to false as we just enrolled the certificate
		IsRevoked:            types.Bool{Value: false}, // Set to false as we just enrolled the certificate
		IsPendingRevocation:  types.Bool{Value: false}, // Newly enrolled certificates are not pending revocation
		RenewalConfig:        plan.RenewalConfig,
		CertificateFormat:    plan.CertificateFormat,
		OwnerRoleName:        plan.OwnerRoleName,
		EnrollmentPattern:    plan.EnrollmentPattern,
		NotBefore:            types.String{Null: true}, // Not provided in enroll response
		NotAfter:             types.String{Null: true}, // Not provided in enroll response
		RevocationEffDate:    types.String{Null: true}, // Not provided in enroll response
		RevokeOnDestroy:      plan.RevokeOnDestroy,
		KeyType:              knownStringFromPlan(plan.KeyType),
		KeySize:              knownInt64FromPlan(plan.KeySize),
		Curve:                knownStringFromPlan(plan.Curve),
	}

	switch certificateFormat {
	case "JKS":
		tflog.Debug(ctx, "Certificate format is JKS, setting JKS as the content of the PKCS12 blob.")
		result.JKS = types.String{
			Value: enrollResponse.CertificateInformation.PKCS12Blob,
			Null:  isNullString(enrollResponse.CertificateInformation.PKCS12Blob),
		}
		result.PEM = types.String{Null: true}
		result.PEMCACert = types.String{Null: true}
		result.PEMChain = types.String{Null: true}
		result.PrivateKey = types.String{Null: true}
	case "ZIP":
		tflog.Debug(ctx, "Certificate format is ZIP, setting ZIP as the content of the PKCS12 blob.")
		result.Zip = types.String{
			Value: enrollResponse.CertificateInformation.PKCS12Blob,
			Null:  isNullString(enrollResponse.CertificateInformation.PKCS12Blob),
		}
		result.PEM = types.String{Null: true}
		result.PEMCACert = types.String{Null: true}
		result.PEMChain = types.String{Null: true}
		result.PrivateKey = types.String{Null: true}
	case "PFX", DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT:
		result.PEM = types.String{Null: true}
		result.PEMCACert = types.String{Null: true}
		result.PEMChain = types.String{Null: true}
		result.PrivateKey = types.String{Null: true}

		result.JKS = types.String{Null: true}
		result.Zip = types.String{Null: true}
		result.PFX = types.String{Null: true}

		if certificateFormat == "PFX" {
			tflog.Debug(ctx, "Certificate format is PFX, setting PFX as the content of the PKCS12 blob.")
			result.PFX = types.String{
				Value: enrollResponse.CertificateInformation.PKCS12Blob,
				Null:  isNullString(enrollResponse.CertificateInformation.PKCS12Blob),
			}
			return &result, diags
		}

		tflog.Debug(ctx, "Unpacking PKCS12 blob to PEM")
		var (
			pfxErr error
		)
		pKeyPEM, leafPEM, pChain, pfxErr = api.UnpackPkcs12(
			enrollResponse.CertificateInformation.PKCS12Blob,
			lookupPassword,
		)
		chainPEM = strings.Join(pChain, "")

		if pfxErr != nil {
			// If the PKCS#12 contains a key algorithm unsupported by Go's pkcs12/x509
			// libraries (e.g. Ed448, OID 1.3.101.113), private key extraction is not
			// possible at all — skip it and fall back to a PEM download for cert data.
			if strings.Contains(pfxErr.Error(), "unknown algorithm") {
				tflog.Warn(ctx, fmt.Sprintf(
					"Cannot extract private key from PFX for certificate %d — unsupported algorithm: %v",
					enrolledId, pfxErr,
				))
				leafPEM, chainPEM, _, _ = downloadCertificateFromKeyfactorCommand(ctx, enrolledId, collectionIdInt, r.p.client)
				// pKeyPEM remains empty; PrivateKey will be null in state
			} else {
				tflog.Error(ctx, "Error unpacking PKCS12 blob, attempting to recover private key.")
				//attempt to recover private key
				rErr := diag.Diagnostics{}
				pKeyPEM, leafPEM, chainPEM, _, rErr = recoverPrivateKeyFromKeyfactorCommand(
					ctx,
					enrolledId,
					collectionIdInt,
					lookupPassword,
					r.p.client,
					"PFX",
				)
				diags.Append(rErr...)
				if diags.HasError() {
					diags.AddError(
						"Private key recovery failed.",
						"Could not recover private key from Keyfactor Command: "+pfxErr.Error(),
					)
					return nil, diags
				}
			}
		}

		leafPEM = normalizePEMLineEndings(leafPEM)
		chainPEM = normalizePEMLineEndings(chainPEM)
		result.PEM = types.String{Value: leafPEM, Null: isNullString(leafPEM)}
		result.PEMCACert = types.String{Value: chainPEM, Null: isNullString(chainPEM)}
		result.PEMChain = types.String{Value: leafPEM + chainPEM, Null: isNullString(leafPEM + chainPEM)}
		result.PrivateKey = types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)}
		// Parse leaf to populate validity window fields from the enrolled certificate.
		if leafPEM != "" {
			if leafObj, leafParseErr := parseLeafCert(ctx, leafPEM); !leafParseErr.HasError() && leafObj != nil {
				result.NotBefore = types.String{Value: leafObj.NotBefore.UTC().Format(time.RFC3339)}
				result.NotAfter = types.String{Value: leafObj.NotAfter.UTC().Format(time.RFC3339)}
				result.IsExpired = types.Bool{Value: time.Now().After(leafObj.NotAfter)}
			}
		}
	default:
		tflog.Error(ctx, "Invalid certificate format, this should have been caught earlier.")
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			fmt.Sprintf(
				"Invalid certificate format '%s'. Valid formats are: %s",
				certificateFormat,
				strings.Join(VALID_CERTIFICATE_FORMATS, ", "),
			),
		)
		return nil, diags
	}

	return &result, diags
}

// ParseCertSubjectAltNames parses a PEM-encoded X.509 certificate
// and returns DNS names, IP addresses, and URIs from its SAN extension.
func ParseCertSubjectAltNames(certPEM string) ([]string, []net.IP, []*url.URL, error) {
	// Decode PEM block
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract SANs
	dnsNames := cert.DNSNames
	ipAddresses := cert.IPAddresses
	uris := cert.URIs

	return dnsNames, ipAddresses, uris, nil
}

// ParseCSRSubjectAltNames takes a PEM-encoded CSR and extracts the DNS names,
// IP addresses, and URIs from the SAN extension.
func (r resourceCommandCertificate) ParseCSRSubjectAltNames(csrPEM string) ([]string, []net.IP, []*url.URL, error) {
	// Decode PEM block
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, nil, fmt.Errorf("failed to decode PEM block containing CSR")
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Check for signature validity (optional but recommended)
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Extract SANs
	dnsNames := csr.DNSNames
	ipAddresses := csr.IPAddresses
	uris := csr.URIs

	return dnsNames, ipAddresses, uris, nil
}

func (r resourceCommandCertificate) parseSans(ctx context.Context, plan *CommandCertificate) (
	[]string, []string,
	[]string, diag.Diagnostics,
) {
	var dnsSANs []string
	var ipSANs []string
	var uriSANs []string
	diags := diag.Diagnostics{}

	tflog.Debug(ctx, fmt.Sprintf("Parsing DNS SANs: %s", plan.DNSSANs))
	diags = plan.DNSSANs.ElementsAs(ctx, &dnsSANs, true)
	tflog.Debug(ctx, fmt.Sprintf("Parsing IP SANs: %s", plan.IPSANs))
	diags = plan.IPSANs.ElementsAs(ctx, &ipSANs, true)
	tflog.Debug(ctx, fmt.Sprintf("Parsing URI SANs: %s", plan.URISANs))
	diags = plan.URISANs.ElementsAs(ctx, &uriSANs, true)

	return dnsSANs, ipSANs, uriSANs, diags
}

func (r resourceCommandCertificate) LookupEnrollmentPatternIDByName(
	ctx context.Context,
	patternName string,
) (int, error) {
	tflog.Debug(ctx, fmt.Sprintf("Looking up enrollment pattern ID for pattern name: %s", patternName))
	patterns, err := r.p.client.GetEnrollmentPatterns()
	if err != nil {
		return 0, fmt.Errorf("could not list enrollment patterns: %w", err)
	}
	for _, pattern := range patterns {
		if pattern.Name != "" && pattern.Name == patternName {
			tflog.Debug(
				ctx,
				fmt.Sprintf("Found enrollment pattern ID %d for pattern name: %s", pattern.ID, patternName),
			)
			return pattern.ID, nil
		}
	}
	return 0, fmt.Errorf("enrollment pattern with name '%s' not found", patternName)
}

// LookupEnrollmentPatternIDByTemplateName finds the enrollment pattern for the
// given template short name. The resolution policy is:
//
//   - 0 matches → return (0, nil) — fall through to direct template enrollment
//     (pre-v25 / standalone CA).
//   - 1 match → return that pattern's ID — unambiguous.
//   - 2+ matches, exactly one has TemplateDefault=true → return the default's ID.
//   - 2+ matches, zero or 2+ have TemplateDefault=true → return an error so the
//     user must set certificate_enrollment_pattern explicitly.
func (r resourceCommandCertificate) LookupEnrollmentPatternIDByTemplateName(
	ctx context.Context,
	templateName string,
) (int, error) {
	tflog.Debug(ctx, fmt.Sprintf("Looking up default enrollment pattern for template: %s", templateName))
	patterns, err := r.p.client.GetEnrollmentPatterns()
	if err != nil {
		// Pre-v25 servers may return 404/501 — treat as "not found" and fall through.
		tflog.Warn(ctx, fmt.Sprintf("Could not list enrollment patterns (may be pre-v25): %s", err.Error()))
		return 0, nil
	}

	// Collect all patterns linked to this template.
	type match struct {
		id              int
		name            string
		templateDefault bool
	}
	var matches []match
	for _, pattern := range patterns {
		if pattern.Template != nil && pattern.Template.TemplateName == templateName {
			matches = append(matches, match{
				id:              pattern.ID,
				name:            pattern.Name,
				templateDefault: pattern.TemplateDefault,
			})
		}
	}

	switch len(matches) {
	case 0:
		tflog.Debug(ctx, fmt.Sprintf("No enrollment pattern found for template '%s', proceeding without one", templateName))
		return 0, nil
	case 1:
		tflog.Debug(ctx, fmt.Sprintf(
			"Found enrollment pattern '%s' (ID=%d) for template '%s'",
			matches[0].name, matches[0].id, templateName,
		))
		return matches[0].id, nil
	default:
		// 2+ matches — look for a unique default.
		var defaults []match
		for _, m := range matches {
			if m.templateDefault {
				defaults = append(defaults, m)
			}
		}
		if len(defaults) == 1 {
			tflog.Debug(ctx, fmt.Sprintf(
				"Found default enrollment pattern '%s' (ID=%d) for template '%s' (%d total patterns)",
				defaults[0].name, defaults[0].id, templateName, len(matches),
			))
			return defaults[0].id, nil
		}
		return 0, fmt.Errorf(
			"template %q has %d associated enrollment patterns with no unique default; "+
				"set certificate_enrollment_pattern explicitly to disambiguate",
			templateName, len(matches),
		)
	}
}

// normalizeKeyAlgorithm maps OID strings returned by EJBCA and some CA
// implementations to the provider's canonical key-type names.  If the value
// is already a friendly name or is unrecognized it is returned unchanged.
func normalizeKeyAlgorithm(algo string) string {
	switch algo {
	case "1.2.840.113549.1.1.1":
		return "RSA"
	case "1.2.840.10045.2.1":
		return "ECC"
	case "ECDSA":
		return "ECC"
	case "1.3.101.112":
		return "Ed25519"
	case "1.3.101.113":
		return "Ed448"
	default:
		return algo
	}
}

// curveNameToKeyLength returns the KeyLength value the Command API needs for
// a given ECC curve name. Returns 0 if the curve is unrecognized (caller
// should leave KeyLength unset rather than send 0).
func curveNameToKeyLength(curve string) int {
	switch curve {
	case "P-256", "prime256v1", "secp256r1":
		return 256
	case "P-384", "secp384r1":
		return 384
	case "P-521", "secp521r1":
		return 521
	default:
		return 0
	}
}

// curveNameToOID converts a user-friendly ECC curve name to the OID string
// required by the Keyfactor Command PFX enrollment API.  Per the API docs,
// "ECC curves must be specified using the OID for the ECC algorithm."
// If the value is already an OID or unrecognized it is returned unchanged.
func curveNameToOID(curve string) string {
	switch curve {
	case "P-256", "prime256v1", "secp256r1":
		return "1.2.840.10045.3.1.7"
	case "P-384", "secp384r1":
		return "1.3.132.0.34"
	case "P-521", "secp521r1":
		return "1.3.132.0.35"
	default:
		return curve // pass through if already OID or unknown name
	}
}

// curveOIDToName converts an OID returned by the API back to the user-friendly
// curve name stored in provider state.
func curveOIDToName(oid string) string {
	switch oid {
	case "1.2.840.10045.3.1.7":
		return "P-256"
	case "1.3.132.0.34":
		return "P-384"
	case "1.3.132.0.35":
		return "P-521"
	default:
		return oid
	}
}

// knownMetadataFromPlan returns plan.Metadata if it is a known value, or an
// empty map if it is Unknown (i.e. Computed and not set in config). This
// ensures the provider never stores an unknown metadata value in state.
func knownMetadataFromPlan(m types.Map) types.Map {
	if m.Unknown {
		return types.Map{ElemType: types.StringType, Elems: map[string]attr.Value{}}
	}
	return m
}

// knownStringFromPlan returns plan value if known, otherwise types.String{Null: true}.
// Prevents storing Unknown in state for Computed string fields.
func knownStringFromPlan(s types.String) types.String {
	if s.Unknown {
		return types.String{Null: true}
	}
	return s
}

// knownInt64FromPlan returns plan value if known, otherwise types.Int64{Null: true}.
// Prevents storing Unknown in state for Computed int64 fields.
func knownInt64FromPlan(i types.Int64) types.Int64 {
	if i.Unknown {
		return types.Int64{Null: true}
	}
	return i
}

func (r resourceCommandCertificate) parseMetadata(
	ctx context.Context,
	plan *CommandCertificate,
) (map[string]interface{}, diag.Diagnostics) {
	// iterate over metadata map and convert to map[string]interface{}
	tflog.Debug(ctx, fmt.Sprintf("Parsing metadata: %s", plan.Metadata))
	metaDataElms := plan.Metadata.Elems
	metadata := make(map[string]interface{})
	for k, elm := range metaDataElms {
		metadata[k] = strings.Replace(elm.String(), "\"", "", -1)
	}
	return metadata, nil
}

func (r resourceCommandCertificate) enrollCSR(
	ctx context.Context, csr string,
	plan *CommandCertificate,
) (
	*CommandCertificate,
	diag.Diagnostics,
) {
	//ensure that conflicting values are not set
	diags := diag.Diagnostics{}
	if plan.CommonName.Value != "" || plan.Organization.Value != "" || plan.OrganizationalUnit.Value != "" || plan.Locality.Value != "" || plan.State.Value != "" || plan.Country.Value != "" || plan.PrivateKey.Value != "" || plan.KeyPassword.Value != "" {
		diags.AddError(
			ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
			"You cannot set the private_key, password, common_name, organization, organizational_unit, locality, state, or country when using a CSR.",
		)
		return nil, diags
	}

	tflog.Debug(ctx, "Calling parseSans()")
	dnsSANs, ipSANs, uriSANs, dnsSANsDiags := r.parseSans(ctx, plan)
	if dnsSANsDiags.HasError() {
		diags.Append(dnsSANsDiags...)
	}

	metadata, metadataDiags := r.parseMetadata(ctx, plan)
	if metadataDiags.HasError() {
		diags.Append(metadataDiags...)
	}

	certificateFormat := DEFAULT_CERTIFICATE_CSR_ENROLLMENT_FORMAT
	if !plan.CertificateFormat.IsNull() {
		certificateFormat = strings.ToUpper(fmt.Sprintf("%s", plan.CertificateFormat.Value))
		//check if certificate format is valid by seeing if it's in the list of valid formats
		if !stringContains(VALID_CSR_CERTIFICATE_FORMATS, certificateFormat) {
			diags.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"Invalid certificate format '%s'. Valid formats are: %s",
					certificateFormat,
					strings.Join(VALID_CSR_CERTIFICATE_FORMATS, ", "),
				),
			)
			return nil, diags
		}
	}
	ctx = tflog.SetField(ctx, "certificate_format", certificateFormat)

	var enrollmentPatternId int
	if !plan.EnrollmentPattern.IsNull() {
		// try to convert string to int
		var erpErr error
		var convErr error

		enrollmentPatternId, convErr = strconv.Atoi(plan.EnrollmentPattern.Value)
		if convErr != nil {
			tflog.Debug(ctx, "Enrollment pattern is not an integer, looking up by name.")
			enrollmentPatternId, erpErr = r.LookupEnrollmentPatternIDByName(
				ctx,
				plan.EnrollmentPattern.Value,
			) // API PERMISSIONS: Enrollment Pattern - READ
			if erpErr != nil {
				diags.AddError(
					ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
					fmt.Sprintf(
						"Could not find enrollment pattern '%s' on Keyfactor: %s",
						plan.EnrollmentPattern.Value,
						erpErr.Error(),
					),
				)
				return nil, diags
			}
		}

	} else if !plan.CertificateTemplate.IsNull() && plan.CertificateTemplate.Value != "" {
		// No enrollment pattern specified but a template was given.  On v25+
		// Command servers require an enrollment pattern — look up the default
		// one for this template. On pre-v25 servers this returns (0, nil) and
		// enrollment proceeds with the template name alone.
		var epErr error
		enrollmentPatternId, epErr = r.LookupEnrollmentPatternIDByTemplateName(
			ctx,
			plan.CertificateTemplate.Value,
		)
		if epErr != nil {
			diags.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"Could not look up enrollment pattern for template '%s': %s",
					plan.CertificateTemplate.Value,
					epErr.Error(),
				),
			)
			return nil, diags
		}
	}

	// When an enrollment pattern is used, do not also send the Template name.
	// See the same comment in enrollPFXV2 for details.
	enrollCSRTemplate := plan.CertificateTemplate.Value
	if enrollmentPatternId > 0 {
		enrollCSRTemplate = ""
	}

	tflog.Debug(ctx, "Creating certificate from CSR.")
	CSRArgs := &api.EnrollCSRFctArgs{
		CSR:                  csr,
		CertificateAuthority: plan.CertificateAuthority.Value,
		Template:             enrollCSRTemplate,
		EnrollmentPatternId:  enrollmentPatternId,
		IncludeChain:         true,
		CertFormat:           certificateFormat,
		SANs: &api.SANs{
			IP4: ipSANs,
			IP6: nil, //TODO: ipv6 SANs support
			DNS: dnsSANs,
			URI: uriSANs,
		},
		Metadata:      metadata,
		OwnerRoleName: plan.OwnerRoleName.Value,
	}
	tflog.Trace(
		ctx, "Passing args to Keyfactor API.", map[string]interface{}{
			"args": CSRArgs,
		},
	)
	enrollResponse, err := r.p.client.EnrollCSR(CSRArgs)
	if err != nil {
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			"Could not create certificate in Keyfactor: "+err.Error(),
		)
		return nil, diags
	}

	//Collection

	// iterate through CertificateInformation.Certificates and concatenate
	var (
		fullChain string
		caCert    string
		leaf      string
	)

	for i, cert := range enrollResponse.CertificateInformation.Certificates {
		cert = normalizePEMLineEndings(cert)
		// split by \r\n and remove first line if '#' is present
		tflog.Trace(ctx, fmt.Sprintf("Processing certificate %d: %s", i, cert))
		if strings.Contains(cert, "#") {
			tflog.Debug(ctx, "Certificate contains '#', removing first line.")
			parts := strings.SplitN(cert, "\n", 2)
			if len(parts) > 1 {
				cert = strings.Join(parts[1:], "")
			} else {
				tflog.Warn(ctx, "Certificate contains '#' but no newline character. Skipping first line removal.")
			}
		}

		fullChain += cert
		tflog.Trace(ctx, fmt.Sprintf("Full chain after adding certificate %d: %s", i, fullChain))
		if i > 0 { //caCert returns full chain minus leaf
			tflog.Trace(ctx, fmt.Sprintf("Adding certificate %d to CA cert chain.", i))
			caCert += cert
		} else {
			// assume 0th certificate is the leaf
			leaf = cert
			tflog.Trace(ctx, fmt.Sprintf("Leaf certificate: %s", leaf))
		}

	}

	// Set state
	if plan.RenewalConfig != nil {
		plan.RenewalConfig.RenewEligible = types.Bool{
			Value: false, // Assume not eligible for renewal as this is a new certificate
		} // Assume not eligible for renewal as this is a new certificate
	}

	// Check if DNSSANs, IPSANs, and URISANs are empty and set them to null if they are
	if len(plan.DNSSANs.Elems) != 0 {
		diags.AddWarning(
			"`dns_sans` are set but not used in CSR enrollment.",
			"The `dns_sans` field is not used in CSR enrollment, "+
				"they will be ignored. Please include the SANs in the CSR instead.",
		)
	}
	if len(plan.IPSANs.Elems) != 0 {
		diags.AddWarning(
			"`ip_sans` are set but not used in CSR enrollment.",
			"The `ip_sans` field is not used in CSR enrollment, "+
				"they will be ignored. Please include the SANs in the CSR instead.",
		)
	}
	if len(plan.URISANs.Elems) != 0 {
		diags.AddWarning(
			"`uri_sans` are set but not used in CSR enrollment.",
			"The `uri_sans` field is not used in CSR enrollment, "+
				"they will be ignored. Please include the SANs in the CSR instead.",
		)
	}

	var result = CommandCertificate{
		ID: types.String{
			Value: fmt.Sprintf(
				"%v",
				enrollResponse.CertificateInformation.KeyfactorID,
			),
		},
		CSR:                types.String{Value: csr},
		CommonName:         plan.CommonName,
		Organization:       plan.Organization,
		OrganizationalUnit: plan.OrganizationalUnit,
		Locality:           plan.Locality,
		State:              plan.State,
		Country:            plan.Country,
		DNSSANs:            plan.DNSSANs,
		IPSANs:             plan.IPSANs,
		URISANs:            plan.URISANs,
		SerialNumber:       types.String{Value: normalizeSerialNumber(enrollResponse.CertificateInformation.SerialNumber)},
		IssuerDN:           types.String{Value: enrollResponse.CertificateInformation.IssuerDN},
		Thumbprint:         types.String{Value: normalizeThumbprint(enrollResponse.CertificateInformation.Thumbprint)},
		PEM:                types.String{Value: leaf},
		PEMCACert:          types.String{Value: caCert},
		PEMChain:           types.String{Value: fullChain},
		PrivateKey: types.String{
			Value: plan.PrivateKey.Value,
			Null:  true,
		}, // Null because CSR enrollment does not provide a private key
		KeyPassword: types.String{
			Value: plan.KeyPassword.Value,
			Null:  true,
		}, // Null because CSR enrollment does not provide a private key
		EnrollmentPassword:   types.String{Null: true}, // Null because CSR enrollment does not provide an enrollment password
		CertificateAuthority: knownStringFromPlan(plan.CertificateAuthority),
		CertificateId:        types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorID)},
		CertificateTemplate:  plan.CertificateTemplate,
		Metadata:             knownMetadataFromPlan(plan.Metadata),
		CollectionId:         plan.CollectionId,
		FriendlyName:         plan.FriendlyName,
		UseCNAsFriendlyName:  plan.UseCNAsFriendlyName,
		ExpiryWarningDays:    plan.ExpiryWarningDays,
		IsExpired:            types.Bool{Value: false}, //Assuming the certificate is not expired as it should be newly created
		IsRevoked:            types.Bool{Value: false}, //Assuming the certificate is not revoked as it should be newly created
		IsPendingRevocation:  types.Bool{Value: false}, // Newly enrolled certificates are not pending revocation
		RenewalConfig:        plan.RenewalConfig,
		EnrollmentPattern:    plan.EnrollmentPattern,
		CertificateFormat:    plan.CertificateFormat,
		OwnerRoleName:        plan.OwnerRoleName,
		PFX:                  types.String{Null: true}, // Null because CSR enrollment does not provide a PFX
		JKS:                  types.String{Null: true}, // Null because CSR enrollment does not provide a JKS
		Zip:                  types.String{Null: true}, // Null because CSR enrollment does not provide a ZIP
		NotBefore:            types.String{Null: true}, // Null because CSR enrollment does not provide NotBefore
		NotAfter:             types.String{Null: true}, // Null because CSR enrollment does not provide NotAfter
		RevocationEffDate:    types.String{Null: true}, // Not provided in enroll response
		RevokeOnDestroy:      plan.RevokeOnDestroy,
		KeyType:              types.String{Null: true}, // Not applicable for CSR enrollment
		KeySize:              types.Int64{Null: true},  // Not applicable for CSR enrollment
		Curve:                types.String{Null: true}, // Not applicable for CSR enrollment
	}

	leafObj, leafErr := parseLeafCert(ctx, leaf)
	if leafErr == nil {
		result.NotBefore = types.String{Value: leafObj.NotBefore.Format(time.RFC3339)}
		result.NotAfter = types.String{Value: leafObj.NotAfter.Format(time.RFC3339)}
		result.IsExpired = types.Bool{Value: time.Now().After(leafObj.NotAfter)}
	}

	return &result, diags
}
