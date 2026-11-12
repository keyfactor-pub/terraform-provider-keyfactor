package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
	"strings"
)

type resourceCertificateTemplateRoleBindingType struct{}

func (r resourceCertificateTemplateRoleBindingType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "ID of template role binding.",
			},
			"role_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor. Changing this to a different role forces the binding to be replaced; a change that only differs in letter case (Command matches role names case-insensitively) is applied in place.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplaceIf(
						roleNameRequiresReplace,
						"Triggers resource replacement when 'role_name' changes to a different role (a case-only change does not).",
						"Triggers resource replacement when `role_name` changes to a different role (a case-only change does not).",
					),
				},
			},
			"template_short_names": {
				Type:        types.ListType{ElemType: types.StringType},
				Optional:    true,
				Description: "A list of certificate template short name in Keyfactor that the role will be attached to.",
			},
		},
		Description:         "Grants a Keyfactor security role enrollment permissions on one or more certificate templates by managing the template's allowed requesters list via the `/Templates` PUT API.",
		MarkdownDescription: "\nGrants a Keyfactor security role enrollment permissions on one or more certificate templates by managing the template's allowed requesters list via the `/Templates` PUT API. On Keyfactor Command v25.0+, enrollment patterns provide an additional enrollment-configuration layer alongside certificate templates.\n",
	}, nil
}

func (r resourceCertificateTemplateRoleBindingType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCertificateTemplateRoleBinding{
		p: *(p.(*provider)),
	}, nil
}

type resourceCertificateTemplateRoleBinding struct {
	p provider
}

func (r resourceCertificateTemplateRoleBinding) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan CertificateTemplateRoleBinding
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	kfClient := r.p.client
	roleName := plan.RoleName.Value

	tflog.Info(ctx, "Create called on certificate template role binding.")

	// Verify template names
	var templateNames []string
	var validTemplateIds []int
	var apiDiags []diag.Diagnostic

	response.Diagnostics.Append(plan.TemplateNames.ElementsAs(ctx, &templateNames, true)...)
	if response.Diagnostics.HasError() {
		return
	}

	bindingID := templateRoleBindingID(roleName, templateNames)
	ctx = tflog.SetField(ctx, "role_binding_id", bindingID.Value)

	// List all templates
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}
	validTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, templateNames, templateNameSidePlan)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", validTemplateIds))
	response.Diagnostics.Append(apiDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Create role binding: attach the role to every template in the plan.
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, uniqueInts(validTemplateIds), nil)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	result := CertificateTemplateRoleBinding{
		ID:            bindingID,
		RoleName:      plan.RoleName,
		TemplateNames: plan.TemplateNames,
	}
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

func (r resourceCertificateTemplateRoleBinding) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state CertificateTemplateRoleBinding
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client
	roleName := state.RoleName.Value

	tflog.Info(ctx, "Create called on certificate template role binding.")

	var templateNames []string
	response.Diagnostics.Append(state.TemplateNames.ElementsAs(ctx, &templateNames, true)...)
	if response.Diagnostics.HasError() {
		return
	}
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}

	// Keep the stored id when there is one: it was assigned by Create/ImportState/Update with
	// templateRoleBindingID, and rewriting a computed id during refresh would only add noise. An
	// empty id (for example a state written before the id existed) is recomputed with the same helper.
	if state.ID.Null || state.ID.Unknown || state.ID.Value == "" {
		state.ID = templateRoleBindingID(roleName, templateNames)
	}
	ctx = tflog.SetField(ctx, "role_binding_id", state.ID.Value)

	// A template that no longer exists in Command can no longer carry the binding, so drop it from
	// state: the next plan then shows the drift (the configuration still lists the template) instead
	// of silently reporting no changes.
	if !state.TemplateNames.Null && !state.TemplateNames.Unknown {
		keptNames, droppedNames := partitionTemplateNamesByExistence(kfTemplates, templateNames)
		if len(droppedNames) > 0 {
			response.Diagnostics.AddWarning(
				"Template(s) no longer exist in Keyfactor Command; removed from state.",
				"The following template(s) in the role binding for role "+roleName+" were not found in Keyfactor Command (they may have been deleted) and have been removed from state: "+
					strings.Join(droppedNames, ", ")+". The next plan will show the difference from the configuration.",
			)
			elems := make([]attr.Value, 0, len(keptNames))
			for _, n := range keptNames {
				elems = append(elems, types.String{Value: n})
			}
			state.TemplateNames = types.List{ElemType: types.StringType, Elems: elems}
		}
	}

	// Set state
	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCertificateTemplateRoleBinding) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// Get plan values
	var plan CertificateTemplateRoleBinding
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state CertificateTemplateRoleBinding
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	kfClient := r.p.client
	roleName := state.RoleName.Value

	tflog.Info(ctx, "Create called on certificate template role binding.")

	// Validate template names
	var stateTemplateNames []string
	var planTemplateNames []string
	var stateValidTemplateIds []int
	var apiDiags []diag.Diagnostic
	response.Diagnostics.Append(state.TemplateNames.ElementsAs(ctx, &stateTemplateNames, true)...)
	response.Diagnostics.Append(plan.TemplateNames.ElementsAs(ctx, &planTemplateNames, true)...)
	if response.Diagnostics.HasError() {
		return
	}
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}
	stateValidTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, stateTemplateNames, templateNameSideState)
	response.Diagnostics.Append(apiDiags...)
	planValidTemplateIds, planApiDiags := verifyTemplateNames(ctx, kfTemplates, planTemplateNames, templateNameSidePlan)
	response.Diagnostics.Append(planApiDiags...)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", stateValidTemplateIds))
	if response.Diagnostics.HasError() {
		return
	}

	// The binding id is derived from the role and the template list, so it is recomputed from the
	// planned values (the same helper Create and ImportState use). A stale id kept from state would
	// no longer match what Create/ImportState would produce for this configuration.
	bindingID := templateRoleBindingID(plan.RoleName.Value, planTemplateNames)
	ctx = tflog.SetField(ctx, "role_binding_id", bindingID.Value)

	// Attach the role only to templates that are new in the plan and detach it only from templates
	// that left the plan; templates present on both sides need no call at all.
	additions, removals := diffTemplateIDSets(stateValidTemplateIds, planValidTemplateIds)
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, additions, removals)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	result := CertificateTemplateRoleBinding{
		ID:            bindingID,
		RoleName:      plan.RoleName,
		TemplateNames: plan.TemplateNames,
	}
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCertificateTemplateRoleBinding) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	var state CertificateTemplateRoleBinding
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	kfClient := r.p.client
	roleName := state.RoleName.Value

	// Verify template names
	var templateNames []string
	var validTemplateIds []int
	var apiDiags []diag.Diagnostic

	diags = state.TemplateNames.ElementsAs(ctx, &templateNames, true)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "role_binding_id", templateRoleBindingID(roleName, templateNames).Value)

	// List all templates
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}
	validTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, templateNames, templateNameSideState)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", validTemplateIds))
	response.Diagnostics.Append(apiDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Destroy only ever detaches the role; it never attaches it to anything.
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, nil, uniqueInts(validTemplateIds))
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceCertificateTemplateRoleBinding) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on certificate template role binding resource")

	roleName := request.ID
	if roleName == "" {
		response.Diagnostics.AddError(
			"Invalid import ID",
			"Expected role name as import ID, got empty string.",
		)
		return
	}

	kfClient := r.p.client

	// Discover all templates where this role is listed as an allowed requester.
	diags, templateIds := findTemplateRoleAttachments(ctx, kfClient, roleName)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Map template IDs back to short names via the full template list.
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}

	idSet := make(map[int]struct{}, len(templateIds))
	for _, id := range templateIds {
		idSet[id.(int)] = struct{}{}
	}

	var templateNames []string
	for _, t := range kfTemplates {
		if _, ok := idSet[t.Id]; ok {
			templateNames = append(templateNames, t.CommonName)
		}
	}

	elems := make([]attr.Value, 0, len(templateNames))
	for _, n := range templateNames {
		elems = append(elems, types.String{Value: n})
	}

	result := CertificateTemplateRoleBinding{
		ID:            templateRoleBindingID(roleName, templateNames),
		RoleName:      types.String{Value: roleName},
		TemplateNames: types.List{ElemType: types.StringType, Elems: elems},
	}

	diags2 := response.State.Set(ctx, result)
	response.Diagnostics.Append(diags2...)
}

// templateRoleBindingID is the single definition of the keyfactor_template_role_binding resource
// id: the hex SHA-256 of "<role>-<template1>-<template2>...". Create, Update, Read (when the state
// has no id) and ImportState all use it, so every code path agrees on the format.
func templateRoleBindingID(roleName string, templateNames []string) types.String {
	hid := fmt.Sprintf("%s-%s", roleName, strings.Join(templateNames, "-"))
	return types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))}
}

// templateNameSide says where a list of template names passed to verifyTemplateNames came from.
type templateNameSide int

const (
	// templateNameSidePlan: names the user configured. A name that matches no template is an error.
	templateNameSidePlan templateNameSide = iota
	// templateNameSideState: names recorded in prior state. A name that matches no template means
	// the template was deleted in Command; there is nothing left to bind or un-bind for it, so it
	// is skipped with a warning rather than blocking the operation.
	templateNameSideState
)

// findTemplateByName returns the first template whose common name equals name, compared
// case-insensitively (the way Command resolves template names), or nil when name is empty or
// matches no template. It is the single matching rule shared by verifyTemplateNames and
// partitionTemplateNamesByExistence.
func findTemplateByName(templates []api.GetTemplateResponse, name string) *api.GetTemplateResponse {
	if name == "" {
		return nil
	}
	for i := range templates {
		if strings.EqualFold(templates[i].CommonName, name) {
			return &templates[i]
		}
	}
	return nil
}

// verifyTemplateNames resolves template names to template IDs. An empty name is an error on
// either side. A name that matches no template is an error for plan-side names and a warning
// (the name is skipped) for state-side names.
func verifyTemplateNames(ctx context.Context, templates []api.GetTemplateResponse, templateNames []string, side templateNameSide) (
	[]int,
	[]diag.Diagnostic,
) {
	var diags diag.Diagnostics
	var result []int
	for _, templateName := range templateNames {
		if templateName == "" {
			diags.AddError("Error empty template name.", "Template name provided")
			continue
		}
		if template := findTemplateByName(templates, templateName); template != nil {
			result = append(result, template.Id)
		} else {
			if side == templateNameSideState {
				diags.AddWarning(
					"Template name not found; skipping.",
					"Template name "+templateName+" from the existing binding was not found in Keyfactor Command (it may have been deleted); there is nothing to un-bind for it, so it is skipped.",
				)
			} else {
				diags.AddError(
					"Template not found in Keyfactor Command.",
					"Template '"+templateName+"' listed in template_short_names does not exist in Keyfactor Command "+
						"(it may have been deleted or renamed, or the name is misspelled). Remove it from "+
						"template_short_names, or recreate the template, and apply again.",
				)
			}
		}

	}
	return result, diags
}

// roleNameRequiresReplace is the tfsdk.RequiresReplaceIfFunc for role_name. Command matches
// security role names case-insensitively (and refuses two roles whose names differ only by case),
// so a change that differs only in letter case still names the same role and is applied in place.
// Any other change, including an unknown value, replaces the binding.
func roleNameRequiresReplace(_ context.Context, state, config attr.Value, _ path.Path) (bool, diag.Diagnostics) {
	stateStr, sOk := state.(types.String)
	configStr, cOk := config.(types.String)
	if !sOk || !cOk {
		return true, nil
	}
	return roleNameChangeRequiresReplace(stateStr, configStr), nil
}

// roleNamesEqual reports whether two security role names refer to the same role. Command matches
// role names case-insensitively, so an allowed-requester entry written with different casing than
// the configured role_name is still the same role.
func roleNamesEqual(a, b string) bool {
	return strings.EqualFold(a, b)
}

// roleNameChangeRequiresReplace reports whether moving role_name from state to config names a
// different role. Values are compared case-insensitively.
func roleNameChangeRequiresReplace(state, config types.String) bool {
	if state.Null || state.Unknown || config.Null || config.Unknown {
		return !(state.Null == config.Null && state.Unknown == config.Unknown)
	}
	return !strings.EqualFold(state.Value, config.Value)
}

// partitionTemplateNamesByExistence splits templateNames into the names that match an existing
// template (case-insensitively, the way Command resolves template names) and the names that do not.
// Order is preserved and the kept names keep their original (configured) casing.
func partitionTemplateNamesByExistence(templates []api.GetTemplateResponse, templateNames []string) (kept []string, dropped []string) {
	for _, name := range templateNames {
		if findTemplateByName(templates, name) != nil {
			kept = append(kept, name)
		} else {
			dropped = append(dropped, name)
		}
	}
	return kept, dropped
}

// buildTemplateRoleBindingUpdateArg constructs an api.UpdateTemplateArg that
// carries forward EVERY field the legacy v3/api.GetTemplateResponse model
// exposes, overriding only AllowedRequesters/UseAllowedRequesters (the
// fields this resource actually manages). PUT /Templates is a full-replace
// endpoint: any field left off the request is cleared server-side, not left
// unchanged. Before this fix, addAllowedRequesterToTemplate/
// removeRoleFromTemplate only carried a fixed subset of fields (Id,
// CommonName, TemplateName, Oid, KeySize, ForestRoot, FriendlyName,
// AllowedEnrollmentTypes, KeyRetention, RFCEnforcement, TemplatePolicy),
// which silently cleared everything else the template had configured on
// every role-binding update -- including KeyRetentionDays, which produces a
// live, user-facing error the moment a template has a KeyRetention policy
// that requires a day count: "In order to enable a retention policy on a
// template, the number of days to retain after expiration must be defined."
//
// A second, related defect existed even after that fix: KeyType, FriendlyName,
// AllowedEnrollmentTypes, KeyRetention, and KeyRetentionDays were carried
// forward via intToPointer/stringToPointer, which collapse a genuinely-zero
// int (0) or empty string ("") to nil. Those helpers are correct for a
// user-supplied Optional plan value (0/"" there really does mean "not set"),
// but wrong for these carry-forward fields, whose value always comes from a
// fresh GetTemplate immediately before this call -- it is never "unset,"
// even when it happens to be the zero value. This dropped a real
// KeyRetentionDays==0 (a valid combination alongside e.g.
// KeyRetention=="FromIssuance") from the PUT while KeyRetention itself was
// still sent, and Command rejected the whole request. Fixed by taking the
// address of the fetched value directly via the generic ptr() helper
// instead.
//
// Not every field GetTemplateResponse returns can be represented here:
//   - CertificateCleanupEnabled, TimeAfterExpiration, TimeAfterExpirationUnits,
//     DeleteWithArchivedKey, AllowOneClickRenewals, and TemplateDefaults (the
//     per-subject-part default values, not to be confused with the unrelated
//     TemplateDefault bool used by enrollment_patterns_models.go) do not exist
//     anywhere in the v3/api.GetTemplateResponse / api.UpdateTemplateArg
//     models at all (confirmed against keyfactor-go-client v3.5.6) -- the
//     newer keyfactor-go-client-sdk v1 TemplatesTemplateRetrievalResponse /
//     TemplatesTemplateUpdateRequest models used by
//     resource_keyfactor_certificate_template.go DO model these fields, but
//     this resource (keyfactor_template_role_binding) is still built on the
//     older client. A future migration to the v1 SDK client would close this
//     gap; until then, an update through this resource cannot preserve those
//     fields because it has no way to even read their current value.
func buildTemplateRoleBindingUpdateArg(template *api.GetTemplateResponse, allowedRequesters []string, useAllowedRequesters bool) *api.UpdateTemplateArg {
	// KeyUsage is a carry-forward value read fresh from GetTemplate
	// immediately above, exactly like KeyType/FriendlyName/KeyRetention/
	// KeyRetentionDays below -- it always has a real current value, even
	// when that value is the zero bitmask (0). Take its address directly
	// rather than collapsing 0 to nil. keyfactor-go-client/v3 v3.6.0+
	// types UpdateTemplateArg.KeyUsage as *int (matching
	// GetTemplateResponse.KeyUsage's int bitmask and Command's wire
	// format); earlier client versions typed it *bool, which Command
	// rejects with a live HTTP 400 ("Unexpected character encountered
	// while parsing value: t. Path 'KeyUsage'") and which had no lossless
	// conversion from the bitmask anyway, so this field was previously
	// left nil/omitted -- silently resetting the template's KeyUsage to 0
	// on every role attach/detach, since PUT /Templates is a full-replace
	// endpoint.
	keyUsage := template.KeyUsage
	return &api.UpdateTemplateArg{
		Id:           template.Id,
		CommonName:   template.CommonName,
		TemplateName: template.TemplateName,
		Oid:          template.Oid,
		KeySize:      template.KeySize,
		KeyUsage:     &keyUsage,
		// KeyType/FriendlyName/AllowedEnrollmentTypes/KeyRetention/
		// KeyRetentionDays are carry-forward values read fresh from
		// GetTemplate immediately above -- they came from the server, so
		// they are always "set," even when the real current value is the
		// zero value (0/""). Take their address directly via the generic
		// ptr() helper rather than routing through intToPointer/
		// stringToPointer: those helpers intentionally collapse 0/"" to nil,
		// which is correct for a genuinely-optional user-supplied plan value
		// but wrong here -- it silently drops a legitimately-zero/empty
		// current value from the PUT. Observed live: a template with
		// KeyRetention="FromIssuance" and KeyRetentionDays==0 (a real,
		// valid combination) got KeyRetentionDays collapsed to nil while
		// KeyRetention was still sent, and Command 25.x rejected the
		// request outright with "In order to enable a retention policy on a
		// template, the number of days to retain after expiration must be
		// defined." (0xA011000F).
		KeyType:                ptr(template.KeyType),
		ForestRoot:             template.ForestRoot,
		UseAllowedRequesters:   boolToPointer(useAllowedRequesters),
		AllowedRequesters:      &allowedRequesters,
		FriendlyName:           ptr(template.FriendlyName),
		AllowedEnrollmentTypes: ptr(template.AllowedEnrollmentTypes),
		KeyRetention:           ptr(template.KeyRetention),
		KeyRetentionDays:       ptr(template.KeyRetentionDays),
		KeyArchival:            boolToPointer(template.KeyArchival),
		EnrollmentFields:       &template.EnrollmentFields,
		MetadataFields:         &template.MetadataFields,
		TemplateRegexes:        &template.TemplateRegexes,
		RFCEnforcement:         boolToPointer(template.RFCEnforcement),
		RequiresApproval:       boolToPointer(template.RequiresApproval),
		// TemplatePolicy: carry the template's existing policy through
		// unchanged. PUT /Templates is a full-replace endpoint: omitting
		// TemplatePolicy here would silently clear it, and for a template
		// linked to an enrollment pattern Command 25.x then rejects the
		// request with "'Policies' cannot be empty" because its internal
		// policy set derives from TemplatePolicy's key-algorithm lists. This
		// binding resource only manages allowed_requesters, so it must never
		// alter unrelated policy content.
		TemplatePolicy: template.TemplatePolicy,
	}
}

// diffTemplateIDSets returns the template IDs that are in plan but not in state (additions) and the
// IDs that are in state but not in plan (removals). Duplicates are collapsed and order is preserved.
func diffTemplateIDSets(state, plan []int) (additions, removals []int) {
	for _, id := range uniqueInts(plan) {
		if !Contains(state, id) {
			additions = append(additions, id)
		}
	}
	for _, id := range uniqueInts(state) {
		if !Contains(plan, id) {
			removals = append(removals, id)
		}
	}
	return additions, removals
}

// uniqueInts returns ids with duplicates removed, preserving the order of first occurrence.
func uniqueInts(ids []int) []int {
	seen := make(map[int]struct{}, len(ids))
	var out []int
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// setRoleAllowedRequester attaches roleName to the templates in additions and detaches it from the
// templates in removals. Callers pass exactly what has to change: Create passes the planned set as
// additions, Update passes the plan/state difference, and Destroy passes the bound set as removals
// only. A template is never touched unless it is listed here, and each attach/detach sends a PUT only
// when the template's allowed-requester list or enforcement actually has to change (see
// addAllowedRequesterToTemplate and removeRoleFromTemplate). Every template is attempted; all errors
// are returned together.
func setRoleAllowedRequester(
	ctx context.Context,
	kfClient *api.Client,
	roleName string,
	additions []int,
	removals []int,
) diag.Diagnostics {
	var diags diag.Diagnostics

	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(
		ctx, "Setting Keyfactor role allowed requester bindings", map[string]interface{}{
			"additions": additions,
			"removals":  removals,
		},
	)

	for _, template := range additions {
		tempCtx := tflog.SetField(ctx, "template_id", template)
		tflog.Info(tempCtx, "Attaching role to template ID ")
		if aErr := addAllowedRequesterToTemplate(ctx, kfClient, roleName, strconv.Itoa(template)); aErr != nil {
			tflog.Error(tempCtx, "Error attaching role to template")
			diags = append(diags, aErr...)
		}
	}

	for _, template := range removals {
		tempCtx := tflog.SetField(ctx, "template_id", template)
		tflog.Info(tempCtx, "Detaching role from template ID ")
		if rErr := removeRoleFromTemplate(ctx, kfClient, roleName, template); rErr != nil {
			tflog.Error(tempCtx, "Error detaching role from template")
			diags = append(diags, rErr...)
		}
	}

	return diags
}

func Contains(sl []int, val int) bool {
	for _, value := range sl {
		if value == val {
			return true
		}
	}
	return false
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func addAllowedRequesterToTemplate(
	ctx context.Context,
	kfClient *api.Client,
	roleName string,
	templateId string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	ctx = tflog.SetField(ctx, "template_id", templateId)
	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Adding Keyfactor role with ID to template with ID")

	// First get info about template from Keyfactor
	if _, err := strconv.Atoi(templateId); err == nil {
		tflog.Debug(ctx, fmt.Sprintf("Getting template info from Keyfactor using ID '%s'", templateId))
	}
	templateIdNumber, err := strconv.Atoi(templateId)
	ctx = tflog.SetField(ctx, "template_id", templateIdNumber)
	if err != nil {
		tflog.Info(ctx, "Assuming templateId is a short name")
		tflog.Debug(ctx, "Fetching templates from Keyfactor")
		templates, err2 := kfClient.GetTemplates()
		if err2 != nil {
			tflog.Error(
				ctx, "Error fetching templates from Keyfactor", map[string]interface{}{
					"error": err2,
				},
			)
			diags.AddError("Error fetching templates from Keyfactor", err2.Error())
			return diags
		}
		tflog.Debug(ctx, "Finding template in returned templates")
		found := findTemplateByName(templates, templateId)
		if found == nil {
			diags.AddError(
				"Template not found in Keyfactor Command.",
				"Template '"+templateId+"' does not exist in Keyfactor Command.",
			)
			return diags
		}
		templateIdNumber = found.Id
		ctx = tflog.SetField(ctx, "template_id", templateIdNumber)
	}

	tflog.Debug(ctx, "Fetching template from Keyfactor")
	template, err := kfClient.GetTemplate(templateIdNumber)
	if err != nil {
		tflog.Error(
			ctx, "Error fetching template from Keyfactor", map[string]interface{}{
				"error": err,
			},
		)
		diags.AddError("Error fetching template from Keyfactor", err.Error())
		return diags
	}

	// The role only counts as already attached when it is listed AND Command actually enforces the
	// list: while UseAllowedRequesters is false the list is ignored, so the role grants nothing and
	// the template must still be updated to switch enforcement on.
	roleListed := allowedRequestersContainRole(template.AllowedRequesters, roleName)
	if roleListed && template.UseAllowedRequesters {
		tflog.Warn(
			ctx,
			"Keyfactor security role is already listed as an allowed requester for template.",
			map[string]interface{}{
				"role":     roleName,
				"template": template.CommonName,
			},
		)
		return diags
	}
	tflog.Debug(
		ctx, "Adding role to allowed requesters", map[string]interface{}{
			"role":                   roleName,
			"template":               template.CommonName,
			"already_listed":         roleListed,
			"use_allowed_requesters": template.UseAllowedRequesters,
		},
	)
	newAllowedRequester := append([]string(nil), template.AllowedRequesters...)

	// Append the role unless it is already listed (listed but not enforced): the existing list is
	// kept as is, so no duplicate entry is created.
	if !roleListed {
		newAllowedRequester = append(newAllowedRequester, roleName)
	}
	// The role is now in the list, so enforcement must be on for it to take effect.
	useAllowedRequesters := true
	// Fill required fields with information retrieved from the get request above
	tflog.Debug(ctx, "Creating update context to add role to template")
	updateContext := buildTemplateRoleBindingUpdateArg(template, newAllowedRequester, useAllowedRequesters)

	tflog.Trace(
		ctx, "Updating template in Keyfactor with context:", map[string]interface{}{
			"context": updateContext,
		},
	)
	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		tflog.Error(
			ctx, "Error updating template in Keyfactor", map[string]interface{}{
				"error": err,
			},
		)
		diags.AddError("Error updating template in Keyfactor", err.Error())
		return diags
	}

	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func removeRoleFromTemplate(
	ctx context.Context,
	kfClient *api.Client,
	roleName string,
	templateId int,
) diag.Diagnostics {
	var diags diag.Diagnostics
	ctx = tflog.SetField(ctx, "template_id", templateId)
	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Removing Keyfactor role with ID from template")
	// First get info about template from Keyfactor
	template, err := kfClient.GetTemplate(templateId)
	if err != nil {
		tflog.Error(
			ctx, "Error fetching template from Keyfactor", map[string]interface{}{
				"error": err,
			},
		)
		diags.AddError("Error fetching template from Keyfactor", err.Error())
		return diags
	}

	// A role that is not listed needs no change: PUT /Templates is a full-replace endpoint, so
	// sending one anyway would only risk clobbering the template for no benefit.
	if !allowedRequestersContainRole(template.AllowedRequesters, roleName) {
		tflog.Debug(ctx, "Role is not listed as an allowed requester for the template; nothing to remove.")
		return diags
	}

	// Rebuild allowed requester list without roleName
	tflog.Debug(ctx, "Rebuild allowed requester list without roleName")
	newAllowedRequester := allowedRequestersWithoutRole(template.AllowedRequesters, roleName)

	// Preserve the template's own UseAllowedRequesters choice: the template's administrator decides
	// whether the list is enforced, and removing one role must not switch enforcement ON for a
	// template that had it off. The one exception is an emptied list: with enforcement on and nobody
	// left in the list, nobody could enroll, so enforcement is switched off in that case only.
	useAllowedRequesters := template.UseAllowedRequesters
	if len(newAllowedRequester) == 0 {
		useAllowedRequesters = false
	}
	// Fill required fields with information retrieved from the get request above --
	// see buildTemplateRoleBindingUpdateArg for why every representable field
	// (not just the requester list) must be carried forward here.
	updateContext := buildTemplateRoleBindingUpdateArg(template, newAllowedRequester, useAllowedRequesters)

	tflog.Trace(
		ctx, "Updating template in Keyfactor with context:", map[string]interface{}{
			"context": updateContext,
		},
	)
	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		tflog.Error(
			ctx, "Error updating template in Keyfactor", map[string]interface{}{
				"error": err,
			},
		)
		diags.AddError("Error updating template in Keyfactor", err.Error())
		return diags
	}
	return diags
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func flattenAttachRoleSchema(ctx context.Context, roleName string, templateIds []interface{}) map[string]interface{} {
	tflog.Debug(ctx, "Flattening Keyfactor role resource schema.")
	data := make(map[string]interface{})

	data["role_name"] = roleName

	tempSet := schema.NewSet(schema.HashInt, templateIds)
	data["template_ids"] = tempSet

	return data
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func findTemplateRoleAttachments(ctx context.Context, kfClient *api.Client, roleName string) (
	diag.Diagnostics,
	[]interface{},
) {
	// Goal here is to find every template that the role is listed as an allowed requester. First thing that needs
	// to happen is retrieve a complete list of all certificate templates.

	var diags diag.Diagnostics
	tflog.Debug(ctx, "Fetching all templates from Keyfactor")
	templates, err := kfClient.GetTemplates()
	if err != nil {
		diags.AddError("Error fetching templates from Keyfactor", err.Error())
		return diags, make([]interface{}, 0)
	}

	var templateRoleAttachmentList []interface{}

	for _, template := range templates {
		// We only want to check the allowed requester list if UseAllowedRequesters is true
		if template.UseAllowedRequesters {
			for _, role := range template.AllowedRequesters {
				if roleNamesEqual(role, roleName) {
					templateRoleAttachmentList = append(templateRoleAttachmentList, template.Id)
				}
			}
		}
	}

	return diags, templateRoleAttachmentList
}

// allowedRequestersContainRole reports whether role is already in a template's allowed-requesters
// list. Names are compared case-insensitively (see roleNamesEqual).
func allowedRequestersContainRole(allowedRequesters []string, role string) bool {
	for _, name := range allowedRequesters {
		if roleNamesEqual(name, role) {
			return true
		}
	}
	return false
}

// allowedRequestersWithoutRole returns a copy of allowedRequesters with every entry naming role
// (case-insensitively) removed, preserving the order of the remaining entries.
func allowedRequestersWithoutRole(allowedRequesters []string, role string) []string {
	var out []string
	for _, name := range allowedRequesters {
		if !roleNamesEqual(name, role) {
			out = append(out, name)
		}
	}
	return out
}
