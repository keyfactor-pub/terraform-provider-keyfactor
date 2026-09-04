package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
				Description: "An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor.",
			},
			"template_short_names": {
				Type:        types.ListType{ElemType: types.StringType},
				Optional:    true,
				Description: "A list of certificate template short name in Keyfactor that the role will be attached to.",
			},
		},
		Description: "Grants a Keyfactor security role enrollment permissions on one or more certificate templates by managing the template's allowed requesters list via the `/Templates` PUT API.",
		MarkdownDescription: `
Grants a Keyfactor security role enrollment permissions on one or more certificate templates by managing the template's allowed requesters list via the "/Templates" PUT API. On Keyfactor Command v25.0+, enrollment patterns provide an additional enrollment-configuration layer alongside certificate templates.
`,
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

	diags = plan.TemplateNames.ElementsAs(ctx, &templateNames, true)

	tNameStr := strings.Join(templateNames, "-")

	hid := fmt.Sprintf("%s-%s", roleName, tNameStr)
	ctx = tflog.SetField(ctx, "role_binding_id", hid)

	// List all templates
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}
	validTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, templateNames)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", validTemplateIds))
	response.Diagnostics.Append(apiDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Create role binding
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, validTemplateIds, []int{}, "create")
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	result := CertificateTemplateRoleBinding{
		ID:            types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
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
	var validTemplateIds []int
	var apiDiags []diag.Diagnostic
	diags = state.TemplateNames.ElementsAs(ctx, &templateNames, true)
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		return
	}
	validTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, templateNames)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", validTemplateIds))
	response.Diagnostics.Append(apiDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	hid := fmt.Sprintf("%v%v", roleName, templateNames)
	ctx = tflog.SetField(ctx, "role_binding_id", hid)

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
	diags = state.TemplateNames.ElementsAs(ctx, &stateTemplateNames, true)
	diags = plan.TemplateNames.ElementsAs(ctx, &planTemplateNames, true)
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		return
	}
	stateValidTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, stateTemplateNames)
	planValidTemplateIds, apiDiags := verifyTemplateNames(ctx, kfTemplates, planTemplateNames)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", stateValidTemplateIds))
	response.Diagnostics.Append(apiDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Set binding ID
	hid := fmt.Sprintf("%v%v", roleName, stateTemplateNames)
	ctx = tflog.SetField(ctx, "role_binding_id", hid)

	// Set role allowed requester
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, stateValidTemplateIds, planValidTemplateIds, "update")
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	result := CertificateTemplateRoleBinding{
		ID:            state.ID,
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

	kfClient := r.p.client
	roleName := state.RoleName.Value

	// Verify template names
	var templateNames []string
	var validTemplateIds []int
	var apiDiags []diag.Diagnostic

	diags = state.TemplateNames.ElementsAs(ctx, &templateNames, true)

	hid := fmt.Sprintf("%v%v", roleName, templateNames)
	ctx = tflog.SetField(ctx, "role_binding_id", hid)

	// List all templates
	kfTemplates, err := kfClient.GetTemplates()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_TEMPLATE_READ,
			"There was an error getting templates from Keyfactor Command: "+err.Error(),
		)
		return
	}
	validTemplateIds, apiDiags = verifyTemplateNames(ctx, kfTemplates, templateNames)
	tflog.Debug(ctx, fmt.Sprintf("Valid template IDs: %v", validTemplateIds))
	response.Diagnostics.Append(apiDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Create role binding
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, validTemplateIds, []int{}, "destroy")
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

	// Recompute the stable ID hash (same algorithm as Create).
	tNameStr := strings.Join(templateNames, "-")
	hid := fmt.Sprintf("%s-%s", roleName, tNameStr)

	elems := make([]attr.Value, 0, len(templateNames))
	for _, n := range templateNames {
		elems = append(elems, types.String{Value: n})
	}

	result := CertificateTemplateRoleBinding{
		ID:            types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		RoleName:      types.String{Value: roleName},
		TemplateNames: types.List{ElemType: types.StringType, Elems: elems},
	}

	diags2 := response.State.Set(ctx, result)
	response.Diagnostics.Append(diags2...)
}

func verifyTemplateNames(ctx context.Context, templates []api.GetTemplateResponse, templateNames []string) (
	[]int,
	[]diag.Diagnostic,
) {
	var diags diag.Diagnostics
	var result []int
	for _, templateName := range templateNames {
		if templateName == "" {
			diags.AddError("Error empty template name.", "Template name provided")
		}
		found := false
		for _, template := range templates {
			if strings.EqualFold(template.CommonName, templateName) {
				//result.Elems = append(result.Elems, types.Int64{Value: int64(template.Id)})
				result = append(result, template.Id)
				found = true
				break
			}
		}
		if !found {
			diags.AddError("Error template name not found.", "Template name "+templateName+" not found")
		}

	}
	return result, diags
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
// See dev-harness Gap C (extends GH issue #190).
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
// instead. See dev-harness Gap C live-verification follow-up.
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
		// defined." (0xA011000F). See dev-harness Gap C, completes #190.
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
		// alter unrelated policy content. See issue #190.
		TemplatePolicy: template.TemplatePolicy,
	}
}

/*
 * The resourceTemplateAttachRoleUpdate function is responsible for updating a Keyfactor security role.
 */
func setRoleAllowedRequester(
	ctx context.Context,
	kfClient *api.Client,
	roleName string,
	stateTemplateSet []int,
	planTemplateSet []int,
	caller string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Setting Keyfactor role with name to be allowed requester for the following templates:")

	templateList := stateTemplateSet
	tflog.Debug(
		ctx, "Template IDs: ", map[string]interface{}{
			"template_ids": templateList,
		},
	)

	// First thing to do is blindly attach the passed role as an allowed requester to each of the template IDs passed in
	// the Set.
	if len(templateList) > 0 {
		for _, template := range templateList {
			tempCtx := tflog.SetField(ctx, "template_id", template)
			tempCtx = tflog.SetField(tempCtx, "role_name", roleName)
			tflog.Info(tempCtx, "Attaching role to template ID ")
			err := addAllowedRequesterToTemplate(ctx, kfClient, roleName, strconv.Itoa(template))
			if err != nil {
				tflog.Error(tempCtx, "Error attaching role to template")
				diags = append(diags, err...)
			}
		}
	}

	if diags != nil {
		return diags
	}

	// Then, build a list of all templates that the role is attached to as an allowed requester
	tflog.Debug(ctx, "Building list of templates that the role is attached to as an allowed requester")
	err, roleAttachments := findTemplateRoleAttachments(ctx, kfClient, roleName)
	if err != nil {
		return err
	}

	// Finally, find the difference between stateTemplateSet and roleAttachments. Recall that Terraform acts as the primary
	// manager of the role roleName, and Terraform is calling this function to explicitly set the allowed requesters.

	tflog.Debug(ctx, "Finding difference between stateTemplateSet and roleAttachments")
	list := make(map[string]struct{}, len(templateList))
	for _, x := range templateList {
		list[strconv.Itoa(x)] = struct{}{}
	}
	var diff []int
	for _, x := range roleAttachments {
		if _, found := list[strconv.Itoa(x.(int))]; !found {
			tflog.Debug(
				ctx, "Found difference between stateTemplateSet and roleAttachments", map[string]interface{}{
					"template_id": x,
				},
			)
			diff = append(diff, x.(int))
		}
	}
	additions := []int{}
	removals := []int{}

	for _, templateId := range planTemplateSet {
		if !Contains(stateTemplateSet, templateId) {
			additions = append(additions, templateId)
		}
	}

	for _, templateId := range stateTemplateSet {
		if !Contains(planTemplateSet, templateId) {
			removals = append(removals, templateId)
		}
	}

	if caller == "destroy" {
		removals = append(removals, additions...)
		additions = []int{}
	} else if caller == "create" {
		additions = append(additions, removals...)
		removals = []int{}
	}

	tflog.Debug(ctx, "Adding difference between stateTemplateSet and roleAttachments")
	for _, template := range additions {
		tempCtx := tflog.SetField(ctx, "template_id", template)
		tempCtx = tflog.SetField(tempCtx, "role_name", roleName)
		tflog.Info(tempCtx, "Attaching role to template ID ")
		aErr := addAllowedRequesterToTemplate(ctx, kfClient, roleName, strconv.Itoa(template))
		if aErr != nil {
			tflog.Error(tempCtx, "Error attaching role to template")
			diags = append(diags, aErr...)
		}
	}

	tflog.Debug(ctx, "Removing difference between stateTemplateSet and roleAttachments")
	for _, template := range removals {
		tempCtx := tflog.SetField(ctx, "template_id", template)
		tempCtx = tflog.SetField(tempCtx, "role_name", roleName)
		tflog.Info(tempCtx, "Detaching role from template ID ")
		rErr := removeRoleFromTemplate(ctx, kfClient, roleName, template)
		if rErr != nil {
			tflog.Error(tempCtx, "Error detaching role from template")
			diags = append(diags, rErr...)
		}
	}

	tflog.Debug(ctx, "Removing difference between stateTemplateSet and roleAttachments")
	//for _, template := range diff {
	//	tempCtx := tflog.SetField(ctx, "template_id", template)
	//	tflog.Debug(tempCtx, "Removing role from template")
	//	err = removeRoleFromTemplate(ctx, kfClient, roleName, template)
	//	if err != nil {
	//		tflog.Error(tempCtx, "Error removing role from template")
	//		diags = append(diags, err...)
	//	}
	//}
	//
	//tflog.Info(ctx, "Finished binding roles to templates")
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
		}
		tflog.Debug(ctx, "Finding template in returned templates")
		for template := range templates {
			tflog.Debug(
				ctx, "Looking up template", map[string]interface{}{
					"template": template,
				},
			)
			kfTemplate, err3 := kfClient.GetTemplate(template)
			if err3 != nil {
				tflog.Error(
					ctx, "Error fetching template from Keyfactor", map[string]interface{}{
						"error": err3,
					},
				)
				diags.AddError("Error fetching template from Keyfactor", err3.Error())
				continue
			}
			tflog.Debug(
				ctx, "Found template", map[string]interface{}{
					"template": kfTemplate,
				},
			)
			if kfTemplate.CommonName == templateId {
				tflog.Debug(ctx, "Found matching template.")
				templateIdNumber = kfTemplate.Id
				break
			}
		}
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

	// Check if role is already assigned as an allowed requester for the template, and
	var newAllowedRequester []string
	for _, name := range template.AllowedRequesters {
		if name == roleName {
			tflog.Warn(
				ctx,
				"Keyfactor security role is already listed as an allowed requester for template.",
				map[string]interface{}{
					"role":     roleName,
					"template": template.CommonName,
					"name":     name,
				},
			)
			return diags
		}
		tflog.Debug(
			ctx, "Adding role to allowed requesters", map[string]interface{}{
				"role":     roleName,
				"template": template.CommonName,
			},
		)
		newAllowedRequester = append(newAllowedRequester, name)
	}

	// If it's not already added, create update context to add role to template.

	newAllowedRequester = append(newAllowedRequester, roleName)
	useAllowedRequesters := false
	if len(newAllowedRequester) > 0 {
		useAllowedRequesters = true
	}
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
	}

	// Rebuild allowed requester list without roleName
	var newAllowedRequester []string
	tflog.Debug(ctx, "Rebuild allowed requester list without roleName")
	for _, name := range template.AllowedRequesters {
		if name != roleName {
			tflog.Trace(
				ctx, "Adding role to allowed requesters", map[string]interface{}{
					"allowed_requester": newAllowedRequester,
					"name":              name,
				},
			)
			newAllowedRequester = append(newAllowedRequester, name)
		}
	}

	useAllowedRequesters := false
	if len(newAllowedRequester) > 0 {
		useAllowedRequesters = true
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
				if role == roleName {
					templateRoleAttachmentList = append(templateRoleAttachmentList, template.Id)
				}
			}
		}
	}

	return diags, templateRoleAttachmentList
}
