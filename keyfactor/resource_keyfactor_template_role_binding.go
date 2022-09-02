package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
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
	}, nil
}

func (r resourceCertificateTemplateRoleBindingType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceCertificateTemplateRoleBinding{
		p: *(p.(*provider)),
	}, nil
}

type resourceCertificateTemplateRoleBinding struct {
	p provider
}

func (r resourceCertificateTemplateRoleBinding) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
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
			"Error getting templates",
			"There was an error getting templates from Keyfactor: "+err.Error(),
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
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, validTemplateIds)
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

func (r resourceCertificateTemplateRoleBinding) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
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

func (r resourceCertificateTemplateRoleBinding) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
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

	// Set binding ID
	hid := fmt.Sprintf("%v%v", roleName, templateNames)
	ctx = tflog.SetField(ctx, "role_binding_id", hid)

	// Set role allowed requester
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, validTemplateIds)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	result := CertificateTemplateRoleBinding{
		ID:            types.String{Value: fmt.Sprintf("%s", sha256.Sum256([]byte(hid)))},
		RoleName:      plan.RoleName,
		TemplateNames: plan.TemplateNames,
	}
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCertificateTemplateRoleBinding) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
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
			"Error getting templates",
			"There was an error getting templates from Keyfactor: "+err.Error(),
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
	diags = setRoleAllowedRequester(ctx, kfClient, roleName, validTemplateIds)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceCertificateTemplateRoleBinding) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
	var state CertificateTemplateRoleBinding
	var diags diag.Diagnostics
	//diags := request.ID
	diags.AddError("Import not implemented", "Import is not implemented for this resource")
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	response.State.Set(ctx, state)
}

func verifyTemplateNames(ctx context.Context, templates []api.GetTemplateResponse, templateNames []string) ([]int, []diag.Diagnostic) {
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

/*
 * The resourceTemplateAttachRoleUpdate function is responsible for updating a Keyfactor security role.
 */
func setRoleAllowedRequester(ctx context.Context, kfClient *api.Client, roleName string, templateSet []int) diag.Diagnostics {
	var diags diag.Diagnostics

	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Setting Keyfactor role with name to be allowed requester for the following templates:")

	templateList := templateSet
	tflog.Debug(ctx, "Template IDs: ", map[string]interface{}{
		"template_ids": templateList,
	})

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

	// Finally, find the difference between templateSet and roleAttachments. Recall that Terraform acts as the primary
	// manager of the role roleName, and Terraform is calling this function to explicitly set the allowed requesters.

	tflog.Debug(ctx, "Finding difference between templateSet and roleAttachments")
	list := make(map[string]struct{}, len(templateList))
	for _, x := range templateList {
		list[strconv.Itoa(x)] = struct{}{}
	}
	var diff []int
	for _, x := range roleAttachments {
		if _, found := list[strconv.Itoa(x.(int))]; !found {
			tflog.Debug(ctx, "Found difference between templateSet and roleAttachments", map[string]interface{}{
				"template_id": x,
			})
			diff = append(diff, x.(int))
		}
	}

	tflog.Debug(ctx, "Removing difference between templateSet and roleAttachments")
	for _, template := range diff {
		tempCtx := tflog.SetField(ctx, "template_id", template)
		tflog.Debug(tempCtx, "Removing role from template")
		err = removeRoleFromTemplate(ctx, kfClient, roleName, template)
		if err != nil {
			tflog.Error(tempCtx, "Error removing role from template")
			diags = append(diags, err...)
		}
	}

	tflog.Info(ctx, "Finished binding roles to templates")
	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func addAllowedRequesterToTemplate(ctx context.Context, kfClient *api.Client, roleName string, templateId string) diag.Diagnostics {
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
			tflog.Error(ctx, "Error fetching templates from Keyfactor", map[string]interface{}{
				"error": err2,
			})
			diags.AddError("Error fetching templates from Keyfactor", err2.Error())
		}
		tflog.Debug(ctx, "Finding template in returned templates")
		for template := range templates {
			tflog.Debug(ctx, "Looking up template", map[string]interface{}{
				"template": template,
			})
			kfTemplate, err3 := kfClient.GetTemplate(template)
			if err3 != nil {
				tflog.Error(ctx, "Error fetching template from Keyfactor", map[string]interface{}{
					"error": err3,
				})
				diags.AddError("Error fetching template from Keyfactor", err3.Error())
				continue
			}
			tflog.Debug(ctx, "Found template", map[string]interface{}{
				"template": kfTemplate,
			})
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
		tflog.Error(ctx, "Error fetching template from Keyfactor", map[string]interface{}{
			"error": err,
		})
		diags.AddError("Error fetching template from Keyfactor", err.Error())
		return diags
	}

	// Check if role is already assigned as an allowed requester for the template, and
	var newAllowedRequester []string
	for _, name := range template.AllowedRequesters {
		if name == roleName {
			tflog.Warn(ctx, "Keyfactor security role is already listed as an allowed requester for template.", map[string]interface{}{
				"role":     roleName,
				"template": template.CommonName,
				"name":     name,
			})
			return diags
		}
		tflog.Debug(ctx, "Adding role to allowed requesters", map[string]interface{}{
			"role":     roleName,
			"template": template.CommonName,
		})
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
	updateContext := &api.UpdateTemplateArg{
		Id:                     template.Id,
		CommonName:             template.CommonName,
		TemplateName:           template.TemplateName,
		Oid:                    template.Oid,
		KeySize:                template.KeySize,
		ForestRoot:             template.ForestRoot,
		UseAllowedRequesters:   boolToPointer(useAllowedRequesters),
		AllowedRequesters:      &newAllowedRequester,
		FriendlyName:           stringToPointer(template.FriendlyName),
		AllowedEnrollmentTypes: intToPointer(template.AllowedEnrollmentTypes),
		KeyRetention:           stringToPointer(template.KeyRetention),
		RFCEnforcement:         boolToPointer(template.RFCEnforcement),
	}

	tflog.Trace(ctx, "Updating template in Keyfactor with context:", map[string]interface{}{
		"context": updateContext,
	})
	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		tflog.Error(ctx, "Error updating template in Keyfactor", map[string]interface{}{
			"error": err,
		})
		diags.AddError("Error updating template in Keyfactor", err.Error())
		return diags
	}

	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func removeRoleFromTemplate(ctx context.Context, kfClient *api.Client, roleName string, templateId int) diag.Diagnostics {
	var diags diag.Diagnostics
	ctx = tflog.SetField(ctx, "template_id", templateId)
	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Removing Keyfactor role with ID from template")
	// First get info about template from Keyfactor
	template, err := kfClient.GetTemplate(templateId)
	if err != nil {
		tflog.Error(ctx, "Error fetching template from Keyfactor", map[string]interface{}{
			"error": err,
		})
		diags.AddError("Error fetching template from Keyfactor", err.Error())
	}

	// Rebuild allowed requester list without roleName
	var newAllowedRequester []string
	tflog.Debug(ctx, "Rebuild allowed requester list without roleName")
	for _, name := range template.AllowedRequesters {
		if name != roleName {
			tflog.Trace(ctx, "Adding role to allowed requesters", map[string]interface{}{
				"allowed_requester": newAllowedRequester,
				"name":              name,
			})
			newAllowedRequester = append(newAllowedRequester, name)
		}
	}

	useAllowedRequesters := false
	if len(newAllowedRequester) > 0 {
		useAllowedRequesters = true
	}
	// Fill required fields with information retrieved from the get request above
	updateContext := &api.UpdateTemplateArg{
		Id:                     template.Id,
		CommonName:             template.CommonName,
		TemplateName:           template.TemplateName,
		Oid:                    template.Oid,
		KeySize:                template.KeySize,
		ForestRoot:             template.ForestRoot,
		UseAllowedRequesters:   boolToPointer(useAllowedRequesters),
		AllowedRequesters:      &newAllowedRequester,
		FriendlyName:           stringToPointer(template.FriendlyName),
		AllowedEnrollmentTypes: intToPointer(template.AllowedEnrollmentTypes),
		KeyRetention:           stringToPointer(template.KeyRetention),
		RFCEnforcement:         boolToPointer(template.RFCEnforcement),
	}

	tflog.Trace(ctx, "Updating template in Keyfactor with context:", map[string]interface{}{
		"context": updateContext,
	})
	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		tflog.Error(ctx, "Error updating template in Keyfactor", map[string]interface{}{
			"error": err,
		})
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
func findTemplateRoleAttachments(ctx context.Context, kfClient *api.Client, roleName string) (diag.Diagnostics, []interface{}) {
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
