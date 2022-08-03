package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
	"strings"
)

/*
 * The resourceTemplateRoleBinding resource is designed to act as a proxy that acts to attach a given Keyfactor security
 * role to specific Keyfactor objects. Version 1.0 of this resource will be configured with a single Keyfactor security
 * role with the ability to attach to Keyfactor certificate templates.

 * Rationale: It is possible to create a resource for CRUD operations on Keyfactor security roles, but typically
 * these are only created once at the beginning of an instance's configuration, and then typically not touched. For this
 * reason, this resource acting as a hybrid between a template resource (infeasible due to Keyfactor API design) and
 * a security role resource.
 */

func resourceTemplateRoleBinding() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceTemplateRoleBindingCreate,
		ReadContext:   resourceTemplateAttachRoleRead,
		UpdateContext: resourceTemplateAttachRoleUpdate,
		DeleteContext: resourceTemplateAttachRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor.",
			},
			// Configure template config as list of integers to simplify flattening functions
			"template_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of integers associated with certificate templates in Keyfactor that the role will be attached to.",
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
				//ValidateFunc: validation.ListOfUniqueStrings, // * resource keyfactor_template_role_binding: template_ids: ValidateFunc and ValidateDiagFunc are not yet supported on lists or sets.
			},
			"template_short_names": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of certificate template short name in Keyfactor that the role will be attached to.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func verifyTemplateIds(kfClient *api.Client, templateIds []interface{}) ([]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	var validTemplateIds []interface{}
	for _, templateId := range templateIds {
		_, err := kfClient.GetTemplate(templateId.(int))
		if err != nil {
			diags = append(diags, diag.FromErr(err)...)
		} else {
			validTemplateIds = append(validTemplateIds, templateId)
		}
	}
	return validTemplateIds, diags
}

/*
 * The resourceTemplateRoleBindingCreate function is responsible for creating a Keyfactor security role.
 */
func resourceTemplateRoleBindingCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	//var diags diag.Diagnostics
	tflog.Debug(ctx, "Creating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	ctx = tflog.SetField(ctx, "role_name", roleName)

	templateIds := d.Get("template_ids").(*schema.Set).List()
	templateNames := d.Get("template_short_names")

	tflog.Debug(ctx, "templateNames: ", map[string]interface{}{
		"template_ids":         templateIds,
		"template_short_names": templateNames,
	})

	validTemplateIds, diags := verifyTemplateIds(kfClient, templateIds)
	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequester(ctx, kfClient, roleName.(string), validTemplateIds, templateNames.(*schema.Set))
	if err != nil {
		return err
	}

	if len(diags) > 0 {
		return diags
	}

	// Other role attachments happen should below
	d.SetId(roleName.(string))
	tflog.Info(ctx, "Created Attach Keyfactor Role resource")
	resourceTemplateAttachRoleRead(ctx, d, m)

	return diags
}

/*
 * The resourceTemplateAttachRoleUpdate function is responsible for updating a Keyfactor security role.
 * TODO: Can this be used with Identitys?
 */
func setRoleAllowedRequester(ctx context.Context, kfClient *api.Client, roleName string, templateSet []interface{}, namedTemplateSet *schema.Set) diag.Diagnostics {
	var diags diag.Diagnostics

	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Setting Keyfactor role with name to be allowed requester for the following templates:")

	templateList := templateSet
	tflog.Debug(ctx, "Template IDs: ", map[string]interface{}{
		"template_ids": templateList,
	})
	var namedTemplateList []interface{}
	if namedTemplateSet != nil {
		namedTemplateList = namedTemplateSet.List()
		tflog.Debug(ctx, "Template short names: ", map[string]interface{}{
			"template_short_names": namedTemplateList,
		})
	}

	// First thing to do is blindly attach the passed role as an allowed requester to each of the template IDs passed in
	// the Set.
	if len(templateList) > 0 {
		for _, template := range templateList {
			tempCtx := tflog.SetField(ctx, "template_id", template)
			tempCtx = tflog.SetField(tempCtx, "role_name", roleName)
			tflog.Info(tempCtx, "Attaching role to template ID ")
			err := addAllowedRequesterToTemplate(ctx, kfClient, roleName, strconv.Itoa(template.(int)))
			if err != nil {
				tflog.Error(tempCtx, "Error attaching role to template")
				diags = append(diags, err...)
			}
		}
	}

	if len(namedTemplateList) > 0 {
		for _, template := range namedTemplateList {
			tempCtx := tflog.SetField(ctx, "template_name", template)
			tempCtx = tflog.SetField(tempCtx, "role_name", roleName)
			tflog.Info(tempCtx, "Attaching role to template")
			err := addAllowedRequesterToTemplate(ctx, kfClient, roleName, template.(string))
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
		list[strconv.Itoa(x.(int))] = struct{}{}
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
 * TODO: Can this be used with Identitys?
 */
func addAllowedRequesterToTemplate(ctx context.Context, kfClient *api.Client, roleName string, templateId string) diag.Diagnostics {
	var diags diag.Diagnostics
	ctx = tflog.SetField(ctx, "template_id", templateId)
	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Adding Keyfactor role with ID to template with ID")

	// First get info about template from Keyfactor
	if _, err := strconv.Atoi(templateId); err == nil {
		fmt.Printf("[DEBUG] %q looks like a number.\n", templateId)
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
			diags = append(diags, diag.FromErr(err2)...)
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
				diags = append(diags, diag.FromErr(err3)...)
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
		diags = append(diags, diag.FromErr(err)...)
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
	// Fill required fields with information retrieved from the get request above
	tflog.Debug(ctx, "Creating update context to add role to template")
	updateContext := &api.UpdateTemplateArg{
		Id:                   template.Id,
		CommonName:           template.CommonName,
		TemplateName:         template.TemplateName,
		Oid:                  template.Oid,
		KeySize:              template.KeySize,
		ForestRoot:           template.ForestRoot,
		UseAllowedRequesters: boolToPointer(true),
		AllowedRequesters:    &newAllowedRequester,
	}

	tflog.Trace(ctx, "Updating template in Keyfactor with context:", map[string]interface{}{
		"context": updateContext,
	})
	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		tflog.Error(ctx, "Error updating template in Keyfactor", map[string]interface{}{
			"error": err,
		})
		diags = append(diags, diag.FromErr(err)...)
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
		return diag.FromErr(err)
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

	// Fill required fields with information retrieved from the get request above
	updateContext := &api.UpdateTemplateArg{
		Id:                   template.Id,
		CommonName:           template.CommonName,
		TemplateName:         template.TemplateName,
		Oid:                  template.Oid,
		KeySize:              template.KeySize,
		ForestRoot:           template.ForestRoot,
		UseAllowedRequesters: boolToPointer(true),
		AllowedRequesters:    &newAllowedRequester,
	}

	tflog.Trace(ctx, "Updating template in Keyfactor with context:", map[string]interface{}{
		"context": updateContext,
	})
	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		tflog.Error(ctx, "Error updating template in Keyfactor", map[string]interface{}{
			"error": err,
		})
		return diag.FromErr(err)
	}
	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func resourceTemplateAttachRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[DEBUG] Read called on Attach Keyfactor Role resource")
	kfClient := m.(*api.Client)

	templateIds := d.Get("template_ids").(*schema.Set).List()

	roleName := d.Id()
	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, "Reading Keyfactor role with ID")

	// Check that templates exist
	newSchema := flattenAttachRoleSchema(ctx, roleName, templateIds)
	_, err := verifyTemplateIds(kfClient, templateIds)

	// Convert to a warning on read so manual state editing isn't required.
	for _, dg := range err {
		diags = append(diags, diag.Diagnostic{
			Severity:      diag.Warning,
			Summary:       strings.TrimSuffix(strings.Split(dg.Summary, "Message:")[1], "]"),
			Detail:        dg.Detail,
			AttributePath: dg.AttributePath,
		})
	}
	if len(diags) > 0 {
		diags = append(diags, diag.FromErr(fmt.Errorf("templates dont exist"))...)
		return diags
	}

	for key, value := range newSchema {
		err := d.Set(key, value)
		if err != nil {
			diags = append(diags, diag.FromErr(err)[0])
		}
	}

	//d.Set("template_ids", validTemplateIds)

	tflog.Info(ctx, "Read attached roles complete.")
	return diags
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 * TODO: Is this specific to templates or can this be abstracted to a general helper for roles?
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
		return diag.FromErr(err), make([]interface{}, 0)
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

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func resourceTemplateAttachRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	//var diags diag.Diagnostics
	tflog.Info(ctx, "Updating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_ids").(*schema.Set).List()
	templateNames := d.Get("template_short_names")
	ctx = tflog.SetField(ctx, "role_name", roleName)
	ctx = tflog.SetField(ctx, "template_ids", templateIds)
	ctx = tflog.SetField(ctx, "template_short_names", templateNames)

	tflog.Debug(ctx, "Verifying template IDs exist in Keyfactor")
	validTemplateIds, _ := verifyTemplateIds(kfClient, templateIds)
	//if err != nil {
	//	return err
	//}
	//d.Set("template_ids", validTemplateIds)
	// Add provided role to each of the certificate templates provided in configuration

	tflog.Debug(ctx, "Setting allowed requester for templates")
	err := setRoleAllowedRequester(ctx, kfClient, roleName.(string), validTemplateIds, templateNames.(*schema.Set))
	if err != nil {
		tflog.Error(ctx, "Error setting allowed requester for templates", map[string]interface{}{
			"error": err,
		})
		return err
	}

	// Other role attachments happen should below
	return resourceTemplateAttachRoleRead(ctx, d, m)
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func resourceTemplateAttachRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[INFO] Deleting Attach Keyfactor Role resource")
	kfClient := m.(*api.Client)
	roleName := d.Id()

	tempSet := schema.Set{F: schema.HashInt} //TODO: What is this doing?
	validTemplateIds, _ := verifyTemplateIds(kfClient, tempSet.List())
	err := setRoleAllowedRequester(ctx, kfClient, roleName, validTemplateIds, nil)
	if err != nil {
		return err
	}

	return diags
}
