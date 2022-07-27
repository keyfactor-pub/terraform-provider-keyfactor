package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strconv"
)

/*
 * IMPORTANT NOTICE - Not yet implemented.
 */

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
			"template_id_list": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of integers associated with certificate templates in Keyfactor that the role will be attached to.",
				Elem:        &schema.Schema{Type: schema.TypeInt},
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

/*
 * The resourceTemplateRoleBindingCreate function is responsible for creating a Keyfactor security role.
 */
func resourceTemplateRoleBindingCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[DEBUG] Creating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_id_list")
	templateNames := d.Get("template_short_names")

	log.Printf("[DEBUG] templateNames: %v", templateNames)

	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequester(kfClient, roleName.(string), templateIds.(*schema.Set), templateNames.(*schema.Set))
	if err != nil {
		return diag.FromErr(err)
	}

	// Other role attachments happen should below
	d.SetId(roleName.(string))
	resourceTemplateAttachRoleRead(ctx, d, m)

	return diags
}

/*
 * The resourceTemplateAttachRoleUpdate function is responsible for updating a Keyfactor security role.
 * TODO: Can this be used with Identitys?
 */
func setRoleAllowedRequester(kfClient *api.Client, roleName string, templateSet *schema.Set, namedTemplateSet *schema.Set) error {
	log.Println("[DEBUG] Setting Keyfactor role with name " + roleName + " to be allowed requester for the following templates:")
	templateList := templateSet.List()
	log.Println("[DEBUG] Template IDs: " + strconv.Itoa(len(templateList)))
	namedTemplateList := namedTemplateSet.List()
	// First thing to do is blindly attach the passed role as an allowed requester to each of the template IDs passed in
	// the Set.
	if len(templateList) > 0 {
		for _, template := range templateList {
			err := addAllowedRequesterToTemplate(kfClient, roleName, template.(string))
			if err != nil {
				return err
			}
		}
	}

	if len(namedTemplateList) > 0 {
		for _, template := range templateList {
			err := addAllowedRequesterToTemplate(kfClient, roleName, template.(string))
			if err != nil {
				return err
			}
		}
	}

	// Then, build a list of all templates that the role is attached to as an allowed requester
	err, roleAttachments := findTemplateRoleAttachments(kfClient, roleName)
	if err != nil {
		return err
	}

	// Finally, find the difference between templateSet and roleAttachments. Recall that Terraform acts as the primary
	// manager of the role roleName, and Terraform is calling this function to explicitly set the allowed requesters.
	list := make(map[string]struct{}, len(templateList))
	for _, x := range templateList {
		list[strconv.Itoa(x.(int))] = struct{}{}
	}
	var diff []int
	for _, x := range roleAttachments {
		if _, found := list[strconv.Itoa(x.(int))]; !found {
			diff = append(diff, x.(int))
		}
	}

	for _, template := range diff {
		err = removeRoleFromTemplate(kfClient, roleName, template)
		if err != nil {
			return err
		}
	}

	return nil
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 * TODO: Can this be used with Identitys?
 */
func addAllowedRequesterToTemplate(kfClient *api.Client, roleName string, templateId string) error {
	log.Printf("[DEBUG] Adding Keyfactor role with ID %s to template with ID %v", roleName, templateId)

	// First get info about template from Keyfactor
	if _, err := strconv.Atoi(templateId); err == nil {
		fmt.Printf("[DEBUG] %q looks like a number.\n", templateId)
	}
	templateIdNumber, err := strconv.Atoi(templateId)
	if err != nil {
		log.Printf("[ERROR] %s", err)
		log.Println("Assuming templateId is a short name")
		templates, err := kfClient.GetTemplates()
		if err != nil {
			log.Printf("[ERROR] %s", err)
		}
		for template := range templates {
			//if template.CommonName == templateId {
			//	templateIdNumber = template.ID
			//	break
			//}
			log.Printf("[DEBUG] %v", template)
		}
	}

	template, err := kfClient.GetTemplate(templateIdNumber)
	if err != nil {
		return err
	}

	// Check if role is already assigned as an allowed requester for the template, and
	var newAllowedRequester []string
	for _, name := range template.AllowedRequesters {
		if name == roleName {
			log.Printf("Keyfactor security role %v is already listed as an allowed requester for template %v (ID %v)", roleName, template.TemplateName, templateId)
			return nil
		}
		newAllowedRequester = append(newAllowedRequester, name)
	}

	// If it's not already added, create update context to add role to template.
	newAllowedRequester = append(newAllowedRequester, roleName)
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

	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		return err
	}

	return nil
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func removeRoleFromTemplate(kfClient *api.Client, roleName string, templateId int) error {
	log.Printf("[DEBUG] Removing Keyfactor role with ID %s from template with ID %d", roleName, templateId)
	// First get info about template from Keyfactor
	template, err := kfClient.GetTemplate(templateId)
	if err != nil {
		return err
	}

	// Rebuild allowed requester list without roleName
	var newAllowedRequester []string
	for _, name := range template.AllowedRequesters {
		if name != roleName {
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

	_, err = kfClient.UpdateTemplate(updateContext)
	if err != nil {
		return err
	}
	return nil
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func resourceTemplateAttachRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[DEBUG] Read called on Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Id()
	log.Printf("[DEBUG] Reading Keyfactor role with ID %s", roleName)

	// Get all templates that contain the provided role as an allowed requester
	err, templateIds := findTemplateRoleAttachments(kfClient, roleName)
	if err != nil {
		return diag.FromErr(err)
	} else if templateIds == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Role '%v' not found.", roleName),
			Detail:   fmt.Sprintf("Role '%v' not found attached to any templates.", roleName),
		})
		return diags
	}

	newSchema := flattenAttachRoleSchema(roleName, templateIds)
	for key, value := range newSchema {
		err = d.Set(key, value)
		if err != nil {
			diags = append(diags, diag.FromErr(err)[0])
		}
	}

	return diags
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 * TODO: Is this specific to templates or can this be abstracted to a general helper for roles?
 */
func flattenAttachRoleSchema(roleName string, templateIds []interface{}) map[string]interface{} {
	log.Println("[DEBUG] Flattening Keyfactor role resource schema.")
	data := make(map[string]interface{})

	data["role_name"] = roleName

	tempSet := schema.NewSet(schema.HashInt, templateIds)
	data["template_id_list"] = tempSet

	return data
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func findTemplateRoleAttachments(kfClient *api.Client, roleName string) (error, []interface{}) {
	// Goal here is to find every template that the role is listed as an allowed requester. First thing that needs
	// to happen is retrieve a complete list of all certificate templates.

	log.Println("[DEBUG]: Fetching all templates from Keyfactor")
	templates, err := kfClient.GetTemplates()
	if err != nil {
		return err, make([]interface{}, 0)
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

	return nil, templateRoleAttachmentList
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func resourceTemplateAttachRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Updating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_id_list")
	templateNames := d.Get("template_short_names")

	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequester(kfClient, roleName.(string), templateIds.(*schema.Set), templateNames.(*schema.Set))
	if err != nil {
		_ = append(diags, diag.FromErr(err)[0])
	}

	// Other role attachments happen should below
	return resourceTemplateAttachRoleRead(ctx, d, m)
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func resourceTemplateAttachRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Deleting Attach Keyfactor Role resource")
	kfClient := m.(*api.Client)
	roleName := d.Id()

	tempSet := schema.Set{F: schema.HashInt}
	err := setRoleAllowedRequester(kfClient, roleName, &tempSet, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}
