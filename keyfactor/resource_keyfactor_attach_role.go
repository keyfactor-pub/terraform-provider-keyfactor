package keyfactor

import (
	"context"
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
 * The resourceKeyfactorAttachRole resource is designed to act as a proxy that acts to attach a given Keyfactor security
 * role to specific Keyfactor objects. Version 1.0 of this resource will be configured with a single Keyfactor security
 * role with the ability to attach to Keyfactor certificate templates.

 * Rationale: It is possible to create a resource for CRUD operations on Keyfactor security roles, but typically
 * these are only created once at the beginning of an instance's configuration, and then typically not touched. For this
 * reason, this resource acting as a hybrid between a template resource (infeasible due to Kefactor API design) and
 * a security role resource.
 */

func resourceKeyfactorAttachRole() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAttachRoleCreate,
		ReadContext:   resourceAttachRoleRead,
		UpdateContext: resourceAttachRoleUpdate,
		DeleteContext: resourceAttachRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor.",
			},
			// Configure template config as list of integers to simplify flattening functions
			"template_id_list": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of integers associaed with certificate templates in Keyfactor that the role will be attached to.",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
		},
	}
}

func resourceAttachRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Creating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_id_list")

	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequestor(kfClient, roleName.(string), templateIds.(*schema.Set))
	if err != nil {
		return diag.FromErr(err)
	}

	// Other role attachments happen should below
	d.SetId(roleName.(string))
	resourceAttachRoleRead(ctx, d, m)

	return diags
}

func setRoleAllowedRequestor(kfClient *api.Client, roleName string, templateSet *schema.Set) error {
	templateList := templateSet.List()
	// First thing to do is blindly attach the passed role as an allowed requestor to each of the template IDs passed in
	// the Set.
	if len(templateList) > 0 {
		for _, template := range templateList {
			err := addAllowedRequestorToTemplate(kfClient, roleName, template.(int))
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

func addAllowedRequestorToTemplate(kfClient *api.Client, roleName string, templateId int) error {
	log.Printf("[DEBUG] Adding Keyfactor role with ID %s to template with ID %d", roleName, templateId)

	// First get info about template from Keyfactor
	template, err := kfClient.GetTemplate(templateId)
	if err != nil {
		return err
	}

	// Check if role is already assigned as an allowed requester for the template, and
	var newAllowedRequester []string
	for _, name := range template.AllowedRequesters {
		if name == roleName {
			log.Printf("Keyfactor security role %s is already listed as an allowed requester for template %s (ID %d)", roleName, template.TemplateName, templateId)
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

func resourceAttachRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Read called on Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Id()

	// Get all templates that contain the provided role as an allowed requester
	err, templateIds := findTemplateRoleAttachments(kfClient, roleName)
	if err != nil {
		return diag.FromErr(err)
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

func flattenAttachRoleSchema(roleName string, templateIds []interface{}) map[string]interface{} {
	data := make(map[string]interface{})

	data["role_name"] = roleName

	tempSet := schema.NewSet(schema.HashInt, templateIds)
	data["template_id_list"] = tempSet

	return data
}

func findTemplateRoleAttachments(kfClient *api.Client, roleName string) (error, []interface{}) {
	// Goal here is to find every template that the role is listed as an allowed requester. First thing that needs
	// to happen is retrieve a complete list of all certificate templates.

	templates, err := kfClient.GetTemplates()
	if err != nil {
		return err, make([]interface{}, 0, 0)
	}

	var templateRoleAttachmentList []interface{}

	for _, template := range templates {
		// We only want to check the allowed requester list if UseAllowedRequesters is true
		if template.UseAllowedRequesters == true {
			for _, role := range template.AllowedRequesters {
				if role == roleName {
					templateRoleAttachmentList = append(templateRoleAttachmentList, template.Id)
				}
			}
		}
	}

	return nil, templateRoleAttachmentList
}

func resourceAttachRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Updating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_id_list")

	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequestor(kfClient, roleName.(string), templateIds.(*schema.Set))
	if err != nil {
		diags = append(diags, diag.FromErr(err)[0])
	}

	// Other role attachments happen should below
	return resourceAttachRoleRead(ctx, d, m)
}

func resourceAttachRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Deleting Attach Keyfactor Role resource")
	kfClient := m.(*api.Client)
	roleName := d.Id()

	tempSet := schema.Set{F: schema.HashInt}
	err := setRoleAllowedRequestor(kfClient, roleName, &tempSet)
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}
