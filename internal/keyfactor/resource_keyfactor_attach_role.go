package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
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
		Schema: map[string]*schema.Schema{
			"attach_security_role": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor.",
						},
						// Configure template config as list of integers to simplify flattening functions
						"template_id_list": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "A list of integers associaed with certificate templates in Keyfactor that the role will be attached to.",
							Elem:        &schema.Schema{Type: schema.TypeInt},
						},
					},
				},
			},
		},
	}
}

func resourceAttachRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Creating Attach Keyfactor Role resource")

	kfClient := m.(*keyfactor.Client)

	roleConfig := d.Get("attach_security_role").([]interface{})
	for _, i := range roleConfig {
		role := i.(map[string]interface{})

		roleName := role["role_name"].(string)

		// Add provided role to each of the certificate templates provided in configuration
		templateIds := role["template_id_list"].([]interface{})
		if len(templateIds) > 0 {
			for _, templateId := range templateIds {
				if err := addAllowedRequestorToTemplate(kfClient, roleName, templateId.(int)); err != nil {
					resourceAttachRoleRead(ctx, d, m)
					return diag.FromErr(err)
				}
			}
		}

		// Other role attachments happen should below

		d.SetId(roleName)
		resourceAttachRoleRead(ctx, d, m)
	}

	return diags
}

func addAllowedRequestorToTemplate(kfClient *keyfactor.Client, roleName string, templateId int) error {
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
	updateContext := &keyfactor.UpdateTemplateArg{
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

func removeRoleFromTemplate(kfClient *keyfactor.Client, roleId int, templateId int) error {
	return nil
}

func resourceAttachRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Read called on Attach Keyfactor Role resource")

	kfClient := m.(*keyfactor.Client)

	roleName := d.Id()

	// Get all templates that contain the provided role as an allowed requester
	err, templateIds := findTemplateRoleAttachments(kfClient, roleName)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("attach_security_role", flattenAttachRoleSchema(roleName, templateIds)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func flattenAttachRoleSchema(roleName string, templateIds []interface{}) []interface{} {
	temp := make([]interface{}, 1, 1)
	data := make(map[string]interface{})

	data["role_name"] = roleName
	data["template_id_list"] = templateIds

	temp[0] = data
	return temp
}

func findTemplateRoleAttachments(kfClient *keyfactor.Client, roleName string) (error, []interface{}) {
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

	kfClient := m.(*keyfactor.Client)
	roleConfig := d.Get("attach_security_role").([]interface{})
	for _, i := range roleConfig {
		role := i.(map[string]interface{})

		roleName := role["role_name"].(string)

		// Add provided role to each of the certificate templates provided in configuration
		templateIds := role["template_id_list"].([]interface{})
		if len(templateIds) > 0 {
			for _, templateId := range templateIds {
				if err := addAllowedRequestorToTemplate(kfClient, roleName, templateId.(int)); err != nil {
					resourceAttachRoleRead(ctx, d, m)
					return diag.FromErr(err)
				}
			}
		}
	}

	// Other role attachments happen should below
	resourceAttachRoleRead(ctx, d, m)

	return diags
}

func templateIdSchemaHasChange(d *schema.ResourceData) bool {
	templateIdSearchTerm := "attach_security_role.0.template_id_list"

	// Most obvious change to detect is the number of template ID schema blocks changed.
	if d.HasChange(fmt.Sprintf("%s.#", templateIdSearchTerm)) == true {
		return true
	}

	// Next, for each element, attempt to detect a change.
	// templateId*

	return false
}

func resourceAttachRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Deleting Attach Keyfactor Role resource")

	// kfClient := m.(*keyfactor.Client)

	return diags
}
