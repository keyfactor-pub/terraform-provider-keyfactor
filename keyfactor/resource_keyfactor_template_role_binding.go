package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
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
	log.Println("[DEBUG] Creating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_ids").(*schema.Set).List()
	templateNames := d.Get("template_short_names")

	log.Printf("[DEBUG] templateNames: %v\n", templateNames)

	validTemplateIds, diags := verifyTemplateIds(kfClient, templateIds)
	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequester(kfClient, roleName.(string), validTemplateIds, templateNames.(*schema.Set))
	if err != nil {
		return err
	}

	if len(diags) > 0 {
		return diags
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
func setRoleAllowedRequester(kfClient *api.Client, roleName string, templateSet []interface{}, namedTemplateSet *schema.Set) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[DEBUG] Setting Keyfactor role with name " + roleName + " to be allowed requester for the following templates:")
	templateList := templateSet
	log.Println("[DEBUG] Template IDs: " + strconv.Itoa(len(templateList)))
	var namedTemplateList []interface{}
	if namedTemplateSet != nil {
		namedTemplateList = namedTemplateSet.List()
	}

	// First thing to do is blindly attach the passed role as an allowed requester to each of the template IDs passed in
	// the Set.
	if len(templateList) > 0 {
		for _, template := range templateList {
			log.Println("[DEBUG] Attaching role " + roleName + " to template ID " + strconv.Itoa(template.(int)))
			err := addAllowedRequesterToTemplate(kfClient, roleName, strconv.Itoa(template.(int)))
			if err != nil {
				diags = append(diags, err...)
			}
		}
	}

	if len(namedTemplateList) > 0 {
		for _, template := range namedTemplateList {
			log.Println("[DEBUG] Attaching role " + roleName + " to template " + template.(string))
			err := addAllowedRequesterToTemplate(kfClient, roleName, template.(string))
			if err != nil {
				diags = append(diags, err...)
			}
		}
	}

	if diags != nil {
		return diags
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
			diags = append(diags, err...)
		}
	}

	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 * TODO: Can this be used with Identitys?
 */
func addAllowedRequesterToTemplate(kfClient *api.Client, roleName string, templateId string) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Printf("[DEBUG] Adding Keyfactor role with ID %s to template with ID %v\n", roleName, templateId)

	// First get info about template from Keyfactor
	if _, err := strconv.Atoi(templateId); err == nil {
		fmt.Printf("[DEBUG] %q looks like a number.\n", templateId)
	}
	templateIdNumber, err := strconv.Atoi(templateId)
	if err != nil {
		log.Printf("[ERROR] %s\n", err)
		log.Println("Assuming templateId is a short name")
		templates, err2 := kfClient.GetTemplates()
		if err2 != nil {
			log.Printf("[ERROR] %s\n", err2)
			diags = append(diags, diag.FromErr(err2)...)
		}
		for template := range templates {
			log.Printf("[DEBUG] Template ID: %v\n", template)
			kfTemplate, err3 := kfClient.GetTemplate(template)
			log.Printf("[DEBUG] Keyfactor Template: %v\n", kfTemplate)
			if err3 != nil {
				log.Printf("[ERROR] %s\n", err3)
				diags = append(diags, diag.FromErr(err3)...)
				continue
			}
			if kfTemplate.CommonName == templateId {
				templateIdNumber = kfTemplate.Id
				break
			}
		}
	}

	template, err := kfClient.GetTemplate(templateIdNumber)
	if err != nil {
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}

	// Check if role is already assigned as an allowed requester for the template, and
	var newAllowedRequester []string
	for _, name := range template.AllowedRequesters {
		if name == roleName {
			log.Printf("[WARNING] Keyfactor security role %v is already listed as an allowed requester for template %v (ID %v)\n", roleName, template.TemplateName, templateId)
			return diags
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
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}

	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func removeRoleFromTemplate(kfClient *api.Client, roleName string, templateId int) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Printf("[DEBUG] Removing Keyfactor role with ID %s from template with ID %d", roleName, templateId)
	// First get info about template from Keyfactor
	template, err := kfClient.GetTemplate(templateId)
	if err != nil {
		return diag.FromErr(err)
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
		return diag.FromErr(err)
	}
	return diags
}

/*
 * The resourceTemplateAttachRoleRead function is responsible for reading a Keyfactor security role.
 */
func resourceTemplateAttachRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[DEBUG] Read called on Attach Keyfactor Role resource")
	kfClient := m.(*api.Client)

	templateIds := d.Get("template_ids").(*schema.Set).List()

	roleName := d.Id()
	log.Printf("[DEBUG] Reading Keyfactor role with ID %s", roleName)

	// Check that templates exist
	newSchema := flattenAttachRoleSchema(roleName, templateIds)
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

	log.Printf("[DEBUG] Data: %v", d)
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
	data["template_ids"] = tempSet

	return data
}

/*
 * The resourceTemplateAttachRoleDelete function is responsible for deleting a Keyfactor security role.
 */
func findTemplateRoleAttachments(kfClient *api.Client, roleName string) (diag.Diagnostics, []interface{}) {
	// Goal here is to find every template that the role is listed as an allowed requester. First thing that needs
	// to happen is retrieve a complete list of all certificate templates.

	var diags diag.Diagnostics
	log.Println("[DEBUG]: Fetching all templates from Keyfactor")
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
	log.Println("[INFO] Updating Attach Keyfactor Role resource")

	kfClient := m.(*api.Client)

	roleName := d.Get("role_name")
	templateIds := d.Get("template_ids").(*schema.Set).List()
	templateNames := d.Get("template_short_names")
	log.Printf("[DEBUG] roleName: %s\n", roleName)
	log.Printf("[DEBUG] Template IDs: %s\n", templateIds)
	log.Printf("[DEBUG] Template names: %s\n", templateNames)

	validTemplateIds, _ := verifyTemplateIds(kfClient, templateIds)
	//if err != nil {
	//	return err
	//}
	//d.Set("template_ids", validTemplateIds)
	// Add provided role to each of the certificate templates provided in configuration
	err := setRoleAllowedRequester(kfClient, roleName.(string), validTemplateIds, templateNames.(*schema.Set))
	if err != nil {
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
	log.Println("[INFO] Deleting Attach Keyfactor Role resource")
	kfClient := m.(*api.Client)
	roleName := d.Id()

	tempSet := schema.Set{F: schema.HashInt} //TODO: What is this doing?
	validTemplateIds, _ := verifyTemplateIds(kfClient, tempSet.List())
	err := setRoleAllowedRequester(kfClient, roleName, validTemplateIds, nil)
	if err != nil {
		return err
	}

	return diags
}
