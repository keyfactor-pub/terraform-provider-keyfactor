package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
	"strings"
)

//func dataSourceKeyfactorTemplate() *schema.Resource {
//	return &schema.Resource{
//		ReadContext: dataSourceKeyfactorTemplateRead,
//		Schema: map[string]*schema.Schema{
//			"templates": {
//				Type:        schema.TypeSet,
//				Computed:    true,
//				Description: "List of templates that exist in Keyfactor.",
//				Elem:        schemaDataSourceTemplate(),
//			},
//		},
//	}
//}

func dataSourceKeyfactorTemplate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceKeyfactorTemplateRead,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "An integer indicating the ID of the template in Keyfactor Command.",
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A string containing the common name (short name) of the template. This name typically does not contain spaces. For a template created using a Microsoft management tool, this will be the Microsoft template name. This field is populated from Active Directory and is not configurable.",
			},
			"template_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A string containing the name of the template. For a template created using a Microsoft management tool, this will be the Microsoft template display name. This field is populated from Active Directory and is not configurable.",
			},
			"oid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A string containing the object ID of the template in Active Directory. This field is populated from Active Directory and is not configurable.",
			},
			"key_size": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A string indicating the minimum supported key size of the template. This field is populated from Active Directory and is not configurable.",
			},
			"key_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A string indicating the key type of the template. This field is populated from Active Directory and is not configurable.",
			},
			"forest_root": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Forest root that the template is stored under/created by",
			},
			"key_retention": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A string indicating the type of key retention certificates enrolled with this template will use to store their private key in Keyfactor Command. ClosedShow key retention details.",
			},
			"key_retention_days": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Duration that the private key should be retained",
			},
			"key_archival": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "A Boolean indicating whether the template has been configured with the key archival setting in Active Directory (true) or not (false). This is a reference field and is not configurable.",
			},
			"enrollment_fields": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "An array containing custom enrollment fields. These are configured on a per-template basis to allow you to submit custom fields with CSR enrollments and PFX enrollments to supply custom request attributes to the CA during the enrollment process.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Template ID",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name that the enrollment field will be displayed under",
						},
						"options": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "List of options that will be displayed to the requester, if the datatype is 2",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"datatype": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Data type of the option given to user",
						},
					},
				},
			},
			"allowed_enrollment_types": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "An integer indicating the type of enrollment allowed for the certificate template. Setting these options causes the template to appear in dropdowns in the corresponding section of the Management Portal. In the case of CSR Enrollment and PFX Enrollment, the templates only appear in dropdowns on the enrollment pages if they are available for enrollment from a CA also configured for enrollment within Keyfactor Command.",
			},
			"use_allowed_requesters": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "A Boolean that indicates whether the Restrict Allowed Requesters option should be enabled (true) or not (false). The Restrict Allowed Requesters option is used to select Keyfactor Command security roles that a user must belong to in order to successfully enroll for certificates in Keyfactor Command using this template. This is typically used for templates for untrusted CAs, since Keyfactor Command cannot make use of the access control model of the CA itself to determine which users can enroll for certificates at either a template or CA level; this setting replaces that functionality.",
			},
			/*
				"allowed_requesters": {
					Type:        schema.TypeList,
					Description: "An array containing the list of Keyfactor Command security roles—as strings—that have been granted enroll permission on the template.",
					Optional:    true,
					Computed:    true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			*/
			"rfc_enforcement": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "A Boolean indicating whether certificate enrollments made through Keyfactor Command for this template must include at least one DNS SAN (true) or not (false). In the Keyfactor Command Management Portal, this causes the CN entered in PFX enrollment to automatically be replicated as a SAN, which the user can either change or accept.",
			},
			"key_usage": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "An integer indicating the total key usage of the certificate. Key usage is stored in Active Directory as a single value made of a combination of values.",
			},
		},
	}
}

func dataSourceKeyfactorTemplateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	conn := m.(*api.Client)

	templates, err := conn.GetTemplates()
	fmt.Printf("[DEBUG] templates: %v\n", templates)
	templateName := d.Get("common_name").(string)
	fmt.Printf("[DEBUG] templateName: %v\n", templateName)
	for _, template := range templates {

		fmt.Printf("[DEBUG] template_common_name: %v\n", template.CommonName)
		if strings.EqualFold(template.CommonName, templateName) {
			d.SetId(strconv.Itoa(template.Id))
			d.Set("common_name", template.CommonName)
			//d.Set("description", template.Description)
			d.Set("key_type", template.KeyType)
			d.Set("forest_root", template.ForestRoot)
			d.Set("key_retention", template.KeyRetention)
			d.Set("key_retention_days", template.KeyRetentionDays)
			d.Set("key_archival", template.KeyArchival)
			d.Set("enrollment_fields", template.EnrollmentFields)
			d.Set("allowed_enrollment_types", template.AllowedEnrollmentTypes)
			d.Set("use_allowed_requesters", template.UseAllowedRequesters)
			d.Set("rfc_enforcement", template.RFCEnforcement)
			d.Set("key_usage", template.KeyUsage)
			return nil
		}
	}

	//err = d.Set("templates", flattenTemplates(templates))
	if err != nil {
		return diag.FromErr(err)
	}

	//d.SetId("keyfactor_template-" + acctest.RandStringFromCharSet(5, acctest.CharSetAlphaNum))
	//
	//return nil
	return diag.Diagnostics{
		{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Keyfactor certificate %s was not found.", templateName),
			Detail:   "Please ensure that role_name contains a certificate that exists in Keyfactor.",
		},
	}
}

//func flattenTemplates(templates []api.GetTemplateResponse) *schema.Set {
//	temp := make([]interface{}, len(templates))
//	for i, template := range templates {
//		data := make(map[string]interface{})
//		data["id"] = template.Id
//		data["common_name"] = template.CommonName
//		data["template_name"] = template.TemplateName
//		data["oid"] = template.Oid
//		data["key_size"] = template.KeySize
//		data["key_type"] = template.KeyType
//		data["forest_root"] = template.ForestRoot
//		data["key_retention"] = template.KeyRetention
//		data["key_retention_days"] = template.KeyRetentionDays
//		data["key_archival"] = template.KeyArchival
//		if len(template.EnrollmentFields) > 0 {
//			data["enrollment_fields"] = flattenEnrollmentFields(template.EnrollmentFields)
//		}
//		data["allowed_enrollment_types"] = template.AllowedEnrollmentTypes
//		data["use_allowed_requesters"] = template.UseAllowedRequesters
//		//data["allowed_requesters"] = template.AllowedRequesters
//		data["rfc_enforcement"] = template.RFCEnforcement
//		data["key_usage"] = template.KeyUsage
//		temp[i] = data
//	}
//	return schema.NewSet(schema.HashResource(dataSourceKeyfactorTemplate()), temp)
//}

func flattenEnrollmentFields(ef []api.TemplateEnrollmentFields) []interface{} {
	data := make([]interface{}, len(ef))
	for i, field := range ef {
		temp := make(map[string]interface{})
		temp["id"] = field.Id
		temp["name"] = field.Name
		temp["options"] = field.Options
		temp["datatype"] = field.DataType
		data[i] = temp
	}
	return data
}
