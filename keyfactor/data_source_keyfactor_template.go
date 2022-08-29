package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/spbsoluble/kfctl/api"
	"strconv"
)

type dataSourceCertificateTemplateType struct{}

func (r dataSourceCertificateTemplateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the ID of the template in Keyfactor Command.",
			},
			"short_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the common name (short name) of the template. This name typically does not contain spaces. For a template created using a Microsoft management tool, this will be the Microsoft template name. This field is populated from Active Directory and is not configurable.",
			},
			"name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the name of the template. For a template created using a Microsoft management tool, this will be the Microsoft template display name. This field is populated from Active Directory and is not configurable.",
			},
			"oid": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the object ID of the template in Active Directory. This field is populated from Active Directory and is not configurable.",
			},
			"key_size": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the minimum supported key size of the template. This field is populated from Active Directory and is not configurable.",
			},
			"key_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the key type of the template. This field is populated from Active Directory and is not configurable.",
			},
			"forest_root": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Forest root that the template is stored under/created by",
			},
			"friendly_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Forest root that the template is stored under/created by",
			},
			"key_retention": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the type of key retention certificates enrolled with this template will use to store their private key in Keyfactor Command. ClosedShow key retention details.",
			},
			"key_retention_days": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Duration that the private key should be retained",
			},
			"key_archival": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean indicating whether the template has been configured with the key archival setting in Active Directory (true) or not (false). This is a reference field and is not configurable.",
			},
			"enrollment_fields": {
				Type:        types.ListType{ElemType: types.MapType{ElemType: types.StringType}},
				Computed:    true,
				Description: "An array containing custom enrollment fields. These are configured on a per-template basis to allow you to submit custom fields with CSR enrollments and PFX enrollments to supply custom request attributes to the CA during the enrollment process.",
			},
			"allowed_enrollment_types": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the type of enrollment allowed for the certificate template. Setting these options causes the template to appear in dropdowns in the corresponding section of the Management Portal. In the case of CSR Enrollment and PFX Enrollment, the templates only appear in dropdowns on the enrollment pages if they are available for enrollment from a CA also configured for enrollment within Keyfactor Command.",
			},
			"template_regexes": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "List of regexes that the template will be matched against during enrollment.",
			},
			//"use_allowed_requesters": {
			//	Type:        types.BoolType,
			//	Computed:    true,
			//	Description: "A Boolean that indicates whether the Restrict Allowed Requesters option should be enabled (true) or not (false). The Restrict Allowed Requesters option is used to select Keyfactor Command security templates that a user must belong to in order to successfully enroll for certificates in Keyfactor Command using this template. This is typically used for templates for untrusted CAs, since Keyfactor Command cannot make use of the access control model of the CA itself to determine which users can enroll for certificates at either a template or CA level; this setting replaces that functionality.",
			//},

			"allowed_requesters": {
				Type:        types.ListType{ElemType: types.StringType},
				Description: "An array containing the list of Keyfactor Command security templates—as strings—that have been granted enroll permission on the template.",
				Optional:    true,
				Computed:    true,
			},
			"rfc_enforcement": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean indicating whether certificate enrollments made through Keyfactor Command for this template must include at least one DNS SAN (true) or not (false). In the Keyfactor Command Management Portal, this causes the CN entered in PFX enrollment to automatically be replicated as a SAN, which the user can either change or accept.",
			},
			"requires_approval": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean indicating whether certificate enrollments require approval (true) or not (false).",
			},
			"key_usage": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the total key usage of the certificate. Key usage is stored in Active Directory as a single value made of a combination of values.",
			},
			//"extended_key_usage": {
			//	Type:        types.ListType{ElemType: types.MapType{}},
			//	Computed:    true,
			//	Description: "An array containing custom enrollment fields. These are configured on a per-template basis to allow you to submit custom fields with CSR enrollments and PFX enrollments to supply custom request attributes to the CA during the enrollment process.",
			//},
		},
	}, nil
}

func (r dataSourceCertificateTemplateType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertificateTemplate{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificateTemplate struct {
	p provider
}

func (r dataSourceCertificateTemplate) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	var state CertificateTemplate
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate template resource")
	templateId := state.ID.Value
	templateName := state.CommonName.Value
	tflog.SetField(ctx, "template_name", templateId)

	templates, err := r.p.client.GetTemplates()

	if err != nil {
		response.Diagnostics.AddError("Error listing templates from Keyfactor.", "Error reading templates: "+err.Error())
	}

	var result CertificateTemplate
	for _, template := range templates {
		if templateName == template.CommonName {
			allowedRequesters := flattenAllowedRequesters(template.AllowedRequesters)
			templateRegexes := flattenTemplateRegexes(template.TemplateRegexes)
			enrollmentFields := flattenEnrollmentFields(template.EnrollmentFields)
			tflog.Debug(ctx, fmt.Sprintf("Enrollment fields: %v", enrollmentFields))
			tflog.Info(ctx, fmt.Sprintf("Found template with account name: %s", templateName))
			result = CertificateTemplate{
				ID:                     types.Int64{Value: int64(template.Id)},
				CommonName:             types.String{Value: template.CommonName},
				TemplateName:           types.String{Value: template.TemplateName},
				OID:                    types.String{Value: template.Oid},
				KeySize:                types.String{Value: template.KeySize},
				ForestRoot:             types.String{Value: template.ForestRoot},
				FriendlyName:           types.String{Value: template.FriendlyName},
				KeyRetention:           types.String{Value: template.KeyRetention},
				KeyRetentionDays:       types.Int64{Value: int64(template.KeyRetentionDays)},
				KeyArchival:            types.Bool{Value: template.KeyArchival},
				EnrollmentFields:       state.EnrollmentFields,
				AllowedEnrollmentTypes: types.Int64{Value: int64(template.AllowedEnrollmentTypes)},
				TemplateRegexes:        templateRegexes,
				AllowedRequesters:      allowedRequesters,
				RFCEnforcement:         types.Bool{Value: template.RFCEnforcement},
				RequiresApproval:       types.Bool{Value: template.RequiresApproval},
				KeyUsage:               types.Int64{Value: int64(template.KeyUsage)},
			}
			break
		}
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func flattenEnrollmentFields(efs []api.TemplateEnrollmentFields) types.List {

	result := types.List{
		ElemType: types.MapType{},
		Elems:    []attr.Value{},
	}
	for _, ef := range efs {
		var options []attr.Value
		for _, op := range ef.Options {
			options = append(options, types.String{
				Value: op,
			})
		}
		result.Elems = append(result.Elems, types.Map{
			ElemType: types.StringType,
			Elems: map[string]attr.Value{
				"id":   types.Int64{Value: int64(ef.Id)},
				"name": types.String{Value: ef.Name},
				"type": types.String{Value: strconv.Itoa(ef.DataType)},
				"options": types.List{
					Elems:    options,
					ElemType: types.StringType,
				},
			},
		})
	}

	return result
}

func flattenTemplateRegexes(regexes []api.TemplateRegex) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	for _, regex := range regexes {
		result.Elems = append(result.Elems, types.String{Value: regex.RegEx})
	}
	return result
}

func flattenAllowedRequesters(requesters []string) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}

	if len(requesters) > 0 {
		for _, requester := range requesters {
			result.Elems = append(result.Elems, types.String{Value: requester})
		}
	}

	return result
}
