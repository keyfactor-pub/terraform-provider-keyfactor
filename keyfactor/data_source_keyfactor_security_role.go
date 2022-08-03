package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
)

func dataSourceKeyfactorSecurityRole() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceKeyfactorSecurityRoleRead,
		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "An string associated with a Keyfactor security role.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A string containing the description of the role in Keyfactor",
			},
			"identities": {
				Type:        schema.TypeSet,
				Computed:    true,
				Optional:    true,
				Description: "A string containing the description of the role in Keyfactor",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"account_name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name.",
						},
						"id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name.",
						},
						"identity_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "A string indicating the type of identity—User or Group.",
						},
						"sid": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "A string containing the security identifier from the source identity store (e.g. Active Directory) for the security identity.",
						},
					},
				},
			},
			"permissions": {
				Type:        schema.TypeSet,
				Computed:    true,
				Optional:    true,
				Description: "An array containing the permissions assigned to the role in a list of Name:Value pairs",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceKeyfactorSecurityRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	conn := m.(*api.Client)
	roleName := d.Get("role_name").(string)
	roles, err := conn.GetSecurityRoles()
	if err != nil {
		return nil
	}

	for _, role := range roles {
		if roleName == role.Name {
			d.SetId(strconv.Itoa(role.Id))
			return resourceSecurityRoleRead(ctx, d, m)
		}
	}

	// If we get here, the role name doesn't exist in Keyfactor.
	return diag.Diagnostics{
		{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Keyfactor role %s was not found.", roleName),
			Detail:   "Please ensure that role_name contains a role that exists in Keyfactor.",
		},
	}
}
