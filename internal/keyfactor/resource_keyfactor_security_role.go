package keyfactor

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strconv"
)

func resourceSecurityRole() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSecurityRoleCreate,
		ReadContext:   resourceSecurityRoleRead,
		UpdateContext: resourceSecurityRoleUpdate,
		DeleteContext: resourceSecurityRoleDelete,
		Schema: map[string]*schema.Schema{
			"security_role": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "An string associated with a Keyfactor security role.",
						},
						"description": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "A string containing the description of the role in Keyfactor",
						},
						"identities": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "A string containing the description of the role in Keyfactor",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"account_name": {
										Type:        schema.TypeString,
										Required:    true,
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
							Type:        schema.TypeList,
							Optional:    true,
							Description: "An array containing the permissions assigned to the role in a list of Name:Value pairs",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
		},
	}
}

func resourceSecurityRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Creating Keyfactor Security Role resource")

	kfClient := m.(*keyfactor.Client)

	roles := d.Get("security_role").([]interface{})

	for _, i := range roles {
		role := i.(map[string]interface{})

		createArg := &keyfactor.CreateSecurityRoleArg{
			Name:        role["role_name"].(string),
			Description: role["description"].(string),
			Permissions: unpackPermissionInterface(role["permissions"].([]interface{})),
			Identities:  unpackIdentityInterface(role["identities"].([]interface{})),
		}

		createResp, err := kfClient.CreateSecurityRole(createArg)
		if err != nil {
			resourceSecurityRoleRead(ctx, d, m)
			return diag.FromErr(err)
		}

		// Set resource ID to tell Terraform that operation was successful
		d.SetId(strconv.Itoa(createResp.Id))
	}
	resourceSecurityRoleRead(ctx, d, m)
	return diags
}

func unpackPermissionInterface(permissions []interface{}) *[]string {
	if len(permissions) > 0 {
		var tempString []string
		for _, permission := range permissions {
			tempString = append(tempString, permission.(string))
		}
		return &tempString
	}
	return nil
}

func unpackIdentityInterface(identities []interface{}) *[]keyfactor.SecurityRoleIdentityConfig {
	if len(identities) > 0 {
		var identityConfig []keyfactor.SecurityRoleIdentityConfig
		for _, i := range identities {
			identity := i.(map[string]interface{})
			temp := keyfactor.SecurityRoleIdentityConfig{
				AccountName: identity["account_name"].(string),
				SID:         stringToPointer(identity["sid"].(string)),
			}
			identityConfig = append(identityConfig, temp)
		}
		return &identityConfig
	}
	return nil
}

func resourceSecurityRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Reading Keyfactor Security Role resource")

	kfClient := m.(*keyfactor.Client)

	id := d.Id()
	roleId, err := strconv.Atoi(id)
	if err != nil {
		return diag.FromErr(err)
	}

	role, err := kfClient.GetSecurityRole(roleId)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("security_role", flattenSecurityRole(role)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func flattenSecurityRole(roleContext *keyfactor.GetSecurityRolesResponse) []interface{} {
	if roleContext != nil {
		temp := make([]interface{}, 1, 1)
		data := make(map[string]interface{})

		// Assign response data to associated schema
		data["role_name"] = roleContext.Name
		data["description"] = roleContext.Description
		data["permissions"] = roleContext.Permissions

		// Assign schema that require flattening
		data["identities"] = flattenSecurityRoleIdentities(roleContext.Identities)

		temp[0] = data
		return temp
	}
	return make([]interface{}, 0)
}

func flattenSecurityRoleIdentities(identities []keyfactor.SecurityIdentity) []interface{} {
	// If the list of identities passed to this function has length > 0, iterate through each identity provided
	// and build a map[string]interface{} for each one, then push back onto a temporary []interface{}
	if len(identities) > 0 {
		var temp []interface{}
		for _, identity := range identities {
			data := make(map[string]interface{})

			data["account_name"] = identity.AccountName
			data["id"] = identity.Id
			data["identity_type"] = identity.IdentityType
			data["sid"] = identity.Sid

			temp = append(temp, data)
		}
		return temp
	}
	return make([]interface{}, 0)
}

func resourceSecurityRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Updating Keyfactor Security Role resource")

	kfClient := m.(*keyfactor.Client)
	roles := d.Get("security_role").([]interface{})

	id := d.Id()
	roleId, err := strconv.Atoi(id)
	if err != nil {
		return diag.FromErr(err)
	}

	for _, i := range roles {
		role := i.(map[string]interface{})

		updateArg := &keyfactor.UpdatteSecurityRoleArg{
			Id: roleId,
			CreateSecurityRoleArg: keyfactor.CreateSecurityRoleArg{
				Name:        role["role_name"].(string),
				Description: role["description"].(string),
				Permissions: unpackPermissionInterface(role["permissions"].([]interface{})),
				Identities:  unpackIdentityInterface(role["identities"].([]interface{})),
			},
		}

		_, err = kfClient.UpdateSecurityRole(updateArg)
		if err != nil {
			resourceSecurityRoleRead(ctx, d, m)
			return diag.FromErr(err)
		}
	}
	resourceSecurityRoleRead(ctx, d, m)
	return diags
}

func resourceSecurityRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Deleting Keyfactor Security Role resource")

	kfClient := m.(*keyfactor.Client)

	id := d.Id()
	roleId, err := strconv.Atoi(id)
	if err != nil {
		return diag.FromErr(err)
	}

	err = kfClient.DeleteSecurityRole(roleId)
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}
