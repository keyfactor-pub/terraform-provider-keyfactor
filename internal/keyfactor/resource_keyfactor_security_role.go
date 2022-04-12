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
				Type:        schema.TypeSet,
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
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "An array containing the permissions assigned to the role in a list of Name:Value pairs",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceSecurityRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[INFO] Creating Keyfactor Security Role resource")

	kfClient := m.(*keyfactor.Client)

	createArg := &keyfactor.CreateSecurityRoleArg{
		Name:        d.Get("role_name").(string),
		Description: d.Get("description").(string),
	}

	if permission, ok := d.GetOk("permissions"); ok {
		createArg.Permissions = unpackPermissionSet(permission.(*schema.Set))
	}

	if identity, ok := d.GetOk("identities"); ok {
		createArg.Identities = unpackIdentitySet(identity.(*schema.Set))
	}

	createResp, err := kfClient.CreateSecurityRole(createArg)
	if err != nil {
		resourceSecurityRoleRead(ctx, d, m)
		return diag.FromErr(err)
	}

	// Set resource ID to tell Terraform that operation was successful
	d.SetId(strconv.Itoa(createResp.Id))

	return resourceSecurityRoleRead(ctx, d, m)
}

func unpackPermissionSet(set *schema.Set) *[]string {
	permissions := set.List()
	if len(permissions) > 0 {
		var tempString []string
		for _, permission := range permissions {
			tempString = append(tempString, permission.(string))
		}
		return &tempString
	}
	return nil
}

func unpackIdentitySet(set *schema.Set) *[]keyfactor.SecurityRoleIdentityConfig {
	identities := set.List()
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

	newSchema := flattenSecurityRole(role)
	for key, value := range newSchema {
		err = d.Set(key, value)
		if err != nil {
			diags = append(diags, diag.FromErr(err)[0])
		}
	}

	return diags
}

func flattenSecurityRole(roleContext *keyfactor.GetSecurityRolesResponse) map[string]interface{} {
	data := make(map[string]interface{})
	if roleContext != nil {
		// Assign response data to associated schema
		data["role_name"] = roleContext.Name
		data["description"] = roleContext.Description
		permissionSet := newStringSet(schema.HashString, roleContext.Permissions)
		data["permissions"] = permissionSet

		// Assign schema that require flattening
		data["identities"] = flattenSecurityRoleIdentities(roleContext.Identities)
	}
	return data
}

// This came from the Kubernetes provider... ran out of time
func newStringSet(f schema.SchemaSetFunc, in []string) *schema.Set {
	var out = make([]interface{}, len(in), len(in))
	for i, v := range in {
		out[i] = v
	}
	return schema.NewSet(f, out)
}

func flattenSecurityRoleIdentities(identities []keyfactor.SecurityIdentity) *schema.Set {
	// If the list of identities passed to this function has length > 0, iterate through each identity provided
	// and build a map[string]interface{} for each one, then push back onto a temporary []interface{}
	var temp []interface{}
	if len(identities) > 0 {
		for _, identity := range identities {
			data := make(map[string]interface{})

			data["account_name"] = identity.AccountName
			data["id"] = identity.Id
			data["identity_type"] = identity.IdentityType
			data["sid"] = identity.Sid

			temp = append(temp, data)
		}
	}

	return schema.NewSet(schema.HashResource(schemaSecurityRoleIdentities()), temp)
}

func schemaSecurityRoleIdentities() *schema.Resource {
	return &schema.Resource{
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
	}
}

func resourceSecurityRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[INFO] Updating Keyfactor Security Role resource")

	kfClient := m.(*keyfactor.Client)

	id := d.Id()
	roleId, err := strconv.Atoi(id)
	if err != nil {
		return diag.FromErr(err)
	}

	updateArg := &keyfactor.UpdatteSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: keyfactor.CreateSecurityRoleArg{
			Name:        d.Get("role_name").(string),
			Description: d.Get("description").(string),
		},
	}

	if permission, ok := d.GetOk("permissions"); ok {
		updateArg.Permissions = unpackPermissionSet(permission.(*schema.Set))
	}

	if identity, ok := d.GetOk("identities"); ok {
		updateArg.Identities = unpackIdentitySet(identity.(*schema.Set))
	}

	_, err = kfClient.UpdateSecurityRole(updateArg)
	if err != nil {
		resourceSecurityRoleRead(ctx, d, m)
		return diag.FromErr(err)
	}

	return resourceSecurityRoleRead(ctx, d, m)
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
