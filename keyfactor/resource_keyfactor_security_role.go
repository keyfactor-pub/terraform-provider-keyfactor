package keyfactor

//
//import (
//	"context"
//	"github.com/Keyfactor/keyfactor-go-client/api"
//	"github.com/hashicorp/terraform-plugin-log/tflog"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
//	"strconv"
//)
//
//func resourceSecurityRole() *schema.Resource {
//	return &schema.Resource{
//		CreateContext: resourceSecurityRoleCreate,
//		ReadContext:   resourceSecurityRoleRead,
//		UpdateContext: resourceSecurityRoleUpdate,
//		DeleteContext: resourceSecurityRoleDelete,
//		Importer: &schema.ResourceImporter{
//			StateContext: schema.ImportStatePassthroughContext,
//		},
//		Schema: map[string]*schema.Schema{
//			"role_name": {
//				Type:        schema.TypeString,
//				Required:    true,
//				Description: "An string associated with a Keyfactor security role.",
//			},
//			"description": {
//				Type:        schema.TypeString,
//				Required:    true,
//				Description: "A string containing the description of the role in Keyfactor",
//			},
//			"identities": {
//				Type:        schema.TypeSet,
//				Optional:    true,
//				Description: "A string containing the description of the role in Keyfactor",
//				Elem: &schema.Resource{
//					Schema: map[string]*schema.Schema{
//						"account_name": {
//							Type:        schema.TypeString,
//							Required:    true,
//							Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name.",
//						},
//						"id": {
//							Type:        schema.TypeInt,
//							Computed:    true,
//							Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name.",
//						},
//						"identity_type": {
//							Type:        schema.TypeString,
//							Computed:    true,
//							Description: "A string indicating the type of identity—User or Group.",
//						},
//						"sid": {
//							Type:        schema.TypeString,
//							Computed:    true,
//							Description: "A string containing the security identifier from the source identity store (e.g. Active Directory) for the security identity.",
//						},
//					},
//				},
//			},
//			"users": {
//				Type:        schema.TypeSet,
//				Optional:    true,
//				Description: "List of users to grant access to the role.",
//				Elem:        &schema.Schema{Type: schema.TypeString},
//			},
//			"permissions": {
//				Type:        schema.TypeSet,
//				Optional:    true,
//				Description: "An array containing the permissions assigned to the role in a list of Name:Value pairs",
//				Elem:        &schema.Schema{Type: schema.TypeString},
//			},
//		},
//	}
//}
//
//func resourceSecurityRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
//	tflog.Info(ctx, "Creating Keyfactor Security Role resource")
//
//	kfClient := m.(*api.Client)
//
//	createArg := &api.CreateSecurityRoleArg{
//		Name:        d.Get("role_name").(string),
//		Description: d.Get("description").(string),
//	}
//	tflog.Trace(ctx, "Creating Keyfactor Security Role resource with arguments: ", map[string]interface{}{
//		"create_arg": createArg,
//	})
//
//	if permission, ok := d.GetOk("permissions"); ok {
//		tflog.Debug(ctx, "Unpacking permissions")
//		createArg.Permissions = unpackPermissionSet(permission.(*schema.Set))
//	}
//
//	if identity, ok := d.GetOk("identities"); ok {
//		tflog.Debug(ctx, "Unpacking identities")
//		createArg.Identities = unpackIdentitySet(identity.(*schema.Set))
//	}
//
//	tflog.Debug(ctx, "Creating Keyfactor Security Role resource")
//	createResp, err := kfClient.CreateSecurityRole(createArg)
//	if err != nil {
//		tflog.Error(ctx, "Error creating Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		resourceSecurityRoleRead(ctx, d, m)
//		return diag.FromErr(err)
//	}
//
//	// Set resource ID to tell Terraform that operation was successful
//	d.SetId(strconv.Itoa(createResp.Id))
//	tflog.Info(ctx, "Created Keyfactor Security Role resource")
//
//	return resourceSecurityRoleRead(ctx, d, m)
//}
//
//func unpackPermissionSet(set *schema.Set) *[]string {
//	permissions := set.List()
//	if len(permissions) > 0 {
//		var tempString []string
//		for _, permission := range permissions {
//			tempString = append(tempString, permission.(string))
//		}
//		return &tempString
//	}
//	return nil
//}
//
//func unpackIdentitySet(set *schema.Set) *[]api.SecurityRoleIdentityConfig {
//	identities := set.List()
//	if len(identities) > 0 {
//		var identityConfig []api.SecurityRoleIdentityConfig
//		for _, i := range identities {
//			identity := i.(map[string]interface{})
//			temp := api.SecurityRoleIdentityConfig{
//				AccountName: identity["account_name"].(string),
//				SID:         stringToPointer(identity["sid"].(string)),
//			}
//			identityConfig = append(identityConfig, temp)
//		}
//		return &identityConfig
//	}
//	return nil
//}
//
//func resourceSecurityRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
//	var diags diag.Diagnostics
//	tflog.Info(ctx, "Reading Keyfactor Security Role resource")
//
//	kfClient := m.(*api.Client)
//
//	id := d.Id()
//	tflog.Trace(ctx, "Reading Keyfactor Security Role resource with id: ", map[string]interface{}{
//		"id": id,
//	})
//	roleId, err := strconv.Atoi(id)
//	ctx = tflog.SetField(ctx, "role_id", roleId)
//	if err != nil {
//		tflog.Error(ctx, "Error reading Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		return diag.FromErr(err)
//	}
//
//	tflog.Debug(ctx, "Reading Keyfactor Security Role resource")
//	role, err := kfClient.GetSecurityRole(roleId)
//	if err != nil {
//		tflog.Error(ctx, "Error reading Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		return diag.FromErr(err)
//	}
//
//	tflog.Debug(ctx, "Populating Keyfactor Security Role resource")
//	newSchema := flattenSecurityRole(role)
//	for key, value := range newSchema {
//		tflog.Trace(ctx, "Populating Keyfactor Security Role resource with key: ", map[string]interface{}{
//			"key":   key,
//			"value": value,
//		})
//		err = d.Set(key, value)
//		if err != nil {
//			tflog.Error(ctx, "Error populating Keyfactor Security Role resource: ", map[string]interface{}{
//				"error": err,
//			})
//			diags = append(diags, diag.FromErr(err)[0])
//		}
//	}
//
//	return diags
//}
//
//func flattenSecurityRole(roleContext *api.GetSecurityRolesResponse) map[string]interface{} {
//	data := make(map[string]interface{})
//	if roleContext != nil {
//		// Assign response data to associated schema
//		data["role_name"] = roleContext.Name
//		data["description"] = roleContext.Description
//		permissionSet := newStringSet(schema.HashString, roleContext.Permissions)
//		data["permissions"] = permissionSet
//
//		// Assign schema that require flattening
//		data["identities"] = flattenSecurityRoleIdentities(roleContext.Identities)
//	}
//	return data
//}
//
//// This came from the Kubernetes provider... ran out of time
//func newStringSet(f schema.SchemaSetFunc, in []string) *schema.Set {
//	var out = make([]interface{}, len(in))
//	for i, v := range in {
//		out[i] = v
//	}
//	return schema.NewSet(f, out)
//}
//
//func flattenSecurityRoleIdentities(identities []api.SecurityIdentity) *schema.Set {
//	// If the list of identities passed to this function has length > 0, iterate through each identity provided
//	// and build a map[string]interface{} for each one, then push back onto a temporary []interface{}
//	var temp []interface{}
//	if len(identities) > 0 {
//		for _, identity := range identities {
//			data := make(map[string]interface{})
//
//			data["account_name"] = identity.AccountName
//			data["id"] = identity.Id
//			data["identity_type"] = identity.IdentityType
//			data["sid"] = identity.Sid
//
//			temp = append(temp, data)
//		}
//	}
//
//	return schema.NewSet(schema.HashResource(schemaSecurityRoleIdentities()), temp)
//}
//
//func schemaSecurityRoleIdentities() *schema.Resource {
//	return &schema.Resource{
//		Schema: map[string]*schema.Schema{
//			"account_name": {
//				Type:        schema.TypeString,
//				Required:    true,
//				Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name.",
//			},
//			"id": {
//				Type:        schema.TypeInt,
//				Computed:    true,
//				Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name.",
//			},
//			"identity_type": {
//				Type:        schema.TypeString,
//				Computed:    true,
//				Description: "A string indicating the type of identity—User or Group.",
//			},
//			"sid": {
//				Type:        schema.TypeString,
//				Computed:    true,
//				Description: "A string containing the security identifier from the source identity store (e.g. Active Directory) for the security identity.",
//			},
//		},
//	}
//}
//
//func resourceSecurityRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
//	tflog.Info(ctx, "Updating Keyfactor Security Role resource")
//
//	kfClient := m.(*api.Client)
//
//	id := d.Id()
//	roleId, err := strconv.Atoi(id)
//	ctx = tflog.SetField(ctx, "role_id", roleId)
//	if err != nil {
//		tflog.Error(ctx, "Error updating Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		return diag.FromErr(err)
//	}
//
//	updateArg := &api.UpdatteSecurityRoleArg{
//		Id: roleId,
//		CreateSecurityRoleArg: api.CreateSecurityRoleArg{
//			Name:        d.Get("role_name").(string),
//			Description: d.Get("description").(string),
//		},
//	}
//
//	if permission, ok := d.GetOk("permissions"); ok {
//		tflog.Debug(ctx, "Unpacking permissions")
//		updateArg.Permissions = unpackPermissionSet(permission.(*schema.Set))
//	}
//
//	if identity, ok := d.GetOk("identities"); ok {
//		tflog.Debug(ctx, "Unpacking identities")
//		updateArg.Identities = unpackIdentitySet(identity.(*schema.Set))
//	}
//
//	tflog.Debug(ctx, "Updating Keyfactor Security Role resource", map[string]interface{}{
//		"update_arg": updateArg,
//	})
//	_, err = kfClient.UpdateSecurityRole(updateArg)
//	if err != nil {
//		tflog.Error(ctx, "Error updating Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		resourceSecurityRoleRead(ctx, d, m)
//		return diag.FromErr(err)
//	}
//
//	return resourceSecurityRoleRead(ctx, d, m)
//}
//
//func resourceSecurityRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
//	var diags diag.Diagnostics
//	tflog.Info(ctx, "Deleting Keyfactor Security Role resource")
//
//	kfClient := m.(*api.Client)
//
//	id := d.Id()
//	roleId, err := strconv.Atoi(id)
//	ctx = tflog.SetField(ctx, "role_id", roleId)
//	if err != nil {
//		tflog.Error(ctx, "Error deleting Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		return diag.FromErr(err)
//	}
//
//	err = kfClient.DeleteSecurityRole(roleId)
//	if err != nil {
//		tflog.Error(ctx, "Error deleting Keyfactor Security Role resource: ", map[string]interface{}{
//			"error": err,
//		})
//		return diag.FromErr(err)
//	}
//
//	return diags
//}
