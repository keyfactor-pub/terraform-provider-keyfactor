package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strconv"
	"strings"
)

func resourceSecurityIdentity() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSecurityIdentityCreate,
		ReadContext:   resourceSecurityIdentityRead,
		UpdateContext: resourceSecurityIdentityUpdate,
		DeleteContext: resourceSecurityIdentityDelete,
		Schema: map[string]*schema.Schema{
			"security_identity": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"account_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name",
						},
						"roles": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "An array containing the roles that the identity is attached to.",
							Elem:        &schema.Schema{Type: schema.TypeInt},
						},
						"id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "An integer containing the Keyfactor Command identifier for the security identity.",
						},
						"identity_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "A string indicating the type of identity—User or Group.",
						},
						"valid": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "A Boolean that indicates whether the security identity's audit XML is valid (true) or not (false). A security identity may become invalid if Keyfactor Command determines that it appears to have been tampered with.",
						},
					},
				},
			},
		},
	}
}

func resourceSecurityIdentityCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClient := m.(*keyfactor.Client)

	log.Println("[INFO] Creating Keyfactor security identity resource")

	securityIdentities := d.Get("security_identity").([]interface{})
	for _, identity := range securityIdentities {
		i := identity.(map[string]interface{})

		identityArg := &keyfactor.CreateSecurityIdentityArg{
			AccountName: i["account_name"].(string),
		}

		createResponse, err := kfClient.CreateSecurityIdentity(identityArg)
		if err != nil {
			resourceSecurityIdentityRead(ctx, d, m)
			return diag.FromErr(err)
		}

		// Keyfactor security roles are often created once at the beginning of a deployment and then subsequently used
		// to regulate an identities access to a resource. As per customer request, the Terraform provider modifies
		// the intended use of the roles element returned by the identities endpoint by making it non-readonly.
		// Accomplish this by attaching the identity to each role provided by Terraform configuration
		roles := i["roles"].([]interface{})
		err = setIdentityRole(kfClient, identityArg.AccountName, roles)
		if err != nil {
			return diag.FromErr(err)
		}

		// Set resource ID to tell Terraform that operation was successful
		d.SetId(strconv.Itoa(createResponse.Id))
		resourceSecurityIdentityRead(ctx, d, m)
	}

	return diags
}

func setIdentityRole(kfClient *keyfactor.Client, identityAccountName string, roleIds []interface{}) error {
	// Basic idea here is that we want to sync the output of the GET identity endpoint with the roleIds passed to
	// this function. This could mean that we are removing the identity from a role, adding an identity, or not making
	// any change. This is required because no PUT endpoint exists for /identity.

	// Start by blindly adding the identity to each role.
	if len(roleIds) > 0 {
		for _, role := range roleIds {
			err := addIdentityToRole(kfClient, identityAccountName, role.(int))
			if err != nil {
				return err
			}
		}
	}

	// Then, build a list of all roles associated with the identity and make sure that only the ones specified by
	// this function are added.
	// Get all Keyfactor security identities
	identities, err := kfClient.GetSecurityIdentities()
	if err != nil {
		return err
	}
	var identity keyfactor.GetSecurityIdentityResponse
	for _, identity = range identities {
		if strings.ToLower(identity.AccountName) == strings.ToLower(identityAccountName) {
			break
		}
	}

	// Now, build a list of the roles associated with the identity. Note that any differences found here will be removals
	// because we already added the roles that we want above. The below method doesn't require the slices to be sorted,
	// and operates at approximately O(n)

	list := make(map[string]struct{}, len(roleIds))
	for _, x := range roleIds {
		list[strconv.Itoa(x.(int))] = struct{}{}
	}
	var diff []int
	for _, x := range identity.Roles {
		if _, found := list[strconv.Itoa(x.Id)]; !found {
			diff = append(diff, x.Id)
		}
	}

	for _, role := range diff {
		err = removeIdentityFromRole(kfClient, identity.AccountName, role)
		if err != nil {
			return err
		}
	}
	return nil
}

func removeIdentityFromRole(kfClient *keyfactor.Client, identityAccountName string, roleId int) error {
	log.Printf("[DEBUG] Removing account %s from Keyfactor role %d", identityAccountName, roleId)
	// Construct a list of security identities currently attached to role
	role, err := kfClient.GetSecurityRole(roleId)
	if err != nil {
		return err
	}
	var identityList []keyfactor.SecurityRoleIdentityConfig
	for _, identity := range role.Identities {
		if strings.ToLower(identityAccountName) != strings.ToLower(identity.AccountName) {
			temp := keyfactor.SecurityRoleIdentityConfig{
				AccountName: identity.AccountName,
			}
			identityList = append(identityList, temp)
		}
	}

	// Note - update security role wraps the create role structure but compiles to the desired JSON request body.
	updateArg := &keyfactor.UpdatteSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: keyfactor.CreateSecurityRoleArg{
			Name:        role.Name,
			Identities:  &identityList,
			Description: role.Description,
			Permissions: &role.Permissions,
		},
	}

	_, err = kfClient.UpdateSecurityRole(updateArg)
	if err != nil {
		return err
	}

	return nil
}

func addIdentityToRole(kfClient *keyfactor.Client, identityAccountName string, roleId int) error {
	log.Printf("[DEBUG] Adding account %s to Keyfactor role %d", identityAccountName, roleId)
	// Construct a list of security identities currently attached to role
	role, err := kfClient.GetSecurityRole(roleId)
	if err != nil {
		return err
	}

	identityList := make([]keyfactor.SecurityRoleIdentityConfig, len(role.Identities), len(role.Identities))
	for i, identity := range role.Identities {
		if identity.AccountName == identityAccountName {
			log.Printf("[DEBUG] Account %s is already associated with Keyfactor role %d", identityAccountName, roleId)
			return nil
		}
		temp := keyfactor.SecurityRoleIdentityConfig{
			AccountName: identity.AccountName,
		}
		identityList[i] = temp
	}

	// Add new identity to identity list and update role
	temp := keyfactor.SecurityRoleIdentityConfig{
		AccountName: identityAccountName,
	}
	identityList = append(identityList, temp)

	// Note - update security role wraps the create role structure but compiles to the desired JSON request body.
	updateArg := &keyfactor.UpdatteSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: keyfactor.CreateSecurityRoleArg{
			Name:        role.Name,
			Identities:  &identityList,
			Description: role.Description,
			Permissions: &role.Permissions,
		},
	}

	_, err = kfClient.UpdateSecurityRole(updateArg)
	if err != nil {
		return err
	}

	return nil
}

func resourceSecurityIdentityRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	var identityContext keyfactor.GetSecurityIdentityResponse

	log.Println("[INFO] Read called on security identity resource")

	kfClient := m.(*keyfactor.Client)

	// Get all Keyfactor security identities
	identities, err := kfClient.GetSecurityIdentities()
	if err != nil {
		return diag.FromErr(err)
	}

	Id := d.Id()
	identityId, err := strconv.Atoi(Id)
	if err != nil {
		return diag.FromErr(err)
	}

	// Isolate the identity associated with resource
	for _, identity := range identities {
		if identity.Id == identityId {
			identityContext = identity
		}
	}

	// Set schema values
	if err := d.Set("security_identity", flattenSecurityIdentity(&identityContext)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func flattenSecurityIdentity(identityContext *keyfactor.GetSecurityIdentityResponse) []interface{} {
	if identityContext != nil {
		temp := make([]interface{}, 1, 1)
		data := make(map[string]interface{})

		// Create list of identities
		var rolesList []int
		for _, role := range identityContext.Roles {
			rolesList = append(rolesList, role.Id)
		}

		// Assign response data to associated schema
		data["account_name"] = identityContext.AccountName
		data["roles"] = rolesList
		data["id"] = identityContext.Id
		data["identity_type"] = identityContext.IdentityType
		data["valid"] = identityContext.Valid

		temp[0] = data
		return temp
	}
	return make([]interface{}, 0)
}

func resourceSecurityIdentityUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClient := m.(*keyfactor.Client)
	log.Println("[INFO] Update called on security identity resource")

	if roleSchemaHasChange(d) == true {
		securityIdentities := d.Get("security_identity").([]interface{})
		for _, identity := range securityIdentities {
			i := identity.(map[string]interface{})

			// Keyfactor security roles are often created once at the beginning of a deployment and then subsequently used
			// to regulate an identities access to a resource. As per customer request, the Terraform provider modifies
			// the intended use of the roles element returned by the identities endpoint by making it non-readonly.
			// Accomplish this by attaching the identity to each role provided by Terraform configuration
			roles := i["roles"].([]interface{})
			err := setIdentityRole(kfClient, i["account_name"].(string), roles)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Update is not supported for the Keyfactor Security Identity resource unless the policy attribute was changed.",
			Detail:   "To update this resource, please delete the current resource and create a new one.",
		})
	}

	resourceSecurityIdentityRead(ctx, d, m)
	return diags
}

func roleSchemaHasChange(d *schema.ResourceData) bool {
	roleRootSearchTerm := "security_identity.0.roles"
	// Most obvious change to detect is the number of policy schema blocks changed.

	if d.HasChange(fmt.Sprintf("%s.#", roleRootSearchTerm)) == true {
		return true
	}

	// Next, for each element, attempt to detect a change.
	// todo if something is broken, this is probably where it broke
	roleCount := d.Get(fmt.Sprintf("%s.#", roleRootSearchTerm))
	for i := 0; i < roleCount.(int); i++ {
		if d.HasChange(fmt.Sprintf("%s.%d", roleRootSearchTerm, i)) {
			return true
		}
	}

	// If we got this far, it's safe to assume that we didn't experience a change.
	return false
}

func resourceSecurityIdentityDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	log.Println("[INFO] Deleting Keyfactor security identity resource")

	kfClient := m.(*keyfactor.Client)

	securityIdentities := d.Get("security_identity").([]interface{})
	for _, identity := range securityIdentities {
		i := identity.(map[string]interface{})

		err := kfClient.DeleteSecurityIdentity(i["id"].(int))
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}
