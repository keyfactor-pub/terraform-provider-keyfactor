package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDeploy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceDeploymentCreate,
		ReadContext:   resourceDeploymentRead,
		UpdateContext: resourceDeploymentUpdate,
		DeleteContext: resourceDeploymentDelete,
		Schema: map[string]*schema.Schema{
			"deployment": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "PFX certificate deployment options. Specify at least one certificate store to deploy into",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"keyfactor_certificate_id": {
							Type:        schema.TypeInt,
							Required:    true,
							Description: "Keyfactor certificate ID",
						},
						"keyfactor_request_id": {
							Type:        schema.TypeInt,
							Required:    true,
							Description: "Keyfactor PFX certificate request ID from enrollment job. This is the same field computed by create certificate method.",
						},
						"key_password": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Password used to protect certificate private key",
						},
						"store_ids": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of store IDs to deploy PFX certificate into",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"store_type_ids": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of store IDs to deploy PFX certificate into",
							Elem:        &schema.Schema{Type: schema.TypeInt},
						},
						"alias": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "Alias that certificate will be stored under in new certificate",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
		},
	}
}

func resourceDeploymentCreate(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClientData := m.(*keyfactor.Client)

	deployment := d.Get("deployment").([]interface{})

	// If deployment options were provided by user, deploy the certificate
	for _, deploy := range deployment {
		i := deploy.(map[string]interface{})

		// Extract store IDs, alias', and store type IDs from Schema. The length of these should be equal
		storeIdsInterface := i["store_ids"].([]interface{})
		aliasInterface := i["alias"].([]interface{})
		storeTypeIdsInterface := i["store_type_ids"].([]interface{})

		// Check if the correct number of arguments were specified to deploy the certificate (should all be equal)
		if len(storeIdsInterface) != len(aliasInterface) || len(aliasInterface) != len(storeTypeIdsInterface) {
			deployFailureString := fmt.Sprintf("Store IDs provided: %d - Store alias' provided: %d - Store type IDs provided: %d", len(storeIdsInterface), len(aliasInterface), len(storeTypeIdsInterface))
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Not enough information provided to deploy certificate.",
				Detail:   deployFailureString,
			})
			// Just becuase we failed to deploy doesn't mean that the create failed.
		} else {
			// Build []string of store IDs from interface

			deployStoreIds := make([]string, len(storeIdsInterface), len(storeIdsInterface))
			for i, id := range storeIdsInterface {
				deployStoreIds[i] = id.(string)
			}

			// Build []string of alias' from interface
			aliasArray := make([]string, len(aliasInterface), len(aliasInterface))
			for i, alias := range aliasInterface {
				aliasArray[i] = alias.(string)
			}

			// Build []StoreTypes of store type from interface
			storeTypes := make([]keyfactor.StoreTypes, len(storeTypeIdsInterface), len(storeTypeIdsInterface))
			for i, id := range storeTypeIdsInterface {
				storeTypes[i] = keyfactor.StoreTypes{
					StoreTypeId: id.(int),
					Alias:       stringToPointer(aliasArray[i]),
				}
			}

			deployPFXArgs := &keyfactor.DeployPFXArgs{
				StoreIds:      deployStoreIds,
				Password:      i["key_password"].(string),
				StoreTypes:    storeTypes,
				CertificateId: i["keyfactor_id"].(int),
				RequestId:     i["keyfactor_request_id"].(int),
				JobTime:       nil,
			}

			deployResp, err := kfClientData.DeployPFXCertificate(deployPFXArgs)
			if err != nil {
				return diag.FromErr(err)
			}

			if len(deployResp.FailedStores) != 0 {
				var failedStoresString string

				for _, failedStore := range deployResp.FailedStores {
					failedStoresString += failedStore + ", "
				}

				diags = append(diags, diag.Diagnostic{
					Severity: diag.Warning,
					Summary:  "Failed to deploy to one or more certificate stores",
					Detail:   failedStoresString,
				})
			}
		}
	}

	return diags
}

func resourceDeploymentRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceDeploymentUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceDeploymentDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}
