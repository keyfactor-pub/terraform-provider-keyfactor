package keyfactor

/*
 * Resource designed to add one certificate to one or many certificate stores
 */

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/spbsoluble/kfctl/api"
	"strconv"
	"time"
)

func resourceCertificateDeploy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceDeploymentCreate,
		ReadContext:   resourceDeploymentRead,
		UpdateContext: resourceDeploymentUpdate,
		DeleteContext: resourceDeploymentDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"certificate_id": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Keyfactor certificate ID",
			},
			"store": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of certificates stores that the certificate should be deployed into.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"certificate_store_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "A string containing the GUID for the certificate store to which the certificate should be added.",
						},
						"alias": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type. Please ensure that the alias is lowercase, or problems can arise in Terraform Plan.",
						},
					},
				},
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Password that protects PFX certificate, if the certificate was enrolled using PFX enrollment, or is password protected in general. This value cannot change, and Terraform will throw an error if a change is attempted.",
			},
		},
	}
}

func resourceDeploymentCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	conn := m.(*api.Client)

	certId := d.Get("certificate_id").(int)

	err := setCertificatesInStore(conn, d)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.Itoa(certId))

	return resourceDeploymentRead(ctx, d, m)
}

// addCertificateToStore adds certificate certId to each of the stores configured by stores. Note that stores is a list of
// map[string]interface{} and contains the required configuration for api.AddCertificateToStores().
func addCertificateToStores(conn *api.Client, certId int, stores []interface{}, password string) error {
	var storesStruct []api.CertificateStore
	if len(stores) <= 0 {
		return nil
	}

	for _, store := range stores {
		i := store.(map[string]interface{})
		temp := new(api.CertificateStore)

		id, ok := i["certificate_store_id"]
		if ok {
			temp.CertificateStoreId = id.(string)
		}
		alias, ok := i["alias"]
		if ok {
			temp.Alias = alias.(string)
		}
		temp.IncludePrivateKey = true
		temp.Overwrite = true
		temp.PfxPassword = password
		storesStruct = append(storesStruct, *temp)
	}
	// We want Keyfactor to immediately apply these changes.
	schedule := &api.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &api.AddCertificateToStore{
		CertificateId:     certId,
		CertificateStores: &storesStruct,
		InventorySchedule: schedule,
	}
	_, err := conn.AddCertificateToStores(config)
	if err != nil {
		return err
	}

	return nil
}

// The Keyfactor RemoveCertificateFromStores function works by removing a certificate stored under a specific alias in a store.
// The certificateStores argument must contain a list of Keyfactor CertificateStore structs configured with a store ID and
// the alias name that the certificate is stored under.
func removeCertificateAliasFromStore(conn *api.Client, certificateStores *[]api.CertificateStore) error {
	// We want Keyfactor to immediately apply these changes.
	schedule := &api.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &api.RemoveCertificateFromStore{
		CertificateStores: certificateStores,
		InventorySchedule: schedule,
	}

	_, err := conn.RemoveCertificateFromStores(config)
	if err != nil {
		return err
	}

	return nil
}

// Return elements in 'a' that aren't in 'b'
func findStringDifference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func validateCertificatesInStore(conn *api.Client, certificateStores []string, certificateId int) error {
	valid := false
	for i := 0; i < 1200; i++ {
		args := &api.GetCertificateContextArgs{
			IncludeLocations: boolToPointer(true),
			Id:               certificateId,
		}
		certificateData, err := conn.GetCertificateContext(args)
		if err != nil {
			return err
		}
		storeList := make([]string, len(certificateData.Locations))
		for j, store := range certificateData.Locations {
			storeList[j] = store.CertStoreId
		}

		if len(findStringDifference(certificateStores, storeList)) == 0 && len(findStringDifference(storeList, certificateStores)) == 0 {
			valid = true
			break
		}

		time.Sleep(2 * time.Second)
	}
	if !valid {
		return fmt.Errorf("validateCertificatesInStore timed out. certificate could deploy eventually, but terraform change operation will fail. run terraform plan later to verify that the certificate was deployed successfully")
	}
	return nil
}

func setCertificatesInStore(conn *api.Client, d *schema.ResourceData) error {
	certId := d.Get("certificate_id").(int)
	stores := d.Get("store").(*schema.Set).List()
	password := d.Get("password").(string)

	if len(stores) > 0 {
		// First, blindly add the certificate to each of the certificate stores found in storeList.
		err := addCertificateToStores(conn, certId, stores, password)
		if err != nil {
			return err
		}
	}

	// Then, compile a list of stores that the certificate is found in, and figure out the delta
	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certId,
	}
	certificateData, err := conn.GetCertificateContext(args)
	if err != nil {
		return err
	}
	locations := certificateData.Locations
	expectedStores := make([]string, len(stores))

	// Want to find the elements in locations that are not in stores
	// We also want to retain the alias
	list := make(map[string]struct{}, len(stores))
	for i, x := range stores {
		j := x.(map[string]interface{})

		storeId := j["certificate_store_id"].(string)
		list[storeId] = struct{}{}

		// Since we're already looping through the store IDs, place them in a more readable data structre for later use
		expectedStores[i] = storeId
	}

	// The elements of diff should be removed
	// Also, removing a certificate from a certificate store implies that the certificate is currently in the store.
	var diff []api.CertificateStore
	for _, x := range locations {
		if _, found := list[x.CertStoreId]; !found {
			temp := api.CertificateStore{
				CertificateStoreId: x.CertStoreId,
				Alias:              x.Alias,
			}
			diff = append(diff, temp)
		}
	}

	if len(diff) > 0 {
		err = removeCertificateAliasFromStore(conn, &diff)
		if err != nil {
			return err
		}
	}

	// Finally, Keyfactor tends to take a hot second to enact these changes despite being told to make them immediately.
	// Block for a long time until the changes are validated.
	err = validateCertificatesInStore(conn, expectedStores, certId)
	if err != nil {
		return err
	}

	return nil
}

func resourceDeploymentRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := m.(*api.Client)

	certId, err := strconv.Atoi(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	// Then, compile a list of stores that the certificate is found in, and figure out the delta
	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certId,
	}
	certificateData, err := conn.GetCertificateContext(args)
	if err != nil {
		return diag.FromErr(err)
	}
	locations := certificateData.Locations

	password := d.Get("password").(string)

	newSchema := flattenLocationData(certId, password, locations)
	for key, value := range newSchema {
		err = d.Set(key, value)
		if err != nil {
			diags = append(diags, diag.FromErr(err)[0])
		}
	}

	return diags
}

func flattenLocationData(certId int, password string, locations []api.CertificateLocations) map[string]interface{} {
	data := make(map[string]interface{})
	data["certificate_id"] = certId
	data["password"] = password
	data["store"] = flattenStoresData(locations)
	return data
}

func schemaCertificateDeployStores() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"certificate_store_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A string containing the GUID for the certificate store to which the certificate should be added.",
			},
			"alias": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type.",
			},
		},
	}
}

func flattenStoresData(locations []api.CertificateLocations) *schema.Set {
	var temp []interface{}
	if len(locations) > 0 {
		for _, location := range locations {
			data := make(map[string]interface{})
			data["certificate_store_id"] = location.CertStoreId
			data["alias"] = location.Alias
			temp = append(temp, data)
		}
	}
	return schema.NewSet(schema.HashResource(schemaCertificateDeployStores()), temp)
}

func resourceDeploymentUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	conn := m.(*api.Client)

	if d.HasChange("store") {
		err := setCertificatesInStore(conn, d)
		if err != nil {
			return diag.FromErr(err)
		}
	} else {
		var diags diag.Diagnostics
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Failed to update deployment resource. Invalid schema",
			Detail: "The only supported update field is stores, since password and certificate ID are both configuration" +
				"used to facilitate the addition/removal of the certificate to each of the stores specified in 'stores'.",
			AttributePath: nil,
		})
		resourceDeploymentRead(ctx, d, m)
		return diags
	}

	return resourceDeploymentRead(ctx, d, m)
}

func resourceDeploymentDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	conn := m.(*api.Client)

	// Set 'stores' schema with blank set.
	empty := schema.NewSet(schema.HashResource(schemaCertificateDeployStores()), nil)
	err := d.Set("store", empty)
	if err != nil {
		return diag.FromErr(err)
	}

	// Call setCertificatesInStore, which will match Keyfactor store configuration to schema 'd', which
	// contains an empty list of stores.
	err = setCertificatesInStore(conn, d)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceDeploymentRead(ctx, d, m)
}
