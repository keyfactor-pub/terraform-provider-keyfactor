package keyfactor

/*
 * Resource designed to add one certificate to one or many certificate stores
 */

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
)

func resourceCertificateDeploy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceDeploymentCreate,
		ReadContext:   resourceDeploymentRead,
		UpdateContext: resourceDeploymentUpdate,
		DeleteContext: resourceDeploymentDelete,
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
							Description: "A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type.",
						},
					},
				},
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password that protects PFX certificate, if the certificate was enrolled using PFX enrollment, or is password protected in general. This value cannot change, and Terraform will throw an error if a change is attempted.",
			},
		},
	}
}

func resourceDeploymentCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	conn := m.(*keyfactor.Client)

	certId := d.Get("certificate_id").(int)

	err := setCertificatesInStore(conn, d)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.Itoa(certId))

	return resourceDeploymentRead(ctx, d, m)
}

// addCertificateToStore adds certificate certId to each of the stores configured by stores. Note that stores is a list of
// map[string]interface{} and contains the required configuration for keyfactor.AddCertificateToStores().
func addCertificateToStores(conn *keyfactor.Client, certId int, stores []interface{}, password string) error {
	var storesStruct []keyfactor.CertificateStore
	if len(stores) <= 0 {
		return nil
	}

	for _, store := range stores {
		i := store.(map[string]interface{})
		temp := new(keyfactor.CertificateStore)

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
	schedule := &keyfactor.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &keyfactor.AddCertificateToStore{
		CertificateId:     certId,
		CertificateStores: nil,
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
func removeCertificateAliasFromStore(conn *keyfactor.Client, certificateStores *[]keyfactor.CertificateStore) error {
	// We want Keyfactor to immediately apply these changes.
	schedule := &keyfactor.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &keyfactor.RemoveCertificateFromStore{
		CertificateStores: certificateStores,
		InventorySchedule: schedule,
	}

	_, err := conn.RemoveCertificateFromStores(config)
	if err != nil {
		return err
	}
	return nil
}

func setCertificatesInStore(conn *keyfactor.Client, d *schema.ResourceData) error {
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
	args := &keyfactor.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certId,
	}
	certificateData, err := conn.GetCertificateContext(args)
	if err != nil {
		return err
	}
	locations := certificateData.Locations
	list := make(map[string]struct{}, len(stores))
	for _, x := range stores {
		i := x.(map[string]interface{})
		list[i["certificate_store_id"].(string)] = struct{}{}
	}
	for i, x := range locations {
		if _, found := list[x.CertStoreId]; found {
			locations = append(locations[:i], locations[i+1:]...)
		}
	}

	// Now, locations contains a list of stores that the certificate should be REMOVED from.
	if len(locations) > 0 {
		var remove []keyfactor.CertificateStore
		for _, location := range locations {
			temp := keyfactor.CertificateStore{
				CertificateStoreId: location.CertStoreId,
				Alias:              location.Alias,
			}
			remove = append(remove, temp)
		}

		err = removeCertificateAliasFromStore(conn, &remove)
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceDeploymentRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := m.(*keyfactor.Client)

	certId, err := strconv.Atoi(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	// Then, compile a list of stores that the certificate is found in, and figure out the delta
	args := &keyfactor.GetCertificateContextArgs{
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

func flattenLocationData(certId int, password string, locations []keyfactor.CertificateLocations) map[string]interface{} {
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

func flattenStoresData(locations []keyfactor.CertificateLocations) *schema.Set {
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
	conn := m.(*keyfactor.Client)

	if d.HasChange("stores") {
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
	conn := m.(*keyfactor.Client)

	// Set 'stores' schema with blank set.
	err := d.Set("stores", schema.Set{F: schema.HashInt})
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
