package keyfactor

import (
	"context"
	"log"

	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceStore() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceStoreCreate,
		ReadContext:   resourceStoreRead,
		UpdateContext: resourceStoreUpdate,
		DeleteContext: resourceStoreDelete,
		Schema: map[string]*schema.Schema{
			"store": &schema.Schema{
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"container_id": &schema.Schema{
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Container identifier of the store's associated certificate store container.",
						},
						"client_machine": &schema.Schema{
							Type:        schema.TypeString,
							Required:    true,
							Description: "Client machine name; value depends on certificate store type. See API reference guide",
						},
						"store_path": &schema.Schema{
							Type:        schema.TypeString,
							Required:    true,
							Description: "Path to the new certificate store on a target. Format varies depending on type.",
						},
						"cert_store_inventory_job_id": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Description: "GUID identifying the inventory job for the certificate store. Null if inventory is not configured",
						},
						"cert_store_type": &schema.Schema{
							Type:        schema.TypeInt,
							Required:    true,
							Description: "Integer specifying the store type. Specific types require different parameters.",
						},
						"approved": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Bool that indicates the approval status of store created. Default is true, omit if unsure",
						},
						"create_if_missing": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Bool that indicates if the store should be created with information provided. Valid only for JKS type, omit if unsure",
						},
						"property": &schema.Schema{
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Certificate properties specific to certificate store type",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Name of property field required by certificate store",
									},
									"value": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Property value",
									},
								},
							},
						},
						"agent_id": &schema.Schema{
							Type:        schema.TypeString,
							Required:    true,
							Description: "String indicating the Keyfactor Command GUID of the orchestrator for the created store",
						},
						"agent_assigned": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Bool indicating if there is an orchestrator assigned to the new certificate store",
						},
						"container_name": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Name of certificate store's associated container, if applicable",
						},
						"inventory_schedule": &schema.Schema{
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "Inventory schedule for new certificate store",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"immediate": &schema.Schema{
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Boolean that indicates whether the job should run immediately",
									},
									"interval": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Indicates that the job should be scheduled to run every x minutes",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"minutes": &schema.Schema{
													Type:        schema.TypeInt,
													Required:    true,
													Description: "An integer indicating the number of minutes between each interval",
												},
											},
										},
									},
									"daily": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Indicates that the job should be scheduled to run every day at the same time",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"time": &schema.Schema{
													Type:        schema.TypeString,
													Required:    true,
													Description: "The date and time to next run the job. The date and time should be given using the ISO 8601 UTC time format",
												},
											},
										},
									},
									"exactly_once": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Indicates that the job should be scheduled to run at the time specified",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"time": &schema.Schema{
													Type:        schema.TypeString,
													Required:    true,
													Description: "The date and time to next run the job. The date and time should be given using the ISO 8601 UTC time format",
												},
											},
										},
									},
								},
							},
						},
						"set_new_password_allowed": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Indicates whether the store password can be changed",
						},
						"password": &schema.Schema{
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "Configures credential options for certificate store",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"value": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Configures a password to be stored a Keyfactor secret",
									},
								},
							},
						},
						"keyfactor_id": &schema.Schema{
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Keyfactor certificate store GUID",
						},
					},
				},
			},
		},
	}
}

func resourceStoreCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClientData := m.(*keyfactor.APIClient)

	stores := d.Get("store").([]interface{})
	for _, store := range stores {
		i := store.(map[string]interface{})
		properties := i["property"].([]interface{})
		newStoreArgs := &keyfactor.CreateStoreFctArgs{
			ContainerId:             intToPointer(i["container_id"].(int)),
			ClientMachine:           i["client_machine"].(string),
			StorePath:               i["store_path"].(string),
			CertStoreInventoryJobId: stringToPointer(i["cert_store_inventory_job_id"].(string)),
			CertStoreType:           i["cert_store_type"].(int),
			Approved:                boolToPointer(i["approved"].(bool)),
			CreateIfMissing:         boolToPointer(i["create_if_missing"].(bool)),
			Properties:              interfaceArrayToStringTuple(properties),
			AgentId:                 i["agent_id"].(string),
			AgentAssigned:           boolToPointer(i["agent_assigned"].(bool)),
			ContainerName:           stringToPointer(i["container_name"].(string)),
			InventorySchedule:       createInventorySchedule(i["inventory_schedule"].([]interface{})),
			SetNewPasswordAllowed:   boolToPointer(i["set_new_password_allowed"].(bool)),
			Password:                createPasswordConfig(i["password"].([]interface{})),
		}

		createResp, err := keyfactor.CreateStore(newStoreArgs, kfClientData)
		if err != nil {
			return diag.FromErr(err)
		}

		// Set resource ID to certificate ID
		d.SetId(createResp.Id)

		// Call read function to update schema with new state
		resourceStoreRead(ctx, d, m)
	}

	return diags
}

func createInventorySchedule(m []interface{}) *keyfactor.InventorySchedule {
	// todo Map []interface{} to keyfactor.InventorySchedule4
	inventorySchedule := &keyfactor.InventorySchedule{}
	i := m[0].(map[string]interface{})
	for key, value := range i {
		if key == "immediate" {
			if value == true {
				inventorySchedule.Immediate = boolToPointer(value.(bool))
				return inventorySchedule
			}
			// If the value isn't true, the user probably didn't specify immediate interval. Next!
		} else {
			// Expecting EITHER daily/exactly_once/interval. Element found if/when length of inner array > 0
			temp := value.([]interface{})
			if len(temp) > 0 {
				// We don't know what the key/value will be for element. Use a for loop to iterate
				// Return from if statement is found. This prevents user from inputting multiple
				for _, innerValue := range temp[0].(map[string]interface{}) {
					if key == "interval" {
						interval := &keyfactor.InventoryInterval{Minutes: innerValue.(int)}
						inventorySchedule.Interval = interval
						return inventorySchedule
					}
					if key == "daily" {
						daily := &keyfactor.InventoryDaily{Time: innerValue.(string)}
						inventorySchedule.Daily = daily
						return inventorySchedule
					}
					if key == "exactly_once" {
						once := &keyfactor.InventoryOnce{Time: innerValue.(string)}
						inventorySchedule.ExactlyOnce = once
						return inventorySchedule
					}
				}
			}
		}
	}
	return inventorySchedule
}

func createPasswordConfig(m []interface{}) *keyfactor.StorePasswordConfig {
	password := stringToPointer(m[0].(map[string]interface{})["value"].(string))
	res := &keyfactor.StorePasswordConfig{
		Value: password,
	}

	return res
}

func resourceStoreRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	kfClientData := m.(*keyfactor.APIClient)

	var diags diag.Diagnostics
	storeId := d.Id()

	storeData, err := keyfactor.GetCertificateStoreByID(storeId, kfClientData)
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the password out of current schema
	schemaState := d.Get("store").([]interface{})
	// Extract the password schema from current stored schema and pass it right back
	password := schemaState[0].(map[string]interface{})["password"].([]interface{})

	storeItems := flattenCertificateStoreItems(storeData, password)
	if err := d.Set("store", storeItems); err != nil {
		return diag.FromErr(err)
	}
	return diags
}

func flattenCertificateStoreItems(storeContext *keyfactor.GetStoreByIDResp, password []interface{}) []interface{} {
	if storeContext != nil {
		data := make(map[string]interface{})

		// Assign response data to associated schema
		data["keyfactor_id"] = storeContext.Id
		data["container_id"] = storeContext.ContainerId
		data["client_machine"] = storeContext.ClientMachine
		data["store_path"] = storeContext.StorePath
		data["cert_store_inventory_job_id"] = storeContext.CertStoreInventoryJobId
		data["cert_store_type"] = storeContext.CertStoreType
		data["approved"] = storeContext.Approved
		data["create_if_missing"] = storeContext.CreateIfMissing
		data["agent_id"] = storeContext.AgentId
		data["agent_assigned"] = storeContext.AgentAssigned
		data["container_name"] = storeContext.ContainerName
		data["set_new_password_allowed"] = storeContext.SetNewPasswordAllowed

		// Assign schema that require flattening
		data["property"] = flattenCertificateStoreProperty(storeContext.Properties)
		data["inventory_schedule"] = flattenCertificateStoreInventorySched(storeContext.InventorySchedule)
		data["password"] = password

		temp := make([]interface{}, 1, 1)
		temp[0] = data
		return temp
	}

	return make([]interface{}, 0)
}

func flattenCertificateStoreProperty(properties []keyfactor.StringTuple) []interface{} {
	if len(properties) > 0 {
		var propertiesArray []interface{}
		for _, property := range properties {
			temp := make(map[string]interface{})

			temp["name"] = property.Elem1
			temp["value"] = property.Elem2

			propertiesArray = append(propertiesArray, temp)
		}
		return propertiesArray
	}

	return make([]interface{}, 0)
}

func flattenCertificateStoreInventorySched(schedule keyfactor.InventorySchedule) []interface{} {
	medium := make(map[string]interface{})
	// Structure being constructed:
	// 	inventory_schedule -> []interface{} (1 wide)
	//      interval/daily/exactly_once -> []interface{} (1 wide)
	// 		    minutes/time -> map[string]interface{}

	// Build medium and inner layers
	// Immediate schedule has no child structure
	if schedule.Immediate != nil {
		medium["immediate"] = schedule.Immediate
	} else {
		tempArray := make([]interface{}, 1, 1)
		tempMap := make(map[string]interface{})
		// Build inner layers
		if schedule.Daily != nil {
			tempMap["time"] = schedule.Daily.Time
			tempArray[0] = tempMap
			medium["daily"] = tempArray
		} else if schedule.ExactlyOnce != nil {
			tempMap["time"] = schedule.ExactlyOnce.Time
			tempArray[0] = tempMap
			medium["exactly_once"] = tempArray
		} else if schedule.Interval != nil {
			tempMap["minutes"] = schedule.Interval.Minutes
			tempArray[0] = tempMap
			medium["interval"] = tempArray
		} else {
			// If the API returned nothing, return a blank slice
			return make([]interface{}, 0, 0) // Return blank array if none
		}

	}
	// Append medium layer to outer
	scheduleInterface := make([]interface{}, 1, 1)
	scheduleInterface[0] = medium
	return scheduleInterface
}

func resourceStoreUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceStoreDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClientData := m.(*keyfactor.APIClient)

	log.Println("[INFO] Deleting certificate resource")

	stores := d.Get("store").([]interface{})

	for _, store := range stores {
		i := store.(map[string]interface{})
		id := i["keyfactor_id"].(string)
		log.Printf("[INFO] Deleting certificate store with ID %s in Keyfactor", id)

		err := keyfactor.DeleteCertificateStore(id, kfClientData)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}
