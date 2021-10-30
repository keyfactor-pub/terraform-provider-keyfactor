package keyfactor

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"keyfactor-go-client/pkg/keyfactor"
	"log"
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
						"properties_json": &schema.Schema{
							Type:        schema.TypeList,
							Required:    true,
							Description: "JSON key-value pair strings representing the properties for the specified certificate store",
							Elem:        &schema.Schema{Type: schema.TypeString},
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
						"reenrollment_status": &schema.Schema{
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Configures the re-enrollnent function with accompanying data",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"data": &schema.Schema{
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Indicates whether the certificate store can use the re-enrollment function",
									},
									"agent_id": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "String indicating the Keyfactor Command GUID of the orchestrator that can re-enroll the store",
									},
									"message": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Reason the certificate store cannot reenroll, if applicable",
									},
									"job_properties": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of key-value pairs as strings for the unique parameters defined for store type",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"custom_alias_allowed": &schema.Schema{
										Type:        schema.TypeInt,
										Optional:    true,
										Description: "An integer indicating the option for a custom alias for this certificate store",
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
					},
				},
			},
		},
	}
}

func resourceStoreCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	stores := d.Get("store").([]interface{})

	for _, store := range stores {
		i := store.(map[string]interface{})
		newStoreArgs := &keyfactor.CreateStoreFctArgs{
			ContainerId:     i["container_id"].(int),
			ClientMachine:   i["client_machine"].(string),
			StorePath:       i["store_path"].(string),
			CertStoreType:   i["cert_store_type"].(int),
			Approved:        i["approved"].(bool),
			CreateIfMissing: i["create_if_missing"].(bool),
		}
		log.Printf("args: %d", newStoreArgs.ContainerId)
	}
	// CertStoreInventoryJobId: i["cert_store_inventory_job_id"].(string),
	return diags
}

func resourceStoreRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceStoreUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceStoreDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}
