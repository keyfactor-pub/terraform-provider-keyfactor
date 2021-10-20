package keyfactor

import (
	"context"
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
			"container_id": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Container identifier of the store's associated certificate store container",
			},
		},
	}
}

func resourceStoreCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
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
