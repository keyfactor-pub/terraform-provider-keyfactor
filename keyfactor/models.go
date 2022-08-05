package keyfactor

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Security Identity -
type SecurityIdentity struct {
	ID           types.Int64  `tfsdk:"identity_id"`
	AccountName  types.String `tfsdk:"account_name"`
	Roles        []Role       `tfsdk:"roles"`
	IdentityType types.String `tfsdk:"identity_type"`
	Valid        types.Bool   `tfsdk:"valid"`
}

// Role -
type Role struct {
	Name types.String `tfsdk:"role_name"`
}
