package keyfactor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// attr.Type maps used to build types.Object values at read time.
var certStoreTypePropAttrTypes = map[string]attr.Type{
	"name":          types.StringType,
	"display_name":  types.StringType,
	"type":          types.StringType,
	"depends_on":    types.StringType,
	"default_value": types.StringType,
	"required":      types.BoolType,
}

var certStoreTypeEntryParamAttrTypes = map[string]attr.Type{
	"name":                          types.StringType,
	"display_name":                  types.StringType,
	"type":                          types.StringType,
	"depends_on":                    types.StringType,
	"default_value":                 types.StringType,
	"options":                       types.StringType,
	"required_when_has_private_key": types.BoolType,
	"required_when_on_add":          types.BoolType,
	"required_when_on_remove":       types.BoolType,
	"required_when_on_reenrollment": types.BoolType,
}

var certStoreTypeItemAttrTypes = map[string]attr.Type{
	"id":                       types.StringType,
	"name":                     types.StringType,
	"short_name":               types.StringType,
	"capability":               types.StringType,
	"local_store":              types.BoolType,
	"store_path_type":          types.StringType,
	"store_path_value":         types.StringType,
	"private_key_allowed":      types.StringType,
	"server_required":          types.BoolType,
	"power_shell":              types.BoolType,
	"blueprint_allowed":        types.BoolType,
	"custom_alias_allowed":     types.StringType,
	"supports_add":             types.BoolType,
	"supports_create":          types.BoolType,
	"supports_discovery":       types.BoolType,
	"supports_enrollment":      types.BoolType,
	"supports_remove":          types.BoolType,
	"password_entry_supported": types.BoolType,
	"password_store_required":  types.BoolType,
	"password_style":           types.StringType,
	"import_type":              types.Int64Type,
	"server_registration":      types.Int64Type,
	"inventory_endpoint":       types.StringType,
	"inventory_job_type":       types.StringType,
	"management_job_type":      types.StringType,
	"discovery_job_type":       types.StringType,
	"enrollment_job_type":      types.StringType,
	"properties":               types.ListType{ElemType: types.ObjectType{AttrTypes: certStoreTypePropAttrTypes}},
	"entry_parameters":         types.ListType{ElemType: types.ObjectType{AttrTypes: certStoreTypeEntryParamAttrTypes}},
}

// ---------------------------------------------------------------------------
// Type registration
// ---------------------------------------------------------------------------

type dataSourceCertStoreTypesType struct{}

func (d dataSourceCertStoreTypesType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	storeTypeAttrs := map[string]tfsdk.Attribute{
		"id":                       {Type: types.StringType, Computed: true, Description: "Numeric ID of the store type (as a string)."},
		"name":                     {Type: types.StringType, Computed: true, Description: "Display name."},
		"short_name":               {Type: types.StringType, Computed: true, Description: "Short/programmatic name."},
		"capability":               {Type: types.StringType, Computed: true, Description: "Capability string."},
		"local_store":              {Type: types.BoolType, Computed: true, Description: "Whether the store is a local store."},
		"store_path_type":          {Type: types.StringType, Computed: true, Description: "Store path type hint."},
		"store_path_value":         {Type: types.StringType, Computed: true, Description: "Store path value or template."},
		"private_key_allowed":      {Type: types.StringType, Computed: true, Description: "Whether private keys are allowed."},
		"server_required":          {Type: types.BoolType, Computed: true, Description: "Whether server credentials are required."},
		"power_shell":              {Type: types.BoolType, Computed: true, Description: "Whether the store type uses PowerShell."},
		"blueprint_allowed":        {Type: types.BoolType, Computed: true, Description: "Whether blueprint provisioning is allowed."},
		"custom_alias_allowed":     {Type: types.StringType, Computed: true, Description: "Whether custom aliases are allowed."},
		"supports_add":             {Type: types.BoolType, Computed: true, Description: "Whether the store type supports adding certificates."},
		"supports_create":          {Type: types.BoolType, Computed: true, Description: "Whether the store type supports creating stores."},
		"supports_discovery":       {Type: types.BoolType, Computed: true, Description: "Whether the store type supports discovery."},
		"supports_enrollment":      {Type: types.BoolType, Computed: true, Description: "Whether the store type supports enrollment."},
		"supports_remove":          {Type: types.BoolType, Computed: true, Description: "Whether the store type supports removing certificates."},
		"password_entry_supported": {Type: types.BoolType, Computed: true, Description: "Whether per-entry passwords are supported."},
		"password_store_required":  {Type: types.BoolType, Computed: true, Description: "Whether a store-level password is required."},
		"password_style":           {Type: types.StringType, Computed: true, Description: "Password style."},
		"import_type":              {Type: types.Int64Type, Computed: true, Description: "Import type identifier."},
		"server_registration":      {Type: types.Int64Type, Computed: true, Description: "Server registration type."},
		"inventory_endpoint":       {Type: types.StringType, Computed: true, Description: "Inventory job endpoint path."},
		"inventory_job_type":       {Type: types.StringType, Computed: true, Description: "GUID of the inventory job type."},
		"management_job_type":      {Type: types.StringType, Computed: true, Description: "GUID of the management job type."},
		"discovery_job_type":       {Type: types.StringType, Computed: true, Description: "GUID of the discovery job type."},
		"enrollment_job_type":      {Type: types.StringType, Computed: true, Description: "GUID of the enrollment job type."},
		"properties": {
			Type:        types.ListType{ElemType: types.ObjectType{AttrTypes: certStoreTypePropAttrTypes}},
			Computed:    true,
			Description: "Property definitions for stores of this type.",
		},
		"entry_parameters": {
			Type:        types.ListType{ElemType: types.ObjectType{AttrTypes: certStoreTypeEntryParamAttrTypes}},
			Computed:    true,
			Description: "Entry parameter definitions for this store type.",
		},
	}

	return tfsdk.Schema{
		Description: "Returns a list of certificate store types defined in Keyfactor Command. " +
			"Supports optional filtering by short name and capability string.",
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Placeholder ID for Terraform framework compatibility.",
			},
			"short_name_filter": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Filter store types by short name (case-insensitive substring match).",
			},
			"capability_filter": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Filter store types by capability string (case-insensitive substring match).",
			},
			"store_types": {
				Computed:    true,
				Description: "List of certificate store types matching the filter criteria.",
				Attributes:  tfsdk.ListNestedAttributes(storeTypeAttrs),
			},
		},
	}, nil
}

func (d dataSourceCertStoreTypesType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertStoreTypes{p: *(p.(*provider))}, nil
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

type dataSourceCertStoreTypes struct {
	p provider
}

type dataSourceCertStoreTypesModel struct {
	ID               types.String `tfsdk:"id"`
	ShortNameFilter  types.String `tfsdk:"short_name_filter"`
	CapabilityFilter types.String `tfsdk:"capability_filter"`
	StoreTypes       types.List   `tfsdk:"store_types"`
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (d dataSourceCertStoreTypes) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourceCertStoreTypes.Read")

	var config dataSourceCertStoreTypesModel
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Listing all certificate store types")

	all, err := d.p.client.ListCertificateStoreTypes()
	if err != nil {
		response.Diagnostics.AddError(
			"Error listing certificate store types",
			fmt.Sprintf("Could not retrieve certificate store types: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Retrieved %d certificate store types", len(*all)))

	var filtered []attr.Value
	for _, st := range *all {
		// short_name_filter: case-insensitive substring match
		if !config.ShortNameFilter.IsNull() && config.ShortNameFilter.Value != "" {
			if !strings.Contains(strings.ToLower(st.ShortName), strings.ToLower(config.ShortNameFilter.Value)) {
				continue
			}
		}
		// capability_filter: case-insensitive substring match on Capability field
		if !config.CapabilityFilter.IsNull() && config.CapabilityFilter.Value != "" {
			if !strings.Contains(strings.ToLower(st.Capability), strings.ToLower(config.CapabilityFilter.Value)) {
				continue
			}
		}

		obj := certStoreTypeToAttrValue(st)
		filtered = append(filtered, obj)
	}

	if filtered == nil {
		filtered = []attr.Value{}
	}

	tflog.Debug(ctx, fmt.Sprintf("Returning %d store types after filtering", len(filtered)))

	result := dataSourceCertStoreTypesModel{
		ID:               types.String{Value: "certificate_store_types"},
		ShortNameFilter:  config.ShortNameFilter,
		CapabilityFilter: config.CapabilityFilter,
		StoreTypes: types.List{
			ElemType: types.ObjectType{AttrTypes: certStoreTypeItemAttrTypes},
			Elems:    filtered,
		},
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "dataSourceCertStoreTypes.Read")
}

// certStoreTypeToAttrValue converts a CertificateStoreType API response to a
// types.Object suitable for inclusion in the store_types list.
func certStoreTypeToAttrValue(st api.CertificateStoreType) attr.Value {
	supportsAdd, supportsCreate, supportsDiscovery, supportsEnrollment, supportsRemove := false, false, false, false, false
	if st.SupportedOperations != nil {
		supportsAdd = st.SupportedOperations.Add
		supportsCreate = st.SupportedOperations.Create
		supportsDiscovery = st.SupportedOperations.Discovery
		supportsEnrollment = st.SupportedOperations.Enrollment
		supportsRemove = st.SupportedOperations.Remove
	}

	pwEntrySupported, pwStoreRequired := false, false
	pwStyle := ""
	if st.PasswordOptions != nil {
		pwEntrySupported = st.PasswordOptions.EntrySupported
		pwStoreRequired = st.PasswordOptions.StoreRequired
		pwStyle = st.PasswordOptions.Style
	}

	// Build properties list
	propElems := []attr.Value{}
	if st.Properties != nil {
		for _, p := range *st.Properties {
			propElems = append(propElems, types.Object{
				AttrTypes: certStoreTypePropAttrTypes,
				Attrs: map[string]attr.Value{
					"name":          types.String{Value: p.Name},
					"display_name":  types.String{Value: p.DisplayName},
					"type":          types.String{Value: p.Type},
					"depends_on":    types.String{Value: interfaceToString(p.DependsOn)},
					"default_value": types.String{Value: interfaceToString(p.DefaultValue)},
					"required":      types.Bool{Value: p.Required},
				},
			})
		}
	}

	// Build entry_parameters list
	epElems := []attr.Value{}
	if st.EntryParameters != nil {
		for _, ep := range *st.EntryParameters {
			epElems = append(epElems, types.Object{
				AttrTypes: certStoreTypeEntryParamAttrTypes,
				Attrs: map[string]attr.Value{
					"name":                          types.String{Value: ep.Name},
					"display_name":                  types.String{Value: ep.DisplayName},
					"type":                          types.String{Value: ep.Type},
					"depends_on":                    types.String{Value: ep.DependsOn},
					"default_value":                 types.String{Value: ep.DefaultValue},
					"options":                       types.String{Value: ep.Options},
					"required_when_has_private_key": types.Bool{Value: ep.RequiredWhen.HasPrivateKey},
					"required_when_on_add":          types.Bool{Value: ep.RequiredWhen.OnAdd},
					"required_when_on_remove":       types.Bool{Value: ep.RequiredWhen.OnRemove},
					"required_when_on_reenrollment": types.Bool{Value: ep.RequiredWhen.OnReenrollment},
				},
			})
		}
	}

	return types.Object{
		AttrTypes: certStoreTypeItemAttrTypes,
		Attrs: map[string]attr.Value{
			"id":                       types.String{Value: strconv.Itoa(st.StoreType)},
			"name":                     types.String{Value: st.Name},
			"short_name":               types.String{Value: st.ShortName},
			"capability":               types.String{Value: st.Capability},
			"local_store":              types.Bool{Value: derefBool(st.LocalStore)},
			"store_path_type":          types.String{Value: st.StorePathType},
			"store_path_value":         types.String{Value: st.StorePathValue},
			"private_key_allowed":      types.String{Value: st.PrivateKeyAllowed},
			"server_required":          types.Bool{Value: derefBool(st.ServerRequired)},
			"power_shell":              types.Bool{Value: derefBool(st.PowerShell)},
			"blueprint_allowed":        types.Bool{Value: derefBool(st.BlueprintAllowed)},
			"custom_alias_allowed":     types.String{Value: st.CustomAliasAllowed},
			"supports_add":             types.Bool{Value: supportsAdd},
			"supports_create":          types.Bool{Value: supportsCreate},
			"supports_discovery":       types.Bool{Value: supportsDiscovery},
			"supports_enrollment":      types.Bool{Value: supportsEnrollment},
			"supports_remove":          types.Bool{Value: supportsRemove},
			"password_entry_supported": types.Bool{Value: pwEntrySupported},
			"password_store_required":  types.Bool{Value: pwStoreRequired},
			"password_style":           types.String{Value: pwStyle},
			"import_type":              types.Int64{Value: int64(st.ImportType)},
			"server_registration":      types.Int64{Value: int64(st.ServerRegistration)},
			"inventory_endpoint":       types.String{Value: st.InventoryEndpoint},
			"inventory_job_type":       types.String{Value: st.InventoryJobType},
			"management_job_type":      types.String{Value: st.ManagementJobType},
			"discovery_job_type":       types.String{Value: st.DiscoveryJobType},
			"enrollment_job_type":      types.String{Value: st.EnrollmentJobType},
			"properties": types.List{
				ElemType: types.ObjectType{AttrTypes: certStoreTypePropAttrTypes},
				Elems:    propElems,
			},
			"entry_parameters": types.List{
				ElemType: types.ObjectType{AttrTypes: certStoreTypeEntryParamAttrTypes},
				Elems:    epElems,
			},
		},
	}
}
