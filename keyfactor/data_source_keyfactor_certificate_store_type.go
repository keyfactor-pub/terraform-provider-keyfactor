package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ---------------------------------------------------------------------------
// Type registration
// ---------------------------------------------------------------------------

type dataSourceCertStoreTypeDefType struct{}

func (d dataSourceCertStoreTypeDefType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	propAttrs := map[string]tfsdk.Attribute{
		"name":          {Type: types.StringType, Computed: true, Description: "Internal property name."},
		"display_name":  {Type: types.StringType, Computed: true, Description: "Human-readable display name."},
		"type":          {Type: types.StringType, Computed: true, Description: "Property value type."},
		"depends_on":    {Type: types.StringType, Computed: true, Description: "Name of another property this one depends on."},
		"default_value": {Type: types.StringType, Computed: true, Description: "Default value for the property."},
		"required":      {Type: types.BoolType, Computed: true, Description: "Whether the property is required."},
	}

	entryParamAttrs := map[string]tfsdk.Attribute{
		"name":                          {Type: types.StringType, Computed: true, Description: "Entry parameter name."},
		"display_name":                  {Type: types.StringType, Computed: true, Description: "Human-readable display name."},
		"type":                          {Type: types.StringType, Computed: true, Description: "Parameter value type."},
		"depends_on":                    {Type: types.StringType, Computed: true, Description: "Name of another parameter this one depends on."},
		"default_value":                 {Type: types.StringType, Computed: true, Description: "Default value for the parameter."},
		"options":                       {Type: types.StringType, Computed: true, Description: "Comma-separated list of allowed values."},
		"required_when_has_private_key": {Type: types.BoolType, Computed: true, Description: "Required when entry has a private key."},
		"required_when_on_add":          {Type: types.BoolType, Computed: true, Description: "Required when adding a certificate."},
		"required_when_on_remove":       {Type: types.BoolType, Computed: true, Description: "Required when removing a certificate."},
		"required_when_on_reenrollment": {Type: types.BoolType, Computed: true, Description: "Required on re-enrollment."},
	}

	return tfsdk.Schema{
		Description: "Reads an existing Keyfactor Command Certificate Store Type by integer ID or short name.",
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Integer ID or short name (e.g. PEM, JKS, K8STLSSecr) of the certificate store type.",
			},
			"id":                       {Type: types.StringType, Computed: true, Description: "Numeric ID of the certificate store type (as a string)."},
			"name":                     {Type: types.StringType, Computed: true, Description: "Display name of the certificate store type."},
			"short_name":               {Type: types.StringType, Computed: true, Description: "Short/programmatic name."},
			"capability":               {Type: types.StringType, Computed: true, Description: "Capability string."},
			"local_store":              {Type: types.BoolType, Computed: true, Description: "Whether the store is a local store."},
			"store_path_type":          {Type: types.StringType, Computed: true, Description: "Store path type hint."},
			"store_path_value":         {Type: types.StringType, Computed: true, Description: "Store path value or template."},
			"private_key_allowed":      {Type: types.StringType, Computed: true, Description: "Whether private keys are allowed: Forbidden, Optional, or Required."},
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
				Computed:    true,
				Description: "Property definitions for stores of this type.",
				Attributes:  tfsdk.ListNestedAttributes(propAttrs),
			},
			"entry_parameters": {
				Computed:    true,
				Description: "Entry parameter definitions for certificate entries in stores of this type.",
				Attributes:  tfsdk.ListNestedAttributes(entryParamAttrs),
			},
		},
	}, nil
}

func (d dataSourceCertStoreTypeDefType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertStoreTypeDefImpl{p: *(p.(*provider))}, nil
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

type dataSourceCertStoreTypeDefImpl struct {
	p provider
}

type KeyfactorCertStoreTypeDefDataSource struct {
	Identifier             types.String              `tfsdk:"identifier"`
	ID                     types.String              `tfsdk:"id"`
	Name                   types.String              `tfsdk:"name"`
	ShortName              types.String              `tfsdk:"short_name"`
	Capability             types.String              `tfsdk:"capability"`
	LocalStore             types.Bool                `tfsdk:"local_store"`
	StorePathType          types.String              `tfsdk:"store_path_type"`
	StorePathValue         types.String              `tfsdk:"store_path_value"`
	PrivateKeyAllowed      types.String              `tfsdk:"private_key_allowed"`
	ServerRequired         types.Bool                `tfsdk:"server_required"`
	PowerShell             types.Bool                `tfsdk:"power_shell"`
	BlueprintAllowed       types.Bool                `tfsdk:"blueprint_allowed"`
	CustomAliasAllowed     types.String              `tfsdk:"custom_alias_allowed"`
	SupportsAdd            types.Bool                `tfsdk:"supports_add"`
	SupportsCreate         types.Bool                `tfsdk:"supports_create"`
	SupportsDiscovery      types.Bool                `tfsdk:"supports_discovery"`
	SupportsEnrollment     types.Bool                `tfsdk:"supports_enrollment"`
	SupportsRemove         types.Bool                `tfsdk:"supports_remove"`
	PasswordEntrySupported types.Bool                `tfsdk:"password_entry_supported"`
	PasswordStoreRequired  types.Bool                `tfsdk:"password_store_required"`
	PasswordStyle          types.String              `tfsdk:"password_style"`
	ImportType             types.Int64               `tfsdk:"import_type"`
	ServerRegistration     types.Int64               `tfsdk:"server_registration"`
	InventoryEndpoint      types.String              `tfsdk:"inventory_endpoint"`
	InventoryJobType       types.String              `tfsdk:"inventory_job_type"`
	ManagementJobType      types.String              `tfsdk:"management_job_type"`
	DiscoveryJobType       types.String              `tfsdk:"discovery_job_type"`
	EnrollmentJobType      types.String              `tfsdk:"enrollment_job_type"`
	Properties             []CertStoreTypeProperty   `tfsdk:"properties"`
	EntryParameters        []CertStoreTypeEntryParam `tfsdk:"entry_parameters"`
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (d dataSourceCertStoreTypeDefImpl) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourceCertStoreTypeDef.Read")

	var cfg KeyfactorCertStoreTypeDefDataSource
	diags := request.Config.Get(ctx, &cfg)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	identifier := cfg.Identifier.Value
	tflog.Info(ctx, fmt.Sprintf("Reading certificate store type with identifier %q", identifier))

	var resourceState *KeyfactorCertStoreTypeDef
	if numID, parseErr := strconv.Atoi(identifier); parseErr == nil {
		resp, err := d.p.client.GetCertificateStoreTypeById(numID)
		if err != nil {
			response.Diagnostics.AddError(
				"Error reading certificate store type",
				fmt.Sprintf("Could not find certificate store type with ID %d: %s", numID, err.Error()),
			)
			return
		}
		s := certStoreTypeDefToState(resp)
		resourceState = &s
	} else {
		resp, err := d.p.client.GetCertificateStoreTypeByName(identifier)
		if err != nil {
			response.Diagnostics.AddError(
				"Error reading certificate store type",
				fmt.Sprintf("Could not find certificate store type %q: %s", identifier, err.Error()),
			)
			return
		}
		s := certStoreTypeDefToState(resp)
		resourceState = &s
	}

	result := KeyfactorCertStoreTypeDefDataSource{
		Identifier:             cfg.Identifier,
		ID:                     resourceState.ID,
		Name:                   resourceState.Name,
		ShortName:              resourceState.ShortName,
		Capability:             resourceState.Capability,
		LocalStore:             resourceState.LocalStore,
		StorePathType:          resourceState.StorePathType,
		StorePathValue:         resourceState.StorePathValue,
		PrivateKeyAllowed:      resourceState.PrivateKeyAllowed,
		ServerRequired:         resourceState.ServerRequired,
		PowerShell:             resourceState.PowerShell,
		BlueprintAllowed:       resourceState.BlueprintAllowed,
		CustomAliasAllowed:     resourceState.CustomAliasAllowed,
		SupportsAdd:            resourceState.SupportsAdd,
		SupportsCreate:         resourceState.SupportsCreate,
		SupportsDiscovery:      resourceState.SupportsDiscovery,
		SupportsEnrollment:     resourceState.SupportsEnrollment,
		SupportsRemove:         resourceState.SupportsRemove,
		PasswordEntrySupported: resourceState.PasswordEntrySupported,
		PasswordStoreRequired:  resourceState.PasswordStoreRequired,
		PasswordStyle:          resourceState.PasswordStyle,
		ImportType:             resourceState.ImportType,
		ServerRegistration:     resourceState.ServerRegistration,
		InventoryEndpoint:      resourceState.InventoryEndpoint,
		InventoryJobType:       resourceState.InventoryJobType,
		ManagementJobType:      resourceState.ManagementJobType,
		DiscoveryJobType:       resourceState.DiscoveryJobType,
		EnrollmentJobType:      resourceState.EnrollmentJobType,
		Properties:             resourceState.Properties,
		EntryParameters:        resourceState.EntryParameters,
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "dataSourceCertStoreTypeDef.Read")
}
