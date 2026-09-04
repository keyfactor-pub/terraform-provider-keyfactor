package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ---------------------------------------------------------------------------
// Plan modifiers
// ---------------------------------------------------------------------------

// nullIfUnknownListModifier converts an Unknown list plan value to Null so
// that Optional+Computed list attributes can be decoded when not set in config.
type nullIfUnknownListModifier struct{}

func (m nullIfUnknownListModifier) Modify(_ context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	list, ok := resp.AttributePlan.(types.List)
	if !ok {
		return
	}
	resp.AttributePlan = types.List{Null: true, ElemType: list.ElemType}
}

func (m nullIfUnknownListModifier) Description(_ context.Context) string {
	return "Treats unset Optional+Computed list as null rather than unknown."
}

func (m nullIfUnknownListModifier) MarkdownDescription(_ context.Context) string {
	return "Treats unset Optional+Computed list as null rather than unknown."
}

// ---------------------------------------------------------------------------
// Type registration
// ---------------------------------------------------------------------------

type resourceCertStoreTypeDefType struct{}

func (r resourceCertStoreTypeDefType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	propAttrs := map[string]tfsdk.Attribute{
		"name": {
			Type:        types.StringType,
			Required:    true,
			Description: "Internal property name.",
		},
		"display_name": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Human-readable display name.",
		},
		"type": {
			Type:        types.StringType,
			Required:    true,
			Description: "Property value type (e.g. String, Bool, Secret, MultipleChoice).",
		},
		"depends_on": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Name of another property this one depends on.",
		},
		"default_value": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Default value for the property.",
		},
		"required": {
			Type:        types.BoolType,
			Optional:    true,
			Computed:    true,
			Description: "Whether the property is required.",
		},
	}

	entryParamAttrs := map[string]tfsdk.Attribute{
		"name": {
			Type:        types.StringType,
			Required:    true,
			Description: "Entry parameter name.",
		},
		"display_name": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Human-readable display name.",
		},
		"type": {
			Type:        types.StringType,
			Required:    true,
			Description: "Parameter value type.",
		},
		"depends_on": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Name of another parameter this one depends on.",
		},
		"default_value": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Default value for the parameter.",
		},
		"options": {
			Type:        types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Comma-separated list of allowed values (for MultipleChoice type).",
		},
		"required_when_has_private_key": {
			Type:        types.BoolType,
			Optional:    true,
			Computed:    true,
			Description: "Parameter is required when the entry has a private key.",
		},
		"required_when_on_add": {
			Type:        types.BoolType,
			Optional:    true,
			Computed:    true,
			Description: "Parameter is required when adding a certificate to the store.",
		},
		"required_when_on_remove": {
			Type:        types.BoolType,
			Optional:    true,
			Computed:    true,
			Description: "Parameter is required when removing a certificate from the store.",
		},
		"required_when_on_reenrollment": {
			Type:        types.BoolType,
			Optional:    true,
			Computed:    true,
			Description: "Parameter is required on re-enrollment.",
		},
	}

	return tfsdk.Schema{
		Description: "Manages a Keyfactor Command Certificate Store Type definition. Store types define the capabilities and configuration schema for certificate stores of that type.",
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Numeric ID of the certificate store type (as a string).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Display name of the certificate store type.",
			},
			"short_name": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Short/programmatic name of the certificate store type (e.g. PEM, JKS, K8STLSSecr). Changing this forces a new resource.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"capability": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Capability string used to identify matching orchestrator plugins.",
			},
			"local_store": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store is a local store (no orchestrator required).",
			},
			"store_path_type": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Store path type hint (e.g. Freeform, Fixed).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"store_path_value": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Store path value or template.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"private_key_allowed": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Whether private keys are allowed: Forbidden, Optional, or Required.",
			},
			"server_required": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether server credentials (ServerUsername/ServerPassword) are required.",
			},
			"power_shell": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store type uses PowerShell.",
			},
			"blueprint_allowed": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether blueprint provisioning is allowed for this store type.",
			},
			"custom_alias_allowed": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Whether custom aliases are allowed: Forbidden, Optional, or Required.",
			},
			// Supported operations (flattened from SupportedOperations nested struct)
			"supports_add": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store type supports adding certificates.",
			},
			"supports_create": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store type supports creating stores.",
			},
			"supports_discovery": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store type supports discovery.",
			},
			"supports_enrollment": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store type supports enrollment.",
			},
			"supports_remove": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether the store type supports removing certificates.",
			},
			// Password options (flattened from PasswordOptions nested struct)
			"password_entry_supported": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether per-entry passwords are supported.",
			},
			"password_store_required": {
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				Description: "Whether a store-level password is required.",
			},
			"password_style": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Password style (e.g. Default).",
			},
			// Computed-only job/registration fields
			"import_type": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Import type identifier assigned by Keyfactor Command.",
			},
			"server_registration": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Server registration type.",
			},
			"inventory_endpoint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Inventory job endpoint path.",
			},
			"inventory_job_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "GUID of the inventory job type.",
			},
			"management_job_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "GUID of the management job type.",
			},
			"discovery_job_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "GUID of the discovery job type.",
			},
			"enrollment_job_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "GUID of the enrollment job type.",
			},
			// Nested lists
			"properties": {
				Optional:      true,
				Computed:      true,
				Description:   "Property definitions for stores of this type.",
				Attributes:    tfsdk.ListNestedAttributes(propAttrs),
				PlanModifiers: tfsdk.AttributePlanModifiers{nullIfUnknownListModifier{}},
			},
			"entry_parameters": {
				Optional:      true,
				Computed:      true,
				Description:   "Entry parameter definitions for certificate entries in stores of this type.",
				Attributes:    tfsdk.ListNestedAttributes(entryParamAttrs),
				PlanModifiers: tfsdk.AttributePlanModifiers{nullIfUnknownListModifier{}},
			},
		},
	}, nil
}

func (r resourceCertStoreTypeDefType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceCertStoreTypeDef{p: *(p.(*provider))}, nil
}

// ---------------------------------------------------------------------------
// State models
// ---------------------------------------------------------------------------

type resourceCertStoreTypeDef struct {
	p provider
}

type KeyfactorCertStoreTypeDef struct {
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

type CertStoreTypeProperty struct {
	Name         types.String `tfsdk:"name"`
	DisplayName  types.String `tfsdk:"display_name"`
	Type         types.String `tfsdk:"type"`
	DependsOn    types.String `tfsdk:"depends_on"`
	DefaultValue types.String `tfsdk:"default_value"`
	Required     types.Bool   `tfsdk:"required"`
}

type CertStoreTypeEntryParam struct {
	Name          types.String `tfsdk:"name"`
	DisplayName   types.String `tfsdk:"display_name"`
	Type          types.String `tfsdk:"type"`
	DependsOn     types.String `tfsdk:"depends_on"`
	DefaultValue  types.String `tfsdk:"default_value"`
	Options       types.String `tfsdk:"options"`
	ReqHasPrivKey types.Bool   `tfsdk:"required_when_has_private_key"`
	ReqOnAdd      types.Bool   `tfsdk:"required_when_on_add"`
	ReqOnRemove   types.Bool   `tfsdk:"required_when_on_remove"`
	ReqOnReenroll types.Bool   `tfsdk:"required_when_on_reenrollment"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// passwordStyleOrDefault returns the given password style, defaulting to "Default"
// when the value is empty. The API requires a non-empty style value.
func passwordStyleOrDefault(style string) string {
	if style == "" {
		return "Default"
	}
	return style
}

func interfaceToString(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func certStoreTypeDefToState(resp *api.CertificateStoreType) KeyfactorCertStoreTypeDef {
	state := KeyfactorCertStoreTypeDef{
		ID:                 types.String{Value: strconv.Itoa(resp.StoreType)},
		Name:               types.String{Value: resp.Name},
		ShortName:          types.String{Value: resp.ShortName},
		Capability:         types.String{Value: resp.Capability},
		LocalStore:         boolPtrToTfBool(resp.LocalStore),
		StorePathType:      types.String{Value: resp.StorePathType},
		StorePathValue:     types.String{Value: resp.StorePathValue},
		PrivateKeyAllowed:  types.String{Value: resp.PrivateKeyAllowed},
		ServerRequired:     boolPtrToTfBool(resp.ServerRequired),
		PowerShell:         boolPtrToTfBool(resp.PowerShell),
		BlueprintAllowed:   boolPtrToTfBool(resp.BlueprintAllowed),
		CustomAliasAllowed: types.String{Value: resp.CustomAliasAllowed},
		ImportType:         types.Int64{Value: int64(resp.ImportType)},
		ServerRegistration: types.Int64{Value: int64(resp.ServerRegistration)},
		InventoryEndpoint:  types.String{Value: resp.InventoryEndpoint},
		InventoryJobType:   types.String{Value: resp.InventoryJobType},
		ManagementJobType:  types.String{Value: resp.ManagementJobType},
		DiscoveryJobType:   types.String{Value: resp.DiscoveryJobType},
		EnrollmentJobType:  types.String{Value: resp.EnrollmentJobType},
	}

	if resp.SupportedOperations != nil {
		state.SupportsAdd = types.Bool{Value: resp.SupportedOperations.Add}
		state.SupportsCreate = types.Bool{Value: resp.SupportedOperations.Create}
		state.SupportsDiscovery = types.Bool{Value: resp.SupportedOperations.Discovery}
		state.SupportsEnrollment = types.Bool{Value: resp.SupportedOperations.Enrollment}
		state.SupportsRemove = types.Bool{Value: resp.SupportedOperations.Remove}
	}

	if resp.PasswordOptions != nil {
		state.PasswordEntrySupported = types.Bool{Value: resp.PasswordOptions.EntrySupported}
		state.PasswordStoreRequired = types.Bool{Value: resp.PasswordOptions.StoreRequired}
		state.PasswordStyle = types.String{Value: resp.PasswordOptions.Style}
	}

	// Command's GET response for a store type's Properties/EntryParameters
	// is a JSON array that is empty ([]), not null, whenever the store type
	// has none. Build a non-nil (possibly zero-length) Go slice whenever the
	// API returned the field at all, so this function has full fidelity to
	// what the server actually sent; a nil pointer (field truly absent) is
	// the only case that yields a nil slice here. Callers in Create/Read/
	// Update additionally reconcile this against the plan/prior state via
	// preserveListEmptyVsNull so that "declared empty in config" reads back
	// as [] while "left unset" still reads back as null -- see
	// preserveListEmptyVsNull's doc comment for why that distinction cannot
	// be made from the server response alone.
	if resp.Properties != nil {
		state.Properties = make([]CertStoreTypeProperty, 0, len(*resp.Properties))
		for _, p := range *resp.Properties {
			state.Properties = append(state.Properties, CertStoreTypeProperty{
				Name:         types.String{Value: p.Name},
				DisplayName:  types.String{Value: p.DisplayName},
				Type:         types.String{Value: p.Type},
				DependsOn:    types.String{Value: interfaceToString(p.DependsOn)},
				DefaultValue: types.String{Value: interfaceToString(p.DefaultValue)},
				Required:     types.Bool{Value: p.Required},
			})
		}
	} else {
		state.Properties = nil
	}

	if resp.EntryParameters != nil {
		state.EntryParameters = make([]CertStoreTypeEntryParam, 0, len(*resp.EntryParameters))
		for _, ep := range *resp.EntryParameters {
			state.EntryParameters = append(state.EntryParameters, CertStoreTypeEntryParam{
				Name:          types.String{Value: ep.Name},
				DisplayName:   types.String{Value: ep.DisplayName},
				Type:          types.String{Value: ep.Type},
				DependsOn:     types.String{Value: ep.DependsOn},
				DefaultValue:  types.String{Value: ep.DefaultValue},
				Options:       types.String{Value: ep.Options},
				ReqHasPrivKey: types.Bool{Value: ep.RequiredWhen.HasPrivateKey},
				ReqOnAdd:      types.Bool{Value: ep.RequiredWhen.OnAdd},
				ReqOnRemove:   types.Bool{Value: ep.RequiredWhen.OnRemove},
				ReqOnReenroll: types.Bool{Value: ep.RequiredWhen.OnReenrollment},
			})
		}
	} else {
		state.EntryParameters = nil
	}

	return state
}

// preserveListEmptyVsNull reconciles the null-vs-empty shape of a
// Optional+Computed list attribute against what was actually declared in
// config/prior state, rather than trusting the server response's shape
// alone.
//
// Background: the terraform-plugin-framework reflection layer encodes a nil
// Go slice as a null list and a non-nil-but-zero-length Go slice as an empty
// (known) list -- see internal/reflect/slice.go's FromSlice, which special-
// cases val.IsNil(). Command's certificate store type API always returns
// Properties/EntryParameters as [] (never null) once a store type is
// created, whether or not the user's config declared the attribute at all.
// certStoreTypeDefToState therefore cannot, by itself, tell "user wrote
// entry_parameters = []" apart from "user never mentioned entry_parameters"
// -- both produce an empty API response. Left alone this collapses either
// into a permanent mismatch against a numeric-empty config
// ("Provider produced inconsistent result after apply") or spurious drift on
// every refresh of an undeclared attribute.
//
// The fix: after computing state from the server response, if the resulting
// list is empty, fall back to whatever null-ness the plan/prior state
// (decoded from config/prior state, which the reflection layer *does*
// represent faithfully) already had. A populated list from the server is
// left untouched -- there both shapes agree.
func preserveListEmptyVsNull[T any](target *[]T, reference []T) {
	if len(*target) > 0 {
		return
	}
	if reference != nil {
		*target = []T{}
	} else {
		*target = nil
	}
}

// tfBoolToBoolPtr converts a types.Bool from plan/config into a *bool for the
// SDK request. Null or Unknown becomes nil so an unset/undetermined attribute
// is omitted from the request (the CertificateStoreType JSON tags carry
// omitempty) rather than coercing it to an explicit false the user never
// asked for; a known value -- including explicit false -- is sent as-is,
// since a non-nil *bool is not subject to Go's zero-value omitempty elision.
func tfBoolToBoolPtr(v types.Bool) *bool {
	if v.Null || v.Unknown {
		return nil
	}
	val := v.Value
	return &val
}

func certStoreTypeDefToAPIRequest(plan KeyfactorCertStoreTypeDef) api.CertificateStoreType {
	req := api.CertificateStoreType{
		Name:               plan.Name.Value,
		ShortName:          plan.ShortName.Value,
		Capability:         plan.Capability.Value,
		LocalStore:         tfBoolToBoolPtr(plan.LocalStore),
		StorePathType:      plan.StorePathType.Value,
		StorePathValue:     plan.StorePathValue.Value,
		PrivateKeyAllowed:  plan.PrivateKeyAllowed.Value,
		ServerRequired:     tfBoolToBoolPtr(plan.ServerRequired),
		PowerShell:         tfBoolToBoolPtr(plan.PowerShell),
		BlueprintAllowed:   tfBoolToBoolPtr(plan.BlueprintAllowed),
		CustomAliasAllowed: plan.CustomAliasAllowed.Value,
		SupportedOperations: &api.StoreTypeSupportedOperations{
			Add:        plan.SupportsAdd.Value,
			Create:     plan.SupportsCreate.Value,
			Discovery:  plan.SupportsDiscovery.Value,
			Enrollment: plan.SupportsEnrollment.Value,
			Remove:     plan.SupportsRemove.Value,
		},
		PasswordOptions: &api.StoreTypePasswordOptions{
			EntrySupported: plan.PasswordEntrySupported.Value,
			StoreRequired:  plan.PasswordStoreRequired.Value,
			Style:          passwordStyleOrDefault(plan.PasswordStyle.Value),
		},
	}

	if len(plan.Properties) > 0 {
		props := make([]api.StoreTypePropertyDefinition, len(plan.Properties))
		for i, p := range plan.Properties {
			props[i] = api.StoreTypePropertyDefinition{
				Name:         p.Name.Value,
				DisplayName:  p.DisplayName.Value,
				Type:         p.Type.Value,
				DependsOn:    p.DependsOn.Value,
				DefaultValue: p.DefaultValue.Value,
				Required:     p.Required.Value,
			}
		}
		req.Properties = &props
	}

	if len(plan.EntryParameters) > 0 {
		eps := make([]api.EntryParameter, len(plan.EntryParameters))
		for i, ep := range plan.EntryParameters {
			eps[i] = api.EntryParameter{
				Name:         ep.Name.Value,
				DisplayName:  ep.DisplayName.Value,
				Type:         ep.Type.Value,
				DependsOn:    ep.DependsOn.Value,
				DefaultValue: ep.DefaultValue.Value,
				Options:      ep.Options.Value,
			}
			eps[i].RequiredWhen.HasPrivateKey = ep.ReqHasPrivKey.Value
			eps[i].RequiredWhen.OnAdd = ep.ReqOnAdd.Value
			eps[i].RequiredWhen.OnRemove = ep.ReqOnRemove.Value
			eps[i].RequiredWhen.OnReenrollment = ep.ReqOnReenroll.Value
		}
		req.EntryParameters = &eps
	}

	return req
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r resourceCertStoreTypeDef) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertStoreTypeDef.Create")

	var plan KeyfactorCertStoreTypeDef
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Creating certificate store type %q (%q)", plan.Name.Value, plan.ShortName.Value))

	createReq := certStoreTypeDefToAPIRequest(plan)
	resp, err := r.p.client.CreateStoreType(&createReq)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating certificate store type",
			fmt.Sprintf("Could not create certificate store type %q: %s", plan.ShortName.Value, err.Error()),
		)
		return
	}

	state := certStoreTypeDefToState(resp)

	// StorePathType and StorePathValue are write-only: the API accepts them
	// on POST/PUT but does not return them in GET responses. Preserve the
	// plan values so the post-apply consistency check passes.
	// Guard !Unknown: when the field is not in config for a new resource the
	// plan is Unknown (Computed); copying Unknown into state causes Terraform
	// to fail with "provider still indicated an unknown value after apply".
	if state.StorePathType.Value == "" && !plan.StorePathType.Null && !plan.StorePathType.Unknown {
		state.StorePathType = plan.StorePathType
	}
	if state.StorePathValue.Value == "" && !plan.StorePathValue.Null && !plan.StorePathValue.Unknown {
		state.StorePathValue = plan.StorePathValue
	}

	// Command always returns Properties/EntryParameters as [] (never null)
	// once a store type exists, so an empty result from the server does not
	// by itself tell us whether the user declared an empty list or left the
	// attribute unset. Reconcile against the plan so a config-declared empty
	// list reads back as [] while an undeclared attribute stays null. See
	// preserveListEmptyVsNull's doc comment.
	preserveListEmptyVsNull(&state.Properties, plan.Properties)
	preserveListEmptyVsNull(&state.EntryParameters, plan.EntryParameters)

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertStoreTypeDef.Create")
}

func (r resourceCertStoreTypeDef) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertStoreTypeDef.Read")

	var state KeyfactorCertStoreTypeDef
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store type ID",
			fmt.Sprintf("State ID %q is not a valid integer: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading certificate store type ID %d", id))

	resp, err := r.p.client.GetCertificateStoreTypeById(id)
	if err != nil {
		if isNotFoundError(err) {
			tflog.Info(ctx, fmt.Sprintf("Certificate store type %d not found, removing from state", id))
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError(
			"Error reading certificate store type",
			fmt.Sprintf("Could not read certificate store type %d: %s", id, err.Error()),
		)
		return
	}

	newState := certStoreTypeDefToState(resp)

	// StorePathType and StorePathValue are write-only: the API does not
	// return them in GET responses. Preserve prior state values.
	if newState.StorePathType.Value == "" && !state.StorePathType.Null {
		newState.StorePathType = state.StorePathType
	}
	if newState.StorePathValue.Value == "" && !state.StorePathValue.Null {
		newState.StorePathValue = state.StorePathValue
	}

	// See the identical reconciliation in Create for why this is necessary:
	// reconcile against prior state rather than the server
	// response's shape alone.
	preserveListEmptyVsNull(&newState.Properties, state.Properties)
	preserveListEmptyVsNull(&newState.EntryParameters, state.EntryParameters)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertStoreTypeDef.Read")
}

func (r resourceCertStoreTypeDef) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertStoreTypeDef.Update")

	var state KeyfactorCertStoreTypeDef
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var plan KeyfactorCertStoreTypeDef
	diags = request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError("Invalid certificate store type ID", state.ID.Value)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Updating certificate store type %d", id))

	updateReq := certStoreTypeDefToAPIRequest(plan)
	updateReq.StoreType = id

	resp, err := r.p.client.UpdateStoreType(&updateReq)
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating certificate store type",
			fmt.Sprintf("Could not update certificate store type %d: %s", id, err.Error()),
		)
		return
	}

	newState := certStoreTypeDefToState(resp)

	// StorePathType and StorePathValue are write-only: the API does not
	// return them in responses. Preserve plan values (which reflect config).
	if newState.StorePathType.Value == "" && !plan.StorePathType.Null && !plan.StorePathType.Unknown {
		newState.StorePathType = plan.StorePathType
	}
	if newState.StorePathValue.Value == "" && !plan.StorePathValue.Null && !plan.StorePathValue.Unknown {
		newState.StorePathValue = plan.StorePathValue
	}

	// See the identical reconciliation in Create for why this is necessary:
	// reconcile against plan rather than the server response's
	// shape alone.
	preserveListEmptyVsNull(&newState.Properties, plan.Properties)
	preserveListEmptyVsNull(&newState.EntryParameters, plan.EntryParameters)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertStoreTypeDef.Update")
}

func (r resourceCertStoreTypeDef) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertStoreTypeDef.Delete")

	var state KeyfactorCertStoreTypeDef
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError("Invalid certificate store type ID", state.ID.Value)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting certificate store type %d", id))

	_, err = r.p.client.DeleteCertificateStoreType(id)
	if err != nil {
		response.Diagnostics.AddError(
			"Error deleting certificate store type",
			fmt.Sprintf("Could not delete certificate store type %d: %s", id, err.Error()),
		)
		return
	}

	LogFunctionExit(ctx, "resourceCertStoreTypeDef.Delete")
}

func (r resourceCertStoreTypeDef) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("Importing certificate store type %q", request.ID))

	var resp *api.CertificateStoreType
	var err error

	// Accept integer ID or short name.
	if numID, parseErr := strconv.Atoi(request.ID); parseErr == nil {
		resp, err = r.p.client.GetCertificateStoreTypeById(numID)
	} else {
		resp, err = r.p.client.GetCertificateStoreTypeByName(request.ID)
	}

	if err != nil {
		response.Diagnostics.AddError(
			"Error importing certificate store type",
			fmt.Sprintf("Could not find certificate store type %q: %s", request.ID, err.Error()),
		)
		return
	}

	state := certStoreTypeDefToState(resp)
	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
}
