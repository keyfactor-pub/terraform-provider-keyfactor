package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourcePAMProviderResourceType struct{}

func (r resourcePAMProviderResourceType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Integer ID of the PAM provider in Keyfactor Command.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Name of the PAM provider.",
			},
			"provider_type_id": {
				Type:          types.StringType,
				Required:      true,
				Description:   "GUID of the PAM provider type. Changing this value forces a new resource.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"remote": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether the PAM provider runs remotely.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"area": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Area (zone) integer identifier for this PAM provider.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"param_values": {
				Optional:    true,
				Description: "Parameter values for this PAM provider. Secret parameter values (data_type=2) are write-only and cannot be read back from the server.",
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"param_id": {
						Type:        types.Int64Type,
						Required:    true,
						Description: "Integer ID of the PAM provider type parameter.",
					},
					"name": {
						Type:        types.StringType,
						Required:    true,
						Description: "Name of the PAM provider type parameter. Required by the Keyfactor API.",
					},
					"value": {
						Type:        types.StringType,
						Required:    true,
						Sensitive:   true,
						Description: "Value for this parameter. For secret parameters, this value is write-only; it will not drift even if modified outside Terraform.",
					},
				}),
			},
		},
		Description: "Manages a Keyfactor Command PAM Provider. Secret parameter values are write-only — the server stores them as GUID references and never returns the plaintext, so provider reads preserve the configured values from state.",
	}, nil
}

func (r resourcePAMProviderResourceType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourcePAMProvider{
		p: *(p.(*provider)),
	}, nil
}

type resourcePAMProvider struct {
	p provider
}

// KeyfactorPAMProvider is the Terraform state model for keyfactor_pam_provider.
type KeyfactorPAMProvider struct {
	ID             types.String             `tfsdk:"id"`
	Name           types.String             `tfsdk:"name"`
	ProviderTypeID types.String             `tfsdk:"provider_type_id"`
	Remote         types.Bool               `tfsdk:"remote"`
	Area           types.Int64              `tfsdk:"area"`
	ParamValues    []KeyfactorPAMParamValue `tfsdk:"param_values"`
}

// KeyfactorPAMParamValue is a single parameter value entry.
type KeyfactorPAMParamValue struct {
	ParamID types.Int64  `tfsdk:"param_id"`
	Name    types.String `tfsdk:"name"`
	Value   types.String `tfsdk:"value"`
}

// pamProviderResponseToMetadata converts server response fields (excluding param values) into state.
// param_values must be set separately from plan/state to preserve secret values.
func pamProviderResponseToMetadata(resp *v1.PAMProviderResponseLegacy) KeyfactorPAMProvider {
	state := KeyfactorPAMProvider{
		ID:          types.String{Value: strconv.Itoa(int(resp.GetId()))},
		Name:        types.String{Value: resp.GetName()},
		Remote:      types.Bool{Value: resp.GetRemote()},
		Area:        types.Int64{Value: int64(resp.GetArea())},
		ParamValues: []KeyfactorPAMParamValue{},
	}
	if resp.ProviderType != nil {
		state.ProviderTypeID = types.String{Value: resp.ProviderType.GetId()}
	}
	return state
}

func buildPAMParamValues(params []KeyfactorPAMParamValue) []v1.PAMProviderCreateRequestTypeParamValue {
	var result []v1.PAMProviderCreateRequestTypeParamValue
	for _, p := range params {
		paramID := int32(p.ParamID.Value)
		pv := v1.PAMProviderCreateRequestTypeParamValue{}
		pv.SetId(paramID)
		pv.SetValue(p.Value.Value)
		typeParam := v1.PAMProviderCreateRequestProviderTypeParam{}
		typeParam.SetId(paramID)
		typeParam.SetName(p.Name.Value)
		pv.SetProviderTypeParam(typeParam)
		result = append(result, pv)
	}
	return result
}

func (r resourcePAMProvider) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProvider.Create")

	var plan KeyfactorPAMProvider
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Creating PAM provider %q", plan.Name.Value))

	providerType := v1.PAMProviderCreateRequestProviderType{}
	providerType.SetId(plan.ProviderTypeID.Value)

	createReq := v1.PAMProviderCreateRequest{
		Name:         plan.Name.Value,
		ProviderType: providerType,
	}
	if !plan.Remote.Null && !plan.Remote.Unknown {
		createReq.SetRemote(plan.Remote.Value)
	}
	if !plan.Area.Null && !plan.Area.Unknown {
		area := int32(plan.Area.Value)
		createReq.SetArea(area)
	}
	createReq.ProviderTypeParamValues = buildPAMParamValues(plan.ParamValues)

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewCreatePamProvidersRequest(ctx).PAMProviderCreateRequest(createReq)
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error creating PAM provider.",
			fmt.Sprintf("Could not create PAM provider %q: %s. Details: %s", plan.Name.Value, err.Error(), body),
		)
		return
	}

	// Build state from server response, but preserve param_values from plan
	// (secret values are stored as GUID references on the server).
	state := pamProviderResponseToMetadata(resp)
	state.ParamValues = plan.ParamValues

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourcePAMProvider.Create")
}

func (r resourcePAMProvider) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProvider.Read")

	var state KeyfactorPAMProvider
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid PAM provider ID.",
			fmt.Sprintf("Could not parse PAM provider ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading PAM provider ID %d", id))

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewGetPamProvidersByIdRequest(ctx, int32(id))
	resp, httpResp, err := req.Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("PAM provider %d not found, removing from state", id))
			response.State.RemoveResource(ctx)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading PAM provider.",
			fmt.Sprintf("Could not read PAM provider %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	// Update metadata fields from server, but always preserve param_values from
	// existing state because secret param values are stored as GUID references
	// on the server and cannot be recovered as plaintext.
	newState := pamProviderResponseToMetadata(resp)
	newState.ParamValues = state.ParamValues

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourcePAMProvider.Read")
}

func (r resourcePAMProvider) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProvider.Update")

	var plan KeyfactorPAMProvider
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var state KeyfactorPAMProvider
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid PAM provider ID.",
			fmt.Sprintf("Could not parse PAM provider ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Updating PAM provider ID %d", id))

	providerType := v1.PAMProviderCreateRequestProviderType{}
	providerType.SetId(plan.ProviderTypeID.Value)

	updateReq := v1.PAMProviderUpdateRequestLegacy{
		Id:           int32(id),
		Name:         plan.Name.Value,
		ProviderType: providerType,
	}
	if !plan.Remote.Null && !plan.Remote.Unknown {
		updateReq.SetRemote(plan.Remote.Value)
	}
	if !plan.Area.Null && !plan.Area.Unknown {
		area := int32(plan.Area.Value)
		updateReq.SetArea(area)
	}
	updateReq.ProviderTypeParamValues = buildPAMParamValues(plan.ParamValues)

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewUpdatePamProvidersRequest(ctx).PAMProviderUpdateRequestLegacy(updateReq)
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error updating PAM provider.",
			fmt.Sprintf("Could not update PAM provider %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	// Preserve param_values from plan (not server response) for the same reason as Read.
	newState := pamProviderResponseToMetadata(resp)
	newState.ParamValues = plan.ParamValues

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourcePAMProvider.Update")
}

func (r resourcePAMProvider) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProvider.Delete")

	var state KeyfactorPAMProvider
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid PAM provider ID.",
			fmt.Sprintf("Could not parse PAM provider ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting PAM provider ID %d", id))

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewDeletePamProvidersByIdRequest(ctx, int32(id))
	httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error deleting PAM provider.",
			fmt.Sprintf("Could not delete PAM provider %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	LogFunctionExit(ctx, "resourcePAMProvider.Delete")
}

func (r resourcePAMProvider) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("ImportState called on PAM provider with ID %q", request.ID))

	id, err := strconv.Atoi(request.ID)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid PAM provider ID.",
			fmt.Sprintf("Import ID must be an integer, got %q: %s", request.ID, err.Error()),
		)
		return
	}

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewGetPamProvidersByIdRequest(ctx, int32(id))
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error importing PAM provider.",
			fmt.Sprintf("Could not read PAM provider %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	// Import populates metadata only. param_values will be empty because
	// secret values cannot be recovered from the server.
	state := pamProviderResponseToMetadata(resp)
	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
}
