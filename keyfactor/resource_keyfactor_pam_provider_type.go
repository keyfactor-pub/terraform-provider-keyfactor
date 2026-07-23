package keyfactor

import (
	"context"
	"fmt"
	"io"
	"net/http"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourcePAMProviderTypeType struct{}

func (r resourcePAMProviderTypeType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "GUID identifier of the PAM provider type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"name": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Name of the PAM provider type. Changing this value forces a new resource.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"parameters": {
				Optional:      true,
				Description:   "Parameters defined for this PAM provider type. Any change to parameters forces a new resource.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"id": {
						Type:          types.Int64Type,
						Computed:      true,
						Description:   "Integer ID of the parameter.",
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
					},
					"name": {
						Type:        types.StringType,
						Required:    true,
						Description: "Parameter name.",
					},
					"display_name": {
						Type:        types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "Human-readable display name for the parameter.",
					},
					"data_type": {
						Type:        types.Int64Type,
						Optional:    true,
						Computed:    true,
						Description: "Data type of the parameter: 1 = string, 2 = secret.",
					},
					"instance_level": {
						Type:        types.BoolType,
						Optional:    true,
						Computed:    true,
						Description: "Whether this parameter is configured at the instance level.",
					},
				}),
			},
		},
		Description: "Manages a Keyfactor Command PAM Provider Type. There is no update endpoint for PAM provider types — any field change forces a new resource (delete + recreate).",
	}, nil
}

func (r resourcePAMProviderTypeType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourcePAMProviderType{
		p: *(p.(*provider)),
	}, nil
}

type resourcePAMProviderType struct {
	p provider
}

// KeyfactorPAMProviderType is the Terraform state model for keyfactor_pam_provider_type.
type KeyfactorPAMProviderType struct {
	ID         types.String                    `tfsdk:"id"`
	Name       types.String                    `tfsdk:"name"`
	Parameters []KeyfactorPAMProviderTypeParam `tfsdk:"parameters"`
}

// KeyfactorPAMProviderTypeParam is a nested parameter within KeyfactorPAMProviderType.
type KeyfactorPAMProviderTypeParam struct {
	ID            types.Int64  `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	DisplayName   types.String `tfsdk:"display_name"`
	DataType      types.Int64  `tfsdk:"data_type"`
	InstanceLevel types.Bool   `tfsdk:"instance_level"`
}

func pamProviderTypeResponseToState(resp *v1.PAMProviderTypeResponse) KeyfactorPAMProviderType {
	state := KeyfactorPAMProviderType{
		ID:   types.String{Value: resp.GetId()},
		Name: types.String{Value: resp.GetName()},
	}
	// Only populate Parameters when the response contains parameters.
	// When nil, Terraform treats the field as null (matching an unset Optional config).
	// An empty slice would produce an empty list which conflicts with null in plan.
	if len(resp.Parameters) > 0 {
		state.Parameters = []KeyfactorPAMProviderTypeParam{}
	}
	for _, p := range resp.Parameters {
		// DisplayName is NullableString; InstanceLevel is *bool. When the server omits these
		// fields, GetDisplayName/GetInstanceLevel return Go zero values ("" / false) — which
		// would cause "inconsistent result after apply" diagnostics for Optional+Computed
		// schema fields. Map unset/null SDK values to types.Null instead.
		state.Parameters = append(state.Parameters, KeyfactorPAMProviderTypeParam{
			ID:            types.Int64{Value: int64(p.GetId())},
			Name:          types.String{Value: p.GetName()},
			DisplayName:   nullableStringToTfString(p.DisplayName),
			DataType:      pamParameterDataTypePtrToTfInt64(p.DataType),
			InstanceLevel: boolPtrToTfBool(p.InstanceLevel),
		})
	}
	return state
}

// nullableStringToTfString is defined in resource_keyfactor_certificate_authority.go and reused here.

// pamParameterDataTypePtrToTfInt64 converts a *CSSCMSDataModelEnumsPamParameterDataType
// pointer from the SDK response to a types.Int64. DataType is a pointer, same as the
// sibling DisplayName (NullableString) and InstanceLevel (*bool) fields on this struct:
// when the server omits the field, the raw GetDataType() getter returns the enum zero
// value (0), which is itself a valid, meaningful data type value and must not be
// conflated with "not set." Nil maps to Null instead of a spurious concrete 0.
func pamParameterDataTypePtrToTfInt64(v *v1.CSSCMSDataModelEnumsPamParameterDataType) types.Int64 {
	return enumPtrToTfInt64(v)
}

func readHTTPResponseBody(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// buildPAMProviderTypeCreateRequest builds the create request body from the
// plan. Extracted from Create so the parameter mapping is unit-testable.
func buildPAMProviderTypeCreateRequest(plan KeyfactorPAMProviderType) v1.PAMProviderTypeCreateRequest {
	createReq := v1.PAMProviderTypeCreateRequest{Name: plan.Name.Value}
	for _, p := range plan.Parameters {
		param := v1.PAMProviderTypeParameterCreateRequest{Name: p.Name.Value}
		// Send the display name whenever the plan declares it (not Null/Unknown),
		// including an explicit empty string. The prior `!= ""` guard collapsed an
		// explicit display_name = "" with "unset", so the user's explicit empty
		// value was dropped and the server substituted its own default.
		if !p.DisplayName.Null && !p.DisplayName.Unknown {
			param.SetDisplayName(p.DisplayName.Value)
		}
		if !p.DataType.Null && !p.DataType.Unknown {
			dt := v1.CSSCMSDataModelEnumsPamParameterDataType(int32(p.DataType.Value))
			param.SetDataType(dt)
		}
		if !p.InstanceLevel.Null && !p.InstanceLevel.Unknown {
			param.SetInstanceLevel(p.InstanceLevel.Value)
		}
		createReq.Parameters = append(createReq.Parameters, param)
	}
	return createReq
}

func (r resourcePAMProviderType) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProviderType.Create")

	var plan KeyfactorPAMProviderType
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Creating PAM provider type %q", plan.Name.Value))

	createReq := buildPAMProviderTypeCreateRequest(plan)

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewCreatePamProvidersTypesRequest(ctx).PAMProviderTypeCreateRequest(createReq)
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error creating PAM provider type.",
			fmt.Sprintf("Could not create PAM provider type %q: %s. Details: %s", plan.Name.Value, err.Error(), body),
		)
		return
	}

	state := pamProviderTypeResponseToState(resp)
	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourcePAMProviderType.Create")
}

func (r resourcePAMProviderType) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProviderType.Read")

	var state KeyfactorPAMProviderType
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading PAM provider type %q", state.ID.Value))

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewGetPamProvidersTypesRequest(ctx)
	allTypes, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading PAM provider types.",
			fmt.Sprintf("Could not list PAM provider types: %s. Details: %s", err.Error(), body),
		)
		return
	}

	for _, pt := range allTypes {
		if pt.GetId() == state.ID.Value {
			newState := pamProviderTypeResponseToState(&pt)
			diags = response.State.Set(ctx, &newState)
			response.Diagnostics.Append(diags...)
			LogFunctionExit(ctx, "resourcePAMProviderType.Read")
			return
		}
	}

	// Not found — resource was deleted outside Terraform.
	tflog.Info(ctx, fmt.Sprintf("PAM provider type %q not found, removing from state", state.ID.Value))
	response.State.RemoveResource(ctx)
	LogFunctionExit(ctx, "resourcePAMProviderType.Read")
}

func (r resourcePAMProviderType) Update(_ context.Context, _ tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// All user-settable attributes have RequiresReplace, so Update is never called.
	response.Diagnostics.AddError(
		"Update not supported.",
		"PAM Provider Types cannot be updated in place. All changes require replacing the resource.",
	)
}

func (r resourcePAMProviderType) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	LogFunctionEntry(ctx, "resourcePAMProviderType.Delete")

	var state KeyfactorPAMProviderType
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting PAM provider type %q", state.ID.Value))

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewDeletePamProvidersTypesByIdRequest(ctx, state.ID.Value)
	httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error deleting PAM provider type.",
			fmt.Sprintf("Could not delete PAM provider type %q: %s. Details: %s", state.ID.Value, err.Error(), body),
		)
		return
	}

	LogFunctionExit(ctx, "resourcePAMProviderType.Delete")
}

func (r resourcePAMProviderType) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("ImportState called on PAM provider type with ID %q", request.ID))

	pamAPI := r.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewGetPamProvidersTypesRequest(ctx)
	allTypes, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error importing PAM provider type.",
			fmt.Sprintf("Could not list PAM provider types: %s. Details: %s", err.Error(), body),
		)
		return
	}

	for _, pt := range allTypes {
		if pt.GetId() == request.ID {
			state := pamProviderTypeResponseToState(&pt)
			diags := response.State.Set(ctx, &state)
			response.Diagnostics.Append(diags...)
			return
		}
	}

	response.Diagnostics.AddError(
		"PAM provider type not found.",
		fmt.Sprintf("No PAM provider type with GUID %q was found.", request.ID),
	)
}
