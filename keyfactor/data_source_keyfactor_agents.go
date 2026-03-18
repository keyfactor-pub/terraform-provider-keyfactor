package keyfactor

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var agentObjectAttrTypes = map[string]attr.Type{
	"agent_id":                      types.StringType,
	"client_machine":                types.StringType,
	"username":                      types.StringType,
	"agent_platform":                types.Int64Type,
	"status":                        types.Int64Type,
	"version":                       types.StringType,
	"last_seen":                     types.StringType,
	"capabilities":                  types.ListType{ElemType: types.StringType},
	"blueprint":                     types.StringType,
	"thumbprint":                    types.StringType,
	"legacy_thumbprint":             types.StringType,
	"auth_certificate_reenrollment": types.StringType,
	"last_thumbprint_used":          types.StringType,
	"last_error_code":               types.Int64Type,
	"last_error_message":            types.StringType,
}

type dataSourceAgentsType struct{}

func (r dataSourceAgentsType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	agentSchema := map[string]tfsdk.Attribute{
		"agent_id": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The GUID of the orchestrator.",
		},
		"client_machine": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The client machine on which the orchestrator is installed.",
		},
		"username": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The Active Directory user or service account the orchestrator is using.",
		},
		"agent_platform": {
			Type:        types.Int64Type,
			Computed:    true,
			Description: "An integer indicating the platform for the orchestrator.",
		},
		"status": {
			Type:        types.Int64Type,
			Computed:    true,
			Description: "An integer indicating the orchestrator status. 1 = New, 2 = Approved, 3 = Disapproved.",
		},
		"version": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The version of the orchestrator.",
		},
		"last_seen": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The time, in UTC, at which the orchestrator last contacted Keyfactor Command.",
		},
		"capabilities": {
			Type:        types.ListType{ElemType: types.StringType},
			Computed:    true,
			Description: "An array of capabilities reported by the orchestrator.",
		},
		"blueprint": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The name of the blueprint associated with the orchestrator.",
		},
		"thumbprint": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The thumbprint of the certificate used by the orchestrator for client certificate authentication.",
		},
		"legacy_thumbprint": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The thumbprint of the certificate previously used by the orchestrator before a certificate renewal.",
		},
		"auth_certificate_reenrollment": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The value of the orchestrator certificate reenrollment request or require status.",
		},
		"last_thumbprint_used": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The thumbprint of the certificate that the orchestrator most recently used for authentication.",
		},
		"last_error_code": {
			Type:        types.Int64Type,
			Computed:    true,
			Description: "The last error code reported from the orchestrator when trying to register a session.",
		},
		"last_error_message": {
			Type:        types.StringType,
			Computed:    true,
			Description: "The last error message reported from the orchestrator when trying to register a session.",
		},
	}

	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Placeholder ID for Terraform framework compatibility.",
			},
			"status_filter": {
				Type:        types.Int64Type,
				Optional:    true,
				Description: "Filter agents by status. 1 = New, 2 = Approved, 3 = Disapproved. If not set, all agents are returned.",
			},
			"client_machine_filter": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Filter agents by client machine name (case-insensitive substring match).",
			},
			"capability_filter": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Filter agents to those that report a specific capability (e.g., \"K8STLSSecr\", \"SSL\").",
			},
			"agents": {
				Computed:    true,
				Description: "List of orchestrator agents matching the filter criteria.",
				Attributes:  tfsdk.ListNestedAttributes(agentSchema),
			},
		},
		Description: "Returns a list of orchestrator agents registered in Keyfactor Command. " +
			"Supports optional filtering by status, client machine name, and capability.",
	}, nil
}

func (r dataSourceAgentsType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceAgents{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceAgents struct {
	p provider
}

type dataSourceAgentsModel struct {
	ID                  types.String `tfsdk:"id"`
	StatusFilter        types.Int64  `tfsdk:"status_filter"`
	ClientMachineFilter types.String `tfsdk:"client_machine_filter"`
	CapabilityFilter    types.String `tfsdk:"capability_filter"`
	Agents              types.List   `tfsdk:"agents"`
}

func (r dataSourceAgents) Read(
	ctx context.Context,
	request tfsdk.ReadDataSourceRequest,
	response *tfsdk.ReadDataSourceResponse,
) {
	var config dataSourceAgentsModel
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on agents (plural) data source")

	agents, err := r.p.client.GetAgentList()
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_AGENT_READ,
			fmt.Sprintf("Error querying Keyfactor Command for agents: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Retrieved %d agents from Keyfactor Command", len(agents)))

	// Apply client-side filters
	var filtered []attr.Value
	for _, agent := range agents {
		// Status filter
		if !config.StatusFilter.IsNull() && int64(agent.Status) != config.StatusFilter.Value {
			continue
		}

		// Client machine filter (case-insensitive substring)
		if !config.ClientMachineFilter.IsNull() && config.ClientMachineFilter.Value != "" {
			if !strings.Contains(
				strings.ToLower(agent.ClientMachine),
				strings.ToLower(config.ClientMachineFilter.Value),
			) {
				continue
			}
		}

		// Capability filter
		if !config.CapabilityFilter.IsNull() && config.CapabilityFilter.Value != "" {
			found := false
			for _, cap := range agent.Capabilities {
				if strings.EqualFold(cap, config.CapabilityFilter.Value) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Build capabilities list
		var capValues []attr.Value
		for _, cap := range agent.Capabilities {
			capValues = append(capValues, types.String{Value: cap})
		}
		if capValues == nil {
			capValues = []attr.Value{}
		}

		agentObj := types.Object{
			AttrTypes: agentObjectAttrTypes,
			Attrs: map[string]attr.Value{
				"agent_id":                      types.String{Value: agent.AgentId, Null: isNullString(agent.AgentId)},
				"client_machine":                types.String{Value: agent.ClientMachine, Null: isNullString(agent.ClientMachine)},
				"username":                      types.String{Value: agent.Username, Null: isNullString(agent.Username)},
				"agent_platform":                types.Int64{Value: int64(agent.AgentPlatform)},
				"status":                        types.Int64{Value: int64(agent.Status)},
				"version":                       types.String{Value: agent.Version, Null: isNullString(agent.Version)},
				"last_seen":                     types.String{Value: agent.LastSeen, Null: isNullString(agent.LastSeen)},
				"capabilities":                  types.List{ElemType: types.StringType, Elems: capValues},
				"blueprint":                     types.String{Value: agent.Blueprint, Null: isNullString(agent.Blueprint)},
				"thumbprint":                    types.String{Value: agent.Thumbprint, Null: isNullString(agent.Thumbprint)},
				"legacy_thumbprint":             types.String{Value: agent.LegacyThumbprint, Null: isNullString(agent.LegacyThumbprint)},
				"auth_certificate_reenrollment": types.String{Value: agent.AuthCertificateReenrollment, Null: isNullString(agent.AuthCertificateReenrollment)},
				"last_thumbprint_used":          types.String{Value: agent.LastThumbprintUsed, Null: isNullString(agent.LastThumbprintUsed)},
				"last_error_code":               types.Int64{Value: int64(agent.LastErrorCode)},
				"last_error_message":            types.String{Value: agent.LastErrorMessage, Null: isNullString(agent.LastErrorMessage)},
			},
		}
		filtered = append(filtered, agentObj)
	}

	if filtered == nil {
		filtered = []attr.Value{}
	}

	tflog.Debug(ctx, fmt.Sprintf("Returning %d agents after filtering", len(filtered)))

	result := dataSourceAgentsModel{
		ID:                  types.String{Value: "agents"},
		StatusFilter:        config.StatusFilter,
		ClientMachineFilter: config.ClientMachineFilter,
		CapabilityFilter:    config.CapabilityFilter,
		Agents: types.List{
			ElemType: types.ObjectType{AttrTypes: agentObjectAttrTypes},
			Elems:    filtered,
		},
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
}
