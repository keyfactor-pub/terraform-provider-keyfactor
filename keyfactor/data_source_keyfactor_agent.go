package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"time"
)

type dataSourceAgentType struct{}

func (r dataSourceAgentType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"agent_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the GUID of the orchestrator.",
			},
			"agent_identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Either the GUID or ClientMachine name of the Keyfactor Command Agent.",
			},
			"client_machine": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the client machine on which the orchestrator is installed.",
			},
			"username": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the Active Directory user or service account the orchestrator is using to connect to Keyfactor Command.",
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
				Description: "A string indicating the version of the orchestrator.",
			},
			"last_seen": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The time, in UTC, at which the orchestrator last contacted Keyfactor Command.",
			},
			"capabilities": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "An array of strings indicating the capabilities reported by the orchestrator. These may be built-in or custom capabilities. ",
			},
			"blueprint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the name of the blueprint associated with the orchestrator.",
			},
			"thumbprint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the thumbprint of the certificate that Keyfactor Command is expecting the orchestrator to use for client certificate authentication.",
			},
			"legacy_thumbprint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the thumbprint of the certificate previously used by the orchestrator for client certificate authentication before a certificate renewal operation took place (rotating the current thumbprint into the legacy thumbprint). The legacy thumbprint is cleared once the orchestrator successfully registers with the new thumbprint.",
			},
			"auth_certificate_reenrollment": {
				Type:        types.StringType,
				Computed:    true,
				Description: "An integer indicating the value of the orchestrator certificate reenrollment request or require status. \n0 -\tNone—Unset the value so that the orchestrator will not request a new client authentication certificate (based on this value).\n1 -\tRequested—The orchestrator will request a new client authentication certificate when it next registers for a session. Orchestrator activity will be allowed to continue as usual.\n2 -\tRequired—The orchestrator will request a new client authentication certificate when it next registers for a session. A new session will not be granted and orchestrator activity will not be allowed to continue until the orchestrator acquires a new certificate.",
			},
			"last_thumbprint_used": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the thumbprint of the certificate that the orchestrator most recently used for client certificate authentication. In most cases, this will match the Thumbprint.",
			},
			"last_error_code": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the last error code, if any, reported from the orchestrator when trying to register a session. This code is cleared on successful session registration.",
			},
			"last_error_message": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the last error message, if any, reported from the orchestrator when trying to register a session. This message is cleared on successful session registration.",
			},
		},
	}, nil
}

func (r dataSourceAgentType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceAgent{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceAgent struct {
	p provider
}

func (r dataSourceAgent) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	var state KeyfactorAgent
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	if state.AgentIdentifier.IsNull() || state.AgentIdentifier.Value == "" {
		response.Diagnostics.AddError(
			"Invalid Agent Identifier",
			"agent_identifier must not be null or empty, please provide either a GUID or ClientMachine name.",
		)
		return
	}

	tflog.Info(ctx, "Read called on agent data source")
	agentIdentifier := state.AgentIdentifier.Value
	tflog.SetField(ctx, "identifier", agentIdentifier)

	agents, err := r.p.client.GetAgent(agentIdentifier)

	if err != nil {
		response.Diagnostics.AddError(
			"Agent Read Error",
			fmt.Sprintf("Error querying Keyfactor Command for agent '%s': %s", agentIdentifier, err.Error()),
		)
		return
	}

	agent := agents[0]
	if len(agents) == 0 {
		response.Diagnostics.AddError(
			"Agent Not Found",
			fmt.Sprintf("No agent found with identifier '%s'", agentIdentifier),
		)
		return
	} else if len(agents) > 1 {
		response.Diagnostics.AddWarning(
			"Multiple Agents Found",
			fmt.Sprintf("Multiple agents found with identifier '%s'. Returning the most recently seen agent.", agentIdentifier),
		)
		//iterate through agents and find the most recently seen
		for _, a := range agents {
			// 1 = New
			// 2 = Approved
			// 3 = Disapproved
			if a.Status != 2 {
				tflog.Debug(ctx, fmt.Sprintf("Agent '%s' is not approved. Skipping.", a.AgentId))
				continue
			}

			aLastSeen, tErr := time.Parse(time.RFC3339, a.LastSeen)
			if tErr != nil {
				tflog.Warn(ctx, fmt.Sprintf("Error parsing LastSeen time for agent '%s'", a.AgentId))
				continue
			}

			currentAgentLastSeen, tErr2 := time.Parse(time.RFC3339, agent.LastSeen)
			if tErr2 != nil {
				tflog.Warn(ctx, fmt.Sprintf("Error parsing LastSeen time for agent '%s'", agent.AgentId))
				continue
			}
			if aLastSeen.After(currentAgentLastSeen) {
				agent = a
			}
		}
	}

	var cababilityValues []attr.Value
	for _, perm := range agent.Capabilities {
		tflog.Debug(ctx, fmt.Sprintf("Capability: %v", perm))
		cababilityValues = append(cababilityValues, types.String{Value: perm})
	}

	var result = KeyfactorAgent{
		AgentId:                     types.String{Value: agent.AgentId, Null: isNullString(agent.AgentId)},
		AgentIdentifier:             types.String{Value: state.AgentIdentifier.Value, Null: isNullString(state.AgentIdentifier.Value)},
		ClientMachine:               types.String{Value: agent.ClientMachine, Null: isNullString(agent.ClientMachine)},
		Username:                    types.String{Value: agent.Username, Null: isNullString(agent.Username)},
		AgentPlatform:               types.Int64{Value: int64(agent.AgentPlatform)},
		Status:                      types.Int64{Value: int64(agent.Status)},
		Version:                     types.String{Value: agent.Version, Null: isNullString(agent.Version)},
		LastSeen:                    types.String{Value: agent.LastSeen, Null: isNullString(agent.LastSeen)},
		Capabilities:                types.List{ElemType: types.StringType, Elems: cababilityValues},
		Blueprint:                   types.String{Value: agent.Blueprint, Null: isNullString(agent.Blueprint)},
		Thumbprint:                  types.String{Value: agent.Thumbprint, Null: isNullString(agent.Thumbprint)},
		LegacyThumbprint:            types.String{Value: agent.LegacyThumbprint, Null: isNullString(agent.LegacyThumbprint)},
		AuthCertificateReenrollment: types.String{Value: agent.AuthCertificateReenrollment, Null: isNullString(agent.AuthCertificateReenrollment)},
		LastThumbprintUsed:          types.String{Value: agent.LastThumbprintUsed, Null: isNullString(agent.LastThumbprintUsed)},
		LastErrorCode:               types.Int64{Value: int64(agent.LastErrorCode)},
		LastErrorMessage:            types.String{Value: agent.LastErrorMessage, Null: isNullString(agent.LastErrorMessage)},
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
