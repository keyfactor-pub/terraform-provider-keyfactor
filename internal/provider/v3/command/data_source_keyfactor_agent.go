package command

import (
	"context"
	"fmt"
	kfc "github.com/Keyfactor/keyfactor-go-client-sdk/v2/api/command"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"net/http"
)

var _ datasource.DataSource = &AgentDataSource{}

func NewAgentDataSource() datasource.DataSource {
	return &AgentDataSource{}
}

// AgentDataSource defines the data source implementation.
type AgentDataSource struct {
	provider *Provider
	client   *kfc.APIClient
}

func (d *AgentDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "keyfactor_agent"
}

func (d *AgentDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"agent_id": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the GUID of the orchestrator.",
				MarkdownDescription: "A string indicating the GUID of the orchestrator.",
			},
			"agent_identifier": schema.StringAttribute{
				Required:            true,
				Description:         "A string indicating the GUID or client machine name of the orchestrator.",
				MarkdownDescription: "A string indicating the GUID or client machine name of the orchestrator.",
			},
			"agent_platform": schema.Int64Attribute{
				Computed:            true,
				Description:         "An integer indicating the platform for the orchestrator.\n- 0 = Unknown\n- 1 = Keyfactor Windows Orchestrator\n- 2 = Keyfactor Java Agent\n- 3 = Keyfactor Mac Auto-Enrollment Agent\n- 4 = Keyfactor Android Agent\n- 5 = Keyfactor Native Agent\n- 6 = Keyfactor Bash Orchestrator\n- 7 = Keyfactor Universal Orchestrator\n",
				MarkdownDescription: "An integer indicating the platform for the orchestrator.\n- 0 = Unknown\n- 1 = Keyfactor Windows Orchestrator\n- 2 = Keyfactor Java Agent\n- 3 = Keyfactor Mac Auto-Enrollment Agent\n- 4 = Keyfactor Android Agent\n- 5 = Keyfactor Native Agent\n- 6 = Keyfactor Bash Orchestrator\n- 7 = Keyfactor Universal Orchestrator\n",
			},
			"auth_certificate_reenrollment": schema.StringAttribute{
				Computed:            true,
				Description:         "An integer indicating the value of the orchestrator certificate reenrollment request or require status.\nPossible values:\n- 0 = None—Unset the value so that the orchestrator will not request a new client authentication certificate (based on this value).\n- 1 = Requested—The orchestrator will request a new client authentication certificate when it next registers for a session. Orchestrator activity will be allowed to continue as usual.\n- 2 = Required—The orchestrator will request a new client authentication certificate when it next registers for a session. A new session will not be granted and orchestrator activity will not be allowed to continue until the orchestrator acquires a new certificate.\n",
				MarkdownDescription: "An integer indicating the value of the orchestrator certificate reenrollment request or require status.\nPossible values:\n- 0 = None—Unset the value so that the orchestrator will not request a new client authentication certificate (based on this value).\n- 1 = Requested—The orchestrator will request a new client authentication certificate when it next registers for a session. Orchestrator activity will be allowed to continue as usual.\n- 2 = Required—The orchestrator will request a new client authentication certificate when it next registers for a session. A new session will not be granted and orchestrator activity will not be allowed to continue until the orchestrator acquires a new certificate.\n",
			},
			"blueprint": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the name of the blueprint associated with the orchestrator.",
				MarkdownDescription: "A string indicating the name of the blueprint associated with the orchestrator.",
			},
			"capabilities": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				Description:         "An array of strings indicating the capabilities reported by the orchestrator. These may be built-in or custom capabilities.",
				MarkdownDescription: "An array of strings indicating the capabilities reported by the orchestrator. These may be built-in or custom capabilities.",
			},
			"client_machine": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the client machine on which the orchestrator is installed.",
				MarkdownDescription: "A string indicating the client machine on which the orchestrator is installed.",
			},
			"id": schema.StringAttribute{
				//Required:            true,
				Computed:            true,
				Description:         "A string indicating the GUID of the orchestrator.",
				MarkdownDescription: "A string indicating the GUID of the orchestrator.",
			},
			"last_error_code": schema.Int64Attribute{
				Computed:            true,
				Description:         "An integer indicating the last error code, if any, reported from the orchestrator when trying to register a session. This code is cleared on successful session registration.",
				MarkdownDescription: "An integer indicating the last error code, if any, reported from the orchestrator when trying to register a session. This code is cleared on successful session registration.",
			},
			"last_error_message": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the last error message, if any, reported from the orchestrator when trying to register a session. This message is cleared on successful session registration.",
				MarkdownDescription: "A string indicating the last error message, if any, reported from the orchestrator when trying to register a session. This message is cleared on successful session registration.",
			},
			"last_seen": schema.StringAttribute{
				Computed:            true,
				Description:         "The time, in UTC, at which the orchestrator last contacted Keyfactor Command.",
				MarkdownDescription: "The time, in UTC, at which the orchestrator last contacted Keyfactor Command.",
			},
			"last_thumbprint_used": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the thumbprint of the certificate that the orchestrator most recently used for client certificate authentication. In most cases, this will match the Thumbprint.",
				MarkdownDescription: "A string indicating the thumbprint of the certificate that the orchestrator most recently used for client certificate authentication. In most cases, this will match the Thumbprint.",
			},
			"legacy_thumbprint": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the thumbprint of the certificate previously used by the orchestrator for client certificate authentication before a certificate renewal operation took place (rotating the current thumbprint into the legacy thumbprint). The legacy thumbprint is cleared once the orchestrator successfully registers with the new thumbprint.",
				MarkdownDescription: "A string indicating the thumbprint of the certificate previously used by the orchestrator for client certificate authentication before a certificate renewal operation took place (rotating the current thumbprint into the legacy thumbprint). The legacy thumbprint is cleared once the orchestrator successfully registers with the new thumbprint.",
			},
			"status": schema.Int64Attribute{
				Computed:            true,
				Description:         "An integer indicating the orchestrator status:\n- 1 = New\n- 2 = Approved\n- 3 = Disapproved\n",
				MarkdownDescription: "An integer indicating the orchestrator status:\n- 1 = New\n- 2 = Approved\n- 3 = Disapproved\n",
			},
			"thumbprint": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the thumbprint of the certificate that Keyfactor Command is expecting the orchestrator to use for client certificate authentication.",
				MarkdownDescription: "A string indicating the thumbprint of the certificate that Keyfactor Command is expecting the orchestrator to use for client certificate authentication.",
			},
			"username": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the Active Directory user or service account the orchestrator is using to connect to Keyfactor Command.",
				MarkdownDescription: "A string indicating the Active Directory user or service account the orchestrator is using to connect to Keyfactor Command.",
			},
			"version": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the version of the orchestrator.",
				MarkdownDescription: "A string indicating the version of the orchestrator.",
			},
		},
	}
}

type AgentModel struct {
	AgentId                     types.String `tfsdk:"agent_id"`
	AgentIdentifier             types.String `tfsdk:"agent_identifier"`
	AgentPlatform               types.Int64  `tfsdk:"agent_platform"`
	AuthCertificateReenrollment types.String `tfsdk:"auth_certificate_reenrollment"`
	Blueprint                   types.String `tfsdk:"blueprint"`
	Capabilities                types.List   `tfsdk:"capabilities"`
	ClientMachine               types.String `tfsdk:"client_machine"`
	Id                          types.String `tfsdk:"id"`
	LastErrorCode               types.Int64  `tfsdk:"last_error_code"`
	LastErrorMessage            types.String `tfsdk:"last_error_message"`
	LastSeen                    types.String `tfsdk:"last_seen"`
	LastThumbprintUsed          types.String `tfsdk:"last_thumbprint_used"`
	LegacyThumbprint            types.String `tfsdk:"legacy_thumbprint"`
	Status                      types.Int64  `tfsdk:"status"`
	Thumbprint                  types.String `tfsdk:"thumbprint"`
	Username                    types.String `tfsdk:"username"`
	Version                     types.String `tfsdk:"version"`
}

func (d *AgentDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*kfc.APIClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *kfc.APIClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *AgentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AgentModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.AgentIdentifier.IsNull() || data.AgentIdentifier.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Invalid Agent Identifier",
			"agent_identifier must not be null or empty, please provide either a GUID or ClientMachine name.",
		)
		return
	}

	ctx = tflog.SetField(ctx, "agent_identifier", data.AgentIdentifier.ValueString())
	tflog.Info(ctx, "Read called on agent data source")

	agentsResp, httpResp, httpRespErr := d.lookupAgent(ctx, data.AgentIdentifier.ValueString())

	if httpRespErr != nil {
		resp.Diagnostics.AddError(
			"Agent Read Error",
			fmt.Sprintf("Error querying Keyfactor Command for agent '%s': %s", data.AgentIdentifier.ValueString(), httpRespErr.Error()),
		)
		return
	} else if httpResp != nil && httpResp.StatusCode != 200 {
		resp.Diagnostics.AddError(
			"Agent Read Error",
			fmt.Sprintf("Error querying Keyfactor Command for agent '%s': %s", data.AgentIdentifier.String(), httpResp.Status),
		)
		return
	}

	if agentsResp == nil {
		resp.Diagnostics.AddError(
			"Agent Not Found",
			fmt.Sprintf("No agent found with identifier '%s'", data.AgentIdentifier.String()),
		)
		return
	}

	tflog.Info(ctx, "Setting agent data source attributes")
	data.AgentId = types.StringValue(*agentsResp.AgentId)
	data.AgentPlatform = types.Int64Value(convertInt64Ptr(agentsResp.AgentPlatform))
	data.AuthCertificateReenrollment = types.StringValue(*agentsResp.AuthCertificateReenrollment)
	data.Blueprint = types.StringValue(convertStringPtr(agentsResp.Blueprint))
	data.Capabilities, _ = convertToTerraformList(agentsResp.Capabilities)
	data.ClientMachine = types.StringValue(*agentsResp.ClientMachine)
	data.Id = types.StringValue(*agentsResp.AgentId)
	//data.LastErrorCode = types.Int64Value(convertInt64Ptr(int(*agentsResp.LastErrorCode)))
	data.LastErrorMessage = types.StringValue(convertStringPtr(agentsResp.LastErrorMessage))
	data.LastSeen = types.StringValue(convertTimeToStringPtr(agentsResp.LastSeen))
	data.LastThumbprintUsed = types.StringValue(convertStringPtr(agentsResp.LastThumbprintUsed))
	data.LegacyThumbprint = types.StringValue(*agentsResp.LegacyThumbprint)
	data.Status = types.Int64Value(convertInt64Ptr(agentsResp.Status))
	data.Thumbprint = types.StringValue(*agentsResp.Thumbprint)
	data.Username = types.StringValue(*agentsResp.Username)
	data.Version = types.StringValue(*agentsResp.Version)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *AgentDataSource) lookupAgent(ctx context.Context, identifier string) (*kfc.KeyfactorApiModelsOrchestratorsAgentResponse, *http.Response, error) {
	// Check if string is a GUID
	if _, err := uuid.Parse(identifier); err != nil {
		// Not a GUID, so look up by client machine name
		tflog.Info(ctx, fmt.Sprintf("Agent identifier '%s' is not a GUID. Looking up by client machine name.", identifier))
		agents, httpResp, httpRespErr := d.client.AgentApi.AgentGetAgents(ctx).
			PqQueryString(fmt.Sprintf("ClientMachine -eq \"%s\"", identifier)).
			Execute()
		if httpRespErr != nil {
			return nil, httpResp, httpRespErr
		} else if len(agents) == 0 {
			return nil, httpResp, httpRespErr
		} else if len(agents) >= 1 {
			//iterate through agents and find the most recently seen
			mostRecentAgent := agents[0]
			for _, a := range agents {
				// 1 = New
				// 2 = Approved
				// 3 = Disapproved
				if *a.Status != 2 {
					tflog.Debug(ctx, fmt.Sprintf("Agent '%s' is not approved. Skipping.", *a.AgentId))
					continue
				}

				if mostRecentAgent.LastSeen == nil {
					mostRecentAgent = a
					continue
				} else if a.LastSeen == nil {
					continue
				} else if mostRecentAgent.LastSeen.After(*a.LastSeen) {
					mostRecentAgent = a
				}
			}
			return &mostRecentAgent, httpResp, httpRespErr
		}
	}

	// Lookup agent by GUID
	tflog.Info(ctx, fmt.Sprintf("Agent identifier '%s' is a GUID. Looking up by GUID.", identifier))
	agent, httpResp, httpRespErr := d.client.AgentApi.AgentGetAgentDetail(ctx, identifier).Execute()
	if httpRespErr != nil {
		tflog.Error(ctx, fmt.Sprintf("error querying Keyfactor Command for agent '%s': %s", identifier, httpRespErr.Error()))
		return nil, httpResp, httpRespErr
	} else if httpResp.StatusCode != 200 {
		apiErr := fmt.Errorf("error '%s' querying Keyfactor Command for agent '%s'", httpResp.Status, identifier)
		return nil, httpResp, apiErr
	}
	return agent, httpResp, httpRespErr
}

func (d *AgentDataSource) lookupRandomAgent(ctx context.Context) (*kfc.KeyfactorApiModelsOrchestratorsAgentResponse, *http.Response, error) {
	agentResp, httpResp, httpErr := d.client.AgentApi.AgentGetAgents(ctx).Execute()
	if httpErr != nil {
		return nil, httpResp, httpErr
	} else if agentResp != nil {
		for _, agent := range agentResp {
			if agent.AgentId != nil && *agent.AgentId != "" && agent.Status != nil && *agent.Status == ApprovedAgentStatus {
				return &agent, httpResp, httpErr
			}
		}
	}
	return nil, httpResp, fmt.Errorf(AgentNotFound)
}
