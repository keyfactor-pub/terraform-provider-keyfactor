package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceCertificateStoreType struct{}

func (r resourceCertificateStoreType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Keyfactor Command certificate store GUID.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"container_id": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Container identifier of the store's associated certificate store container.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"display_name": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Display name of the certificate store. Is the concatenation of 'ClientMachine - StorePath'.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"client_machine": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Client machine name; value depends on certificate store type. See API reference guide and/or store type documentation.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_path": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Path to the new certificate store on a target. Format varies depending on store type see the store type documentation for more information.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_type": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Short name of certificate store type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"approved": {
				Type:          types.BoolType,
				Description:   "Bool that indicates the approval status of store. Unapproved stores come from store Discovery and cannot be used for certificate operations.",
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"create_if_missing": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Determines whether the store create job will be scheduled. WARNING: If set to TRUE, each apply will trigger a store create job, if the store type support Create. This may cause issues if the store already exists but will depend on the store type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"properties": {
				Type:        types.MapType{ElemType: types.StringType},
				Optional:    true,
				Description: "Certificate properties specific to certificate store type configured as key-value pairs. NOTE: Special properties 'ServerUsername' and 'ServerPassword' are required for some store types and should not be declared in this attribute and have their own dedicated values. See store type documentation for more information.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Can be either ClientMachine or the Keyfactor Command GUID of the orchestrator to use for managing the certificate store. The agent must support the certificate store type and be approved.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "String indicating the Keyfactor Command GUID of the orchestrator for the created store.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"agent_assigned": {
				Type:          types.BoolType,
				Computed:      true,
				Description:   "Bool indicating if there is an orchestrator assigned to the new certificate store.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"container_name": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Name of the container/application to associate with the certificate store. Kept for backwards compatibility; prefer `application_name` for Command v25.x+. NOTE: The container/application must already exist and be of the same certificate store type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"application_name": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Name of the application (formerly 'container') to associate with the certificate store. Preferred field as of Keyfactor Command v25.x. Functionally equivalent to `container_name`. NOTE: The application must already exist and be of the same certificate store type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"inventory_schedule": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   `String indicating the schedule for inventory updates. Valid formats are: "immediate", "Daily at HH:MM:SS", "Exactly once at HH:MM:SS", or interval notation like "30m", "12h".`,
				PlanModifiers: []tfsdk.AttributePlanModifier{useStateOrNullModifier{}},
			},
			"set_new_password_allowed": {
				Type:          types.BoolType,
				Computed:      true,
				Description:   "Indicates whether the store password can be changed.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"store_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "The password to access the contents of the certificate store. In Keyfactor Command this is the 'StorePassword' field. field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"server_username": {
				Type:        types.StringType,
				Optional:    true,
				Description: "The username to access the host of the certificate store. In Keyfactor Command this is the 'ServerUsername' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
			"server_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "The password to access the host of the certificate store. In Keyfactor Command this is the 'ServerUsername' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
			"server_use_ssl": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Indicates whether the certificate store host requires SSL. In Keyfactor Command this is the 'ServerUseSsl' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
		},
		Description: "Used to manage Keyfactor Command certificate stores using the `/CertificateStores` API, which " +
			"can be used with `keyfactor_certificate_deployment` resources.",
	}, nil
}

func (r resourceCertificateStoreType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCertificateStore{
		p: *(p.(*provider)),
	}, nil
}

type resourceCertificateStore struct {
	p provider
}

// resolveApprovedAgentID interprets the result of a GetAgent lookup (identifier,
// the returned agents, and any lookup error) and returns the ID of the first
// approved (Status == 2) agent, or diagnostics explaining why none could be
// resolved. Shared by Create and Update so the two code paths can never diverge.
func resolveApprovedAgentID(identifier string, agents []api.Agent, agentErr error) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	agentId := ""
	if agentErr != nil {
		diags.AddError(
			"Invalid agent identifier.",
			fmt.Sprintf(
				"Agent could not be found on Keyfactor Command using identifier '%s'. %s",
				identifier,
				agentErr.Error(),
			),
		)
		return "", diags
	} else if len(agents) == 0 {
		diags.AddError(
			"Agent Not Found.",
			fmt.Sprintf(
				"no agent found for identifier %q",
				identifier,
			),
		)
		return "", diags
	} else {
		if len(agents) > 1 {
			diags.AddWarning(
				"Agent Not Found.",
				fmt.Sprintf(
					"Multiple agents found with identifier '%s' returned from Keyfactor Command. Using first approved agent",
					identifier,
				),
			)
		}

		//iterate over agents and find the first approved agent
		for _, agent := range agents {
			if agent.Status != 2 {
				continue
			}
			agentId = agent.AgentId
			break
		}

		if agentId == "" {
			diags.AddError(
				"Approved Agent Not Found.",
				fmt.Sprintf(
					"No approved agents with identifier '%s' were found on Keyfactor Command. Please review your agents on the Keyfactor Command Portal by going to Orchestrators > Management, and ensure the one you're looking for is approved.",
					identifier,
				),
			)
			return "", diags
		}
	}

	return agentId, diags
}

func (r resourceCertificateStore) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan CertificateStore
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	//certificateStoreId := plan.ID.Value
	//ctx = tflog.SetField(ctx, "id", certificateStoreId)
	tflog.Info(ctx, "Create called on certificate store resource")

	csType, csTypeErr := r.p.client.GetCertificateStoreTypeByName(plan.StoreType.Value)
	if csTypeErr != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store type.",
			fmt.Sprintf(
				"Could not retrieve certificate store type '%s' from Keyfactor"+csTypeErr.Error(),
				plan.StoreType.Value,
			),
		)
		return
	}

	containerId := 0
	effectiveName, nameIsNull := plan.effectiveContainerName()
	if !nameIsNull {
		var containerErr error
		containerId, containerErr = r.resolveContainerIDByName(effectiveName)
		if containerErr != nil {
			response.Diagnostics.AddError(
				"Invalid application/container name.",
				fmt.Sprintf(
					"Could not retrieve application/container '%s' from Keyfactor: %s",
					effectiveName,
					containerErr.Error(),
				),
			)
			return
		}
	}

	var properties map[string]string
	if plan.Properties.Elems != nil {
		propConvErr := plan.Properties.ElementsAs(ctx, &properties, false)
		if propConvErr != nil {
			response.Diagnostics.AddError(
				"Invalid properties error.",
				fmt.Sprintf("Invalid properties for certificate store creating certificate store: %s", propConvErr),
			)
			return
		}
	} else {
		properties = make(map[string]string)
	}
	//Add Special Properties to properties map
	if !plan.ServerUsername.IsNull() {
		properties["ServerUsername"] = plan.ServerUsername.Value
	}
	if !plan.ServerPassword.IsNull() {
		properties["ServerPassword"] = plan.ServerPassword.Value
	}
	if !plan.ServerUseSsl.IsNull() {
		properties["ServerUseSsl"] = strconv.FormatBool(plan.ServerUseSsl.Value)
	}

	schedule, err := createInventorySchedule(plan.InventorySchedule.Value) // TODO: Implement inventory schedule
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid inventory schedule.",
			fmt.Sprintf("Could not create inventory schedule: %s", err.Error()),
		)
		return
	}

	var storePassFormatted *api.UpdateStorePasswordConfig
	if plan.StorePassword.Null {
		storePassFormatted = nil
	} else {
		storePassFormatted = createPasswordConfig(plan.StorePassword.Value)
	}

	//Lookup agent by AgentIdentifier
	agents, agentErr := kfClient.GetAgent(plan.AgentIdentifier.Value)
	agentId, agentDiags := resolveApprovedAgentID(plan.AgentIdentifier.Value, agents, agentErr)
	response.Diagnostics.Append(agentDiags...)
	if response.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("Agent: %s", agentId))

	//if plan.CreateIfMissing.IsNull() {
	//	plan.CreateIfMissing = types.Bool{Value: false}
	//}
	//convert properties to map[string]interface{} for api call
	propsInterface := make(map[string]interface{})
	for k, v := range properties {
		propsInterface[k] = v
	}

	newStoreArgs := &api.CreateStoreFctArgs{
		ContainerId:           intToPointer(containerId),
		ClientMachine:         plan.ClientMachine.Value,
		StorePath:             plan.StorePath.Value,
		CertStoreType:         csType.StoreType,
		Approved:              &plan.Approved.Value,
		CreateIfMissing:       &plan.CreateIfMissing.Value,
		Properties:            propsInterface,
		AgentId:               agentId,
		AgentAssigned:         &plan.AgentAssigned.Value,
		ContainerName:         containerNameArgPointer(containerId, effectiveName),
		InventorySchedule:     schedule,
		SetNewPasswordAllowed: &plan.SetNewPasswordAllowed.Value,
		Password:              storePassFormatted,
	}

	createStoreResponse, err := kfClient.CreateStore(newStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating certificate store",
			"Error creating certificate store: %s"+err.Error(),
		)
		return
	}

	// Set state
	var result = CertificateStore{
		ID: types.String{Value: createStoreResponse.Id},
		ContainerID: types.Int64{
			Null:  plan.ContainerID.Null,
			Value: int64(createStoreResponse.ContainerId),
		},
		DisplayName:           types.String{Value: fmt.Sprintf("%s - %s", createStoreResponse.ClientMachine, createStoreResponse.Storepath)},
		ClientMachine:         types.String{Value: createStoreResponse.ClientMachine},
		StorePath:             types.String{Value: createStoreResponse.Storepath},
		StoreType:             plan.StoreType,
		Approved:              types.Bool{Value: createStoreResponse.Approved},
		CreateIfMissing:       types.Bool{Value: createStoreResponse.CreateIfMissing},
		Properties:            plan.Properties,
		AgentId:               types.String{Value: createStoreResponse.AgentId},
		AgentIdentifier:       plan.AgentIdentifier,
		AgentAssigned:         types.Bool{Value: createStoreResponse.AgentAssigned},
		InventorySchedule:     resolveInventoryScheduleState(plan.InventorySchedule, &createStoreResponse.InventorySchedule),
		SetNewPasswordAllowed: types.Bool{Value: createStoreResponse.SetNewPasswordAllowed},
		StorePassword:         plan.StorePassword,
		ServerUsername:        plan.ServerUsername,
		ServerPassword:        plan.ServerPassword,
		ServerUseSsl:          plan.ServerUseSsl,
		//Certificates:          types.List{ElemType: types.Int64Type, Elems: []attr.Value{}},
	}
	// The server never echoes ContainerName in Create/GET responses (always null).
	// Resolve the name from the ContainerId by looking up the container directly
	// by ID. The list endpoint is paginated (default 50/page), so a just-created
	// container may not appear on the first page — see lookupContainerNameByID.
	result.syncApplicationAndContainerName(lookupContainerNameByID(ctx, kfClient, createStoreResponse.ContainerId, effectiveName))

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

func (r resourceCertificateStore) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state CertificateStore
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate store resource")
	certificateStoreId := state.ID.Value

	tflog.SetField(ctx, "id", certificateStoreId)

	sResp, err := r.p.client.GetCertificateStoreByID(certificateStoreId)
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERT_STORE_READ,
			fmt.Sprintf("Error reading certificate store: '%s'. %s", certificateStoreId, err.Error()),
		)
		return
	}

	var result = CertificateStore{
		ID: types.String{Value: sResp.Id},
		ContainerID: types.Int64{
			Null:  state.ContainerID.Null,
			Value: int64(sResp.ContainerId),
		},
		DisplayName:     types.String{Value: fmt.Sprintf("%s - %s", sResp.ClientMachine, sResp.StorePath)},
		ClientMachine:   types.String{Value: sResp.ClientMachine},
		StorePath:       types.String{Value: sResp.StorePath},
		StoreType:       state.StoreType,
		Approved:        types.Bool{Value: sResp.Approved},
		CreateIfMissing: state.CreateIfMissing,
		Properties:      state.Properties, //TODO: Parse this w/o special properties included
		AgentId:         types.String{Value: sResp.AgentId},
		AgentIdentifier: state.AgentIdentifier,
		AgentAssigned:   types.Bool{Value: sResp.AgentAssigned},
		InventorySchedule: func() types.String {
			s := parseInventorySchedule(&sResp.InventorySchedule)
			if s == "" {
				return state.InventorySchedule
			}
			return types.String{Value: s}
		}(),
		SetNewPasswordAllowed: types.Bool{Value: sResp.SetNewPasswordAllowed},
		StorePassword:         state.StorePassword,  //TODO: Currently command doesn't return this as of 10.x
		ServerUsername:        state.ServerUsername, //TODO: Parse this from sResp.Properties
		ServerPassword:        state.ServerPassword, //TODO: Parse this from sResp.Properties
		ServerUseSsl:          state.ServerUseSsl,   //TODO: Parse this from sResp.Properties
		//Certificates:          types.List{ElemType: types.Int64Type, Elems: []attr.Value{}},
	}
	// Resolve container name from ContainerId via the by-ID endpoint (the list
	// endpoint is paginated and may not include a recently-created container).
	// Fall back to the prior state value if the API lookup fails.
	stateName, _ := state.effectiveContainerName()
	result.syncApplicationAndContainerName(lookupContainerNameByID(ctx, r.p.client, sResp.ContainerId, stateName))

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

// resolveContainerIDByName looks up a container/application by name and
// returns its numeric ID. Shared by Create() and
// resolveContainerAssignmentForUpdate so the lookup (and its error handling)
// doesn't drift between the two call sites. Guards against a latent
// nil-pointer dereference that existed in both call sites previously: the API
// can return a nil container alongside a nil error (nothing found, no
// explicit failure), and calling .Error() on a nil error panics.
func (r resourceCertificateStore) resolveContainerIDByName(name string) (int, error) {
	storeContainer, err := r.p.client.GetStoreContainer(name)
	if err != nil {
		return 0, err
	}
	if storeContainer == nil || storeContainer.Id == nil {
		return 0, fmt.Errorf("container/application %q not found", name)
	}
	return *storeContainer.Id, nil
}

// containerNameArgPointer builds the ContainerName pointer for
// Create/UpdateStoreFctArgs from a resolved containerId and name.
//
// When containerId is nonzero, an unresolved (empty) name is omitted from the
// request (via stringToPointer, which maps "" to nil, omitted by the
// `omitempty` tag) rather than sent as a literal empty string — pairing a
// real, nonzero containerId with an explicit empty ContainerName is a
// combination that never occurred before GH issue #175's fix and whose
// handling on Command's UpdateStore endpoint is unverified; there's no reason
// to introduce it when omitting the field entirely is both safe and
// sufficient (containerId is what actually carries the assignment).
//
// When containerId is 0, the name is sent explicitly (even if empty) exactly
// as before this fix — this is the long-standing, tested "no
// assignment"/explicit-clear request shape and must not change.
func containerNameArgPointer(containerId int, name string) *string {
	if containerId != 0 {
		return stringToPointer(name)
	}
	return &name
}

// resolveContainerAssignmentForUpdate determines the container/application ID
// (and, best-effort, name) to send in the UpdateStoreFctArgs body during
// Update().
//
// Background (GH issue #175): Command's UpdateStore endpoint treats an
// omitted ContainerId as an explicit instruction to CLEAR the store's
// container/application assignment — UpdateStoreFctArgs.ContainerId is
// `json:"ContainerId,omitempty"`, and intToPointer(0) returns nil, so a
// resolved containerId of 0 is dropped from the request body entirely rather
// than sent as an explicit zero. Previously, whenever the plan gave no
// explicit application_name/container_name (nameIsNull), containerId was
// simply left at 0 with no regard for whether the store already had a real
// assignment server-side. That silently deleted a live container/application
// assignment on the very next Update() — including one that was only ever
// made out-of-band (e.g. directly via the API) and never represented in
// Terraform config — well before Terraform's own "inconsistent result after
// apply" check had a chance to catch anything.
//
// effectiveContainerName() (models.go) only checks .Value != "", never
// .IsNull(), so it collapses two very different signals into the same
// nameIsNull=true result: "the attribute was never declared in config" and
// "the attribute was explicitly set to \"\" to clear the assignment." Those
// must be handled differently — the former should preserve a real existing
// assignment, but the latter is an explicit user instruction to remove it and
// must still resolve containerId to 0, exactly as before this fix. This
// function re-checks plan.ApplicationName/ContainerName directly via
// IsNull() to tell them apart: it only preserves the existing assignment
// when BOTH attributes are genuinely null in the plan (truly undeclared). If
// either was explicitly set (even to ""), that's treated as an explicit
// clear signal.
func (r resourceCertificateStore) resolveContainerAssignmentForUpdate(
	ctx context.Context,
	plan CertificateStore,
	state CertificateStore,
) (containerId int, effectiveName string, err error) {
	effectiveName, nameIsNull := plan.effectiveContainerName()
	if !nameIsNull {
		id, containerErr := r.resolveContainerIDByName(effectiveName)
		if containerErr != nil {
			return 0, effectiveName, containerErr
		}
		return id, effectiveName, nil
	}

	planTrulyUndeclared := plan.ApplicationName.IsNull() && plan.ContainerName.IsNull()
	if planTrulyUndeclared && state.ContainerID.Value != 0 {
		preservedId := int(state.ContainerID.Value)
		preservedName, preservedNameIsNull := state.effectiveContainerName()
		if preservedNameIsNull {
			// The prior state never resolved a name either (e.g. the
			// assignment was made out-of-band and this is the first Read()
			// since). Best-effort re-resolve it directly so the request body
			// stays internally consistent; an unresolved "" is handled
			// safely by containerNameArgPointer (omitted, not sent as a
			// literal empty string) since containerId is what actually
			// preserves the assignment.
			preservedName = lookupContainerNameByID(ctx, r.p.client, preservedId, "")
			if preservedName == "" {
				tflog.Warn(
					ctx,
					fmt.Sprintf(
						"Update: preserving existing container_id (%d) because config declares no application_name/container_name, but could not resolve its name from state or the API; the request will omit ContainerName (see GH issue #175)",
						preservedId,
					),
				)
			} else {
				tflog.Debug(
					ctx,
					fmt.Sprintf(
						"Update: config declares no application_name/container_name; preserving existing container_id (%d), resolved name %q via the API (see GH issue #175)",
						preservedId,
						preservedName,
					),
				)
			}
		} else {
			tflog.Debug(
				ctx,
				fmt.Sprintf(
					"Update: config declares no application_name/container_name; preserving existing container_id (%d) and name %q from state (see GH issue #175)",
					preservedId,
					preservedName,
				),
			)
		}
		return preservedId, preservedName, nil
	}

	return 0, "", nil
}

func (r resourceCertificateStore) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// Get plan values
	var plan CertificateStore
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state CertificateStore
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	csType, csTypeErr := r.p.client.GetCertificateStoreTypeByName(plan.StoreType.Value)
	if csTypeErr != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store type.",
			fmt.Sprintf(
				"Could not retrieve certificate store type '%s' from Keyfactor"+csTypeErr.Error(),
				plan.StoreType.Value,
			),
		)
		return
	}
	schedule, err := inventoryScheduleForRequest(plan.InventorySchedule)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid inventory schedule.",
			fmt.Sprintf("Could not create inventory schedule: %s", err.Error()),
		)
		return
	}

	containerId, updateEffectiveName, containerErr := r.resolveContainerAssignmentForUpdate(ctx, plan, state)
	if containerErr != nil {
		response.Diagnostics.AddError(
			"Invalid application/container name.",
			fmt.Sprintf(
				"Could not retrieve application/container '%s' from Keyfactor: %s",
				updateEffectiveName,
				containerErr.Error(),
			),
		)
		return
	}

	var storePassFormatted *api.UpdateStorePasswordConfig
	if plan.StorePassword.Null {
		storePassFormatted = nil
	} else {
		storePassFormatted = createPasswordConfig(plan.StorePassword.Value)
	}

	agents, agentErr := r.p.client.GetAgent(plan.AgentIdentifier.Value)
	agentId, agentDiags := resolveApprovedAgentID(plan.AgentIdentifier.Value, agents, agentErr)
	response.Diagnostics.Append(agentDiags...)
	if response.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("Agent: %s", agentId))

	properties := make(map[string]interface{})
	var existingProperties map[string]string
	if plan.Properties.Elems != nil {
		propConvErr := plan.Properties.ElementsAs(ctx, &existingProperties, false)
		if propConvErr != nil {
			response.Diagnostics.AddError(
				"Invalid properties error.",
				fmt.Sprintf("Invalid properties for certificate store updating certificate store: %s", propConvErr),
			)
			return
		}
	}
	//add existing properties to properties map
	for k, v := range existingProperties {
		properties[k] = v
	}
	//Add Special Properties to properties map
	if !plan.ServerUsername.IsNull() {
		properties["ServerUsername"] = plan.ServerUsername.Value
	}
	if !plan.ServerPassword.IsNull() {
		properties["ServerPassword"] = plan.ServerPassword.Value
	}
	if !plan.ServerUseSsl.IsNull() {
		properties["ServerUseSsl"] = strconv.FormatBool(plan.ServerUseSsl.Value)
	}

	propertiesStr, psErr := mapToEscapedJSONString(properties)
	if psErr != nil {
		response.Diagnostics.AddError(
			"Invalid properties error.",
			fmt.Sprintf("Invalid properties for certificate store updating certificate store: %s", psErr.Error()),
		)
		return
	}

	// For Computed fields, use state value when plan is Unknown (zero value would corrupt the request).
	approvedVal := state.Approved.Value
	if !plan.Approved.Unknown {
		approvedVal = plan.Approved.Value
	}
	agentAssignedVal := state.AgentAssigned.Value
	if !plan.AgentAssigned.Unknown {
		agentAssignedVal = plan.AgentAssigned.Value
	}
	setNewPasswordAllowedVal := state.SetNewPasswordAllowed.Value
	if !plan.SetNewPasswordAllowed.Unknown {
		setNewPasswordAllowedVal = plan.SetNewPasswordAllowed.Value
	}
	createIfMissingVal := state.CreateIfMissing.Value
	if !plan.CreateIfMissing.Unknown {
		createIfMissingVal = plan.CreateIfMissing.Value
	}

	updateStoreArgs := &api.UpdateStoreFctArgs{
		Id:                    state.ID.Value,
		ContainerId:           intToPointer(containerId),
		ClientMachine:         plan.ClientMachine.Value,
		StorePath:             plan.StorePath.Value,
		CertStoreType:         csType.StoreType,
		Approved:              &approvedVal,
		CreateIfMissing:       &createIfMissingVal,
		Properties:            properties,
		PropertiesString:      propertiesStr,
		AgentId:               agentId,
		AgentAssigned:         &agentAssignedVal,
		ContainerName:         containerNameArgPointer(containerId, updateEffectiveName),
		InventorySchedule:     schedule,
		SetNewPasswordAllowed: &setNewPasswordAllowedVal,
		Password:              storePassFormatted,
	}

	// log updatestore args as json
	tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %v", *updateStoreArgs))
	// convert updatestore args to json string
	updateStoreArgsJson, err := json.Marshal(updateStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store configuration error.",
			fmt.Sprintf("Invalid configuration for certificate store: %s", err.Error()),
		)
		return
	}
	// log updatestore args as json string
	tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %s", updateStoreArgsJson))
	updateResponse, err := r.p.client.UpdateStore(updateStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating certificate store",
			"Error updating certificate store: %s"+err.Error(),
		)
		return
	}

	// Log response
	tflog.Trace(ctx, fmt.Sprintf("UpdateStoreResponse: %v", *updateResponse))

	result := CertificateStore{
		ID: types.String{Value: updateResponse.Id},
		ContainerID: types.Int64{
			Null:  plan.ContainerID.Null,
			Value: int64(updateResponse.ContainerId),
		},
		DisplayName:           types.String{Value: fmt.Sprintf("%s - %s", updateResponse.ClientMachine, updateResponse.Storepath)},
		ClientMachine:         types.String{Value: updateResponse.ClientMachine},
		StorePath:             types.String{Value: updateResponse.Storepath},
		StoreType:             plan.StoreType,
		Approved:              types.Bool{Value: updateResponse.Approved},
		CreateIfMissing:       types.Bool{Value: updateResponse.CreateIfMissing},
		Properties:            plan.Properties,
		AgentId:               types.String{Value: updateResponse.AgentId},
		AgentIdentifier:       plan.AgentIdentifier,
		AgentAssigned:         types.Bool{Value: updateResponse.AgentAssigned},
		InventorySchedule:     resolveInventoryScheduleState(plan.InventorySchedule, &updateResponse.InventorySchedule),
		SetNewPasswordAllowed: types.Bool{Value: updateResponse.SetNewPasswordAllowed},
		StorePassword:         plan.StorePassword,
		ServerUsername:        plan.ServerUsername,
		ServerPassword:        plan.ServerPassword,
		ServerUseSsl:          plan.ServerUseSsl,
	}
	// Resolve container name from ContainerId (server never returns ContainerName).
	//
	// resolveContainerAssignmentForUpdate already confidently resolved
	// updateEffectiveName above (either from an explicit plan value, or by
	// preserving/re-resolving it from state) whenever it's non-empty. As long
	// as the container/application actually assigned server-side
	// (updateResponse.ContainerId) matches what we asked for, reuse that name
	// instead of spending up to 2 more HTTP round trips re-resolving
	// something we already know. Only fall back to a fresh lookup when we
	// don't already have a confident answer (updateEffectiveName is empty) or
	// the server assigned something other than what we requested.
	if updateResponse.ContainerId == containerId && updateEffectiveName != "" {
		result.syncApplicationAndContainerName(updateEffectiveName)
	} else {
		result.syncApplicationAndContainerName(lookupContainerNameByID(ctx, r.p.client, updateResponse.ContainerId, updateEffectiveName))
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCertificateStore) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	var state CertificateStore
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get order ID from state
	certificateStoreId := state.ID.Value
	tflog.SetField(ctx, "id", certificateStoreId)

	// Delete order by calling API
	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.

	tflog.Info(ctx, fmt.Sprintf("Revoking certificate %s in Keyfactor", certificateStoreId))

	err := kfClient.DeleteCertificateStore(certificateStoreId)
	if err != nil {
		response.Diagnostics.AddError(
			"Certificate store delete error.",
			fmt.Sprintf("Could not delete certificate store '%s' on Keyfactor: "+err.Error(), certificateStoreId),
		)
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

// storeImportRef captures the parsed components of a structured import ID for
// the keyfactor_certificate_store resource.
type storeImportRef struct {
	StoreID     string
	ContainerID string // empty when not provided; either numeric ID or container name
}

// parseStoreImportID parses one of the four accepted import ID forms for the
// keyfactor_certificate_store resource:
//
//   - "<guid>"                                          (legacy, bare GUID)
//   - "stores/<guid>"                                   (explicit, equivalent to bare GUID)
//   - "containers/<idOrName>/stores/<guid>"             (scope lookup by container; legacy alias)
//   - "applications/<idOrName>/stores/<guid>"           (scope lookup by application; preferred alias)
//
// "containers" and "applications" are interchangeable — both map to the same
// ContainerID field on the returned storeImportRef.
//
// Anything else returns an error listing the accepted formats.
func parseStoreImportID(raw string) (storeImportRef, error) {
	if raw == "" {
		return storeImportRef{}, fmt.Errorf(
			"import ID is empty; expected one of: \"<guid>\", \"stores/<guid>\", \"containers/<idOrName>/stores/<guid>\", or \"applications/<idOrName>/stores/<guid>\"",
		)
	}

	// Bare GUID — no slashes.
	if !strings.Contains(raw, "/") {
		return storeImportRef{StoreID: raw}, nil
	}

	parts := strings.Split(raw, "/")

	// "stores/<guid>"  → exactly 2 parts, parts[0]=="stores".
	if len(parts) == 2 && parts[0] == "stores" {
		if parts[1] == "" {
			return storeImportRef{}, fmt.Errorf(
				"invalid import ID %q: store GUID is empty; expected \"stores/<guid>\"", raw,
			)
		}
		return storeImportRef{StoreID: parts[1]}, nil
	}

	// "containers/<idOrName>/stores/<guid>" or "applications/<idOrName>/stores/<guid>"
	// → exactly 4 parts, parts[0] is "containers" or "applications", parts[2]=="stores".
	if len(parts) == 4 && (parts[0] == "containers" || parts[0] == "applications") && parts[2] == "stores" {
		if parts[1] == "" {
			return storeImportRef{}, fmt.Errorf(
				"invalid import ID %q: application/container ID or name is empty; expected \"%s/<idOrName>/stores/<guid>\"", raw, parts[0],
			)
		}
		if parts[3] == "" {
			return storeImportRef{}, fmt.Errorf(
				"invalid import ID %q: store GUID is empty; expected \"%s/<idOrName>/stores/<guid>\"", raw, parts[0],
			)
		}
		return storeImportRef{ContainerID: parts[1], StoreID: parts[3]}, nil
	}

	return storeImportRef{}, fmt.Errorf(
		"invalid import ID %q: expected one of: \"<guid>\", \"stores/<guid>\", \"containers/<idOrName>/stores/<guid>\", or \"applications/<idOrName>/stores/<guid>\"",
		raw,
	)
}

// containerArg converts a parsed container ID/name string into the argument
// type accepted by the keyfactor-go-client's GetCertificateStoreByContainerID:
// numeric strings → int, anything else → string (container name).
func containerArg(idOrName string) interface{} {
	if n, err := strconv.Atoi(idOrName); err == nil && n > 0 {
		return n
	}
	return idOrName
}

func (r resourceCertificateStore) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	rawImportID := request.ID

	tflog.Info(ctx, "ImportState called on certificate store resource")
	tflog.SetField(ctx, "id", rawImportID)

	ref, parseErr := parseStoreImportID(rawImportID)
	if parseErr != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store import ID",
			parseErr.Error(),
		)
		return
	}

	certificateStoreId := ref.StoreID

	var readResponse *api.GetCertificateStoreResponse
	if ref.ContainerID == "" {
		// Direct lookup — requires read-on-all-stores permission on the caller.
		resp, err := r.p.client.GetCertificateStoreByID(certificateStoreId)
		if err != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				fmt.Sprintf("Error reading certificate store '%s': "+err.Error(), certificateStoreId),
			)
			return
		}
		readResponse = resp
	} else {
		// Scope the lookup to the supplied container so the caller only needs
		// read permission on that container.
		cArg := containerArg(ref.ContainerID)
		stores, err := r.p.client.GetCertificateStoreByContainerID(cArg)
		if err != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				fmt.Sprintf(
					"Error listing certificate stores in container '%s': %s",
					ref.ContainerID, err.Error(),
				),
			)
			return
		}
		if stores != nil {
			for i := range *stores {
				entry := (*stores)[i]
				if entry.Id == certificateStoreId {
					readResponse = &entry
					break
				}
			}
		}
		if readResponse == nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				fmt.Sprintf(
					"certificate store %s not found in container %v — verify your container access and store ID",
					certificateStoreId, cArg,
				),
			)
			return
		}
	}

	csType, csTypeErr := r.p.client.GetCertificateStoreType(readResponse.CertStoreType)
	if csTypeErr != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Could not retrieve certificate store type '%s' from Keyfactor Command: "+csTypeErr.Error(),
				readResponse.CertStoreType,
			),
		)
		return
	}
	// Build properties map from server response, excluding special credential properties.
	specialProps := map[string]bool{"ServerUsername": true, "ServerPassword": true, "ServerUseSsl": true}
	importedProps := map[string]attr.Value{}
	for k, v := range readResponse.Properties {
		if specialProps[k] {
			continue
		}
		importedProps[k] = types.String{Value: fmt.Sprintf("%v", v)}
	}
	var importedPropsMap types.Map
	if len(importedProps) == 0 {
		importedPropsMap = types.Map{ElemType: types.StringType, Null: true}
	} else {
		importedPropsMap = types.Map{ElemType: types.StringType, Elems: importedProps}
	}

	// Parse inventory schedule from server response.
	importedSchedule := parseInventorySchedule(&readResponse.InventorySchedule)
	importedScheduleVal := types.String{Value: importedSchedule, Null: importedSchedule == ""}

	// Set state
	result := CertificateStore{
		ID:                    types.String{Value: readResponse.Id},
		ContainerID:           types.Int64{Value: int64(readResponse.ContainerId)},
		ClientMachine:         types.String{Value: readResponse.ClientMachine},
		StorePath:             types.String{Value: readResponse.StorePath},
		StoreType:             types.String{Value: csType.Name},
		Approved:              types.Bool{Value: readResponse.Approved},
		CreateIfMissing:       types.Bool{Value: readResponse.CreateIfMissing},
		Properties:            importedPropsMap,
		AgentId:               types.String{Value: readResponse.AgentId},
		AgentIdentifier:       types.String{Value: readResponse.AgentId},
		AgentAssigned:         types.Bool{Value: readResponse.AgentAssigned},
		DisplayName:           types.String{Value: fmt.Sprintf("%s - %s", readResponse.ClientMachine, readResponse.StorePath)},
		InventorySchedule:     importedScheduleVal,
		SetNewPasswordAllowed: types.Bool{Value: readResponse.SetNewPasswordAllowed},
		// StorePassword, ServerUsername, ServerPassword are write-only in the Command API
		// and are never returned by GetCertificateStoreByID. They will be null after import
		// and must be re-supplied in config if needed.
		StorePassword:  types.String{Null: true},
		ServerUsername: types.String{Null: true},
		ServerPassword: types.String{Null: true},
		ServerUseSsl:   types.Bool{Null: true},
	}
	// Resolve container name via the by-ID endpoint (list endpoint is paginated).
	result.syncApplicationAndContainerName(lookupContainerNameByID(ctx, r.p.client, readResponse.ContainerId, ""))
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

// resolveInventoryScheduleState returns a known types.String for inventory_schedule.
// It prefers the plan value when known (user explicitly configured a schedule), then
// falls back to the server response, and finally to null when neither is present.
// This ensures the Create/Update result never contains an Unknown value for the field.
func resolveInventoryScheduleState(planVal types.String, serverSched *api.InventorySchedule) types.String {
	// If the plan has a known (non-Unknown) value, honour it.
	if !planVal.Unknown {
		return planVal
	}
	// Plan is Unknown (field not in config). Use the server-returned schedule if any.
	if serverSched != nil {
		if s := parseInventorySchedule(serverSched); s != "" {
			return types.String{Value: s}
		}
	}
	// No schedule on the server either — return known null.
	return types.String{Null: true}
}

func createPasswordConfig(p string) *api.UpdateStorePasswordConfig {
	password := stringToPointer(p)
	res := &api.UpdateStorePasswordConfig{
		SecretValue: password,
	}

	return res
}

// inventoryScheduleForRequest builds the InventorySchedule for an
// Update/Create request, returning nil when the plan does not declare a
// schedule so the `omitempty` pointer field is omitted from the request body.
//
// createInventorySchedule always returns a non-nil &api.InventorySchedule{}
// even for an empty/unresolved interval, and UpdateStoreFctArgs.InventorySchedule
// is `omitempty` on the pointer — which never fires for a non-nil-but-zero-value
// struct. So an undeclared inventory_schedule was being sent as an explicit
// empty InventorySchedule{} object instead of being omitted. Gate on the plan
// value: Null/Unknown/empty means "no schedule declared" and must omit the field.
func inventoryScheduleForRequest(planVal types.String) (*api.InventorySchedule, error) {
	if planVal.Null || planVal.Unknown || planVal.Value == "" {
		return nil, nil
	}
	return createInventorySchedule(planVal.Value)
}

func createInventorySchedule(interval string) (*api.InventorySchedule, error) {
	inventorySchedule := &api.InventorySchedule{}

	if interval == "immediate" {
		immediate := true
		inventorySchedule.Immediate = &immediate
	} else {
		if strings.HasSuffix(interval, "m") {
			minutes, err := strconv.Atoi(interval[:len(interval)-1])
			if err != nil {
				return nil, err
			}
			iv := &api.InventoryInterval{Minutes: minutes}
			inventorySchedule.Interval = iv
			return inventorySchedule, nil
		}
		if strings.HasSuffix(interval, "h") {
			hours, err := strconv.Atoi(interval[:len(interval)-1])
			if err != nil {
				return nil, err
			}
			if hours >= 24 {
				return nil, fmt.Errorf("hours cannot be greater than or equal to 24. If specifying 24 use 'daily' instead")
			}
			iv := &api.InventoryInterval{Minutes: hours * 60}
			inventorySchedule.Interval = iv
			return inventorySchedule, nil
		}
		if strings.HasSuffix(interval, "d") {
			return nil, fmt.Errorf("days not supported please use 'm', 'daily' or 'exactly_once'")

		}
		if strings.HasPrefix(interval, "Daily at ") {
			daily := &api.InventoryDaily{Time: strings.TrimPrefix(interval, "Daily at ")}
			inventorySchedule.Daily = daily
			return inventorySchedule, nil
		}
		if strings.HasPrefix(interval, "Exactly once at ") {
			once := &api.InventoryOnce{Time: strings.TrimPrefix(interval, "Exactly once at ")}
			inventorySchedule.ExactlyOnce = once
			return inventorySchedule, nil
		}
	}

	return inventorySchedule, nil
}

func parseInventorySchedule(schedule *api.InventorySchedule) string {
	if schedule.Immediate != nil {
		return "immediate"
	}
	if schedule.Interval != nil {
		return fmt.Sprintf("%vm", schedule.Interval.Minutes)
	}
	if schedule.Daily != nil {
		t := schedule.Daily.Time
		// Normalize "2006-01-02T15:04:05Z" → "15:04:05" for stable round-trip
		if idx := strings.Index(t, "T"); idx >= 0 {
			t = strings.TrimSuffix(t[idx+1:], "Z")
		}
		return fmt.Sprintf("Daily at %s", t)
	}
	if schedule.ExactlyOnce != nil {
		t := schedule.ExactlyOnce.Time
		if idx := strings.Index(t, "T"); idx >= 0 {
			t = strings.TrimSuffix(t[idx+1:], "Z")
		}
		return fmt.Sprintf("Exactly once at %s", t)
	}

	return ""
}

func buildPropertiesInterface(properties *map[string]string) map[string]interface{} {
	// Create temporary array of interfaces
	// When updating a property in Keyfactor, API expects {"key": {"value": "key-value"}} - Build this interface
	propertiesInterface := make(map[string]interface{})

	creds := CertificateStoreCredential{
		ServerUsername: struct {
			Value struct {
				SecretValue string `json:"SecretValue"`
			} `json:"value"`
		}{},
		ServerPassword: struct {
			Value struct {
				SecretValue string `json:"SecretValue"`
			} `json:"value"`
		}{},
		ServerUseSsl: struct {
			Value string `json:"value"`
		}{},
	}

	for key, value := range *properties {
		if key == "ServerUsername" || key == "ServerPassword" || key == "Password" {
			if key == "ServerUsername" {
				creds.ServerUsername.Value.SecretValue = value
				// add to propertiesInterface as JSON string
				//jsonBytes, _ := json.Marshal(creds.ServerUsername)
				propertiesInterface[key] = creds.ServerUsername
			}
			if key == "ServerPassword" || key == "Password" {
				creds.ServerPassword.Value.SecretValue = value
				//jsonBytes, _ := json.Marshal(creds.ServerPassword)
				propertiesInterface[key] = creds.ServerPassword
			}
		} else {
			propertiesInterface[key] = value // Create {"<key>": {"value": "key-value"}} interface
		}
	}
	return propertiesInterface
}

func mapToEscapedJSONString(m map[string]interface{}) (string, error) {
	// Convert the map to a byte slice of JSON
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	// Escape any special characters in the JSON string
	escapedString := string(jsonBytes)

	return escapedString, nil
}
