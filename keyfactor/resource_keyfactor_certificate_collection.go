package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ---------------------------------------------------------------------------
// Resource type
// ---------------------------------------------------------------------------

type resourceCertificateCollectionType struct{}

func (r resourceCertificateCollectionType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Description: "Manages a Keyfactor Command certificate collection.",
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "The server-assigned ID of the certificate collection.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "The name of the certificate collection.",
			},
			"description": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A description of the certificate collection.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"query": {
				Type: types.StringType,
				// Required (full-review finding F10; was previously
				// Optional with a hand-rolled ValidateConfig check for
				// "must always be declared"): the schema itself can
				// already express "always declared," which is strictly
				// more correct than a custom runtime check for the same
				// thing -- Required also makes `terraform validate` catch
				// an omitted query before ValidateConfig ever runs, and
				// removes any ambiguity about whether an undeclared query
				// is legal. Note the import asymmetry this doesn't change:
				// `terraform import` still populates state without query
				// ever being declared (ValidateConfig/schema validation
				// doesn't run against import), so the NEXT plan after an
				// import will show query transitioning from absent to a
				// required value -- expected, and no different from any
				// other Required attribute's import behavior.
				Required:    true,
				Description: "The query expression that defines which certificates belong to this collection. This is the resource's defining attribute and must always be declared -- it must never be removed from configuration once set. Not returned by the server on read; the provider preserves the last-known value from state instead. Use `content` to see the server-normalized form. Note: a certificate collection can only be imported and managed by Terraform if it has a non-empty query; genuinely query-less collections are out of scope for this resource.",
			},
			"content": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The server-normalized form of the collection query.",
				// followsDriverModifier (full-review finding F3; type
				// defined in resource_keyfactor_enrollment_pattern.go,
				// shared across resources), not tfsdk.UseStateForUnknown():
				// content must NOT be pinned to its stale, prior
				// server-normalized form when query itself is changing
				// this apply, since Update()'s response carries the
				// NEWLY-normalized content for the new query -- pinning
				// the old value causes "Provider produced inconsistent
				// result after apply" on this resource's primary update
				// path (editing query). estimated_cert_count/last_estimated
				// are unaffected -- they have no plan modifier at all, so
				// they are already always left Unknown and are not part
				// of this fix.
				PlanModifiers: []tfsdk.AttributePlanModifier{
					followsDriverModifier[types.String]{
						driverPath:  path.Root("query"),
						description: "Uses the prior state value unless query is changing this apply, in which case this attribute is left unknown so it can be recomputed from the server's response.",
					},
				},
			},
			"duplication_field": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Determines how duplicate certificate subjects are identified. 0=None, 1=CommonName, 2=DistinguishedName, 3=PrincipalName.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"show_on_dashboard": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to show this collection on the Keyfactor Command dashboard.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"favorite": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether this collection is marked as a favorite.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"estimated_cert_count": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "The estimated number of certificates matching this collection's query.",
			},
			"last_estimated": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Timestamp of when the estimated certificate count was last calculated.",
			},
		},
	}, nil
}

func (r resourceCertificateCollectionType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCertificateCollection{p: *(p.(*provider))}, nil
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

type resourceCertificateCollection struct {
	p provider
}

// KeyfactorCertificateCollectionState is the Terraform state model for
// keyfactor_certificate_collection.
//
// Query is write-only from the server's perspective: Create/Update
// (CertificateCollectionsCertificateCollectionResponse) echo it back, but
// GetById (CSSCMSDataModelModelsCertificateQuery, used by Read/ImportState)
// has no Query field at all -- only the server-normalized Content. Read must
// therefore preserve Query from the prior Terraform state rather than
// hardcode it null, or every refresh would wipe it and force a spurious
// "provider produced inconsistent result" / perpetual diff on the next plan.
type KeyfactorCertificateCollectionState struct {
	ID                 types.Int64  `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Query              types.String `tfsdk:"query"`
	Content            types.String `tfsdk:"content"`
	DuplicationField   types.Int64  `tfsdk:"duplication_field"`
	ShowOnDashboard    types.Bool   `tfsdk:"show_on_dashboard"`
	Favorite           types.Bool   `tfsdk:"favorite"`
	EstimatedCertCount types.Int64  `tfsdk:"estimated_cert_count"`
	LastEstimated      types.String `tfsdk:"last_estimated"`
}

// ---------------------------------------------------------------------------
// Response -> State conversion
// ---------------------------------------------------------------------------

// collectionResponseToState maps the Create/Update response
// (CertificateCollectionsCertificateCollectionResponse), which HAS a Query
// field, to state.
func collectionResponseToState(resp *v1.CertificateCollectionsCertificateCollectionResponse) KeyfactorCertificateCollectionState {
	state := KeyfactorCertificateCollectionState{}

	if resp.Id != nil {
		state.ID = types.Int64{Value: int64(*resp.Id)}
	} else {
		state.ID = types.Int64{Null: true}
	}

	state.Name = nullableStringToTfString(resp.Name)
	state.Description = nullableStringToTfString(resp.Description)
	state.Content = nullableStringToTfString(resp.Content)
	state.Query = nullableStringToTfString(resp.Query)

	if resp.DuplicationField != nil {
		state.DuplicationField = types.Int64{Value: int64(*resp.DuplicationField)}
	} else {
		state.DuplicationField = types.Int64{Null: true}
	}

	state.ShowOnDashboard = boolPtrToTfBool(resp.ShowOnDashboard)
	state.Favorite = boolPtrToTfBool(resp.Favorite)

	if resp.EstimatedCertCount != nil {
		state.EstimatedCertCount = types.Int64{Value: int64(*resp.EstimatedCertCount)}
	} else {
		state.EstimatedCertCount = types.Int64{Null: true}
	}

	if resp.LastEstimated.IsSet() && resp.LastEstimated.Get() != nil {
		state.LastEstimated = types.String{Value: resp.LastEstimated.Get().String()}
	} else {
		state.LastEstimated = types.String{Null: true}
	}

	return state
}

// collectionGetResponseToState maps the GetById response
// (CSSCMSDataModelModelsCertificateQuery), which has NO Query field, to
// state. Query is always left null here -- callers (Read/ImportState) are
// responsible for deciding what, if anything, to preserve in its place.
func collectionGetResponseToState(resp *v1.CSSCMSDataModelModelsCertificateQuery) KeyfactorCertificateCollectionState {
	state := KeyfactorCertificateCollectionState{}

	if resp.Id != nil {
		state.ID = types.Int64{Value: int64(*resp.Id)}
	} else {
		state.ID = types.Int64{Null: true}
	}

	state.Name = nullableStringToTfString(resp.Name)
	state.Description = nullableStringToTfString(resp.Description)
	state.Content = nullableStringToTfString(resp.Content)
	// GetById has no Query field -- always null here; callers preserve it
	// themselves from whatever other source is appropriate (prior state).
	state.Query = types.String{Null: true}

	if resp.DuplicationField != nil {
		state.DuplicationField = types.Int64{Value: int64(*resp.DuplicationField)}
	} else {
		state.DuplicationField = types.Int64{Null: true}
	}

	state.ShowOnDashboard = boolPtrToTfBool(resp.ShowOnDashboard)
	state.Favorite = boolPtrToTfBool(resp.Favorite)

	if resp.EstimatedCertCount != nil {
		state.EstimatedCertCount = types.Int64{Value: int64(*resp.EstimatedCertCount)}
	} else {
		state.EstimatedCertCount = types.Int64{Null: true}
	}

	if resp.LastEstimated.IsSet() && resp.LastEstimated.Get() != nil {
		state.LastEstimated = types.String{Value: resp.LastEstimated.Get().String()}
	} else {
		state.LastEstimated = types.String{Null: true}
	}

	return state
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

// ValidateConfig requires query to always be declared and non-empty.
//
// query is this resource's defining attribute -- a certificate collection
// IS its query -- but Command's GetById (CSSCMSDataModelModelsCertificate-
// Query, used by Read/ImportState) never returns it (see
// KeyfactorCertificateCollectionState's doc comment), so the provider has no
// server-side source of truth to fall back on if a user removes `query` from
// configuration on a later apply. Before this check existed, doing so
// produced a genuine "provider produced inconsistent result after apply":
// query is Optional (not Computed), so an undeclared query plans to a
// definite Null, but Update() -- unable to tell "leave unchanged" apart from
// "clear" without a config-declared value -- fell back to resending the
// prior state's non-null value, leaving a non-null Query in the final state
// that disagreed with the null the plan promised (PR #210 full-review
// finding FIX-2). Rejecting the omission outright at config-validation time,
// before plan/apply ever runs, is simpler and safer than trying to support
// "removing query clears the collection's filter" -- which Command's API
// shape doesn't actually support anyway.
func (r resourceCertificateCollection) ValidateConfig(
	ctx context.Context,
	request tfsdk.ValidateResourceConfigRequest,
	response *tfsdk.ValidateResourceConfigResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateCollection.ValidateConfig")

	var config KeyfactorCertificateCollectionState
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	response.Diagnostics.Append(validateCertificateCollectionConfigConstraints(config)...)

	LogFunctionExit(ctx, "resourceCertificateCollection.ValidateConfig")
}

// validateCertificateCollectionConfigConstraints enforces that query, once
// declared, is non-empty -- the one part of "query must always be declared
// with a non-empty value" (see ValidateConfig's doc comment, PR #210
// full-review finding FIX-2) the schema itself cannot express.
// query.Required = true (full-review finding F10) already guarantees query
// is always declared -- HCL/Core rejects an omitted Required attribute
// before ValidateConfig ever runs -- but Required says nothing about the
// declared value's CONTENT, so `query = ""` still reaches here and must
// still be rejected: Keyfactor Command's GetById API does not return the
// query, so the provider cannot distinguish "leave unchanged" from "clear"
// if it were ever allowed to go empty. A null/unknown query is never
// flagged as an error when Unknown: ValidateConfig only ever sees Config,
// which cannot resolve a value that isn't known yet (e.g. a value chained
// from another not-yet-applied resource); Null is likewise never flagged,
// since it can no longer occur once query.Required = true is enforced by
// Core itself, but the check is left defensive rather than assuming that.
// Factored out of ValidateConfig so it can be unit tested directly against
// a KeyfactorCertificateCollectionState value, matching
// validateEnrollmentPatternConfigConstraints's pattern in resource_keyfactor_
// enrollment_pattern.go.
func validateCertificateCollectionConfigConstraints(cfg KeyfactorCertificateCollectionState) diag.Diagnostics {
	var diags diag.Diagnostics

	if cfg.Query.Null || (!cfg.Query.Unknown && cfg.Query.Value == "") {
		diags.AddAttributeError(
			path.Root("query"),
			"Missing certificate collection query",
			"query defines which certificates belong to this collection and must always be declared with a "+
				"non-empty value. Keyfactor Command's GetById API does not return the query, so the provider "+
				"cannot distinguish \"leave unchanged\" from \"clear\" if it is later removed from configuration -- "+
				"removing query from configuration (or setting it to an empty string) is not supported.",
		)
	}

	return diags
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r resourceCertificateCollection) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateCollection.Create")

	var plan KeyfactorCertificateCollectionState
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	body := v1.NewCertificateCollectionsCertificateCollectionCreateRequest(plan.Name.Value)

	if !plan.Description.Null && !plan.Description.Unknown {
		body.SetDescription(plan.Description.Value)
	}
	// query is Required (full-review finding F10): Core guarantees it is
	// always declared and, by the time Create() actually executes (as
	// opposed to plan time), always resolved to a concrete value -- the
	// previous `!plan.Query.Null && !plan.Query.Unknown` guard was
	// unreachable dead code, since Null could never occur for a Required
	// attribute in the first place.
	body.SetQuery(plan.Query.Value)
	if !plan.DuplicationField.Null && !plan.DuplicationField.Unknown {
		body.SetDuplicationField(v1.CSSCMSCoreEnumsDuplicateSubjectType(int32(plan.DuplicationField.Value)))
	}
	if !plan.ShowOnDashboard.Null && !plan.ShowOnDashboard.Unknown {
		body.SetShowOnDashboard(plan.ShowOnDashboard.Value)
	}
	if !plan.Favorite.Null && !plan.Favorite.Unknown {
		body.SetFavorite(plan.Favorite.Value)
	}

	collectionApi := r.p.sdkClient.V1.CertificateCollectionApi

	LogFunctionCall(ctx, "CertificateCollectionApi.CreateCertificateCollections")
	resp, httpResp, err := collectionApi.NewCreateCertificateCollectionsRequest(ctx).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		CertificateCollectionsCertificateCollectionCreateRequest(*body).
		Execute()
	LogFunctionReturned(ctx, "CertificateCollectionApi.CreateCertificateCollections")
	if err != nil {
		respBody := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error creating certificate collection.",
			fmt.Sprintf("Could not create certificate collection %q: %s. Details: %s", plan.Name.Value, err.Error(), respBody),
		)
		return
	}
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error creating certificate collection.",
			fmt.Sprintf("creating certificate collection %q", plan.Name.Value),
		)...)
		return
	}

	newState := collectionResponseToState(resp)
	tflog.Debug(ctx, fmt.Sprintf("Created certificate collection ID %d", newState.ID.Value))
	// Field-level audit logging for the collection's defining (and only
	// access-control-relevant) field on this initial create -- mirrors the
	// Update() field-change logging below (PR #210 full-review finding
	// FIX-8). Debug level, not Info: query can embed sensitive subject
	// DN/serial/owner filter content, matching the level Update()'s
	// query-change logging uses (see FIX-7).
	tflog.Debug(
		ctx, fmt.Sprintf(
			"Certificate collection %d field set on create: query: %s", newState.ID.Value, tfStringLogString(newState.Query),
		),
	)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateCollection.Create")
}

func (r resourceCertificateCollection) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateCollection.Read")

	var state KeyfactorCertificateCollectionState
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading certificate collection ID %d", state.ID.Value))

	collectionApi := r.p.sdkClient.V1.CertificateCollectionApi

	LogFunctionCall(ctx, "CertificateCollectionApi.GetCertificateCollectionsById")
	resp, httpResp, err := collectionApi.NewGetCertificateCollectionsByIdRequest(ctx, int32(state.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	LogFunctionReturned(ctx, "CertificateCollectionApi.GetCertificateCollectionsById")
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			tflog.Info(ctx, fmt.Sprintf("Certificate collection %d not found, removing from state", state.ID.Value))
			response.State.RemoveResource(ctx)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading certificate collection.",
			fmt.Sprintf("Could not read certificate collection %d: %s. Details: %s", state.ID.Value, err.Error(), body),
		)
		return
	}
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error reading certificate collection.",
			fmt.Sprintf("reading certificate collection %d", state.ID.Value),
		)...)
		return
	}

	newState := collectionGetResponseToState(resp)

	// GetById never returns Query -- preserve it from the prior state so a
	// plain refresh doesn't wipe it out (see KeyfactorCertificateCollectionState
	// doc comment).
	newState.Query = state.Query

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateCollection.Read")
}

func (r resourceCertificateCollection) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateCollection.Update")

	var plan KeyfactorCertificateCollectionState
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var state KeyfactorCertificateCollectionState
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// CONFIG (not plan) is the reliable signal for "did the user actually
	// declare this attribute" -- an Optional+Computed attribute's plan value
	// can be a known, non-null value pinned from prior state by
	// UseStateForUnknown even when config never declared it at all.
	var config KeyfactorCertificateCollectionState
	diags = request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Carry ID from state (plan has it as Unknown during some plan shapes).
	if plan.ID.Value == 0 {
		plan.ID = state.ID
	}

	tflog.Info(ctx, fmt.Sprintf("Updating certificate collection ID %d", plan.ID.Value))

	collectionApi := r.p.sdkClient.V1.CertificateCollectionApi

	// Fresh GET immediately before update to recover the server's current
	// value for any Optional+Computed field config leaves undeclared this
	// apply -- mirrors the read-modify-write pattern used elsewhere in this
	// provider (see preserveUndeclaredTemplateFields in
	// resource_keyfactor_certificate_template.go) so an update that only
	// declares `name` doesn't silently clear every other undeclared field.
	LogFunctionCall(ctx, "CertificateCollectionApi.GetCertificateCollectionsById (pre-update)")
	current, httpResp, err := collectionApi.NewGetCertificateCollectionsByIdRequest(ctx, int32(plan.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	LogFunctionReturned(ctx, "CertificateCollectionApi.GetCertificateCollectionsById (pre-update)")
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading certificate collection before update.",
			fmt.Sprintf(
				"Could not read certificate collection %d to preserve its current field values: %s. Details: %s",
				plan.ID.Value, err.Error(), body,
			),
		)
		return
	}
	if current == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error reading certificate collection before update.",
			fmt.Sprintf("reading certificate collection %d to preserve its current field values", plan.ID.Value),
		)...)
		return
	}
	currentState := collectionGetResponseToState(current)

	updateBody := v1.NewCertificateCollectionsCertificateCollectionUpdateRequest(int32(plan.ID.Value), plan.Name.Value)

	// Description: Optional+Computed NullableString. Config declared ->
	// plan value wins; undeclared -> fall back to the fresh GET's current
	// server value.
	if !config.Description.Null && !config.Description.Unknown {
		if plan.Description.Null {
			updateBody.SetDescriptionNil()
		} else {
			updateBody.SetDescription(plan.Description.Value)
		}
	} else if !currentState.Description.Null {
		updateBody.SetDescription(currentState.Description.Value)
	}

	// Query: write-only from the server's Read/GetById perspective (see
	// collectionGetResponseToState) -- there is no fresh-GET fallback
	// available for "the current server-side value" the way there is for
	// every other field here, because GetById never returns it. query is
	// now Required (full-review finding F10), so config.Query/plan.Query
	// are always declared and non-null by the time an apply actually
	// executes -- the previous "config undeclared, fall back to prior
	// Terraform state" branch (and the SetQueryNil() call, which could
	// only ever fire for a null plan.Query that Required now makes
	// structurally impossible) were dead code once that schema change
	// landed.
	updateBody.SetQuery(plan.Query.Value)
	// Audit-log old (prior state) vs new (declared plan) value for this
	// policy-relevant field -- PR #210 full-review finding F5. Debug
	// level, not Info: unlike enrollment_pattern.go's role-name/CA-id/
	// policy-enum diff logging, query is a free-text search expression
	// that can embed sensitive subject DN/serial/owner content -- Info is
	// a broader-capture level than warranted for that content (PR #210
	// full-review finding FIX-7).
	if tfStringLogString(state.Query) != tfStringLogString(plan.Query) {
		tflog.Debug(
			ctx, fmt.Sprintf(
				"Certificate collection %d field change on update: query: %s -> %s",
				plan.ID.Value, tfStringLogString(state.Query), tfStringLogString(plan.Query),
			),
		)
	}

	// DuplicationField: Optional+Computed, plain enum pointer (no explicit-
	// null support in the SDK model).
	if !config.DuplicationField.Null && !config.DuplicationField.Unknown {
		updateBody.SetDuplicationField(v1.CSSCMSCoreEnumsDuplicateSubjectType(int32(plan.DuplicationField.Value)))
	} else if !currentState.DuplicationField.Null {
		updateBody.SetDuplicationField(v1.CSSCMSCoreEnumsDuplicateSubjectType(int32(currentState.DuplicationField.Value)))
	}

	// ShowOnDashboard: Optional+Computed *bool.
	if !config.ShowOnDashboard.Null && !config.ShowOnDashboard.Unknown {
		updateBody.SetShowOnDashboard(plan.ShowOnDashboard.Value)
	} else if !currentState.ShowOnDashboard.Null {
		updateBody.SetShowOnDashboard(currentState.ShowOnDashboard.Value)
	}

	// Favorite: Optional+Computed *bool.
	if !config.Favorite.Null && !config.Favorite.Unknown {
		updateBody.SetFavorite(plan.Favorite.Value)
	} else if !currentState.Favorite.Null {
		updateBody.SetFavorite(currentState.Favorite.Value)
	}

	LogFunctionCall(ctx, "CertificateCollectionApi.UpdateCertificateCollections")
	resp, httpResp, err := collectionApi.NewUpdateCertificateCollectionsRequest(ctx).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		CertificateCollectionsCertificateCollectionUpdateRequest(*updateBody).
		Execute()
	LogFunctionReturned(ctx, "CertificateCollectionApi.UpdateCertificateCollections")
	if err != nil {
		respBody := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error updating certificate collection.",
			fmt.Sprintf("Could not update certificate collection %d: %s. Details: %s", plan.ID.Value, err.Error(), respBody),
		)
		return
	}
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error updating certificate collection.",
			fmt.Sprintf("updating certificate collection %d", plan.ID.Value),
		)...)
		return
	}

	newState := collectionResponseToState(resp)

	// The update response DOES carry Query, but fall back to whatever we
	// just decided to send (plan/state-derived) in case the server ever
	// omits it in the response body.
	if newState.Query.Null {
		if !plan.Query.Null {
			newState.Query = plan.Query
		} else {
			newState.Query = state.Query
		}
	}

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateCollection.Update")
}

func (r resourceCertificateCollection) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	LogFunctionEntry(ctx, "resourceCertificateCollection.Delete")

	var state KeyfactorCertificateCollectionState
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting certificate collection ID %d", state.ID.Value))

	collectionApi := r.p.sdkClient.V1.CertificateCollectionApi

	LogFunctionCall(ctx, "CertificateCollectionApi.DeleteCertificateCollectionsById")
	httpResp, err := collectionApi.NewDeleteCertificateCollectionsByIdRequest(ctx, int32(state.ID.Value)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	LogFunctionReturned(ctx, "CertificateCollectionApi.DeleteCertificateCollectionsById")
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			tflog.Info(ctx, fmt.Sprintf("Certificate collection %d already deleted", state.ID.Value))
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error deleting certificate collection.",
			fmt.Sprintf("Could not delete certificate collection %d: %s. Details: %s", state.ID.Value, err.Error(), body),
		)
		return
	}

	LogFunctionExit(ctx, "resourceCertificateCollection.Delete")
}

func (r resourceCertificateCollection) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("ImportState called on certificate collection with ID %q", request.ID))

	id, err := strconv.Atoi(request.ID)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate collection ID.",
			fmt.Sprintf("Import ID must be an integer, got %q: %s", request.ID, err.Error()),
		)
		return
	}

	collectionApi := r.p.sdkClient.V1.CertificateCollectionApi

	resp, httpResp, err := collectionApi.NewGetCertificateCollectionsByIdRequest(ctx, int32(id)).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			response.Diagnostics.AddError(
				"Certificate collection not found.",
				fmt.Sprintf("Could not find certificate collection %d to import: %s", id, err.Error()),
			)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error importing certificate collection.",
			fmt.Sprintf("Could not read certificate collection %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error importing certificate collection.",
			fmt.Sprintf("reading certificate collection %d to import", id),
		)...)
		return
	}

	// GetById never returns Query, so an imported collection starts with a
	// null query in state -- the next apply will need `query` declared in
	// configuration (or the drift check will show it being set for the
	// first time from Terraform's point of view).
	newState := collectionGetResponseToState(resp)

	diags := response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
}
