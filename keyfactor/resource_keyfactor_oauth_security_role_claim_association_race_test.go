package keyfactor

import (
	"context"
	"fmt"
	"sync"
	"testing"

	sdkclient "github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// ---------------------------------------------------------------------------
// Tier 0: concurrent-write race reproduction for
// keyfactor_oauth_security_role_claim_association.
//
// Suspected mechanism (see PLAN_v2.10_feedback_followup.md item 0 /
// HANDOFF_v2.10_feedback_followup.md Phase 1): Create and Delete both
// GET the role, add/remove exactly one claim in the in-memory Claims slice,
// then PUT the entire role. Two calls racing on the SAME role with
// DIFFERENT claims can both GET before either PUTs; the second PUT to land
// wins and silently drops whatever the first call wrote. No error surfaces
// to the practitioner -- this is a lost update, not a conflict.
//
// This test calls the resource's real Create/Delete methods directly
// (bypassing the tfsdk request/response plumbing only insofar as building
// the Plan/State by hand -- the exact same production code executes)
// against the real kfclab lab, in concurrent goroutines synchronized on a
// shared start barrier to maximize the chance both goroutines GET before
// either PUTs.
//
// This is a genuine network race and cannot be exercised via VCR/unit
// mocks (each cassette interaction is consumed once in playback, and there
// is no real concurrency in replay) -- hence TestInt*, not TestUnit*, per
// feedback_live_lab_required_before_merge.
// ---------------------------------------------------------------------------

// newSDKTestClient builds a *keyfactor.APIClient (v25 SDK, the same client
// type used internally as provider.sdkClient) from the lab connection env
// vars, for tests that need to call the SDK directly outside of a
// Terraform apply. Skips if the lab is unavailable.
func newSDKTestClient(t *testing.T) *sdkclient.APIClient {
	t.Helper()
	client := newTestClient(t)
	return sdkclient.NewAPIClientWithAuth(client.AuthClient)
}

// concurrentClaimAssociationRaceHarness holds everything needed to drive
// concurrent Create/Delete calls against a single real role + two real
// claims, calling the resourceOAuthSecurityRoleClaimAssociation production
// methods directly.
type concurrentClaimAssociationRaceHarness struct {
	t      *testing.T
	sdk    *sdkclient.APIClient
	schema tfsdk.Schema
	r      resourceOAuthSecurityRoleClaimAssociation
	roleID int32
	claim1 int32
	claim2 int32
}

func newConcurrentClaimAssociationRaceHarness(t *testing.T, sdk *sdkclient.APIClient, roleID, claim1, claim2 int32) *concurrentClaimAssociationRaceHarness {
	t.Helper()

	schema, diags := resourceOAuthSecurityRoleClaimAssociationType{}.GetSchema(context.Background())
	if diags.HasError() {
		t.Fatalf("failed to build schema for race harness: %v", diags.Errors())
	}

	p := provider{configured: true, sdkClient: sdk}

	return &concurrentClaimAssociationRaceHarness{
		t:      t,
		sdk:    sdk,
		schema: schema,
		r:      resourceOAuthSecurityRoleClaimAssociation{p: p},
		roleID: roleID,
		claim1: claim1,
		claim2: claim2,
	}
}

// create invokes the resource's real Create method for (roleID, claimID),
// exactly as Terraform would during an apply.
func (h *concurrentClaimAssociationRaceHarness) create(ctx context.Context, claimID int32) error {
	plan := tfsdk.Plan{Schema: h.schema}
	diags := plan.Set(ctx, &OAuthSecurityRoleClaimAssociation{
		RoleID:  types.Int64{Value: int64(h.roleID)},
		ClaimID: types.Int64{Value: int64(claimID)},
	})
	if diags.HasError() {
		return fmt.Errorf("failed to build create plan: %v", diags.Errors())
	}

	req := tfsdk.CreateResourceRequest{Plan: plan}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: h.schema}}
	h.r.Create(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return fmt.Errorf("Create(role=%d, claim=%d) failed: %v", h.roleID, claimID, resp.Diagnostics.Errors())
	}
	return nil
}

// delete invokes the resource's real Delete method for (roleID, claimID).
func (h *concurrentClaimAssociationRaceHarness) delete(ctx context.Context, claimID int32) error {
	state := tfsdk.State{Schema: h.schema}
	result := mapOAuthSecurityRoleClaimAssociation(ctx, h.roleID, claimID)
	diags := state.Set(ctx, &result)
	if diags.HasError() {
		return fmt.Errorf("failed to build delete state: %v", diags.Errors())
	}

	req := tfsdk.DeleteResourceRequest{State: state}
	resp := &tfsdk.DeleteResourceResponse{State: tfsdk.State{Schema: h.schema}}
	h.r.Delete(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return fmt.Errorf("Delete(role=%d, claim=%d) failed: %v", h.roleID, claimID, resp.Diagnostics.Errors())
	}
	return nil
}

// runConcurrent runs fn(claim1) and fn(claim2) concurrently, synchronized on
// a shared start barrier so both goroutines begin their GET as close to
// simultaneously as possible. Returns both errors (nil if no error).
func (h *concurrentClaimAssociationRaceHarness) runConcurrent(ctx context.Context, fn func(context.Context, int32) error) (err1, err2 error) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		err1 = fn(ctx, h.claim1)
	}()
	go func() {
		defer wg.Done()
		<-start
		err2 = fn(ctx, h.claim2)
	}()

	close(start)
	wg.Wait()
	return
}

// remoteClaimIDs GETs the role from the real lab and returns the set of
// claim IDs currently associated with it.
func (h *concurrentClaimAssociationRaceHarness) remoteClaimIDs(ctx context.Context) (map[int32]bool, error) {
	remoteState, _, err := h.sdk.V2.SecurityRolesApi.NewGetSecurityRolesByIdRequest(ctx, h.roleID).Execute()
	if err != nil {
		return nil, err
	}
	ids := make(map[int32]bool)
	for _, claim := range remoteState.Claims {
		if claim.Id != nil {
			ids[*claim.Id] = true
		}
	}
	return ids, nil
}

// testAccRaceRoleAndClaimsConfig creates 1 role + 2 claims (no
// association resources -- those are driven directly against the SDK by
// the race harness, not via Terraform, since the point is to exercise the
// exact GET-modify-PUT window Create/Delete use).
func testAccRaceRoleAndClaimsConfig(roleName, claimValue1, claimValue2, authScheme string) string {
	return fmt.Sprintf(`
data "keyfactor_permission_set" "global_permission_set" {
	name = "Global"
}

resource "keyfactor_oauth_security_role" "race_test_role" {
	name              = "%s"
	description       = "Terraform race-condition regression test role"
	permission_set_id = data.keyfactor_permission_set.global_permission_set.id
	email_address     = "race-test@example.com"
	permissions       = []
}

resource "keyfactor_oauth_security_claim" "race_claim_1" {
	claim_type                     = "OAuthClientId"
	claim_value                    = "%s"
	provider_authentication_scheme = "%s"
	description                    = "Race test claim 1"
}

resource "keyfactor_oauth_security_claim" "race_claim_2" {
	claim_type                     = "OAuthClientId"
	claim_value                    = "%s"
	provider_authentication_scheme = "%s"
	description                    = "Race test claim 2"

	depends_on = [keyfactor_oauth_security_claim.race_claim_1]
}
`, roleName, claimValue1, authScheme, claimValue2, authScheme)
}

// TestIntKeyfactorOAuthSecurityRoleClaimAssociation_ConcurrentCreateDeleteRace
// is the Tier 0 required test: it creates one role and two claims via a
// normal Terraform apply, then -- while that apply's resources are still
// live, inside the step's Check function, before Terraform's automatic
// destroy -- drives NUM_RACE_ROUNDS rounds of:
//
//  1. Concurrent Create of two role-claim associations on the SAME role
//     with DIFFERENT claims. Asserts both claims are present afterward.
//  2. Concurrent Delete of both associations. Asserts both claims are
//     absent afterward.
//
// If the suspected lost-update race is real, some round's post-Create GET
// will be missing one of the two claims (the second PUT to land silently
// dropped the first PUT's addition), or the post-Delete GET will still show
// a claim that should have been removed.
func TestIntKeyfactorOAuthSecurityRoleClaimAssociation_ConcurrentCreateDeleteRace(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	authScheme := discoverOAuthAuthScheme(t, client)

	const numRaceRounds = 10

	sdk := newSDKTestClient(t)

	roleName := acctest.RandomWithPrefix("tf-int-race-role")
	claimValue1 := acctest.RandomWithPrefix("tf-int-race-claim1")
	claimValue2 := acctest.RandomWithPrefix("tf-int-race-claim2")

	var raceFailures []string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRaceRoleAndClaimsConfig(roleName, claimValue1, claimValue2, authScheme),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_oauth_security_role.race_test_role", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_oauth_security_claim.race_claim_1", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_oauth_security_claim.race_claim_2", "id"),
					func(s *terraform.State) error {
						roleIDStr, err := getResourceIdFromTerraformState(s, "keyfactor_oauth_security_role.race_test_role")
						if err != nil {
							return fmt.Errorf("failed to get role ID from state: %w", err)
						}
						claim1IDStr, err := getResourceIdFromTerraformState(s, "keyfactor_oauth_security_claim.race_claim_1")
						if err != nil {
							return fmt.Errorf("failed to get claim 1 ID from state: %w", err)
						}
						claim2IDStr, err := getResourceIdFromTerraformState(s, "keyfactor_oauth_security_claim.race_claim_2")
						if err != nil {
							return fmt.Errorf("failed to get claim 2 ID from state: %w", err)
						}

						var roleID, claim1ID, claim2ID int32
						if _, err := fmt.Sscanf(roleIDStr, "%d", &roleID); err != nil {
							return fmt.Errorf("failed to parse role ID %q: %w", roleIDStr, err)
						}
						if _, err := fmt.Sscanf(claim1IDStr, "%d", &claim1ID); err != nil {
							return fmt.Errorf("failed to parse claim 1 ID %q: %w", claim1IDStr, err)
						}
						if _, err := fmt.Sscanf(claim2IDStr, "%d", &claim2ID); err != nil {
							return fmt.Errorf("failed to parse claim 2 ID %q: %w", claim2IDStr, err)
						}

						ctx := context.Background()
						h := newConcurrentClaimAssociationRaceHarness(t, sdk, roleID, claim1ID, claim2ID)

						for round := 1; round <= numRaceRounds; round++ {
							// --- Concurrent Create ---
							createErr1, createErr2 := h.runConcurrent(ctx, h.create)
							if createErr1 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: create claim1 error: %v", round, createErr1))
							}
							if createErr2 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: create claim2 error: %v", round, createErr2))
							}

							claimsAfterCreate, err := h.remoteClaimIDs(ctx)
							if err != nil {
								return fmt.Errorf("round %d: failed to GET role after concurrent create: %w", round, err)
							}
							if !claimsAfterCreate[claim1ID] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: RACE REPRODUCED on create -- claim1 (id=%d) missing from role %d after concurrent Create of claim1+claim2", round, claim1ID, roleID))
							}
							if !claimsAfterCreate[claim2ID] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: RACE REPRODUCED on create -- claim2 (id=%d) missing from role %d after concurrent Create of claim1+claim2", round, claim2ID, roleID))
							}

							// --- Concurrent Delete ---
							deleteErr1, deleteErr2 := h.runConcurrent(ctx, h.delete)
							if deleteErr1 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: delete claim1 error: %v", round, deleteErr1))
							}
							if deleteErr2 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: delete claim2 error: %v", round, deleteErr2))
							}

							claimsAfterDelete, err := h.remoteClaimIDs(ctx)
							if err != nil {
								return fmt.Errorf("round %d: failed to GET role after concurrent delete: %w", round, err)
							}
							if claimsAfterDelete[claim1ID] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: RACE REPRODUCED on delete -- claim1 (id=%d) still present on role %d after concurrent Delete of claim1+claim2", round, claim1ID, roleID))
							}
							if claimsAfterDelete[claim2ID] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: RACE REPRODUCED on delete -- claim2 (id=%d) still present on role %d after concurrent Delete of claim1+claim2", round, claim2ID, roleID))
							}
						}

						return nil
					},
				),
			},
		},
	})

	if len(raceFailures) > 0 {
		t.Fatalf("concurrent-write race reproduced (%d/%d rounds had at least one failure):\n%s", len(raceFailures), numRaceRounds, joinRaceFailures(raceFailures))
	} else {
		t.Logf("concurrent-write race did NOT reproduce across %d rounds of concurrent create+delete on the same role with different claims", numRaceRounds)
	}
}

func joinRaceFailures(failures []string) string {
	out := ""
	for _, f := range failures {
		out += "  - " + f + "\n"
	}
	return out
}
