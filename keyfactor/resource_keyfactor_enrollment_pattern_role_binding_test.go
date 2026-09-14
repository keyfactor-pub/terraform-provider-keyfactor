package keyfactor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	sdkclient "github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// ---------------------------------------------------------------------------
// Integration tests for keyfactor_enrollment_pattern_role_binding
// ---------------------------------------------------------------------------

// testAccEnrollmentPatternRoleBindingConfig returns the full HCL config for a
// role binding integration test. It creates the enrollment pattern, the
// security role, and the binding resource.
func testAccEnrollmentPatternRoleBindingConfig(patternName, roleName string, templateID int) string {
	return fmt.Sprintf(`
data "keyfactor_permission_set" "ep_rb_global" {
  name = "Global"
}

resource "keyfactor_oauth_security_role" "ep_rb_role" {
  name              = %q
  description       = "Created by terraform-provider integration test (role binding)"
  permission_set_id = data.keyfactor_permission_set.ep_rb_global.id
  permissions       = ["/metadata/types/read/"]
}

resource "keyfactor_enrollment_pattern" "ep_rb_pattern" {
  name        = %q
  template_id = %d
}

resource "keyfactor_enrollment_pattern_role_binding" "test" {
  enrollment_pattern_name = keyfactor_enrollment_pattern.ep_rb_pattern.name
  role_name               = keyfactor_oauth_security_role.ep_rb_role.name
}
`, roleName, patternName, templateID)
}

// TestIntKeyfactorEnrollmentPatternRoleBindingResource verifies the happy-path
// lifecycle (create, read, import by composite key, delete) for the
// keyfactor_enrollment_pattern_role_binding resource.
func TestIntKeyfactorEnrollmentPatternRoleBindingResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	// Enrollment patterns require Command v25+.
	if _, err := client.GetEnrollmentPatterns(); err != nil {
		t.Skipf("Enrollment patterns API not available (requires Command v25+): %s", err)
	}

	templateID := discoverTemplateID(t, client)
	patternName := acctest.RandomWithPrefix("tf-int-ep-rb")
	roleName := acctest.RandomWithPrefix("tf-int-ep-rb-role")
	bindingPath := "keyfactor_enrollment_pattern_role_binding.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create the binding and verify it exists.
			{
				Config: testAccEnrollmentPatternRoleBindingConfig(patternName, roleName, templateID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(bindingPath, "id"),
					resource.TestCheckResourceAttr(bindingPath, "enrollment_pattern_name", patternName),
					resource.TestCheckResourceAttr(bindingPath, "role_name", roleName),
				),
			},
			// Step 2: import by composite key "<patternName>:<roleName>" and
			// verify the state round-trip matches.
			{
				ResourceName:      bindingPath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(*terraform.State) (string, error) {
					return patternName + ":" + roleName, nil
				},
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Concurrent race test
// ---------------------------------------------------------------------------

// concurrentEPRoleBindingRaceHarness drives concurrent add/remove of two roles
// against the same enrollment pattern, mirroring
// concurrentClaimAssociationRaceHarness's shape from the OAuth claim
// association race test. Each operation uses the same GET-modify-PUT-verify
// retry loop that the provider's Create/Delete methods use, so the race test
// validates that the retry loop actually resolves conflicts without flaking.
type concurrentEPRoleBindingRaceHarness struct {
	t         *testing.T
	sdk       *sdkclient.APIClient
	patternID int32
	role1     string
	role2     string
}

func newConcurrentEPRoleBindingRaceHarness(
	t *testing.T,
	sdk *sdkclient.APIClient,
	patternID int32,
	role1, role2 string,
) *concurrentEPRoleBindingRaceHarness {
	t.Helper()
	return &concurrentEPRoleBindingRaceHarness{
		t: t, sdk: sdk, patternID: patternID, role1: role1, role2: role2,
	}
}

// addRole adds roleName to the pattern's AssociatedRoles via GET-modify-PUT,
// retrying up to oauthRoleClaimReconcileMaxAttempts times on conflict.
func (h *concurrentEPRoleBindingRaceHarness) addRole(ctx context.Context, roleName string) error {
	for attempt := 1; attempt <= oauthRoleClaimReconcileMaxAttempts; attempt++ {
		resp, _, err := h.sdk.V1.EnrollmentPatternApi.
			NewGetEnrollmentPatternsByIdRequest(ctx, h.patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil {
			return fmt.Errorf("addRole GET attempt %d: %w", attempt, err)
		}

		current := extractEnrollmentPatternRoleNames(resp)
		for _, n := range current {
			if n == roleName {
				return nil // already present
			}
		}
		updated := append(current, roleName)

		name := ""
		if resp.Name.IsSet() && resp.Name.Get() != nil {
			name = *resp.Name.Get()
		}
		policy := v1.EnrollmentPatternsEnrollmentPatternPolicyRequest{}
		body := v1.NewEnrollmentPatternsEnrollmentPatternRequest(name, policy)
		body.SetAssociatedRoles(updated)

		putResp, _, putErr := h.sdk.V1.EnrollmentPatternApi.
			NewUpdateEnrollmentPatternsByIdRequest(ctx, h.patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			EnrollmentPatternsEnrollmentPatternRequest(*body).
			Execute()
		if putErr != nil {
			if attempt < oauthRoleClaimReconcileMaxAttempts {
				delay := oauthRoleClaimReconcileBackoff(attempt)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
				continue
			}
			return fmt.Errorf("addRole PUT attempt %d: %w", attempt, putErr)
		}
		if enrollmentPatternHasRole(putResp, roleName) {
			return nil
		}
	}
	return fmt.Errorf("addRole: failed to verify role %q present after %d attempts", roleName, oauthRoleClaimReconcileMaxAttempts)
}

// removeRole removes roleName from the pattern's AssociatedRoles via
// GET-modify-PUT, retrying on conflict.
func (h *concurrentEPRoleBindingRaceHarness) removeRole(ctx context.Context, roleName string) error {
	for attempt := 1; attempt <= oauthRoleClaimReconcileMaxAttempts; attempt++ {
		resp, _, err := h.sdk.V1.EnrollmentPatternApi.
			NewGetEnrollmentPatternsByIdRequest(ctx, h.patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil {
			return fmt.Errorf("removeRole GET attempt %d: %w", attempt, err)
		}

		current := extractEnrollmentPatternRoleNames(resp)
		found := false
		filtered := make([]string, 0, len(current))
		for _, n := range current {
			if n == roleName {
				found = true
			} else {
				filtered = append(filtered, n)
			}
		}
		if !found {
			return nil // already absent
		}

		name := ""
		if resp.Name.IsSet() && resp.Name.Get() != nil {
			name = *resp.Name.Get()
		}
		policy := v1.EnrollmentPatternsEnrollmentPatternPolicyRequest{}
		body := v1.NewEnrollmentPatternsEnrollmentPatternRequest(name, policy)
		body.SetAssociatedRoles(filtered)

		putResp, _, putErr := h.sdk.V1.EnrollmentPatternApi.
			NewUpdateEnrollmentPatternsByIdRequest(ctx, h.patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			EnrollmentPatternsEnrollmentPatternRequest(*body).
			Execute()
		if putErr != nil {
			if attempt < oauthRoleClaimReconcileMaxAttempts {
				delay := oauthRoleClaimReconcileBackoff(attempt)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
				continue
			}
			return fmt.Errorf("removeRole PUT attempt %d: %w", attempt, putErr)
		}
		if !enrollmentPatternHasRole(putResp, roleName) {
			return nil
		}
	}
	return fmt.Errorf("removeRole: failed to verify role %q absent after %d attempts", roleName, oauthRoleClaimReconcileMaxAttempts)
}

// runConcurrent runs fn(role1) and fn(role2) in parallel and returns both errors.
func (h *concurrentEPRoleBindingRaceHarness) runConcurrent(
	ctx context.Context,
	fn func(context.Context, string) error,
) (err1, err2 error) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); err1 = fn(ctx, h.role1) }()
	go func() { defer wg.Done(); err2 = fn(ctx, h.role2) }()
	wg.Wait()
	return
}

// remoteRoles returns the set of role names currently associated with the
// pattern, as seen by a fresh GET.
func (h *concurrentEPRoleBindingRaceHarness) remoteRoles(ctx context.Context) (map[string]bool, error) {
	resp, _, err := h.sdk.V1.EnrollmentPatternApi.
		NewGetEnrollmentPatternsByIdRequest(ctx, h.patternID).
		XKeyfactorRequestedWith("APIClient").
		XKeyfactorApiVersion("1").
		Execute()
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool)
	for _, n := range extractEnrollmentPatternRoleNames(resp) {
		m[n] = true
	}
	return m, nil
}

// testAccRaceEPAndRolesConfig creates an enrollment pattern and two security
// roles that the race test will concurrently bind/unbind.
func testAccRaceEPAndRolesConfig(patternName, role1Name, role2Name string, templateID int) string {
	return fmt.Sprintf(`
data "keyfactor_permission_set" "ep_race_global" {
  name = "Global"
}

resource "keyfactor_enrollment_pattern" "race_pattern" {
  name        = %q
  template_id = %d
}

resource "keyfactor_oauth_security_role" "race_role_1" {
  name              = %q
  description       = "TF EP role binding race test role 1"
  permission_set_id = data.keyfactor_permission_set.ep_race_global.id
  permissions       = ["/metadata/types/read/"]
}

resource "keyfactor_oauth_security_role" "race_role_2" {
  name              = %q
  description       = "TF EP role binding race test role 2"
  permission_set_id = data.keyfactor_permission_set.ep_race_global.id
  permissions       = ["/metadata/types/read/"]

  depends_on = [keyfactor_oauth_security_role.race_role_1]
}
`, patternName, templateID, role1Name, role2Name)
}

// TestIntKeyfactorEnrollmentPatternRoleBinding_ConcurrentCreateDeleteRace
// verifies that concurrent Create and Delete operations on the same enrollment
// pattern do not corrupt role membership. It runs numRaceRounds rounds of
// simultaneous add(role1)+add(role2) followed by remove(role1)+remove(role2),
// checking after each phase that the server state is correct. The
// GET-modify-PUT-verify retry loop in the provider and in this harness must
// resolve all conflicts without a single flake.
func TestIntKeyfactorEnrollmentPatternRoleBinding_ConcurrentCreateDeleteRace(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	if _, err := client.GetEnrollmentPatterns(); err != nil {
		t.Skipf("Enrollment patterns API not available (requires Command v25+): %s", err)
	}

	templateID := discoverTemplateID(t, client)

	const numRaceRounds = 10

	sdk := newSDKTestClient(t)

	patternName := acctest.RandomWithPrefix("tf-int-ep-race")
	role1Name := acctest.RandomWithPrefix("tf-int-ep-race-r1")
	role2Name := acctest.RandomWithPrefix("tf-int-ep-race-r2")

	var raceFailures []string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create the enrollment pattern and two roles via Terraform;
				// then drive concurrent add/remove directly via SDK so all
				// API traffic happens within a single Terraform step.
				Config: testAccRaceEPAndRolesConfig(patternName, role1Name, role2Name, templateID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_enrollment_pattern.race_pattern", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_oauth_security_role.race_role_1", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_oauth_security_role.race_role_2", "id"),
					func(s *terraform.State) error {
						patternIDStr, err := getResourceIdFromTerraformState(s, "keyfactor_enrollment_pattern.race_pattern")
						if err != nil {
							return fmt.Errorf("failed to get pattern ID from state: %w", err)
						}
						var patternID int32
						if _, err := fmt.Sscanf(patternIDStr, "%d", &patternID); err != nil {
							return fmt.Errorf("failed to parse pattern ID %q: %w", patternIDStr, err)
						}

						ctx := context.Background()
						h := newConcurrentEPRoleBindingRaceHarness(t, sdk, patternID, role1Name, role2Name)

						for round := 1; round <= numRaceRounds; round++ {
							// --- Concurrent Add ---
							addErr1, addErr2 := h.runConcurrent(ctx, h.addRole)
							if addErr1 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d add(role1): %v", round, addErr1))
							}
							if addErr2 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d add(role2): %v", round, addErr2))
							}
							if addErr1 != nil || addErr2 != nil {
								continue
							}

							// Verify both roles are present.
							roles, err := h.remoteRoles(ctx)
							if err != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d post-add GET: %v", round, err))
								continue
							}
							if !roles[role1Name] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: role1 missing after concurrent add", round))
							}
							if !roles[role2Name] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: role2 missing after concurrent add", round))
							}

							// --- Concurrent Remove ---
							rmErr1, rmErr2 := h.runConcurrent(ctx, h.removeRole)
							if rmErr1 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d remove(role1): %v", round, rmErr1))
							}
							if rmErr2 != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d remove(role2): %v", round, rmErr2))
							}
							if rmErr1 != nil || rmErr2 != nil {
								continue
							}

							// Verify both roles are absent.
							roles, err = h.remoteRoles(ctx)
							if err != nil {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d post-remove GET: %v", round, err))
								continue
							}
							if roles[role1Name] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: role1 still present after concurrent remove", round))
							}
							if roles[role2Name] {
								raceFailures = append(raceFailures, fmt.Sprintf("round %d: role2 still present after concurrent remove", round))
							}
						}

						if len(raceFailures) > 0 {
							return fmt.Errorf("concurrent role binding race failures (%d):\n%s",
								len(raceFailures), strings.Join(raceFailures, "\n"))
						}
						return nil
					},
				),
			},
		},
	})
}
