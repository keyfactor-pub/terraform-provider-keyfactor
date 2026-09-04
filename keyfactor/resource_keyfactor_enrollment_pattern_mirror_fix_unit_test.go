package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdkclient "github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// ---------------------------------------------------------------------------
// Core-level regression test for full-review findings F1, F2, F4, and F8.
//
// Every existing unit test for these findings calls Create()/Read()/
// Update() directly, bypassing Terraform Core's own plan-validity
// (assertPlannedValueValid) and apply-consistency checks entirely -- which
// is exactly how these findings shipped undetected. This test drives a
// real two-step Terraform lifecycle through resource.UnitTest against a
// cassette recorded from kfclab, so Core's own checks are actually
// exercised:
//
//   - F1: declaring force_template_default = true on an Update() must
//     PLAN successfully at all (before the fix, Core rejected the plan
//     outright with "planned value cty.UnknownVal(cty.Bool) does not
//     match config value cty.True").
//   - F2: changing associated_role_names from one role to another must
//     APPLY successfully (before the fix, the stale associated_roles
//     mirror pinned by useStateOrNullModifier disagreed with Update()'s
//     genuinely-new membership, hard-erroring with "Provider produced
//     inconsistent result after apply").
//   - F4: changing policies.default_certificate_owner_role_id from one
//     role to another must APPLY successfully (identical shape, for the
//     policies.default_certificate_owner_role_name mirror).
//   - F8: force_template_default = true must actually take effect (become
//     the template's default, stealing that status from whichever pattern
//     held it before) AND must settle to a stable plan (no perpetual
//     "template_default = ... -> (known after apply)" diff) on the very
//     same apply's post-apply consistency re-check.
//
// Two keyfactor_role resources are created INLINE by this test's own
// config (not pre-existing lab state) so the "driver changes to a
// genuinely different, known value" scenario is self-contained and doesn't
// depend on kfclab having two suitable pre-existing security roles. F8's
// force_template_default = true DOES interact with pre-existing lab state
// (it steals default status from whichever pattern currently holds it for
// this template), so step 2 undoes that side effect via
// restoreOriginalTemplateDefault before the framework's automatic
// post-test destroy runs -- see that function's doc comment.
//
// To record the cassette against kfclab:
//
//	KEYFACTOR_ENV_FILE=~/.env_kfclab RECORD_CASSETTES=1 \
//	  make testunit-record-one TEST_NAME=TestUnitKeyfactorEnrollmentPatternResource_MirrorFieldsFollowDriverOnUpdate
// ---------------------------------------------------------------------------

type enrollmentPatternMirrorFixTestParams struct {
	TemplateID int    `json:"template_id"`
	Suffix     string `json:"suffix"`
}

func writeEnrollmentPatternMirrorFixTestParams(cassettePath string, params enrollmentPatternMirrorFixTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readEnrollmentPatternMirrorFixTestParams(cassettePath string) enrollmentPatternMirrorFixTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return enrollmentPatternMirrorFixTestParams{}
	}
	var params enrollmentPatternMirrorFixTestParams
	if json.Unmarshal(data, &params) != nil {
		return enrollmentPatternMirrorFixTestParams{}
	}
	return params
}

// testAccEnrollmentPatternMirrorFixConfig builds the two-step lifecycle
// config. step2 selects which set of driver values (role B / a
// force_template_default declaration) is active; step1 (step2=false)
// establishes the baseline (role A, no force_template_default declared).
func testAccEnrollmentPatternMirrorFixConfig(templateID int, suffix string, step2 bool) string {
	// role_b declares depends_on = [keyfactor_role.role_a] deliberately: the
	// VCR matcher (method + normalized URL path + query only, never body --
	// see makeVCRMatcher) cannot distinguish two POST /Security/Roles
	// requests from each other, so replay resolves each one strictly by
	// recorded ORDER. Without a forced dependency, Terraform Core is free
	// to create role_a/role_b concurrently in either completion order,
	// which is nondeterministic run to run and intermittently replays
	// role_a's response for role_b's create (and vice versa) --
	// "Provider produced inconsistent result after apply" on .name/
	// .description that has nothing to do with the enrollment pattern
	// fixes this test actually exercises. Forcing a fixed creation order
	// here matches whatever order was used when the cassette was recorded.
	roles := fmt.Sprintf(`
resource "keyfactor_role" "role_a" {
  name        = "TFEPFixRoleA%s"
  description = "TF F1/F2/F4 regression test role A"
  permissions = ["Certificates:Read"]
}

resource "keyfactor_role" "role_b" {
  name        = "TFEPFixRoleB%s"
  description = "TF F1/F2/F4 regression test role B"
  permissions = ["Certificates:Read"]

  depends_on = [keyfactor_role.role_a]
}
`, suffix, suffix)

	if !step2 {
		return roles + fmt.Sprintf(`
resource "keyfactor_enrollment_pattern" "test" {
  name                  = "TFEPFix%s"
  template_id           = %d
  use_ad_permissions    = false
  associated_role_names = [keyfactor_role.role_a.name]

  policies = {
    certificate_owner_role             = 2
    default_certificate_owner_override = true
    default_certificate_owner_role_id  = keyfactor_role.role_a.id
  }
}
`, suffix, templateID)
	}

	// Step 2: change BOTH driver attributes (F2, F4) and declare
	// force_template_default = true (F1) in the same apply.
	return roles + fmt.Sprintf(`
resource "keyfactor_enrollment_pattern" "test" {
  name                    = "TFEPFix%s"
  template_id             = %d
  use_ad_permissions      = false
  associated_role_names   = [keyfactor_role.role_b.name]
  force_template_default  = true

  policies = {
    certificate_owner_role             = 2
    default_certificate_owner_override = true
    default_certificate_owner_role_id  = keyfactor_role.role_b.id
  }
}
`, suffix, templateID)
}

func TestUnitKeyfactorEnrollmentPatternResource_MirrorFieldsFollowDriverOnUpdate(t *testing.T) {
	cassetteName := "enrollment_pattern_resource_mirror_fields_follow_driver"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var templateID int
	var suffix string
	// originalDefaultPatternID is whichever pre-existing pattern holds
	// TemplateDefault=true for templateID BEFORE this test's own
	// force_template_default=true step steals it away. Only populated
	// (and only ever used) while RECORD_CASSETTES=1 -- see
	// restoreOriginalTemplateDefault below.
	var originalDefaultPatternID int32

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		templateID = discoverTemplateID(t, client)
		suffix = fmt.Sprintf("_TFU%d", time.Now().UnixNano()%1000000)
		writeEnrollmentPatternMirrorFixTestParams(cassettePath, enrollmentPatternMirrorFixTestParams{
			TemplateID: templateID,
			Suffix:     suffix,
		})

		patterns, err := client.GetEnrollmentPatterns()
		if err != nil {
			t.Fatalf("failed to list enrollment patterns to find the template's current default: %v", err)
		}
		for _, p := range patterns {
			if p.Template != nil && p.Template.Id == templateID && p.TemplateDefault {
				originalDefaultPatternID = int32(p.ID)
				break
			}
		}
	} else {
		params := readEnrollmentPatternMirrorFixTestParams(cassettePath)
		templateID = params.TemplateID
		suffix = params.Suffix
		if templateID == 0 || suffix == "" {
			t.Skip("No cassette params recorded for this test -- record with RECORD_CASSETTES=1 against kfclab (see file doc comment)")
		}
	}

	// restoreOriginalTemplateDefault performs a REAL, UNRECORDED PUT
	// /EnrollmentPatterns/{id}?forceTemplateDefault=true call directly
	// against the lab, bypassing Terraform and the VCR recorder entirely
	// -- mirrors resource_keyfactor_certificate_store_container_preservation
	// _test.go's assignContainerOutOfBand pattern for the same reason: this
	// undoes an out-of-band SIDE EFFECT of this test's own step 2 (which
	// steals TemplateDefault status from whichever pattern held it before,
	// via force_template_default=true), so kfclab's shared "Lab - ..."
	// seed pattern for this template is left as the default again once the
	// test finishes -- otherwise the framework's automatic post-test
	// destroy of keyfactor_enrollment_pattern.test fails outright (Command
	// refuses to delete a pattern that currently holds default status
	// while other patterns exist for the same template), and every other
	// test/demo relying on that seed pattern being the template's default
	// is left with unexpectedly-changed shared lab state. It only runs
	// while recording; in replay mode it is a no-op so the test stays
	// network-free.
	restoreOriginalTemplateDefault := func() {
		if os.Getenv("RECORD_CASSETTES") != "1" {
			return
		}
		if originalDefaultPatternID == 0 {
			t.Logf("no pre-existing default pattern found for template %d -- nothing to restore", templateID)
			return
		}

		client := newTestClient(t)
		sdk := sdkclient.NewAPIClientWithAuth(client.AuthClient)
		ctx := context.Background()

		current, _, err := sdk.V1.EnrollmentPatternApi.
			NewGetEnrollmentPatternsByIdRequest(ctx, originalDefaultPatternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil || current == nil {
			t.Fatalf("failed to fetch original default pattern %d for restore: %v", originalDefaultPatternID, err)
		}

		name := ""
		if current.Name.IsSet() && current.Name.Get() != nil {
			name = *current.Name.Get()
		}
		body := v1.NewEnrollmentPatternsEnrollmentPatternRequest(name, v1.EnrollmentPatternsEnrollmentPatternPolicyRequest{})
		body.SetTemplateDefault(true)
		if current.UseADPermissions != nil {
			body.SetUseADPermissions(*current.UseADPermissions)
		}
		if current.AssociatedRoles != nil {
			names := make([]string, 0, len(current.AssociatedRoles))
			for _, r := range current.AssociatedRoles {
				if r.Name.IsSet() && r.Name.Get() != nil {
					names = append(names, *r.Name.Get())
				}
			}
			body.SetAssociatedRoles(names)
		}
		if current.AllowedEnrollmentTypes != nil {
			body.SetAllowedEnrollmentTypes(int32(*current.AllowedEnrollmentTypes))
		}
		if current.RestrictCAs != nil {
			body.SetRestrictCAs(*current.RestrictCAs)
		}

		_, httpResp, err := sdk.V1.EnrollmentPatternApi.
			NewUpdateEnrollmentPatternsByIdRequest(ctx, originalDefaultPatternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			EnrollmentPatternsEnrollmentPatternRequest(*body).
			ForceTemplateDefault(true).
			Execute()
		if err != nil {
			body := ""
			if httpResp != nil && httpResp.Body != nil {
				b, _ := io.ReadAll(httpResp.Body)
				body = string(b)
			}
			t.Fatalf("failed to restore original default pattern %d: %v (response body: %s)", originalDefaultPatternID, err, body)
		}
		t.Logf("Out-of-band: restored pattern %d as template %d's default, undoing this test's own force_template_default steal", originalDefaultPatternID, templateID)
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_enrollment_pattern.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Step 1: baseline -- associated_role_names = [role_a],
				// policies.default_certificate_owner_role_id = role_a.id,
				// force_template_default undeclared.
				Config: testAccEnrollmentPatternMirrorFixConfig(templateID, suffix, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "associated_role_names.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "associated_role_names.0", "keyfactor_role.role_a", "name"),
					resource.TestCheckResourceAttrPair(
						resourceName, "policies.default_certificate_owner_role_id", "keyfactor_role.role_a", "id",
					),
				),
			},
			{
				// Step 2: F2 -- associated_role_names changes to [role_b].
				// F4 -- policies.default_certificate_owner_role_id changes
				// to role_b.id. F1 -- force_template_default = true is
				// declared for the first time. Before any of the three
				// fixes, this step either fails to PLAN (F1) or fails to
				// APPLY with "Provider produced inconsistent result after
				// apply" (F2/F4) -- this step succeeding at all is the
				// regression proof for all three findings.
				Config: testAccEnrollmentPatternMirrorFixConfig(templateID, suffix, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "associated_role_names.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "associated_role_names.0", "keyfactor_role.role_b", "name"),
					resource.TestCheckResourceAttrPair(
						resourceName, "policies.default_certificate_owner_role_id", "keyfactor_role.role_b", "id",
					),
					resource.TestCheckResourceAttr(resourceName, "force_template_default", "true"),
				),
				// Deliberately NOT ExpectNonEmptyPlan here: this step's own
				// automatic post-apply refresh+plan re-check settling to
				// EMPTY is itself part of the F1/F8 regression proof (no
				// perpetual "template_default = ... -> (known after
				// apply)" diff). The out-of-band cleanup that WOULD create
				// a real, expected diff is deferred to step 3 below so it
				// can't interfere with that assertion.
			},
			{
				// Step 3: out-of-band cleanup only (RECORD_CASSETTES=1) --
				// see restoreOriginalTemplateDefault's doc comment. Re-
				// applies the SAME config as step 2 (no Terraform-visible
				// change), then its Check hands TemplateDefault status
				// back to kfclab's pre-existing seed pattern before the
				// framework's automatic post-test destroy runs (which
				// otherwise fails outright: Command refuses to delete a
				// pattern that currently holds default status while other
				// patterns exist for the same template). ExpectNonEmptyPlan
				// is required here because that out-of-band action is a
				// real, deliberate side effect this step's own post-apply
				// refresh+plan re-check will legitimately detect
				// (template_default flips back to false once this test's
				// pattern is no longer the default) -- unrelated to the
				// fixes under test.
				Config: testAccEnrollmentPatternMirrorFixConfig(templateID, suffix, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					func(*terraform.State) error {
						restoreOriginalTemplateDefault()
						return nil
					},
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
