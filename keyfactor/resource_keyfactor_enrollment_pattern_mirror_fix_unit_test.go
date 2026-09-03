package keyfactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Core-level regression test for full-review findings F1, F2, and F4.
//
// Every existing unit test for these findings calls Create()/Read()/
// Update() directly, bypassing Terraform Core's own plan-validity
// (assertPlannedValueValid) and apply-consistency checks entirely -- which
// is exactly how these three findings shipped undetected. This test drives
// a real two-step Terraform lifecycle through resource.UnitTest against a
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
//
// Two keyfactor_role resources are created INLINE by this test's own
// config (not pre-existing lab state) so the "driver changes to a
// genuinely different, known value" scenario is self-contained and doesn't
// depend on kfclab having two suitable pre-existing security roles.
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

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		templateID = discoverTemplateID(t, client)
		suffix = fmt.Sprintf("_TFU%d", time.Now().UnixNano()%1000000)
		writeEnrollmentPatternMirrorFixTestParams(cassettePath, enrollmentPatternMirrorFixTestParams{
			TemplateID: templateID,
			Suffix:     suffix,
		})
	} else {
		params := readEnrollmentPatternMirrorFixTestParams(cassettePath)
		templateID = params.TemplateID
		suffix = params.Suffix
		if templateID == 0 || suffix == "" {
			t.Skip("No cassette params recorded for this test -- record with RECORD_CASSETTES=1 against kfclab (see file doc comment)")
		}
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
			},
		},
	})
}
