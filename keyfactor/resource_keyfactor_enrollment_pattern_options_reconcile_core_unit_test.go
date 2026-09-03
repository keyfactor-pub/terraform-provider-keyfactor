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
// Core-level regression test for full-review finding F7.
//
// Drives a real two-step Terraform lifecycle through resource.UnitTest
// against a cassette recorded from kfclab: declaring an enrollment_fields
// entry with options left undeclared, then applying an unrelated change
// (description) on Update(), must APPLY successfully. Before the fix,
// Command's live echo of "Options": [] for the undeclared entry (verified
// against kfclab -- see reconcileEnrollmentFieldsOptionsFromPlan's doc
// comment) disagreed with the Null the plan promised for that entry's
// options, hard-erroring with "Provider produced inconsistent result after
// apply" on Update() -- not just a contrived edge case, since ANY update
// to a pattern with a plain enrollment field would trip it.
//
// To record the cassette against kfclab:
//
//	KEYFACTOR_ENV_FILE=~/.env_kfclab RECORD_CASSETTES=1 \
//	  make testunit-record-one TEST_NAME=TestUnitKeyfactorEnrollmentPatternResource_UndeclaredEnrollmentFieldOptionsSurviveUpdate
// ---------------------------------------------------------------------------

type enrollmentPatternOptionsFixTestParams struct {
	TemplateID int    `json:"template_id"`
	Suffix     string `json:"suffix"`
}

func writeEnrollmentPatternOptionsFixTestParams(cassettePath string, params enrollmentPatternOptionsFixTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readEnrollmentPatternOptionsFixTestParams(cassettePath string) enrollmentPatternOptionsFixTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return enrollmentPatternOptionsFixTestParams{}
	}
	var params enrollmentPatternOptionsFixTestParams
	if json.Unmarshal(data, &params) != nil {
		return enrollmentPatternOptionsFixTestParams{}
	}
	return params
}

func testAccEnrollmentPatternOptionsFixConfig(templateID int, suffix string, step2 bool) string {
	description := "TF F7 regression test pattern"
	if step2 {
		description = "TF F7 regression test pattern (updated)"
	}
	return fmt.Sprintf(`
resource "keyfactor_role" "test" {
  name        = "TFEPOptFix%s"
  description = "TF F7 regression test role"
  permissions = ["Certificates:Read"]
}

resource "keyfactor_enrollment_pattern" "test" {
  name                  = "TFEPOptFix%s"
  template_id           = %d
  description           = %q
  use_ad_permissions     = false
  associated_role_names = [keyfactor_role.test.name]

  enrollment_fields = [
    {
      name      = "probefield"
      data_type = 1
      # options deliberately left undeclared -- this is the exact F7
      # regression shape: Command echoes "Options": [] for this entry
      # regardless, which must not disagree with the Null the plan
      # promises.
    }
  ]
}
`, suffix, suffix, templateID, description)
}

func TestUnitKeyfactorEnrollmentPatternResource_UndeclaredEnrollmentFieldOptionsSurviveUpdate(t *testing.T) {
	cassetteName := "enrollment_pattern_resource_undeclared_enrollment_field_options"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var templateID int
	var suffix string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		templateID = discoverTemplateID(t, client)
		suffix = fmt.Sprintf("_TFU%d", time.Now().UnixNano()%1000000)
		writeEnrollmentPatternOptionsFixTestParams(cassettePath, enrollmentPatternOptionsFixTestParams{
			TemplateID: templateID,
			Suffix:     suffix,
		})
	} else {
		params := readEnrollmentPatternOptionsFixTestParams(cassettePath)
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
				Config: testAccEnrollmentPatternOptionsFixConfig(templateID, suffix, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "enrollment_fields.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "enrollment_fields.0.name", "probefield"),
					resource.TestCheckNoResourceAttr(resourceName, "enrollment_fields.0.options"),
				),
			},
			{
				// F7: an unrelated Update() (description only) must not
				// trip "Provider produced inconsistent result after
				// apply" on enrollment_fields.0.options -- before the
				// fix, Command's live "Options": [] echo for the still-
				// undeclared entry disagreed with the plan's Null.
				Config: testAccEnrollmentPatternOptionsFixConfig(templateID, suffix, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "description", "TF F7 regression test pattern (updated)"),
					resource.TestCheckResourceAttr(resourceName, "enrollment_fields.#", "1"),
					resource.TestCheckNoResourceAttr(resourceName, "enrollment_fields.0.options"),
				),
			},
		},
	})
}
