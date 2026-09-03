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
// Core-level regression test for full-review finding F3.
//
// Every existing unit test for content/query calls Create()/Read()/
// Update() directly, bypassing Terraform Core's own apply-consistency
// check -- exactly how this finding shipped undetected. This test drives a
// real two-step Terraform lifecycle through resource.UnitTest against a
// cassette recorded from kfclab: editing query on Update() must APPLY
// successfully (before the fix, the stale content mirror pinned by
// tfsdk.UseStateForUnknown() disagreed with Update()'s genuinely
// re-normalized content, hard-erroring with "Provider produced
// inconsistent result after apply" on this resource's primary, defining
// update path).
//
// To record the cassette against kfclab:
//
//	KEYFACTOR_ENV_FILE=~/.env_kfclab RECORD_CASSETTES=1 \
//	  make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateCollectionResource_ContentFollowsQueryOnUpdate
// ---------------------------------------------------------------------------

type certificateCollectionContentFixTestParams struct {
	Suffix string `json:"suffix"`
}

func writeCertificateCollectionContentFixTestParams(cassettePath string, params certificateCollectionContentFixTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCertificateCollectionContentFixTestParams(cassettePath string) certificateCollectionContentFixTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return certificateCollectionContentFixTestParams{}
	}
	var params certificateCollectionContentFixTestParams
	if json.Unmarshal(data, &params) != nil {
		return certificateCollectionContentFixTestParams{}
	}
	return params
}

func testAccCertificateCollectionContentFixConfig(suffix string, step2 bool) string {
	query := `IssuedDN -contains "demo"`
	if step2 {
		query = `IssuedDN -contains "demo-updated"`
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate_collection" "test" {
  name        = "TFCCFix%s"
  description = "TF F3 regression test collection"
  query       = %q
}
`, suffix, query)
}

func TestUnitKeyfactorCertificateCollectionResource_ContentFollowsQueryOnUpdate(t *testing.T) {
	cassetteName := "certificate_collection_resource_content_follows_query"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var suffix string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		suffix = fmt.Sprintf("_TFU%d", time.Now().UnixNano()%1000000)
		writeCertificateCollectionContentFixTestParams(cassettePath, certificateCollectionContentFixTestParams{Suffix: suffix})
	} else {
		params := readCertificateCollectionContentFixTestParams(cassettePath)
		suffix = params.Suffix
		if suffix == "" {
			t.Skip("No cassette params recorded for this test -- record with RECORD_CASSETTES=1 against kfclab (see file doc comment)")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_collection.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateCollectionContentFixConfig(suffix, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "query", `IssuedDN -contains "demo"`),
					resource.TestCheckResourceAttrSet(resourceName, "content"),
				),
			},
			{
				// F3: query changes -- content must be recomputed from
				// Update()'s response instead of being pinned to the
				// stale, pre-update-normalized value. Before the fix, this
				// step hard-errors with "Provider produced inconsistent
				// result after apply" on .content whenever normalization
				// doesn't coincidentally produce the identical string.
				Config: testAccCertificateCollectionContentFixConfig(suffix, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "query", `IssuedDN -contains "demo-updated"`),
					resource.TestCheckResourceAttrSet(resourceName, "content"),
				),
			},
		},
	})
}
