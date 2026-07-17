package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitCAUpdatePreservesScanSchedules is a regression test for the bug where
// an Update() that did not declare the scan/threshold schedule attributes
// (Null in the plan) let buildCARequest omit FullScan/IncrementalScan/
// ThresholdCheck from the PUT body. Because Command's CA PUT is a full
// replacement, an omitted schedule is cleared server-side, silently wiping a
// live scan/threshold schedule on any unrelated Update. The fix preserves the
// prior state value when the plan does not declare the attribute.
func TestUnitCAUpdatePreservesScanSchedules(t *testing.T) {
	ctx := context.Background()

	// State carries a real scan/threshold schedule (as populated from a prior
	// Read of the server). The plan leaves all three undeclared (Null).
	state := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Value: 60},
		IncrementalScanIntervalMinutes: types.Int64{Value: 5},
		ThresholdCheckIntervalMinutes:  types.Int64{Value: 30},
	}
	plan := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
	}

	preserveCAUpdateFields(&plan, state)
	req := buildCARequest(ctx, plan)

	if assert.NotNil(t, req.FullScan, "FullScan must be preserved, not omitted (omission clears it server-side)") {
		assert.NotNil(t, req.FullScan.Interval)
		assert.Equal(t, int32(60), *req.FullScan.Interval.Minutes)
	}
	if assert.NotNil(t, req.IncrementalScan, "IncrementalScan must be preserved") {
		assert.NotNil(t, req.IncrementalScan.Interval)
		assert.Equal(t, int32(5), *req.IncrementalScan.Interval.Minutes)
	}
	if assert.NotNil(t, req.ThresholdCheck, "ThresholdCheck must be preserved") {
		assert.NotNil(t, req.ThresholdCheck.Interval)
		assert.Equal(t, int32(30), *req.ThresholdCheck.Interval.Minutes)
	}
}

// TestUnitCAUpdatePreservesAllowedRequesters covers the allowed_requesters
// finding. Command's GET never returns the allowed-requester list, so it lives
// in state as a write-only field. On an unrelated Update() that leaves the
// attribute undeclared (Null in the plan), buildCARequest previously omitted it,
// and because the CA PUT is a full replacement, the omission cleared the CA's
// real security-role list. The fix preserves the prior state value.
func TestUnitCAUpdatePreservesAllowedRequesters(t *testing.T) {
	ctx := context.Background()

	// Normal lifecycle: state carries the real requester list (preserved from
	// plan on Create/Read), plan leaves it undeclared on an unrelated Update.
	state := KeyfactorCertificateAuthority{
		AllowedRequesters: stringSliceToTfList([]string{"Role-A", "Role-B"}),
	}
	plan := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}

	preserveCAUpdateFields(&plan, state)
	req := buildCARequest(ctx, plan)

	assert.Equal(t, []string{"Role-A", "Role-B"}, req.AllowedRequesters,
		"allowed_requesters must be preserved from state, not cleared, on an undeclared Update")
}

// TestUnitCAUpdatePostImportAllowedRequestersOmitted verifies the post-import
// edge: the server's GET does not return the list, so after ImportState the
// state value is Null and there is nothing to preserve. The request must OMIT
// allowed_requesters (nil slice) rather than send an explicit empty list, so
// Command leaves the existing list unchanged instead of being told to clear it.
func TestUnitCAUpdatePostImportAllowedRequestersOmitted(t *testing.T) {
	ctx := context.Background()

	// caResponseToState leaves allowed_requesters Null after an import.
	state := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}
	plan := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}

	preserveCAUpdateFields(&plan, state)
	req := buildCARequest(ctx, plan)

	assert.Nil(t, req.AllowedRequesters,
		"allowed_requesters must be omitted (nil) when it was never populated, not sent as an explicit empty clear")
}
