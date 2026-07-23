package keyfactor

import (
	"context"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitCAUpdatePreservesScanSchedules is a regression test for the bug where
// an Update() that did not declare the scan/threshold schedule attributes
// (undeclared in config) let buildCARequest omit FullScan/IncrementalScan/
// ThresholdCheck from the PUT body. Because Command's CA PUT is a full
// replacement, an omitted schedule is cleared server-side, silently wiping a
// live scan/threshold schedule on any unrelated Update. The fix preserves the
// prior state value when config does not declare the attribute.
func TestUnitCAUpdatePreservesScanSchedules(t *testing.T) {
	ctx := context.Background()

	// State carries a real scan/threshold schedule (as populated from a prior
	// Read of the server). Config leaves all three undeclared (Null); the raw
	// plan mirrors that (a real UseStateForUnknown-family modifier would have
	// already resolved it, but preserveCAUpdateFields must key on config, not
	// this incoming plan value, per its doc comment).
	state := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Value: 60},
		IncrementalScanIntervalMinutes: types.Int64{Value: 5},
		ThresholdCheckIntervalMinutes:  types.Int64{Value: 30},
	}
	config := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
	}
	plan := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
	}

	preserveCAUpdateFields(&plan, config, state)
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
// attribute undeclared in config, buildCARequest previously omitted it, and
// because the CA PUT is a full replacement, the omission cleared the CA's
// real security-role list. The fix preserves the prior state value.
func TestUnitCAUpdatePreservesAllowedRequesters(t *testing.T) {
	ctx := context.Background()

	// Normal lifecycle: state carries the real requester list (preserved from
	// plan on Create/Read), config leaves it undeclared on an unrelated Update.
	state := KeyfactorCertificateAuthority{
		AllowedRequesters: stringSliceToTfList([]string{"Role-A", "Role-B"}),
	}
	config := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}
	plan := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}

	preserveCAUpdateFields(&plan, config, state)
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
	config := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}
	plan := KeyfactorCertificateAuthority{
		AllowedRequesters: types.List{Null: true, ElemType: types.StringType},
	}

	preserveCAUpdateFields(&plan, config, state)
	req := buildCARequest(ctx, plan)

	assert.Nil(t, req.AllowedRequesters,
		"allowed_requesters must be omitted (nil) when it was never populated, not sent as an explicit empty clear")
}

// TestUnitCAUpdatePreservesScanScheduleWhenPlanIsUnknownNotNull is a
// regression test distinguishing the config-keyed preserveCAUpdateFields from
// the old plan-Null-keyed version. The old check was `if p.Null { ... }`,
// which only catches the case where the incoming plan value is exactly Null
// — it does NOT catch a plan value that is Unknown (a distinct state from
// Null for types.Int64). buildCARequest treats Unknown identically to Null
// (both fail its `!Null && !Unknown` guard and get omitted from the PUT
// body), so an Unknown-but-undeclared plan value would have silently cleared
// the schedule under the old check.
//
// Keying on declaredInConfig(config.X) instead catches this case correctly:
// config is undeclared (Null) regardless of what shape the incoming plan
// value happens to be in, so the prior state value is preserved either way.
func TestUnitCAUpdatePreservesScanScheduleWhenPlanIsUnknownNotNull(t *testing.T) {
	ctx := context.Background()

	state := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes: types.Int64{Value: 60},
	}
	config := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes: types.Int64{Null: true}, // undeclared
	}
	plan := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes: types.Int64{Unknown: true}, // NOT Null -- the case the old plan.Null check missed
	}

	preserveCAUpdateFields(&plan, config, state)
	req := buildCARequest(ctx, plan)

	assert.Equal(t, types.Int64{Value: 60}, plan.FullScanIntervalMinutes,
		"an undeclared-in-config schedule must be preserved from state even when the incoming plan value is Unknown rather than Null")
	if assert.NotNil(t, req.FullScan, "FullScan must be preserved, not omitted (omission clears it server-side)") {
		assert.NotNil(t, req.FullScan.Interval)
		assert.Equal(t, int32(60), *req.FullScan.Interval.Minutes)
	}
}

// TestUnitCAReadSurfacesAllowedRequestersDrift is the regression test for G3:
// preserveSecrets used to echo the prior state/plan's allowed_requesters over
// whatever caResponseToState had just mapped from the server's GET response,
// even though Command v25.5+ genuinely returns the list (confirmed live).
// That meant Read() could never detect a role added/removed from the
// allowed-requester list out-of-band -- it always silently "corrected" the
// server's real value back to the stale one already in state.
//
// This builds a server response reporting a DIFFERENT allowed-requester list
// than prior state/plan carries, runs it through caResponseToState then
// preserveSecrets (mirroring the Read()/Create()/Update() call sequence), and
// asserts the server's list wins -- not the stale echo.
func TestUnitCAReadSurfacesAllowedRequestersDrift(t *testing.T) {
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(9)
	resp.SetLogicalName("Standalone-CA")
	resp.SetHostName("http://ca.lab/ejbca")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	resp.AllowedRequesters = []string{"Role-C"} // server truth, changed out-of-band

	staleSource := KeyfactorCertificateAuthority{
		AllowedRequesters: stringSliceToTfList([]string{"Role-A", "Role-B"}), // what Terraform last knew
	}

	newState := caResponseToState(resp)
	preserveSecrets(&newState, staleSource)

	var got []string
	for _, e := range newState.AllowedRequesters.Elems {
		if sv, ok := e.(types.String); ok {
			got = append(got, sv.Value)
		}
	}

	assert.Equal(t, []string{"Role-C"}, got,
		"Read must surface the server's real allowed_requesters, not silently re-echo a stale prior value")
}

// TestUnitCAUpdateExplicitEmptyAllowedRequestersIsSent is the companion
// regression test for the clear path: with the config-keyed
// preserveCAUpdateFields, an explicitly-declared empty list ([]) in config is
// NOT undeclared (declaredInConfig treats a non-null, even empty, list as
// declared), so it must be sent through to buildCARequest as a real clearing
// value rather than being preserved from the old (non-empty) state.
func TestUnitCAUpdateExplicitEmptyAllowedRequestersIsSent(t *testing.T) {
	ctx := context.Background()

	state := KeyfactorCertificateAuthority{
		AllowedRequesters: stringSliceToTfList([]string{"Role-A", "Role-B"}),
	}
	// An explicit [] in config: Null=false, Elems empty -- declared, not omitted.
	explicitEmpty := types.List{ElemType: types.StringType, Elems: []attr.Value{}}
	config := KeyfactorCertificateAuthority{AllowedRequesters: explicitEmpty}
	plan := KeyfactorCertificateAuthority{AllowedRequesters: explicitEmpty}

	preserveCAUpdateFields(&plan, config, state)
	req := buildCARequest(ctx, plan)

	assert.NotNil(t, req.AllowedRequesters, "an explicitly declared empty list must be sent through, not preserved from the old state")
	assert.Len(t, req.AllowedRequesters, 0, "the cleared list must be sent as an explicit empty list, not the old requesters")
}
