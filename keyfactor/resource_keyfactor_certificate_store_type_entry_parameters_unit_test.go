package keyfactor

import (
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
)

// ---------------------------------------------------------------------------
// Regression tests for GitHub issue #192:
//
// keyfactor_certificate_store_type with entry_parameters = [] (or
// properties = []) read back as null after Create, producing "Provider
// produced inconsistent result after apply". Command's GET response for a
// store type always represents an empty Properties/EntryParameters
// collection as [] rather than null, but certStoreTypeDefToState built its
// result by appending onto a Go nil slice -- which stays nil (and therefore
// encodes as a null list, per terraform-plugin-framework's reflection
// layer) whenever the server array has zero elements, regardless of what
// the user actually declared in config.
//
// The fix has two parts:
//  1. certStoreTypeDefToState now produces a non-nil (possibly zero-length)
//     slice whenever the API returned a non-nil array, giving it full
//     fidelity to the server response.
//  2. preserveListEmptyVsNull reconciles that result against the plan/prior
//     state in Create/Read/Update, since the server response's shape alone
//     cannot distinguish "user wrote entry_parameters = []" from "user
//     never mentioned entry_parameters" -- both produce an empty response.
// ---------------------------------------------------------------------------

func TestUnitCertStoreTypeDefToState_EmptyCollectionsAreNonNil(t *testing.T) {
	t.Parallel()

	// Server response explicitly carries empty (non-nil) arrays, as
	// observed from a live Command instance for store types with no
	// entry parameters -- the JSON is "EntryParameters": [], never null.
	emptyProps := []api.StoreTypePropertyDefinition{}
	emptyEntryParams := []api.EntryParameter{}
	resp := &api.CertificateStoreType{
		Name:            "Test Store Type",
		ShortName:       "TST",
		StoreType:       1,
		Properties:      &emptyProps,
		EntryParameters: &emptyEntryParams,
	}

	state := certStoreTypeDefToState(resp)

	if state.Properties == nil {
		t.Error("Properties: want non-nil empty slice (server returned a non-nil empty array), got nil")
	}
	if len(state.Properties) != 0 {
		t.Errorf("Properties: want length 0, got %d", len(state.Properties))
	}
	if state.EntryParameters == nil {
		t.Error("EntryParameters: want non-nil empty slice (server returned a non-nil empty array), got nil")
	}
	if len(state.EntryParameters) != 0 {
		t.Errorf("EntryParameters: want length 0, got %d", len(state.EntryParameters))
	}
}

func TestUnitCertStoreTypeDefToState_AbsentCollectionsAreNil(t *testing.T) {
	t.Parallel()

	// Pointer left nil (field truly absent from the response) must still
	// decode to a nil Go slice, which the framework encodes as null.
	resp := &api.CertificateStoreType{
		Name:      "Test Store Type",
		ShortName: "TST",
		StoreType: 1,
	}

	state := certStoreTypeDefToState(resp)

	if state.Properties != nil {
		t.Errorf("Properties: want nil, got %+v", state.Properties)
	}
	if state.EntryParameters != nil {
		t.Errorf("EntryParameters: want nil, got %+v", state.EntryParameters)
	}
}

func TestUnitPreserveListEmptyVsNull(t *testing.T) {
	t.Parallel()

	t.Run("declared-empty reference forces empty (not null) target", func(t *testing.T) {
		t.Parallel()

		// Simulates: config declared entry_parameters = [], plan decodes to
		// a non-nil empty slice, but the server-derived target ended up nil
		// (e.g. if the fidelity fix above were absent).
		var target []CertStoreTypeEntryParam // nil, as if the server produced an empty response
		reference := []CertStoreTypeEntryParam{}

		preserveListEmptyVsNull(&target, reference)

		if target == nil {
			t.Fatal("expected target to become a non-nil empty slice, got nil")
		}
		if len(target) != 0 {
			t.Errorf("expected empty slice, got length %d", len(target))
		}
	})

	t.Run("nil reference (undeclared) keeps target nil", func(t *testing.T) {
		t.Parallel()

		target := []CertStoreTypeEntryParam{} // e.g. produced by certStoreTypeDefToState's fidelity fix
		var reference []CertStoreTypeEntryParam = nil

		preserveListEmptyVsNull(&target, reference)

		if target != nil {
			t.Errorf("expected target to become nil (undeclared attribute), got %+v", target)
		}
	})

	t.Run("populated target is left untouched regardless of reference", func(t *testing.T) {
		t.Parallel()

		target := []CertStoreTypeEntryParam{{}}
		var reference []CertStoreTypeEntryParam = nil

		preserveListEmptyVsNull(&target, reference)

		if len(target) != 1 {
			t.Errorf("expected populated target to be left alone, got length %d", len(target))
		}
	})
}

// TestUnitCertStoreTypeCreateRoundTripsDeclaredEmptyEntryParameters exercises
// the full certStoreTypeDefToState + preserveListEmptyVsNull flow the way
// Create calls it, confirming that entry_parameters = [] in config
// round-trips as [] rather than null.
func TestUnitCertStoreTypeCreateRoundTripsDeclaredEmptyEntryParameters(t *testing.T) {
	t.Parallel()

	emptyEntryParams := []api.EntryParameter{}
	resp := &api.CertificateStoreType{
		Name:            "Test Store Type",
		ShortName:       "TST",
		StoreType:       1,
		EntryParameters: &emptyEntryParams,
	}

	// plan.EntryParameters as decoded from a config that declared
	// entry_parameters = [] -- a non-nil, zero-length slice.
	plan := KeyfactorCertStoreTypeDef{
		EntryParameters: []CertStoreTypeEntryParam{},
	}

	state := certStoreTypeDefToState(resp)
	preserveListEmptyVsNull(&state.Properties, plan.Properties)
	preserveListEmptyVsNull(&state.EntryParameters, plan.EntryParameters)

	if state.EntryParameters == nil {
		t.Error("state.EntryParameters: want non-nil empty slice (config declared []), got nil")
	}
}

// TestUnitCertStoreTypeCreateUndeclaredEntryParametersStaysNil is the
// counterpart: when the user never mentions entry_parameters in config,
// the result must stay null even though the server also returns [].
func TestUnitCertStoreTypeCreateUndeclaredEntryParametersStaysNil(t *testing.T) {
	t.Parallel()

	emptyEntryParams := []api.EntryParameter{}
	resp := &api.CertificateStoreType{
		Name:            "Test Store Type",
		ShortName:       "TST",
		StoreType:       1,
		EntryParameters: &emptyEntryParams,
	}

	// plan.EntryParameters as decoded from a config that never mentions
	// entry_parameters -- a nil slice (see internal/reflect/into.go:
	// a null config value decodes to reflect.Zero, i.e. Go nil).
	plan := KeyfactorCertStoreTypeDef{
		EntryParameters: nil,
	}

	state := certStoreTypeDefToState(resp)
	preserveListEmptyVsNull(&state.Properties, plan.Properties)
	preserveListEmptyVsNull(&state.EntryParameters, plan.EntryParameters)

	if state.EntryParameters != nil {
		t.Errorf("state.EntryParameters: want nil (attribute left unset), got %+v", state.EntryParameters)
	}
}
