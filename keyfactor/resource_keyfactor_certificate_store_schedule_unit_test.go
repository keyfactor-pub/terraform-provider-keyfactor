package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitInventoryScheduleForRequest is a regression test for the bug where
// Update built the outgoing InventorySchedule from plan.InventorySchedule.Value
// without checking IsNull. createInventorySchedule always returns a non-nil
// &api.InventorySchedule{} (even for an empty/unresolved interval), and the
// request field's `omitempty` never fires for a non-nil-but-zero struct — so an
// undeclared schedule was sent as an explicit empty InventorySchedule{} object
// instead of being omitted. The gate returns nil when the plan does not declare
// a schedule so the field is omitted.
func TestUnitInventoryScheduleForRequest(t *testing.T) {
	t.Run("null plan value is omitted", func(t *testing.T) {
		sched, err := inventoryScheduleForRequest(types.String{Null: true})
		assert.NoError(t, err)
		assert.Nil(t, sched, "an undeclared (null) inventory_schedule must be omitted, not sent as {}")
	})

	t.Run("unknown plan value is omitted", func(t *testing.T) {
		sched, err := inventoryScheduleForRequest(types.String{Unknown: true})
		assert.NoError(t, err)
		assert.Nil(t, sched, "an unknown inventory_schedule must be omitted")
	})

	t.Run("empty string is omitted", func(t *testing.T) {
		sched, err := inventoryScheduleForRequest(types.String{Value: ""})
		assert.NoError(t, err)
		assert.Nil(t, sched, "an empty inventory_schedule must be omitted, not sent as {}")
	})

	t.Run("real value is built", func(t *testing.T) {
		sched, err := inventoryScheduleForRequest(types.String{Value: "immediate"})
		assert.NoError(t, err)
		if assert.NotNil(t, sched, "a real inventory_schedule must be sent") {
			assert.NotNil(t, sched.Immediate)
		}
	})
}
