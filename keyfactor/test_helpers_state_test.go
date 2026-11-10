package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/require"
)

// Shared helpers for unit tests that build tfsdk state/plan values and compare list values.

func stringList(vals ...string) types.List {
	elems := make([]attr.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, types.String{Value: v})
	}
	return types.List{ElemType: types.StringType, Elems: elems}
}

func listStrings(t *testing.T, l types.List) []string {
	t.Helper()
	out := make([]string, 0, len(l.Elems))
	for _, e := range l.Elems {
		out = append(out, e.(types.String).Value)
	}
	return out
}

func emptyState(ctx context.Context, schema tfsdk.Schema) tfsdk.State {
	return tfsdk.State{Schema: schema, Raw: tftypes.NewValue(schema.TerraformType(ctx), nil)}
}

func stateWith(t *testing.T, schema tfsdk.Schema, v interface{}) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	st := emptyState(ctx, schema)
	diags := st.Set(ctx, v)
	require.False(t, diags.HasError(), "building test state: %v", diags)
	return st
}
