package command

import (
	"context"
	"fmt"
	kfc "github.com/Keyfactor/keyfactor-go-client-sdk/v2/api/command"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

type KeyfactorCertificateStoreModel struct {
	AgentAssigned           types.Bool              `tfsdk:"agent_assigned"`
	AgentId                 types.String            `tfsdk:"agent_id"`
	Approved                types.Bool              `tfsdk:"approved"`
	CertStoreInventoryJobId types.String            `tfsdk:"cert_store_inventory_job_id"`
	CertStoreType           types.Int64             `tfsdk:"cert_store_type"`
	ClientMachine           types.String            `tfsdk:"client_machine"`
	ContainerId             types.Int64             `tfsdk:"container_id"`
	ContainerName           types.String            `tfsdk:"container_name"`
	CreateIfMissing         types.Bool              `tfsdk:"create_if_missing"`
	DisplayName             types.String            `tfsdk:"display_name"`
	Id                      types.String            `tfsdk:"id"`
	InventorySchedule       InventoryScheduleValue  `tfsdk:"inventory_schedule"`
	Properties              types.String            `tfsdk:"properties"`
	ReenrollmentStatus      ReenrollmentStatusValue `tfsdk:"reenrollment_status"`
	SetNewPasswordAllowed   types.Bool              `tfsdk:"set_new_password_allowed"`
	Storepath               types.String            `tfsdk:"storepath"`
}

var _ basetypes.ObjectTypable = InventoryScheduleType{}

type InventoryScheduleType struct {
	basetypes.ObjectType
}

func (t InventoryScheduleType) Equal(o attr.Type) bool {
	other, ok := o.(InventoryScheduleType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t InventoryScheduleType) String() string {
	return "InventoryScheduleType"
}

func (t InventoryScheduleType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	dailyAttribute, ok := attributes["daily"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`daily is missing from object`)

		return nil, diags
	}

	dailyVal, ok := dailyAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`daily expected to be basetypes.ObjectValue, was: %T`, dailyAttribute))
	}

	exactlyOnceAttribute, ok := attributes["exactly_once"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`exactly_once is missing from object`)

		return nil, diags
	}

	exactlyOnceVal, ok := exactlyOnceAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`exactly_once expected to be basetypes.ObjectValue, was: %T`, exactlyOnceAttribute))
	}

	immediateAttribute, ok := attributes["immediate"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`immediate is missing from object`)

		return nil, diags
	}

	immediateVal, ok := immediateAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`immediate expected to be basetypes.BoolValue, was: %T`, immediateAttribute))
	}

	intervalAttribute, ok := attributes["interval"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`interval is missing from object`)

		return nil, diags
	}

	intervalVal, ok := intervalAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`interval expected to be basetypes.ObjectValue, was: %T`, intervalAttribute))
	}

	monthlyAttribute, ok := attributes["monthly"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`monthly is missing from object`)

		return nil, diags
	}

	monthlyVal, ok := monthlyAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`monthly expected to be basetypes.ObjectValue, was: %T`, monthlyAttribute))
	}

	weeklyAttribute, ok := attributes["weekly"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`weekly is missing from object`)

		return nil, diags
	}

	weeklyVal, ok := weeklyAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`weekly expected to be basetypes.ObjectValue, was: %T`, weeklyAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return InventoryScheduleValue{
		Daily:       dailyVal,
		ExactlyOnce: exactlyOnceVal,
		Immediate:   immediateVal,
		Interval:    intervalVal,
		Monthly:     monthlyVal,
		Weekly:      weeklyVal,
		state:       attr.ValueStateKnown,
	}, diags
}

func NewInventoryScheduleValueNull() InventoryScheduleValue {
	return InventoryScheduleValue{
		state: attr.ValueStateNull,
	}
}

func NewInventoryScheduleValueUnknown() InventoryScheduleValue {
	return InventoryScheduleValue{
		state: attr.ValueStateUnknown,
	}
}

func NewInventoryScheduleValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (InventoryScheduleValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing InventoryScheduleValue Attribute Value",
				"While creating a InventoryScheduleValue value, a missing attribute value was detected. "+
					"A InventoryScheduleValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("InventoryScheduleValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid InventoryScheduleValue Attribute ParamType",
				"While creating a InventoryScheduleValue value, an invalid attribute value was detected. "+
					"A InventoryScheduleValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("InventoryScheduleValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("InventoryScheduleValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra InventoryScheduleValue Attribute Value",
				"While creating a InventoryScheduleValue value, an extra attribute value was detected. "+
					"A InventoryScheduleValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra InventoryScheduleValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewInventoryScheduleValueUnknown(), diags
	}

	dailyAttribute, ok := attributes["daily"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`daily is missing from object`)

		return NewInventoryScheduleValueUnknown(), diags
	}

	dailyVal, ok := dailyAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`daily expected to be basetypes.ObjectValue, was: %T`, dailyAttribute))
	}

	exactlyOnceAttribute, ok := attributes["exactly_once"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`exactly_once is missing from object`)

		return NewInventoryScheduleValueUnknown(), diags
	}

	exactlyOnceVal, ok := exactlyOnceAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`exactly_once expected to be basetypes.ObjectValue, was: %T`, exactlyOnceAttribute))
	}

	immediateAttribute, ok := attributes["immediate"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`immediate is missing from object`)

		return NewInventoryScheduleValueUnknown(), diags
	}

	immediateVal, ok := immediateAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`immediate expected to be basetypes.BoolValue, was: %T`, immediateAttribute))
	}

	intervalAttribute, ok := attributes["interval"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`interval is missing from object`)

		return NewInventoryScheduleValueUnknown(), diags
	}

	intervalVal, ok := intervalAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`interval expected to be basetypes.ObjectValue, was: %T`, intervalAttribute))
	}

	monthlyAttribute, ok := attributes["monthly"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`monthly is missing from object`)

		return NewInventoryScheduleValueUnknown(), diags
	}

	monthlyVal, ok := monthlyAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`monthly expected to be basetypes.ObjectValue, was: %T`, monthlyAttribute))
	}

	weeklyAttribute, ok := attributes["weekly"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`weekly is missing from object`)

		return NewInventoryScheduleValueUnknown(), diags
	}

	weeklyVal, ok := weeklyAttribute.(basetypes.ObjectValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`weekly expected to be basetypes.ObjectValue, was: %T`, weeklyAttribute))
	}

	if diags.HasError() {
		return NewInventoryScheduleValueUnknown(), diags
	}

	return InventoryScheduleValue{
		Daily:       dailyVal,
		ExactlyOnce: exactlyOnceVal,
		Immediate:   immediateVal,
		Interval:    intervalVal,
		Monthly:     monthlyVal,
		Weekly:      weeklyVal,
		state:       attr.ValueStateKnown,
	}, diags
}

func NewInventoryScheduleValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) InventoryScheduleValue {
	object, diags := NewInventoryScheduleValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewInventoryScheduleValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t InventoryScheduleType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewInventoryScheduleValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewInventoryScheduleValueUnknown(), nil
	}

	if in.IsNull() {
		return NewInventoryScheduleValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewInventoryScheduleValueMust(t.AttrTypes, attributes), nil
}

func (t InventoryScheduleType) ValueType(ctx context.Context) attr.Value {
	return InventoryScheduleValue{}
}

var _ basetypes.ObjectValuable = InventoryScheduleValue{}

type InventoryScheduleValue struct {
	Daily       basetypes.ObjectValue `tfsdk:"daily"`
	ExactlyOnce basetypes.ObjectValue `tfsdk:"exactly_once"`
	Immediate   basetypes.BoolValue   `tfsdk:"immediate"`
	Interval    basetypes.ObjectValue `tfsdk:"interval"`
	Monthly     basetypes.ObjectValue `tfsdk:"monthly"`
	Weekly      basetypes.ObjectValue `tfsdk:"weekly"`
	state       attr.ValueState
}

func (v InventoryScheduleValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 6)

	var val tftypes.Value
	var err error

	attrTypes["daily"] = basetypes.ObjectType{
		AttrTypes: DailyValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["exactly_once"] = basetypes.ObjectType{
		AttrTypes: ExactlyOnceValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["immediate"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["interval"] = basetypes.ObjectType{
		AttrTypes: IntervalValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["monthly"] = basetypes.ObjectType{
		AttrTypes: MonthlyValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)
	attrTypes["weekly"] = basetypes.ObjectType{
		AttrTypes: WeeklyValue{}.AttributeTypes(ctx),
	}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 6)

		val, err = v.Daily.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["daily"] = val

		val, err = v.ExactlyOnce.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["exactly_once"] = val

		val, err = v.Immediate.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["immediate"] = val

		val, err = v.Interval.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["interval"] = val

		val, err = v.Monthly.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["monthly"] = val

		val, err = v.Weekly.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["weekly"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v InventoryScheduleValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v InventoryScheduleValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v InventoryScheduleValue) String() string {
	return "InventoryScheduleValue"
}

func (v InventoryScheduleValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	var daily basetypes.ObjectValue

	if v.Daily.IsNull() {
		daily = types.ObjectNull(
			DailyValue{}.AttributeTypes(ctx),
		)
	}

	if v.Daily.IsUnknown() {
		daily = types.ObjectUnknown(
			DailyValue{}.AttributeTypes(ctx),
		)
	}

	if !v.Daily.IsNull() && !v.Daily.IsUnknown() {
		daily = types.ObjectValueMust(
			DailyValue{}.AttributeTypes(ctx),
			v.Daily.Attributes(),
		)
	}

	var exactlyOnce basetypes.ObjectValue

	if v.ExactlyOnce.IsNull() {
		exactlyOnce = types.ObjectNull(
			ExactlyOnceValue{}.AttributeTypes(ctx),
		)
	}

	if v.ExactlyOnce.IsUnknown() {
		exactlyOnce = types.ObjectUnknown(
			ExactlyOnceValue{}.AttributeTypes(ctx),
		)
	}

	if !v.ExactlyOnce.IsNull() && !v.ExactlyOnce.IsUnknown() {
		exactlyOnce = types.ObjectValueMust(
			ExactlyOnceValue{}.AttributeTypes(ctx),
			v.ExactlyOnce.Attributes(),
		)
	}

	var interval basetypes.ObjectValue

	if v.Interval.IsNull() {
		interval = types.ObjectNull(
			IntervalValue{}.AttributeTypes(ctx),
		)
	}

	if v.Interval.IsUnknown() {
		interval = types.ObjectUnknown(
			IntervalValue{}.AttributeTypes(ctx),
		)
	}

	if !v.Interval.IsNull() && !v.Interval.IsUnknown() {
		interval = types.ObjectValueMust(
			IntervalValue{}.AttributeTypes(ctx),
			v.Interval.Attributes(),
		)
	}

	var monthly basetypes.ObjectValue

	if v.Monthly.IsNull() {
		monthly = types.ObjectNull(
			MonthlyValue{}.AttributeTypes(ctx),
		)
	}

	if v.Monthly.IsUnknown() {
		monthly = types.ObjectUnknown(
			MonthlyValue{}.AttributeTypes(ctx),
		)
	}

	if !v.Monthly.IsNull() && !v.Monthly.IsUnknown() {
		monthly = types.ObjectValueMust(
			MonthlyValue{}.AttributeTypes(ctx),
			v.Monthly.Attributes(),
		)
	}

	var weekly basetypes.ObjectValue

	if v.Weekly.IsNull() {
		weekly = types.ObjectNull(
			WeeklyValue{}.AttributeTypes(ctx),
		)
	}

	if v.Weekly.IsUnknown() {
		weekly = types.ObjectUnknown(
			WeeklyValue{}.AttributeTypes(ctx),
		)
	}

	if !v.Weekly.IsNull() && !v.Weekly.IsUnknown() {
		weekly = types.ObjectValueMust(
			WeeklyValue{}.AttributeTypes(ctx),
			v.Weekly.Attributes(),
		)
	}

	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"daily": basetypes.ObjectType{
				AttrTypes: DailyValue{}.AttributeTypes(ctx),
			},
			"exactly_once": basetypes.ObjectType{
				AttrTypes: ExactlyOnceValue{}.AttributeTypes(ctx),
			},
			"immediate": basetypes.BoolType{},
			"interval": basetypes.ObjectType{
				AttrTypes: IntervalValue{}.AttributeTypes(ctx),
			},
			"monthly": basetypes.ObjectType{
				AttrTypes: MonthlyValue{}.AttributeTypes(ctx),
			},
			"weekly": basetypes.ObjectType{
				AttrTypes: WeeklyValue{}.AttributeTypes(ctx),
			},
		},
		map[string]attr.Value{
			"daily":        daily,
			"exactly_once": exactlyOnce,
			"immediate":    v.Immediate,
			"interval":     interval,
			"monthly":      monthly,
			"weekly":       weekly,
		})

	return objVal, diags
}

func (v InventoryScheduleValue) Equal(o attr.Value) bool {
	other, ok := o.(InventoryScheduleValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Daily.Equal(other.Daily) {
		return false
	}

	if !v.ExactlyOnce.Equal(other.ExactlyOnce) {
		return false
	}

	if !v.Immediate.Equal(other.Immediate) {
		return false
	}

	if !v.Interval.Equal(other.Interval) {
		return false
	}

	if !v.Monthly.Equal(other.Monthly) {
		return false
	}

	if !v.Weekly.Equal(other.Weekly) {
		return false
	}

	return true
}

func (v InventoryScheduleValue) Type(ctx context.Context) attr.Type {
	return InventoryScheduleType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v InventoryScheduleValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"daily": basetypes.ObjectType{
			AttrTypes: DailyValue{}.AttributeTypes(ctx),
		},
		"exactly_once": basetypes.ObjectType{
			AttrTypes: ExactlyOnceValue{}.AttributeTypes(ctx),
		},
		"immediate": basetypes.BoolType{},
		"interval": basetypes.ObjectType{
			AttrTypes: IntervalValue{}.AttributeTypes(ctx),
		},
		"monthly": basetypes.ObjectType{
			AttrTypes: MonthlyValue{}.AttributeTypes(ctx),
		},
		"weekly": basetypes.ObjectType{
			AttrTypes: WeeklyValue{}.AttributeTypes(ctx),
		},
	}
}

var _ basetypes.ObjectTypable = DailyType{}

type DailyType struct {
	basetypes.ObjectType
}

func (t DailyType) Equal(o attr.Type) bool {
	other, ok := o.(DailyType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t DailyType) String() string {
	return "DailyType"
}

func (t DailyType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return nil, diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return DailyValue{
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewDailyValueNull() DailyValue {
	return DailyValue{
		state: attr.ValueStateNull,
	}
}

func NewDailyValueUnknown() DailyValue {
	return DailyValue{
		state: attr.ValueStateUnknown,
	}
}

func NewDailyValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (DailyValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing DailyValue Attribute Value",
				"While creating a DailyValue value, a missing attribute value was detected. "+
					"A DailyValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("DailyValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid DailyValue Attribute ParamType",
				"While creating a DailyValue value, an invalid attribute value was detected. "+
					"A DailyValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("DailyValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("DailyValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra DailyValue Attribute Value",
				"While creating a DailyValue value, an extra attribute value was detected. "+
					"A DailyValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra DailyValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewDailyValueUnknown(), diags
	}

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return NewDailyValueUnknown(), diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return NewDailyValueUnknown(), diags
	}

	return DailyValue{
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewDailyValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) DailyValue {
	object, diags := NewDailyValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewDailyValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t DailyType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewDailyValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewDailyValueUnknown(), nil
	}

	if in.IsNull() {
		return NewDailyValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewDailyValueMust(t.AttrTypes, attributes), nil
}

func (t DailyType) ValueType(ctx context.Context) attr.Value {
	return DailyValue{}
}

var _ basetypes.ObjectValuable = DailyValue{}

type DailyValue struct {
	Time  basetypes.StringValue `tfsdk:"time"`
	state attr.ValueState
}

func (v DailyValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 1)

	var val tftypes.Value
	var err error

	attrTypes["time"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 1)

		val, err = v.Time.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["time"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v DailyValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v DailyValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v DailyValue) String() string {
	return "DailyValue"
}

func (v DailyValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"time": basetypes.StringType{},
		},
		map[string]attr.Value{
			"time": v.Time,
		})

	return objVal, diags
}

func (v DailyValue) Equal(o attr.Value) bool {
	other, ok := o.(DailyValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Time.Equal(other.Time) {
		return false
	}

	return true
}

func (v DailyValue) Type(ctx context.Context) attr.Type {
	return DailyType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v DailyValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"time": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = ExactlyOnceType{}

type ExactlyOnceType struct {
	basetypes.ObjectType
}

func (t ExactlyOnceType) Equal(o attr.Type) bool {
	other, ok := o.(ExactlyOnceType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t ExactlyOnceType) String() string {
	return "ExactlyOnceType"
}

func (t ExactlyOnceType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return nil, diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return ExactlyOnceValue{
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewExactlyOnceValueNull() ExactlyOnceValue {
	return ExactlyOnceValue{
		state: attr.ValueStateNull,
	}
}

func NewExactlyOnceValueUnknown() ExactlyOnceValue {
	return ExactlyOnceValue{
		state: attr.ValueStateUnknown,
	}
}

func NewExactlyOnceValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (ExactlyOnceValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing ExactlyOnceValue Attribute Value",
				"While creating a ExactlyOnceValue value, a missing attribute value was detected. "+
					"A ExactlyOnceValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ExactlyOnceValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid ExactlyOnceValue Attribute ParamType",
				"While creating a ExactlyOnceValue value, an invalid attribute value was detected. "+
					"A ExactlyOnceValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ExactlyOnceValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("ExactlyOnceValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra ExactlyOnceValue Attribute Value",
				"While creating a ExactlyOnceValue value, an extra attribute value was detected. "+
					"A ExactlyOnceValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra ExactlyOnceValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewExactlyOnceValueUnknown(), diags
	}

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return NewExactlyOnceValueUnknown(), diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return NewExactlyOnceValueUnknown(), diags
	}

	return ExactlyOnceValue{
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewExactlyOnceValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) ExactlyOnceValue {
	object, diags := NewExactlyOnceValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewExactlyOnceValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t ExactlyOnceType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewExactlyOnceValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewExactlyOnceValueUnknown(), nil
	}

	if in.IsNull() {
		return NewExactlyOnceValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewExactlyOnceValueMust(t.AttrTypes, attributes), nil
}

func (t ExactlyOnceType) ValueType(ctx context.Context) attr.Value {
	return ExactlyOnceValue{}
}

var _ basetypes.ObjectValuable = ExactlyOnceValue{}

type ExactlyOnceValue struct {
	Time  basetypes.StringValue `tfsdk:"time"`
	state attr.ValueState
}

func (v ExactlyOnceValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 1)

	var val tftypes.Value
	var err error

	attrTypes["time"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 1)

		val, err = v.Time.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["time"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v ExactlyOnceValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v ExactlyOnceValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v ExactlyOnceValue) String() string {
	return "ExactlyOnceValue"
}

func (v ExactlyOnceValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"time": basetypes.StringType{},
		},
		map[string]attr.Value{
			"time": v.Time,
		})

	return objVal, diags
}

func (v ExactlyOnceValue) Equal(o attr.Value) bool {
	other, ok := o.(ExactlyOnceValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Time.Equal(other.Time) {
		return false
	}

	return true
}

func (v ExactlyOnceValue) Type(ctx context.Context) attr.Type {
	return ExactlyOnceType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v ExactlyOnceValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"time": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = IntervalType{}

type IntervalType struct {
	basetypes.ObjectType
}

func (t IntervalType) Equal(o attr.Type) bool {
	other, ok := o.(IntervalType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t IntervalType) String() string {
	return "IntervalType"
}

func (t IntervalType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	minutesAttribute, ok := attributes["minutes"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`minutes is missing from object`)

		return nil, diags
	}

	minutesVal, ok := minutesAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`minutes expected to be basetypes.Int64Value, was: %T`, minutesAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return IntervalValue{
		Minutes: minutesVal,
		state:   attr.ValueStateKnown,
	}, diags
}

func NewIntervalValueNull() IntervalValue {
	return IntervalValue{
		state: attr.ValueStateNull,
	}
}

func NewIntervalValueUnknown() IntervalValue {
	return IntervalValue{
		state: attr.ValueStateUnknown,
	}
}

func NewIntervalValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (IntervalValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing IntervalValue Attribute Value",
				"While creating a IntervalValue value, a missing attribute value was detected. "+
					"A IntervalValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("IntervalValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid IntervalValue Attribute ParamType",
				"While creating a IntervalValue value, an invalid attribute value was detected. "+
					"A IntervalValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("IntervalValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("IntervalValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra IntervalValue Attribute Value",
				"While creating a IntervalValue value, an extra attribute value was detected. "+
					"A IntervalValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra IntervalValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewIntervalValueUnknown(), diags
	}

	minutesAttribute, ok := attributes["minutes"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`minutes is missing from object`)

		return NewIntervalValueUnknown(), diags
	}

	minutesVal, ok := minutesAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`minutes expected to be basetypes.Int64Value, was: %T`, minutesAttribute))
	}

	if diags.HasError() {
		return NewIntervalValueUnknown(), diags
	}

	return IntervalValue{
		Minutes: minutesVal,
		state:   attr.ValueStateKnown,
	}, diags
}

func NewIntervalValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) IntervalValue {
	object, diags := NewIntervalValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewIntervalValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t IntervalType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewIntervalValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewIntervalValueUnknown(), nil
	}

	if in.IsNull() {
		return NewIntervalValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewIntervalValueMust(t.AttrTypes, attributes), nil
}

func (t IntervalType) ValueType(ctx context.Context) attr.Value {
	return IntervalValue{}
}

var _ basetypes.ObjectValuable = IntervalValue{}

type IntervalValue struct {
	Minutes basetypes.Int64Value `tfsdk:"minutes"`
	state   attr.ValueState
}

func (v IntervalValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 1)

	var val tftypes.Value
	var err error

	attrTypes["minutes"] = basetypes.Int64Type{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 1)

		val, err = v.Minutes.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["minutes"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v IntervalValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v IntervalValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v IntervalValue) String() string {
	return "IntervalValue"
}

func (v IntervalValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"minutes": basetypes.Int64Type{},
		},
		map[string]attr.Value{
			"minutes": v.Minutes,
		})

	return objVal, diags
}

func (v IntervalValue) Equal(o attr.Value) bool {
	other, ok := o.(IntervalValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Minutes.Equal(other.Minutes) {
		return false
	}

	return true
}

func (v IntervalValue) Type(ctx context.Context) attr.Type {
	return IntervalType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v IntervalValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"minutes": basetypes.Int64Type{},
	}
}

var _ basetypes.ObjectTypable = MonthlyType{}

type MonthlyType struct {
	basetypes.ObjectType
}

func (t MonthlyType) Equal(o attr.Type) bool {
	other, ok := o.(MonthlyType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t MonthlyType) String() string {
	return "MonthlyType"
}

func (t MonthlyType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	dayAttribute, ok := attributes["day"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`day is missing from object`)

		return nil, diags
	}

	dayVal, ok := dayAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`day expected to be basetypes.Int64Value, was: %T`, dayAttribute))
	}

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return nil, diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return MonthlyValue{
		Day:   dayVal,
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewMonthlyValueNull() MonthlyValue {
	return MonthlyValue{
		state: attr.ValueStateNull,
	}
}

func NewMonthlyValueUnknown() MonthlyValue {
	return MonthlyValue{
		state: attr.ValueStateUnknown,
	}
}

func NewMonthlyValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (MonthlyValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing MonthlyValue Attribute Value",
				"While creating a MonthlyValue value, a missing attribute value was detected. "+
					"A MonthlyValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("MonthlyValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid MonthlyValue Attribute ParamType",
				"While creating a MonthlyValue value, an invalid attribute value was detected. "+
					"A MonthlyValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("MonthlyValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("MonthlyValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra MonthlyValue Attribute Value",
				"While creating a MonthlyValue value, an extra attribute value was detected. "+
					"A MonthlyValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra MonthlyValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewMonthlyValueUnknown(), diags
	}

	dayAttribute, ok := attributes["day"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`day is missing from object`)

		return NewMonthlyValueUnknown(), diags
	}

	dayVal, ok := dayAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`day expected to be basetypes.Int64Value, was: %T`, dayAttribute))
	}

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return NewMonthlyValueUnknown(), diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return NewMonthlyValueUnknown(), diags
	}

	return MonthlyValue{
		Day:   dayVal,
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewMonthlyValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) MonthlyValue {
	object, diags := NewMonthlyValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewMonthlyValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t MonthlyType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewMonthlyValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewMonthlyValueUnknown(), nil
	}

	if in.IsNull() {
		return NewMonthlyValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewMonthlyValueMust(t.AttrTypes, attributes), nil
}

func (t MonthlyType) ValueType(ctx context.Context) attr.Value {
	return MonthlyValue{}
}

var _ basetypes.ObjectValuable = MonthlyValue{}

type MonthlyValue struct {
	Day   basetypes.Int64Value  `tfsdk:"day"`
	Time  basetypes.StringValue `tfsdk:"time"`
	state attr.ValueState
}

func (v MonthlyValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["day"] = basetypes.Int64Type{}.TerraformType(ctx)
	attrTypes["time"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Day.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["day"] = val

		val, err = v.Time.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["time"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v MonthlyValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v MonthlyValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v MonthlyValue) String() string {
	return "MonthlyValue"
}

func (v MonthlyValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"day":  basetypes.Int64Type{},
			"time": basetypes.StringType{},
		},
		map[string]attr.Value{
			"day":  v.Day,
			"time": v.Time,
		})

	return objVal, diags
}

func (v MonthlyValue) Equal(o attr.Value) bool {
	other, ok := o.(MonthlyValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Day.Equal(other.Day) {
		return false
	}

	if !v.Time.Equal(other.Time) {
		return false
	}

	return true
}

func (v MonthlyValue) Type(ctx context.Context) attr.Type {
	return MonthlyType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v MonthlyValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"day":  basetypes.Int64Type{},
		"time": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = WeeklyType{}

type WeeklyType struct {
	basetypes.ObjectType
}

func (t WeeklyType) Equal(o attr.Type) bool {
	other, ok := o.(WeeklyType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t WeeklyType) String() string {
	return "WeeklyType"
}

func (t WeeklyType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	daysAttribute, ok := attributes["days"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`days is missing from object`)

		return nil, diags
	}

	daysVal, ok := daysAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`days expected to be basetypes.ListValue, was: %T`, daysAttribute))
	}

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return nil, diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return WeeklyValue{
		Days:  daysVal,
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewWeeklyValueNull() WeeklyValue {
	return WeeklyValue{
		state: attr.ValueStateNull,
	}
}

func NewWeeklyValueUnknown() WeeklyValue {
	return WeeklyValue{
		state: attr.ValueStateUnknown,
	}
}

func NewWeeklyValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (WeeklyValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing WeeklyValue Attribute Value",
				"While creating a WeeklyValue value, a missing attribute value was detected. "+
					"A WeeklyValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("WeeklyValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid WeeklyValue Attribute ParamType",
				"While creating a WeeklyValue value, an invalid attribute value was detected. "+
					"A WeeklyValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("WeeklyValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("WeeklyValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra WeeklyValue Attribute Value",
				"While creating a WeeklyValue value, an extra attribute value was detected. "+
					"A WeeklyValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra WeeklyValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewWeeklyValueUnknown(), diags
	}

	daysAttribute, ok := attributes["days"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`days is missing from object`)

		return NewWeeklyValueUnknown(), diags
	}

	daysVal, ok := daysAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`days expected to be basetypes.ListValue, was: %T`, daysAttribute))
	}

	timeAttribute, ok := attributes["time"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`time is missing from object`)

		return NewWeeklyValueUnknown(), diags
	}

	timeVal, ok := timeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`time expected to be basetypes.StringValue, was: %T`, timeAttribute))
	}

	if diags.HasError() {
		return NewWeeklyValueUnknown(), diags
	}

	return WeeklyValue{
		Days:  daysVal,
		Time:  timeVal,
		state: attr.ValueStateKnown,
	}, diags
}

func NewWeeklyValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) WeeklyValue {
	object, diags := NewWeeklyValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewWeeklyValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t WeeklyType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewWeeklyValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewWeeklyValueUnknown(), nil
	}

	if in.IsNull() {
		return NewWeeklyValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewWeeklyValueMust(t.AttrTypes, attributes), nil
}

func (t WeeklyType) ValueType(ctx context.Context) attr.Value {
	return WeeklyValue{}
}

var _ basetypes.ObjectValuable = WeeklyValue{}

type WeeklyValue struct {
	Days  basetypes.ListValue   `tfsdk:"days"`
	Time  basetypes.StringValue `tfsdk:"time"`
	state attr.ValueState
}

func (v WeeklyValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 2)

	var val tftypes.Value
	var err error

	attrTypes["days"] = basetypes.ListType{
		ElemType: types.Int64Type,
	}.TerraformType(ctx)
	attrTypes["time"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 2)

		val, err = v.Days.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["days"] = val

		val, err = v.Time.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["time"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v WeeklyValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v WeeklyValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v WeeklyValue) String() string {
	return "WeeklyValue"
}

func (v WeeklyValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"days": basetypes.ListType{
				ElemType: types.Int64Type,
			},
			"time": basetypes.StringType{},
		},
		map[string]attr.Value{
			"days": v.Days,
			"time": v.Time,
		})

	return objVal, diags
}

func (v WeeklyValue) Equal(o attr.Value) bool {
	other, ok := o.(WeeklyValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.Days.Equal(other.Days) {
		return false
	}

	if !v.Time.Equal(other.Time) {
		return false
	}

	return true
}

func (v WeeklyValue) Type(ctx context.Context) attr.Type {
	return WeeklyType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v WeeklyValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"days": basetypes.ListType{
			ElemType: types.Int64Type,
		},
		"time": basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = ReenrollmentStatusType{}

type ReenrollmentStatusType struct {
	basetypes.ObjectType
}

func (t ReenrollmentStatusType) Equal(o attr.Type) bool {
	other, ok := o.(ReenrollmentStatusType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t ReenrollmentStatusType) String() string {
	return "ReenrollmentStatusType"
}

func (t ReenrollmentStatusType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	agentIdAttribute, ok := attributes["agent_id"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`agent_id is missing from object`)

		return nil, diags
	}

	agentIdVal, ok := agentIdAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`agent_id expected to be basetypes.StringValue, was: %T`, agentIdAttribute))
	}

	customAliasAllowedAttribute, ok := attributes["custom_alias_allowed"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`custom_alias_allowed is missing from object`)

		return nil, diags
	}

	customAliasAllowedVal, ok := customAliasAllowedAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`custom_alias_allowed expected to be basetypes.Int64Value, was: %T`, customAliasAllowedAttribute))
	}

	dataAttribute, ok := attributes["data"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`data is missing from object`)

		return nil, diags
	}

	dataVal, ok := dataAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`data expected to be basetypes.BoolValue, was: %T`, dataAttribute))
	}

	entryParametersAttribute, ok := attributes["entry_parameters"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`entry_parameters is missing from object`)

		return nil, diags
	}

	entryParametersVal, ok := entryParametersAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`entry_parameters expected to be basetypes.ListValue, was: %T`, entryParametersAttribute))
	}

	jobPropertiesAttribute, ok := attributes["job_properties"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`job_properties is missing from object`)

		return nil, diags
	}

	jobPropertiesVal, ok := jobPropertiesAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`job_properties expected to be basetypes.StringValue, was: %T`, jobPropertiesAttribute))
	}

	messageAttribute, ok := attributes["message"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`message is missing from object`)

		return nil, diags
	}

	messageVal, ok := messageAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`message expected to be basetypes.StringValue, was: %T`, messageAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return ReenrollmentStatusValue{
		AgentId:            agentIdVal,
		CustomAliasAllowed: customAliasAllowedVal,
		Data:               dataVal,
		EntryParameters:    entryParametersVal,
		JobProperties:      jobPropertiesVal,
		Message:            messageVal,
		state:              attr.ValueStateKnown,
	}, diags
}

func NewReenrollmentStatusValueNull() ReenrollmentStatusValue {
	return ReenrollmentStatusValue{
		state: attr.ValueStateNull,
	}
}

func NewReenrollmentStatusValueUnknown() ReenrollmentStatusValue {
	return ReenrollmentStatusValue{
		state: attr.ValueStateUnknown,
	}
}

func NewReenrollmentStatusValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (ReenrollmentStatusValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing ReenrollmentStatusValue Attribute Value",
				"While creating a ReenrollmentStatusValue value, a missing attribute value was detected. "+
					"A ReenrollmentStatusValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ReenrollmentStatusValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid ReenrollmentStatusValue Attribute ParamType",
				"While creating a ReenrollmentStatusValue value, an invalid attribute value was detected. "+
					"A ReenrollmentStatusValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("ReenrollmentStatusValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("ReenrollmentStatusValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra ReenrollmentStatusValue Attribute Value",
				"While creating a ReenrollmentStatusValue value, an extra attribute value was detected. "+
					"A ReenrollmentStatusValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra ReenrollmentStatusValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewReenrollmentStatusValueUnknown(), diags
	}

	agentIdAttribute, ok := attributes["agent_id"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`agent_id is missing from object`)

		return NewReenrollmentStatusValueUnknown(), diags
	}

	agentIdVal, ok := agentIdAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`agent_id expected to be basetypes.StringValue, was: %T`, agentIdAttribute))
	}

	customAliasAllowedAttribute, ok := attributes["custom_alias_allowed"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`custom_alias_allowed is missing from object`)

		return NewReenrollmentStatusValueUnknown(), diags
	}

	customAliasAllowedVal, ok := customAliasAllowedAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`custom_alias_allowed expected to be basetypes.Int64Value, was: %T`, customAliasAllowedAttribute))
	}

	dataAttribute, ok := attributes["data"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`data is missing from object`)

		return NewReenrollmentStatusValueUnknown(), diags
	}

	dataVal, ok := dataAttribute.(basetypes.BoolValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`data expected to be basetypes.BoolValue, was: %T`, dataAttribute))
	}

	entryParametersAttribute, ok := attributes["entry_parameters"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`entry_parameters is missing from object`)

		return NewReenrollmentStatusValueUnknown(), diags
	}

	entryParametersVal, ok := entryParametersAttribute.(basetypes.ListValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`entry_parameters expected to be basetypes.ListValue, was: %T`, entryParametersAttribute))
	}

	jobPropertiesAttribute, ok := attributes["job_properties"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`job_properties is missing from object`)

		return NewReenrollmentStatusValueUnknown(), diags
	}

	jobPropertiesVal, ok := jobPropertiesAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`job_properties expected to be basetypes.StringValue, was: %T`, jobPropertiesAttribute))
	}

	messageAttribute, ok := attributes["message"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`message is missing from object`)

		return NewReenrollmentStatusValueUnknown(), diags
	}

	messageVal, ok := messageAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`message expected to be basetypes.StringValue, was: %T`, messageAttribute))
	}

	if diags.HasError() {
		return NewReenrollmentStatusValueUnknown(), diags
	}

	return ReenrollmentStatusValue{
		AgentId:            agentIdVal,
		CustomAliasAllowed: customAliasAllowedVal,
		Data:               dataVal,
		EntryParameters:    entryParametersVal,
		JobProperties:      jobPropertiesVal,
		Message:            messageVal,
		state:              attr.ValueStateKnown,
	}, diags
}

func NewReenrollmentStatusValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) ReenrollmentStatusValue {
	object, diags := NewReenrollmentStatusValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewReenrollmentStatusValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t ReenrollmentStatusType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewReenrollmentStatusValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewReenrollmentStatusValueUnknown(), nil
	}

	if in.IsNull() {
		return NewReenrollmentStatusValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewReenrollmentStatusValueMust(t.AttrTypes, attributes), nil
}

func (t ReenrollmentStatusType) ValueType(ctx context.Context) attr.Value {
	return ReenrollmentStatusValue{}
}

var _ basetypes.ObjectValuable = ReenrollmentStatusValue{}

type ReenrollmentStatusValue struct {
	AgentId            basetypes.StringValue `tfsdk:"agent_id"`
	CustomAliasAllowed basetypes.Int64Value  `tfsdk:"custom_alias_allowed"`
	Data               basetypes.BoolValue   `tfsdk:"data"`
	EntryParameters    basetypes.ListValue   `tfsdk:"entry_parameters"`
	JobProperties      basetypes.StringValue `tfsdk:"job_properties"`
	Message            basetypes.StringValue `tfsdk:"message"`
	state              attr.ValueState
}

func (v ReenrollmentStatusValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 6)

	var val tftypes.Value
	var err error

	attrTypes["agent_id"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["custom_alias_allowed"] = basetypes.Int64Type{}.TerraformType(ctx)
	attrTypes["data"] = basetypes.BoolType{}.TerraformType(ctx)
	attrTypes["entry_parameters"] = basetypes.ListType{
		ElemType: EntryParametersValue{}.Type(ctx),
	}.TerraformType(ctx)
	attrTypes["job_properties"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["message"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 6)

		val, err = v.AgentId.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["agent_id"] = val

		val, err = v.CustomAliasAllowed.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["custom_alias_allowed"] = val

		val, err = v.Data.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["data"] = val

		val, err = v.EntryParameters.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["entry_parameters"] = val

		val, err = v.JobProperties.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["job_properties"] = val

		val, err = v.Message.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["message"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v ReenrollmentStatusValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v ReenrollmentStatusValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v ReenrollmentStatusValue) String() string {
	return "ReenrollmentStatusValue"
}

func (v ReenrollmentStatusValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	entryParameters := types.ListValueMust(
		EntryParametersType{
			basetypes.ObjectType{
				AttrTypes: EntryParametersValue{}.AttributeTypes(ctx),
			},
		},
		v.EntryParameters.Elements(),
	)

	if v.EntryParameters.IsNull() {
		entryParameters = types.ListNull(
			EntryParametersType{
				basetypes.ObjectType{
					AttrTypes: EntryParametersValue{}.AttributeTypes(ctx),
				},
			},
		)
	}

	if v.EntryParameters.IsUnknown() {
		entryParameters = types.ListUnknown(
			EntryParametersType{
				basetypes.ObjectType{
					AttrTypes: EntryParametersValue{}.AttributeTypes(ctx),
				},
			},
		)
	}

	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"agent_id":             basetypes.StringType{},
			"custom_alias_allowed": basetypes.Int64Type{},
			"data":                 basetypes.BoolType{},
			"entry_parameters": basetypes.ListType{
				ElemType: EntryParametersValue{}.Type(ctx),
			},
			"job_properties": basetypes.StringType{},
			"message":        basetypes.StringType{},
		},
		map[string]attr.Value{
			"agent_id":             v.AgentId,
			"custom_alias_allowed": v.CustomAliasAllowed,
			"data":                 v.Data,
			"entry_parameters":     entryParameters,
			"job_properties":       v.JobProperties,
			"message":              v.Message,
		})

	return objVal, diags
}

func (v ReenrollmentStatusValue) Equal(o attr.Value) bool {
	other, ok := o.(ReenrollmentStatusValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.AgentId.Equal(other.AgentId) {
		return false
	}

	if !v.CustomAliasAllowed.Equal(other.CustomAliasAllowed) {
		return false
	}

	if !v.Data.Equal(other.Data) {
		return false
	}

	if !v.EntryParameters.Equal(other.EntryParameters) {
		return false
	}

	if !v.JobProperties.Equal(other.JobProperties) {
		return false
	}

	if !v.Message.Equal(other.Message) {
		return false
	}

	return true
}

func (v ReenrollmentStatusValue) Type(ctx context.Context) attr.Type {
	return ReenrollmentStatusType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v ReenrollmentStatusValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"agent_id":             basetypes.StringType{},
		"custom_alias_allowed": basetypes.Int64Type{},
		"data":                 basetypes.BoolType{},
		"entry_parameters": basetypes.ListType{
			ElemType: EntryParametersValue{}.Type(ctx),
		},
		"job_properties": basetypes.StringType{},
		"message":        basetypes.StringType{},
	}
}

var _ basetypes.ObjectTypable = EntryParametersType{}

type EntryParametersType struct {
	basetypes.ObjectType
}

func (t EntryParametersType) Equal(o attr.Type) bool {
	other, ok := o.(EntryParametersType)

	if !ok {
		return false
	}

	return t.ObjectType.Equal(other.ObjectType)
}

func (t EntryParametersType) String() string {
	return "EntryParametersType"
}

func (t EntryParametersType) ValueFromObject(ctx context.Context, in basetypes.ObjectValue) (basetypes.ObjectValuable, diag.Diagnostics) {
	var diags diag.Diagnostics

	attributes := in.Attributes()

	defaultValueAttribute, ok := attributes["default_value"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`default_value is missing from object`)

		return nil, diags
	}

	defaultValueVal, ok := defaultValueAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`default_value expected to be basetypes.StringValue, was: %T`, defaultValueAttribute))
	}

	dependsOnAttribute, ok := attributes["depends_on"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`depends_on is missing from object`)

		return nil, diags
	}

	dependsOnVal, ok := dependsOnAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`depends_on expected to be basetypes.StringValue, was: %T`, dependsOnAttribute))
	}

	displayNameAttribute, ok := attributes["display_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`display_name is missing from object`)

		return nil, diags
	}

	displayNameVal, ok := displayNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`display_name expected to be basetypes.StringValue, was: %T`, displayNameAttribute))
	}

	nameAttribute, ok := attributes["name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`name is missing from object`)

		return nil, diags
	}

	nameVal, ok := nameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`name expected to be basetypes.StringValue, was: %T`, nameAttribute))
	}

	optionsAttribute, ok := attributes["options"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`options is missing from object`)

		return nil, diags
	}

	optionsVal, ok := optionsAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`options expected to be basetypes.StringValue, was: %T`, optionsAttribute))
	}

	requiredWhenAttribute, ok := attributes["required_when"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`required_when is missing from object`)

		return nil, diags
	}

	requiredWhenVal, ok := requiredWhenAttribute.(basetypes.MapValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`required_when expected to be basetypes.MapValue, was: %T`, requiredWhenAttribute))
	}

	storeTypeIdAttribute, ok := attributes["store_type_id"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`store_type_id is missing from object`)

		return nil, diags
	}

	storeTypeIdVal, ok := storeTypeIdAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`store_type_id expected to be basetypes.Int64Value, was: %T`, storeTypeIdAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return nil, diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return nil, diags
	}

	return EntryParametersValue{
		DefaultValue: defaultValueVal,
		DependsOn:    dependsOnVal,
		DisplayName:  displayNameVal,
		Name:         nameVal,
		Options:      optionsVal,
		RequiredWhen: requiredWhenVal,
		StoreTypeId:  storeTypeIdVal,
		ParamType:    typeVal,
		state:        attr.ValueStateKnown,
	}, diags
}

func NewEntryParametersValueNull() EntryParametersValue {
	return EntryParametersValue{
		state: attr.ValueStateNull,
	}
}

func NewEntryParametersValueUnknown() EntryParametersValue {
	return EntryParametersValue{
		state: attr.ValueStateUnknown,
	}
}

func NewEntryParametersValue(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) (EntryParametersValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Reference: https://github.com/hashicorp/terraform-plugin-framework/issues/521
	ctx := context.Background()

	for name, attributeType := range attributeTypes {
		attribute, ok := attributes[name]

		if !ok {
			diags.AddError(
				"Missing EntryParametersValue Attribute Value",
				"While creating a EntryParametersValue value, a missing attribute value was detected. "+
					"A EntryParametersValue must contain values for all attributes, even if null or unknown. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("EntryParametersValue Attribute Name (%s) Expected ParamType: %s", name, attributeType.String()),
			)

			continue
		}

		if !attributeType.Equal(attribute.Type(ctx)) {
			diags.AddError(
				"Invalid EntryParametersValue Attribute ParamType",
				"While creating a EntryParametersValue value, an invalid attribute value was detected. "+
					"A EntryParametersValue must use a matching attribute type for the value. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("EntryParametersValue Attribute Name (%s) Expected ParamType: %s\n", name, attributeType.String())+
					fmt.Sprintf("EntryParametersValue Attribute Name (%s) Given ParamType: %s", name, attribute.Type(ctx)),
			)
		}
	}

	for name := range attributes {
		_, ok := attributeTypes[name]

		if !ok {
			diags.AddError(
				"Extra EntryParametersValue Attribute Value",
				"While creating a EntryParametersValue value, an extra attribute value was detected. "+
					"A EntryParametersValue must not contain values beyond the expected attribute types. "+
					"This is always an issue with the provider and should be reported to the provider developers.\n\n"+
					fmt.Sprintf("Extra EntryParametersValue Attribute Name: %s", name),
			)
		}
	}

	if diags.HasError() {
		return NewEntryParametersValueUnknown(), diags
	}

	defaultValueAttribute, ok := attributes["default_value"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`default_value is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	defaultValueVal, ok := defaultValueAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`default_value expected to be basetypes.StringValue, was: %T`, defaultValueAttribute))
	}

	dependsOnAttribute, ok := attributes["depends_on"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`depends_on is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	dependsOnVal, ok := dependsOnAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`depends_on expected to be basetypes.StringValue, was: %T`, dependsOnAttribute))
	}

	displayNameAttribute, ok := attributes["display_name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`display_name is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	displayNameVal, ok := displayNameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`display_name expected to be basetypes.StringValue, was: %T`, displayNameAttribute))
	}

	nameAttribute, ok := attributes["name"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`name is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	nameVal, ok := nameAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`name expected to be basetypes.StringValue, was: %T`, nameAttribute))
	}

	optionsAttribute, ok := attributes["options"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`options is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	optionsVal, ok := optionsAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`options expected to be basetypes.StringValue, was: %T`, optionsAttribute))
	}

	requiredWhenAttribute, ok := attributes["required_when"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`required_when is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	requiredWhenVal, ok := requiredWhenAttribute.(basetypes.MapValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`required_when expected to be basetypes.MapValue, was: %T`, requiredWhenAttribute))
	}

	storeTypeIdAttribute, ok := attributes["store_type_id"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`store_type_id is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	storeTypeIdVal, ok := storeTypeIdAttribute.(basetypes.Int64Value)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`store_type_id expected to be basetypes.Int64Value, was: %T`, storeTypeIdAttribute))
	}

	typeAttribute, ok := attributes["type"]

	if !ok {
		diags.AddError(
			"Attribute Missing",
			`type is missing from object`)

		return NewEntryParametersValueUnknown(), diags
	}

	typeVal, ok := typeAttribute.(basetypes.StringValue)

	if !ok {
		diags.AddError(
			"Attribute Wrong ParamType",
			fmt.Sprintf(`type expected to be basetypes.StringValue, was: %T`, typeAttribute))
	}

	if diags.HasError() {
		return NewEntryParametersValueUnknown(), diags
	}

	return EntryParametersValue{
		DefaultValue: defaultValueVal,
		DependsOn:    dependsOnVal,
		DisplayName:  displayNameVal,
		Name:         nameVal,
		Options:      optionsVal,
		RequiredWhen: requiredWhenVal,
		StoreTypeId:  storeTypeIdVal,
		ParamType:    typeVal,
		state:        attr.ValueStateKnown,
	}, diags
}

func NewEntryParametersValueMust(attributeTypes map[string]attr.Type, attributes map[string]attr.Value) EntryParametersValue {
	object, diags := NewEntryParametersValue(attributeTypes, attributes)

	if diags.HasError() {
		// This could potentially be added to the diag package.
		diagsStrings := make([]string, 0, len(diags))

		for _, diagnostic := range diags {
			diagsStrings = append(diagsStrings, fmt.Sprintf(
				"%s | %s | %s",
				diagnostic.Severity(),
				diagnostic.Summary(),
				diagnostic.Detail()))
		}

		panic("NewEntryParametersValueMust received error(s): " + strings.Join(diagsStrings, "\n"))
	}

	return object
}

func (t EntryParametersType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return NewEntryParametersValueNull(), nil
	}

	if !in.Type().Equal(t.TerraformType(ctx)) {
		return nil, fmt.Errorf("expected %s, got %s", t.TerraformType(ctx), in.Type())
	}

	if !in.IsKnown() {
		return NewEntryParametersValueUnknown(), nil
	}

	if in.IsNull() {
		return NewEntryParametersValueNull(), nil
	}

	attributes := map[string]attr.Value{}

	val := map[string]tftypes.Value{}

	err := in.As(&val)

	if err != nil {
		return nil, err
	}

	for k, v := range val {
		a, err := t.AttrTypes[k].ValueFromTerraform(ctx, v)

		if err != nil {
			return nil, err
		}

		attributes[k] = a
	}

	return NewEntryParametersValueMust(t.AttrTypes, attributes), nil
}

func (t EntryParametersType) ValueType(ctx context.Context) attr.Value {
	return EntryParametersValue{}
}

var _ basetypes.ObjectValuable = EntryParametersValue{}

type EntryParametersValue struct {
	DefaultValue basetypes.StringValue `tfsdk:"default_value"`
	DependsOn    basetypes.StringValue `tfsdk:"depends_on"`
	DisplayName  basetypes.StringValue `tfsdk:"display_name"`
	Name         basetypes.StringValue `tfsdk:"name"`
	Options      basetypes.StringValue `tfsdk:"options"`
	RequiredWhen basetypes.MapValue    `tfsdk:"required_when"`
	StoreTypeId  basetypes.Int64Value  `tfsdk:"store_type_id"`
	ParamType    basetypes.StringValue `tfsdk:"type"`
	state        attr.ValueState
}

func (v EntryParametersValue) ToTerraformValue(ctx context.Context) (tftypes.Value, error) {
	attrTypes := make(map[string]tftypes.Type, 8)

	var val tftypes.Value
	var err error

	attrTypes["default_value"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["depends_on"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["display_name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["name"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["options"] = basetypes.StringType{}.TerraformType(ctx)
	attrTypes["required_when"] = basetypes.MapType{
		ElemType: types.BoolType,
	}.TerraformType(ctx)
	attrTypes["store_type_id"] = basetypes.Int64Type{}.TerraformType(ctx)
	attrTypes["type"] = basetypes.StringType{}.TerraformType(ctx)

	objectType := tftypes.Object{AttributeTypes: attrTypes}

	switch v.state {
	case attr.ValueStateKnown:
		vals := make(map[string]tftypes.Value, 8)

		val, err = v.DefaultValue.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["default_value"] = val

		val, err = v.DependsOn.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["depends_on"] = val

		val, err = v.DisplayName.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["display_name"] = val

		val, err = v.Name.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["name"] = val

		val, err = v.Options.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["options"] = val

		val, err = v.RequiredWhen.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["required_when"] = val

		val, err = v.StoreTypeId.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["store_type_id"] = val

		val, err = v.ParamType.ToTerraformValue(ctx)

		if err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		vals["type"] = val

		if err := tftypes.ValidateValue(objectType, vals); err != nil {
			return tftypes.NewValue(objectType, tftypes.UnknownValue), err
		}

		return tftypes.NewValue(objectType, vals), nil
	case attr.ValueStateNull:
		return tftypes.NewValue(objectType, nil), nil
	case attr.ValueStateUnknown:
		return tftypes.NewValue(objectType, tftypes.UnknownValue), nil
	default:
		panic(fmt.Sprintf("unhandled Object state in ToTerraformValue: %s", v.state))
	}
}

func (v EntryParametersValue) IsNull() bool {
	return v.state == attr.ValueStateNull
}

func (v EntryParametersValue) IsUnknown() bool {
	return v.state == attr.ValueStateUnknown
}

func (v EntryParametersValue) String() string {
	return "EntryParametersValue"
}

func (v EntryParametersValue) ToObjectValue(ctx context.Context) (basetypes.ObjectValue, diag.Diagnostics) {
	objVal, diags := types.ObjectValue(
		map[string]attr.Type{
			"default_value": basetypes.StringType{},
			"depends_on":    basetypes.StringType{},
			"display_name":  basetypes.StringType{},
			"name":          basetypes.StringType{},
			"options":       basetypes.StringType{},
			"required_when": basetypes.MapType{
				ElemType: types.BoolType,
			},
			"store_type_id": basetypes.Int64Type{},
			"type":          basetypes.StringType{},
		},
		map[string]attr.Value{
			"default_value": v.DefaultValue,
			"depends_on":    v.DependsOn,
			"display_name":  v.DisplayName,
			"name":          v.Name,
			"options":       v.Options,
			"required_when": v.RequiredWhen,
			"store_type_id": v.StoreTypeId,
			"type":          v.ParamType,
		})

	return objVal, diags
}

func (v EntryParametersValue) Equal(o attr.Value) bool {
	other, ok := o.(EntryParametersValue)

	if !ok {
		return false
	}

	if v.state != other.state {
		return false
	}

	if v.state != attr.ValueStateKnown {
		return true
	}

	if !v.DefaultValue.Equal(other.DefaultValue) {
		return false
	}

	if !v.DependsOn.Equal(other.DependsOn) {
		return false
	}

	if !v.DisplayName.Equal(other.DisplayName) {
		return false
	}

	if !v.Name.Equal(other.Name) {
		return false
	}

	if !v.Options.Equal(other.Options) {
		return false
	}

	if !v.RequiredWhen.Equal(other.RequiredWhen) {
		return false
	}

	if !v.StoreTypeId.Equal(other.StoreTypeId) {
		return false
	}

	if !v.ParamType.Equal(other.ParamType) {
		return false
	}

	return true
}

func (v EntryParametersValue) Type(ctx context.Context) attr.Type {
	return EntryParametersType{
		basetypes.ObjectType{
			AttrTypes: v.AttributeTypes(ctx),
		},
	}
}

func (v EntryParametersValue) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"default_value": basetypes.StringType{},
		"depends_on":    basetypes.StringType{},
		"display_name":  basetypes.StringType{},
		"name":          basetypes.StringType{},
		"options":       basetypes.StringType{},
		"required_when": basetypes.MapType{
			ElemType: types.BoolType,
		},
		"store_type_id": basetypes.Int64Type{},
		"type":          basetypes.StringType{},
	}
}

var _ datasource.DataSource = &CertificateStoreDataSource{}

func NewCertificateStoreDataSourceDataSource() datasource.DataSource {
	return &CertificateStoreDataSource{}
}

// AgentDataSource defines the data source implementation.
type CertificateStoreDataSource struct {
	provider *Provider
	client   *kfc.APIClient
}

func (d *CertificateStoreDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "keyfactor_certificate_store"
}

func (d *CertificateStoreDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"agent_assigned": schema.BoolAttribute{
				Computed:            true,
				Description:         "A Boolean that indicates whether there is an orchestrator assigned to this certificate store (true) or not (false).",
				MarkdownDescription: "A Boolean that indicates whether there is an orchestrator assigned to this certificate store (true) or not (false).",
			},
			"agent_id": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the Keyfactor Command GUID of the orchestrator for this store.",
				MarkdownDescription: "A string indicating the Keyfactor Command GUID of the orchestrator for this store.",
			},
			"approved": schema.BoolAttribute{
				Computed:            true,
				Description:         "A Boolean that indicates whether a certificate store is approved (true) or not (false). If a certificate store is approved, it can be used and updated. A certificate store that has been discovered using the discover feature but not yet marked as approved will be false here.",
				MarkdownDescription: "A Boolean that indicates whether a certificate store is approved (true) or not (false). If a certificate store is approved, it can be used and updated. A certificate store that has been discovered using the discover feature but not yet marked as approved will be false here.",
			},
			"cert_store_inventory_job_id": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the GUID that identifies the inventory job for the certificate store in the Keyfactor Command database. This will be null if an inventory schedule is not set for the certificate store.",
				MarkdownDescription: "A string indicating the GUID that identifies the inventory job for the certificate store in the Keyfactor Command database. This will be null if an inventory schedule is not set for the certificate store.",
			},
			"cert_store_type": schema.Int64Attribute{
				Computed:            true,
				Description:         "An integer indicating the ID of the certificate store type, as defined in Keyfactor Command, for this certificate store. (0-Javakeystore,2-PEMFile, 3-F5SSLProfiles,4-IISRoots, 5-NetScaler, 6-IISPersonal, 7-F5WebServer, 8-IISRevoked, 9-F5WebServerREST, 10-F5SSLProfilesREST, 11-F5CABundlesREST, 100-AmazonWebServices, 101-FileTransferProtocol)",
				MarkdownDescription: "An integer indicating the ID of the certificate store type, as defined in Keyfactor Command, for this certificate store. (0-Javakeystore,2-PEMFile, 3-F5SSLProfiles,4-IISRoots, 5-NetScaler, 6-IISPersonal, 7-F5WebServer, 8-IISRevoked, 9-F5WebServerREST, 10-F5SSLProfilesREST, 11-F5CABundlesREST, 100-AmazonWebServices, 101-FileTransferProtocol)",
			},
			"client_machine": schema.StringAttribute{
				Required:            true,
				Description:         "The string value of the client machine. The value for this will vary depending on the certificate store type. For example, for a Java keystore or an F5 device, it is the hostname of the machine on which the store is located, but for an Amazon Web Services store, it is the FQDN of the Keyfactor Command Windows Orchestrator. See Adding or Modifying a Certificate Store in the Keyfactor Command Reference Guide for more information.",
				MarkdownDescription: "The string value of the client machine. The value for this will vary depending on the certificate store type. For example, for a Java keystore or an F5 device, it is the hostname of the machine on which the store is located, but for an Amazon Web Services store, it is the FQDN of the Keyfactor Command Windows Orchestrator. See Adding or Modifying a Certificate Store in the Keyfactor Command Reference Guide for more information.",
			},
			"container_id": schema.Int64Attribute{
				Computed:            true,
				Description:         "An integer indicating the ID of the certificate store's associated certificate store container, if applicable (see GET Certificate Store Containers).",
				MarkdownDescription: "An integer indicating the ID of the certificate store's associated certificate store container, if applicable (see GET Certificate Store Containers).",
			},
			"container_name": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the name of the certificate store's associated container, if applicable.",
				MarkdownDescription: "A string indicating the name of the certificate store's associated container, if applicable.",
			},
			"create_if_missing": schema.BoolAttribute{
				Computed:            true,
				Description:         "A Boolean that indicates whether a new certificate store should be created with the information provided (true) or not (false). This option is only valid for Java keystores and any custom certificate store types you have defined to support this functionality.",
				MarkdownDescription: "A Boolean that indicates whether a new certificate store should be created with the information provided (true) or not (false). This option is only valid for Java keystores and any custom certificate store types you have defined to support this functionality.",
			},
			"display_name": schema.StringAttribute{
				Computed:            true,
				Description:         "A string indicating the display name of the certificate store.",
				MarkdownDescription: "A string indicating the display name of the certificate store.",
			},
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Keyfactor identifier (GUID) of the certificate store",
				MarkdownDescription: "Keyfactor identifier (GUID) of the certificate store",
			},
			"inventory_schedule": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"daily": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"time": schema.StringAttribute{
								Computed: true,
							},
						},
						CustomType: DailyType{
							ObjectType: types.ObjectType{
								AttrTypes: DailyValue{}.AttributeTypes(ctx),
							},
						},
						Computed: true,
					},
					"exactly_once": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"time": schema.StringAttribute{
								Computed: true,
							},
						},
						CustomType: ExactlyOnceType{
							ObjectType: types.ObjectType{
								AttrTypes: ExactlyOnceValue{}.AttributeTypes(ctx),
							},
						},
						Computed: true,
					},
					"immediate": schema.BoolAttribute{
						Computed: true,
					},
					"interval": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"minutes": schema.Int64Attribute{
								Computed: true,
							},
						},
						CustomType: IntervalType{
							ObjectType: types.ObjectType{
								AttrTypes: IntervalValue{}.AttributeTypes(ctx),
							},
						},
						Computed: true,
					},
					"monthly": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"day": schema.Int64Attribute{
								Computed: true,
							},
							"time": schema.StringAttribute{
								Computed: true,
							},
						},
						CustomType: MonthlyType{
							ObjectType: types.ObjectType{
								AttrTypes: MonthlyValue{}.AttributeTypes(ctx),
							},
						},
						Computed: true,
					},
					"weekly": schema.SingleNestedAttribute{
						Attributes: map[string]schema.Attribute{
							"days": schema.ListAttribute{
								ElementType: types.Int64Type,
								Computed:    true,
							},
							"time": schema.StringAttribute{
								Computed: true,
							},
						},
						CustomType: WeeklyType{
							ObjectType: types.ObjectType{
								AttrTypes: WeeklyValue{}.AttributeTypes(ctx),
							},
						},
						Computed: true,
					},
				},
				CustomType: InventoryScheduleType{
					ObjectType: types.ObjectType{
						AttrTypes: InventoryScheduleValue{}.AttributeTypes(ctx),
					},
				},
				Computed: true,
			},
			"properties": schema.StringAttribute{
				Computed:            true,
				Description:         "Some types of certificate stores have additional properties that are stored in this parameter. The data is stored in a series of, typically, key value pairs that define the property name and value (see GET Certificate Store Types for more information).\n\nAs of Keyfactor Command v10, this parameter is used to store certificate store server usernames, server passwords, and the UseSSL flag. Built-in certificate stores that typically require configuration of certificate store server parameters include NetScaler and F5 stores. The legacy methods for managing certificate store server credentials have been deprecated but are retained for backwards compatiblity. For more information, see POST Certificate Stores Server.\n\nWhen reading this field, the values are returned as simple key value pairs, with the values being individual values. When writing, the values are specified as objects, though they are typically single values.\n",
				MarkdownDescription: "Some types of certificate stores have additional properties that are stored in this parameter. The data is stored in a series of, typically, key value pairs that define the property name and value (see GET Certificate Store Types for more information).\n\nAs of Keyfactor Command v10, this parameter is used to store certificate store server usernames, server passwords, and the UseSSL flag. Built-in certificate stores that typically require configuration of certificate store server parameters include NetScaler and F5 stores. The legacy methods for managing certificate store server credentials have been deprecated but are retained for backwards compatiblity. For more information, see POST Certificate Stores Server.\n\nWhen reading this field, the values are returned as simple key value pairs, with the values being individual values. When writing, the values are specified as objects, though they are typically single values.\n",
			},
			"reenrollment_status": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"agent_id": schema.StringAttribute{
						Computed: true,
					},
					"custom_alias_allowed": schema.Int64Attribute{
						Computed: true,
					},
					"data": schema.BoolAttribute{
						Computed: true,
					},
					"entry_parameters": schema.ListNestedAttribute{
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"default_value": schema.StringAttribute{
									Computed: true,
								},
								"depends_on": schema.StringAttribute{
									Computed: true,
								},
								"display_name": schema.StringAttribute{
									Computed: true,
								},
								"name": schema.StringAttribute{
									Computed: true,
								},
								"options": schema.StringAttribute{
									Computed: true,
								},
								"required_when": schema.MapAttribute{
									ElementType: types.BoolType,
									Computed:    true,
								},
								"store_type_id": schema.Int64Attribute{
									Computed: true,
								},
								"type": schema.StringAttribute{
									Computed: true,
								},
							},
							CustomType: EntryParametersType{
								ObjectType: types.ObjectType{
									AttrTypes: EntryParametersValue{}.AttributeTypes(ctx),
								},
							},
						},
						Computed: true,
					},
					"job_properties": schema.StringAttribute{
						Computed: true,
					},
					"message": schema.StringAttribute{
						Computed: true,
					},
				},
				CustomType: ReenrollmentStatusType{
					ObjectType: types.ObjectType{
						AttrTypes: ReenrollmentStatusValue{}.AttributeTypes(ctx),
					},
				},
				Computed: true,
			},
			"set_new_password_allowed": schema.BoolAttribute{
				Computed:            true,
				Description:         "A Boolean that indicates whether the store password can be changed (true) or not (false).",
				MarkdownDescription: "A Boolean that indicates whether the store password can be changed (true) or not (false).",
			},
			"storepath": schema.StringAttribute{
				Required:            true,
				Description:         "A string indicating the path to the certificate store on the target. The format for this path will vary depending on the certificate store type. For example, for a Java keystore, this will be a file path (e.g. /opt/myapp/store.jks), but for an F5 device, this will be a partition name on the device (e.g. Common). See Adding or Modifying a Certificate Store in the Keyfactor Command Reference Guide for more information. The maximum number of characters supported in this field is 722.",
				MarkdownDescription: "A string indicating the path to the certificate store on the target. The format for this path will vary depending on the certificate store type. For example, for a Java keystore, this will be a file path (e.g. /opt/myapp/store.jks), but for an F5 device, this will be a partition name on the device (e.g. Common). See Adding or Modifying a Certificate Store in the Keyfactor Command Reference Guide for more information. The maximum number of characters supported in this field is 722.",
			},
		},
	}
}

func (d *CertificateStoreDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*kfc.APIClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *kfc.APIClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *CertificateStoreDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data KeyfactorCertificateStoreModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Storepath.IsNull() || data.ClientMachine.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Certificate Store Configuration",
			"store_path and client_machine are required fields",
		)
		return
	}

	ctx = tflog.SetField(ctx, "store_path", data.Storepath.ValueString())
	ctx = tflog.SetField(ctx, "client_machine", data.ClientMachine.ValueString())
	tflog.Info(ctx, "Read called on certificate store data source")

	//storesResp, httpResp, httpRespErr := d.client.CertificateStoreApi.
	//
	//if httpRespErr != nil {
	//	resp.Diagnostics.AddError(
	//		"Certificate Store Read Error",
	//		fmt.Sprintf("Error querying Keyfactor Command for certificate store %s-%s: %s", data.ClientMachine.String(), data.Storepath.String(), httpRespErr.Error()),
	//	)
	//	return
	//} else if httpResp != nil && httpResp.StatusCode != 200 {
	//	resp.Diagnostics.AddError(
	//		"Certificate Store Read Error",
	//		fmt.Sprintf("Error querying Keyfactor Command for certificate store %s-%s: %s", data.ClientMachine.String(), data.Storepath.String(), httpResp.Status),
	//	)
	//	return
	//}
	//
	//if storesResp == nil {
	//	resp.Diagnostics.AddError(
	//		"Certificate Store Not Found Error",
	//		fmt.Sprintf("No certificate store found with client machine %s and store path %s", data.ClientMachine.String(), data.Storepath.String()),
	//	)
	//	return
	//}

	tflog.Info(ctx, "Setting certificate store data source attributes")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
