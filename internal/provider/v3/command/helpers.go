package command

import (
	"context"
	"encoding/json"
	"fmt"
	kfc "github.com/Keyfactor/keyfactor-go-client-sdk/v2/api/command"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"io"
	"net/http"
	"sort"
	"time"
)

func logCommandAPIResponse(ctx context.Context, response *http.Response, err error) {
	tflog.SetField(ctx, "commandResponseCode", response.StatusCode)
	tflog.Debug(ctx, fmt.Sprintf("Command API Response Status: %v", response.Status))
	defer response.Body.Close()
	bodyBytes, _ := io.ReadAll(response.Body)
	bodyString := string(bodyBytes)
	// attempt to convert body string to map[string]string from json
	// if successful, log the map[string]string
	// if not successful, log the body string
	var jsonBody map[string]interface{}
	jErr := json.Unmarshal([]byte(bodyString), &jsonBody)
	if jErr == nil {
		if _, ok := jsonBody["Message"]; ok {
			tflog.Debug(ctx, fmt.Sprintf("Command API Response Body: %v", jsonBody["Message"]))
		} else {
			tflog.Debug(ctx, fmt.Sprintf("Command API Response Body: %v", jsonBody))
		}
	} else {
		var jsonMultiBody []map[string]interface{}
		jErr = json.Unmarshal([]byte(bodyString), &jsonMultiBody)
		if response.StatusCode != http.StatusOK && jErr == nil {
			tflog.Trace(ctx, fmt.Sprintf("Command API Response Body: %v", jsonMultiBody))
		} else {
			tflog.Debug(ctx, fmt.Sprintf("Command API Response Body: %v", bodyString))
		}
	}
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Command API Response Error: %v", err))
	}
}

func convertInt64Ptr(ptr *int32) int64 {
	if ptr != nil {
		// Dereference the pointer safely
		return int64(*ptr)
	} else {
		return 0
	}
}

func convertStringPtr(ptr *string) string {
	if ptr != nil {
		// Dereference the pointer safely
		return *ptr
	} else {
		return attr.NullValueString
	}
}

func convertNullableStringPtr(ptr *kfc.NullableString) string {
	if ptr != nil && ptr.IsSet() && ptr.Get() != nil {
		// Dereference the pointer safely
		return *ptr.Get()
	} else {
		return types.StringNull().String()
	}
}

func convertNullableIntPtr(ptr *kfc.NullableInt32) int64 {
	if ptr != nil && ptr.IsSet() && ptr.Get() != nil {
		// Dereference the pointer safely
		return int64(*ptr.Get())
	} else {
		return types.Int64Null().ValueInt64()
	}
}

func convertNullableTimePtr(ptr *kfc.NullableTime) string {
	if ptr != nil && ptr.IsSet() && ptr.Get() != nil {
		// Dereference the pointer safely and convert to ISO 8601 string
		return ptr.Get().Format(time.RFC3339)
	} else {
		return types.StringNull().String()
	}
}

func convertTimeToStringPtr(ptr *time.Time) string {
	if ptr != nil {
		// Dereference the pointer safely and convert to ISO 8601 string
		return ptr.Format(time.RFC3339)
	} else {
		return types.StringNull().String()
	}
}

func convertBoolToPtr(b bool) *bool {
	return &b
}

func convertToTerraformList(list interface{}) (types.List, diag.Diagnostics) {
	var tfList basetypes.ListValue
	var err diag.Diagnostics
	switch list.(type) {
	case []int:
		// sort input list in place
		sort.Ints(list.([]int))
		tfList, err = types.ListValueFrom(context.Background(), types.Int64Type, list)
	case []string:
		// sort input list in place
		sort.Strings(list.([]string))
		tfList, err = types.ListValueFrom(context.Background(), types.StringType, list)
	}
	if err != nil {
		tflog.Error(context.Background(), fmt.Sprintf("Error converting to terraform list: %v", err))
	}
	return tfList, err
}

func convertToTerraformMap(mapInterface interface{}) (types.Map, diag.Diagnostics) {
	var tfMap basetypes.MapValue
	var err diag.Diagnostics
	switch mapInterface.(type) {
	case *map[string]string:
		tfMap, err = types.MapValueFrom(context.Background(), types.StringType, mapInterface)
	case *map[string]int:
		tfMap, err = types.MapValueFrom(context.Background(), types.Int64Type, mapInterface)
	}
	if err != nil {
		tflog.Error(context.Background(), fmt.Sprintf("Error converting to terraform map: %v", err))
	}
	return tfMap, err
}
