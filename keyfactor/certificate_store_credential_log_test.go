package keyfactor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-log/tflogtest"
)

// decodedLogMessages parses tflogtest's captured newline-delimited JSON log
// lines and returns each line's "@message" field value, decoded back to the
// exact text that was passed to tflog.Debug/tflog.Info/etc -- one level down
// from tflogtest's own JSON serialization of the captured record. Without
// this decode step, a naive strings.Contains(capturedBuffer, ...) check
// would be comparing against a DOUBLY JSON-escaped string (once from the
// production code's own json.Marshal call, once again from tflogtest's
// capture format), which silently produces false negatives for any
// assertion involving a secret that itself required JSON escaping.
func decodedLogMessages(t *testing.T, captured string) []string {
	t.Helper()
	var messages []string
	for _, line := range strings.Split(strings.TrimSpace(captured), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("could not decode captured log line %q: %v", line, err)
		}
		if msg, ok := rec["@message"].(string); ok {
			messages = append(messages, msg)
		}
	}
	return messages
}

// TestUnitCertificateStoreCredentialsNotLoggedInPlaintext is a regression
// test for a HIGH-severity security bug: resource_keyfactor_certificate_store.go's Update() logs
// *api.UpdateStoreFctArgs -- which carries plaintext Sensitive: true
// store/server credentials -- twice at Debug level:
//
//  1. fmt.Sprintf("UpdateStoreFctArgs: %v", *updateStoreArgs) fully expands
//     the Properties map (built from plan.ServerUsername.Value /
//     plan.ServerPassword.Value) inline, leaking server_username and
//     server_password.
//  2. fmt.Sprintf("UpdateStoreFctArgs: %s", json.Marshal(updateStoreArgs))
//     fully serializes the Password pointer (built from
//     plan.StorePassword.Value), leaking store_password, and re-embeds the
//     server credentials a second time via PropertiesString.
//
// An initial fix attempt masked these by calling tflog.MaskMessageStrings /
// tflog.MaskAllFieldValuesStrings with the RAW secret value, which does a
// literal strings.ReplaceAll of that raw value against the rendered log
// text. That is sufficient for call site 1 (a %v on a pointer field only
// ever prints its address, never the unescaped secret), but NOT for call
// site 2: encoding/json escapes '"', '\\', and other characters when
// serializing a string field, so a secret containing any of those no longer
// survives as a contiguous substring of the JSON-rendered text and the mask
// misses it -- reachable at DEBUG, not just TRACE.
//
// The fix (redactUpdateStoreFctArgsForLogging in helpers.go) builds a
// REDACTED COPY of the args -- secrets replaced with a fixed placeholder --
// before either formatting call happens, closing the bypass class entirely
// instead of masking rendered/serialized text after the fact.
func TestUnitCertificateStoreCredentialsNotLoggedInPlaintext(t *testing.T) {
	const (
		// secretStorePassword and secretServerPassword each embed a literal
		// double quote, which encoding/json escapes to \" when serializing --
		// exactly the character class that defeats a literal substring mask
		// against JSON-rendered text but must NOT defeat redaction-before-
		// formatting.
		secretStorePassword  = `S3cr3t-St0reP@ss"w0rd!`
		secretServerUsername = "svc-cert-store-admin"
		secretServerPassword = `S3cr3t-Server"P@ssw0rd!`
	)
	escapedStorePassword := strings.ReplaceAll(secretStorePassword, `"`, `\"`)
	escapedServerPassword := strings.ReplaceAll(secretServerPassword, `"`, `\"`)

	buildArgs := func() *api.UpdateStoreFctArgs {
		properties := map[string]interface{}{
			"ServerUsername": secretServerUsername,
			"ServerPassword": secretServerPassword,
			"ServerUseSsl":   "true",
		}
		propertiesStr, err := mapToEscapedJSONString(properties)
		if err != nil {
			t.Fatalf("mapToEscapedJSONString() returned unexpected error: %v", err)
		}
		secretVal := secretStorePassword
		return &api.UpdateStoreFctArgs{
			Id:               "test-store-id",
			ClientMachine:    "test-client-machine",
			StorePath:        "/test/path",
			CertStoreType:    1,
			Properties:       properties,
			PropertiesString: propertiesStr,
			AgentId:          "test-agent-id",
			Password: &api.UpdateStorePasswordConfig{
				SecretValue: &secretVal,
			},
		}
	}

	logBothDumps := func(args *api.UpdateStoreFctArgs) []string {
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %v", *args))

		argsJson, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}
		tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %s", argsJson))

		return decodedLogMessages(t, buf.String())
	}

	t.Run("without any redaction both dumps leak the secrets (reproduces the finding)", func(t *testing.T) {
		messages := strings.Join(logBothDumps(buildArgs()), "\n")
		// %v struct-dump call: server_username/server_password appear
		// unescaped (Go's %v on a map[string]interface{} doesn't
		// JSON-encode), and json.Marshal call: all three appear
		// JSON-escaped.
		for _, secret := range []string{secretServerUsername} {
			if !strings.Contains(messages, secret) {
				t.Fatalf(
					"expected unredacted log output to contain plaintext secret %q (demonstrating the bug being "+
						"fixed), but it did not -- the reproduction no longer matches the vulnerable code path: %s",
					secret, messages,
				)
			}
		}
		for _, secret := range []string{escapedStorePassword, escapedServerPassword} {
			if !strings.Contains(messages, secret) {
				t.Fatalf(
					"expected unredacted log output to contain JSON-escaped plaintext secret %q (demonstrating "+
						"the bug being fixed), but it did not -- the reproduction no longer matches the "+
						"vulnerable code path: %s", secret, messages,
				)
			}
		}
	})

	t.Run("substring masking of the raw secret against rendered text is bypassed by JSON escaping", func(t *testing.T) {
		// This reproduces the initial fix attempt's approach directly to prove the
		// bypass exists independent of whatever the production code does
		// today.
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)
		for _, secret := range []string{secretStorePassword, secretServerUsername, secretServerPassword} {
			ctx = tflog.MaskAllFieldValuesStrings(ctx, secret)
			ctx = tflog.MaskMessageStrings(ctx, secret)
		}

		args := buildArgs()
		tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %v", *args))
		argsJson, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}
		tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %s", argsJson))

		messages := strings.Join(decodedLogMessages(t, buf.String()), "\n")
		// The quote in each secret is escaped to \" by json.Marshal, so the
		// literal (unescaped) secret substring no longer appears in the JSON
		// dump line -- but the ESCAPED form does, proving the leak survived
		// the mask via the json.Marshal call site.
		if !strings.Contains(messages, escapedStorePassword) {
			t.Fatalf(
				"expected substring masking to be bypassed by JSON escaping for the store password, but the "+
					"escaped secret %q was not found in output -- the reproduction no longer matches the "+
					"documented bypass: %s", escapedStorePassword, messages,
			)
		}
		if !strings.Contains(messages, escapedServerPassword) {
			t.Fatalf(
				"expected substring masking to be bypassed by JSON escaping for the server password, but the "+
					"escaped secret %q was not found in output -- the reproduction no longer matches the "+
					"documented bypass: %s", escapedServerPassword, messages,
			)
		}
	})

	t.Run("with redact-before-format none of the credentials appear in logs, even JSON-escaped", func(t *testing.T) {
		redacted, err := redactUpdateStoreFctArgsForLogging(buildArgs())
		if err != nil {
			t.Fatalf("redactUpdateStoreFctArgsForLogging() returned unexpected error: %v", err)
		}

		messages := strings.Join(logBothDumps(redacted), "\n")

		for _, secret := range []string{secretStorePassword, secretServerUsername, secretServerPassword} {
			if strings.Contains(messages, secret) {
				t.Fatalf("plaintext secret %q leaked into log output: %s", secret, messages)
			}
		}
		for _, escaped := range []string{escapedStorePassword, escapedServerPassword} {
			if strings.Contains(messages, escaped) {
				t.Fatalf("JSON-escaped plaintext secret %q leaked into log output: %s", escaped, messages)
			}
		}
		if !strings.Contains(messages, redactedSecretLogPlaceholder) {
			t.Fatalf("expected redaction placeholder %q to appear in log output, got: %s", redactedSecretLogPlaceholder, messages)
		}
	})
}

// TestUnitRedactUpdateStoreFctArgsForLoggingPreservesNonSecretFields ensures
// redactUpdateStoreFctArgsForLogging only touches the specific
// credential-bearing fields (Password.SecretValue, and ServerUsername/
// ServerPassword within Properties/PropertiesString), leaving everything
// else -- including a non-secret Properties entry -- intact so the debug
// dump remains useful for troubleshooting.
func TestUnitRedactUpdateStoreFctArgsForLoggingPreservesNonSecretFields(t *testing.T) {
	secretVal := "S3cr3t-St0reP@ssw0rd!"
	properties := map[string]interface{}{
		"ServerUsername": "svc-cert-store-admin",
		"ServerPassword": "S3cr3t-ServerP@ssw0rd!",
		"ServerUseSsl":   "true",
	}
	propertiesStr, err := mapToEscapedJSONString(properties)
	if err != nil {
		t.Fatalf("mapToEscapedJSONString() returned unexpected error: %v", err)
	}
	args := &api.UpdateStoreFctArgs{
		Id:               "test-store-id",
		ClientMachine:    "test-client-machine",
		StorePath:        "/test/path",
		CertStoreType:    1,
		Properties:       properties,
		PropertiesString: propertiesStr,
		AgentId:          "test-agent-id",
		Password: &api.UpdateStorePasswordConfig{
			SecretValue: &secretVal,
		},
	}

	redacted, err := redactUpdateStoreFctArgsForLogging(args)
	if err != nil {
		t.Fatalf("redactUpdateStoreFctArgsForLogging() returned unexpected error: %v", err)
	}

	if redacted.Id != args.Id || redacted.ClientMachine != args.ClientMachine || redacted.StorePath != args.StorePath {
		t.Fatalf("expected non-secret top-level fields to be preserved unchanged, got: %+v", *redacted)
	}
	if redacted.Properties["ServerUseSsl"] != "true" {
		t.Fatalf("expected non-secret Properties entry ServerUseSsl to be preserved, got: %v", redacted.Properties["ServerUseSsl"])
	}
	if redacted.Properties["ServerUsername"] != redactedSecretLogPlaceholder {
		t.Fatalf("expected ServerUsername to be redacted, got: %v", redacted.Properties["ServerUsername"])
	}
	if redacted.Properties["ServerPassword"] != redactedSecretLogPlaceholder {
		t.Fatalf("expected ServerPassword to be redacted, got: %v", redacted.Properties["ServerPassword"])
	}
	if redacted.Password == nil || redacted.Password.SecretValue == nil || *redacted.Password.SecretValue != redactedSecretLogPlaceholder {
		t.Fatalf("expected Password.SecretValue to be redacted, got: %+v", redacted.Password)
	}

	// The ORIGINAL args must be untouched -- callers still need the real
	// values for the actual UpdateStore API call.
	if *args.Password.SecretValue != secretVal {
		t.Fatalf("redaction must not mutate the original args.Password.SecretValue, got: %v", *args.Password.SecretValue)
	}
	if args.Properties["ServerUsername"] != "svc-cert-store-admin" {
		t.Fatalf("redaction must not mutate the original args.Properties map, got: %v", args.Properties["ServerUsername"])
	}
}

// TestUnitCertificateStoreUpdateResponseNotLoggedInPlaintext is a regression
// test for a HIGH-severity security bug, adjacent to the one above:
// resource_keyfactor_certificate_store.go's Update() logs the RESPONSE it
// gets back from Command's PUT /CertificateStores at Trace level --
// fmt.Sprintf("UpdateStoreResponse: %v", *updateResponse) -- with no
// redaction at all. Command's own API response ECHOES BACK the store's
// server_username/server_password inside the response's PropertiesString
// field in cleartext. This is confirmed via a real recorded cassette
// fixture (testdata/cassettes/certificate_store_resource_container_preservation_update.yaml),
// whose PUT/Update response body contains
// "Properties":"{...,\"ServerPassword\":\"<plaintext-guid>\",...,\"ServerUsername\":\"<plaintext-guid>\"}".
//
// *api.UpdateStoreResponse is a different type from *api.UpdateStoreFctArgs
// (the request type redactUpdateStoreFctArgsForLogging above handles), so
// that helper does not apply here. The fix
// (redactUpdateStoreResponseForLogging in helpers.go) follows the same
// redact-before-format convention: PropertiesString is decoded, the
// credential-shaped keys are replaced with redactedSecretLogPlaceholder,
// and it is re-serialized BEFORE the Trace call formats it.
func TestUnitCertificateStoreUpdateResponseNotLoggedInPlaintext(t *testing.T) {
	const (
		plaintextServerUsername = "11376ee5-d19d-4265-948e-ce167a320544"
		// Embeds a literal double quote, matching the JSON-escaping-bypass
		// class the sibling request-side test above guards against.
		plaintextServerPassword = `c37bad9a-0e5e-4165-a1c6-a0"feab389cbd`
	)
	escapedServerPassword := strings.ReplaceAll(plaintextServerPassword, `"`, `\"`)

	buildResponse := func() *api.UpdateStoreResponse {
		properties := map[string]interface{}{
			"KubeSecretType": "tls",
			"ServerPassword": plaintextServerPassword,
			"ServerUseSsl":   "true",
			"ServerUsername": plaintextServerUsername,
		}
		propertiesStr, err := mapToEscapedJSONString(properties)
		if err != nil {
			t.Fatalf("mapToEscapedJSONString() returned unexpected error: %v", err)
		}
		resp := &api.UpdateStoreResponse{}
		resp.Id = "5003dfba-3513-4ac7-aec1-a65ffff0e4e3"
		resp.ClientMachine = "kfclab-uo-tertiary-uo"
		resp.Storepath = "default/tf-unit-gh175"
		resp.PropertiesString = propertiesStr
		resp.AgentId = "f5f4d314-16d7-4ed5-a9c0-b16880b75bdd"
		return resp
	}

	logResponse := func(resp *api.UpdateStoreResponse) []string {
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)
		tflog.Trace(ctx, fmt.Sprintf("UpdateStoreResponse: %v", *resp))
		return decodedLogMessages(t, buf.String())
	}

	t.Run("without redaction the raw response leaks server credentials (reproduces the finding)", func(t *testing.T) {
		messages := strings.Join(logResponse(buildResponse()), "\n")
		if !strings.Contains(messages, plaintextServerUsername) {
			t.Fatalf(
				"expected unredacted log output to contain plaintext server_username %q (demonstrating the bug "+
					"being fixed), but it did not -- the reproduction no longer matches the vulnerable code "+
					"path: %s", plaintextServerUsername, messages,
			)
		}
		if !strings.Contains(messages, escapedServerPassword) {
			t.Fatalf(
				"expected unredacted log output to contain plaintext server_password %q (demonstrating the bug "+
					"being fixed), but it did not -- the reproduction no longer matches the vulnerable code "+
					"path: %s", escapedServerPassword, messages,
			)
		}
	})

	t.Run("with redact-before-format neither server credential appears in logs", func(t *testing.T) {
		redacted, err := redactUpdateStoreResponseForLogging(buildResponse())
		if err != nil {
			t.Fatalf("redactUpdateStoreResponseForLogging() returned unexpected error: %v", err)
		}

		messages := strings.Join(logResponse(redacted), "\n")
		for _, secret := range []string{plaintextServerUsername, plaintextServerPassword, escapedServerPassword} {
			if strings.Contains(messages, secret) {
				t.Fatalf("plaintext secret %q leaked into log output: %s", secret, messages)
			}
		}
		if !strings.Contains(messages, redactedSecretLogPlaceholder) {
			t.Fatalf("expected redaction placeholder %q to appear in log output, got: %s", redactedSecretLogPlaceholder, messages)
		}
		// Non-secret fields (Id, ClientMachine, AgentId, and the non-credential
		// ServerUseSsl property) must remain intact so the Trace dump is still
		// useful for troubleshooting.
		for _, nonSecret := range []string{"5003dfba-3513-4ac7-aec1-a65ffff0e4e3", "kfclab-uo-tertiary-uo", "f5f4d314-16d7-4ed5-a9c0-b16880b75bdd", "ServerUseSsl"} {
			if !strings.Contains(messages, nonSecret) {
				t.Fatalf("expected non-secret field %q to remain present in redacted log output, got: %s", nonSecret, messages)
			}
		}
	})

	t.Run("redaction does not mutate the original response used to build state", func(t *testing.T) {
		resp := buildResponse()
		original := resp.PropertiesString

		_, err := redactUpdateStoreResponseForLogging(resp)
		if err != nil {
			t.Fatalf("redactUpdateStoreResponseForLogging() returned unexpected error: %v", err)
		}

		if resp.PropertiesString != original {
			t.Fatalf(
				"redaction must not mutate the original response's PropertiesString (it is still used to build "+
					"Terraform state), got: %s", resp.PropertiesString,
			)
		}
	})

	t.Run("nil response and empty PropertiesString are handled safely", func(t *testing.T) {
		redacted, err := redactUpdateStoreResponseForLogging(nil)
		if err != nil || redacted != nil {
			t.Fatalf("expected (nil, nil) for a nil response, got (%v, %v)", redacted, err)
		}

		resp := &api.UpdateStoreResponse{}
		resp.Id = "empty-properties-store"
		redacted, err = redactUpdateStoreResponseForLogging(resp)
		if err != nil {
			t.Fatalf("redactUpdateStoreResponseForLogging() returned unexpected error for empty PropertiesString: %v", err)
		}
		if redacted.PropertiesString != "" {
			t.Fatalf("expected empty PropertiesString to remain empty, got: %q", redacted.PropertiesString)
		}
	})
}
