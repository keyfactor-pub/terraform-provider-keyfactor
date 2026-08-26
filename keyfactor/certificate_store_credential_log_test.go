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

// TestUnitCertificateStoreCredentialsNotLoggedInPlaintext is a regression
// test for a HIGH-severity security finding from the full-review
// adjudication of PR #203: resource_keyfactor_certificate_store.go's
// Update() logs *api.UpdateStoreFctArgs -- which carries plaintext
// Sensitive: true store/server credentials -- twice at Debug level:
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
// Neither leak is behind a tflog.SetField key, so this reproduces the exact
// log calls the resource performs against a real captured provider logger
// and asserts none of the three plaintext secrets appear anywhere in the
// captured output once maskCertificateStoreCredentialsInLogs is applied.
func TestUnitCertificateStoreCredentialsNotLoggedInPlaintext(t *testing.T) {
	const (
		secretStorePassword  = "S3cr3t-St0reP@ssw0rd!"
		secretServerUsername = "svc-cert-store-admin"
		secretServerPassword = "S3cr3t-ServerP@ssw0rd!"
	)

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

	run := func(t *testing.T, applyMask bool) string {
		t.Helper()
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		updateStoreArgs := buildArgs()

		if applyMask {
			ctx = maskCertificateStoreCredentialsInLogs(
				ctx,
				secretStorePassword,
				secretServerUsername,
				secretServerPassword,
			)
		}

		// Mirrors the exact two Debug calls in Update().
		tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %v", *updateStoreArgs))

		updateStoreArgsJson, err := json.Marshal(updateStoreArgs)
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}
		tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %s", updateStoreArgsJson))

		return buf.String()
	}

	t.Run("without masking the credentials leak (reproduces the finding)", func(t *testing.T) {
		out := run(t, false)
		for _, secret := range []string{secretStorePassword, secretServerUsername, secretServerPassword} {
			if !strings.Contains(out, secret) {
				t.Fatalf(
					"expected unmasked log output to contain plaintext secret %q (demonstrating the bug being "+
						"fixed), but it did not -- the reproduction no longer matches the vulnerable code path",
					secret,
				)
			}
		}
	})

	t.Run("with masking none of the credentials appear in logs", func(t *testing.T) {
		out := run(t, true)
		for _, secret := range []string{secretStorePassword, secretServerUsername, secretServerPassword} {
			if strings.Contains(out, secret) {
				t.Fatalf("plaintext secret %q leaked into log output: %s", secret, out)
			}
		}
	})
}
