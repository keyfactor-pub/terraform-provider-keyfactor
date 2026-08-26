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

// TestUnitPFXEnrollmentPasswordNotLoggedInPlaintext is a regression test for a
// HIGH-severity security finding: the PFX enrollment path in
// resource_keyfactor_certificate.go marshals *api.EnrollPFXFctArgsV2 --
// including its plaintext Password field (the real enrollment password,
// user-supplied via key_password or auto-generated) -- and logs the result
// both directly (tflog.Debug(fmt.Sprintf("PFXArgs: %s", ...))) and via a
// persisted "pfx_args" field set with tflog.SetField. Because SetField
// persists that field onto the ctx for every subsequent log call, the leak
// also reaches every downstream log line reusing the same ctx (e.g. the
// orphan-PFX-recovery logging added alongside this fix). This is reachable
// via the standard TF_LOG=DEBUG troubleshooting flag.
//
// This test reproduces the exact sequence of log calls the resource performs
// (SetField the JSON blob, then Debug-log a message that embeds the same JSON
// directly) against a real captured provider logger, and asserts the
// plaintext password does not appear anywhere in the captured output --
// covering the direct message line, the persisted field, AND a downstream log
// call that reuses the same ctx (standing in for the orphan-recovery logging
// that inherits it in production).
func TestUnitPFXEnrollmentPasswordNotLoggedInPlaintext(t *testing.T) {
	const secretPassword = "S3cr3t-EnrollmentPassw0rd!"

	run := func(t *testing.T, applyMask bool) string {
		t.Helper()
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		pfxArgs := &api.EnrollPFXFctArgsV2{
			CustomFriendlyName:   "test-friendly-name",
			Password:             secretPassword,
			CertificateAuthority: "TestCA",
			Template:             "TestTemplate",
			Subject: &api.CertificateSubject{
				SubjectCommonName: "test.example.com",
			},
		}

		jsonData, err := json.Marshal(pfxArgs)
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}

		ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))
		if applyMask {
			ctx = maskPFXEnrollmentPasswordInLogs(ctx, secretPassword)
		}

		// The direct message line the resource logs -- the password is
		// embedded straight into the message text, not passed as a field.
		tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))

		// Stands in for a downstream call (e.g. inside
		// recoverOrphanedPFXEnrollment / searchCertificatesForOrphanRecovery)
		// that reuses the same ctx without itself referencing the password --
		// the persisted "pfx_args" field alone would still leak it here if
		// unmasked.
		tflog.Debug(ctx, "Searching Keyfactor Command for a possibly-orphaned certificate")

		return buf.String()
	}

	t.Run("without masking the password leaks (reproduces the finding)", func(t *testing.T) {
		out := run(t, false)
		if !strings.Contains(out, secretPassword) {
			t.Fatalf(
				"expected unmasked log output to contain the plaintext password (demonstrating the bug being " +
					"fixed), but it did not -- the reproduction no longer matches the vulnerable code path",
			)
		}
	})

	t.Run("with masking the password never appears in logs", func(t *testing.T) {
		out := run(t, true)
		if strings.Contains(out, secretPassword) {
			t.Fatalf("plaintext password leaked into log output: %s", out)
		}
	})
}
