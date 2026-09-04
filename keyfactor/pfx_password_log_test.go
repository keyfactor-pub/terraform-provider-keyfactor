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

// TestUnitPFXEnrollmentPasswordNotLoggedInPlaintext is a regression test for
// a HIGH-severity security finding: the PFX enrollment path in
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
// An initial fix attempt masked the RAW password value as a literal
// substring out of the already-rendered/serialized log text
// (tflog.MaskFieldValuesWithFieldKeys / MaskAllFieldValuesStrings /
// MaskMessageStrings). That approach has a JSON-escaping
// bypass, confirmed by direct reproduction below: encoding/json escapes '"'
// and '\\' when serializing the Password field, so a password containing
// either character no longer survives as a contiguous substring of the raw
// password in the JSON-rendered text, and the mask misses it.
//
// The fix now redacts the Password field on a COPY of *api.EnrollPFXFctArgsV2
// before marshaling it for logging (enrollPFXV2's jsonData is only ever used
// for logging -- the real PFXArgs, untouched, is what's actually sent to
// EnrollPFXV2), closing the bypass class entirely instead of masking
// rendered text after the fact.
func TestUnitPFXEnrollmentPasswordNotLoggedInPlaintext(t *testing.T) {
	// secretPassword embeds a literal double quote, which encoding/json
	// escapes to \" when serializing -- exactly the character class that
	// defeats a literal substring mask against JSON-rendered text.
	const secretPassword = `S3cr3t-Enroll"mentPassw0rd!`

	buildPFXArgs := func() *api.EnrollPFXFctArgsV2 {
		return &api.EnrollPFXFctArgsV2{
			CustomFriendlyName:   "test-friendly-name",
			Password:             secretPassword,
			CertificateAuthority: "TestCA",
			Template:             "TestTemplate",
			Subject: &api.CertificateSubject{
				SubjectCommonName: "test.example.com",
			},
		}
	}

	escapedSecret := strings.ReplaceAll(secretPassword, `"`, `\"`)

	t.Run("without any redaction the password leaks, including JSON-escaped (reproduces the finding)", func(t *testing.T) {
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		jsonData, err := json.Marshal(buildPFXArgs())
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}
		ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))
		tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))

		messages := strings.Join(decodedLogMessages(t, buf.String()), "\n")
		if !strings.Contains(messages, escapedSecret) {
			t.Fatalf(
				"expected unredacted log output to contain the JSON-escaped plaintext password %q (demonstrating "+
					"the bug being fixed), but it did not -- the reproduction no longer matches the vulnerable "+
					"code path: %s", escapedSecret, messages,
			)
		}
	})

	t.Run("substring masking of the raw password against rendered text is bypassed by JSON escaping", func(t *testing.T) {
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		jsonData, err := json.Marshal(buildPFXArgs())
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}
		ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))
		// Reproduce the initial masking approach directly (the function it
		// used, maskPFXEnrollmentPasswordInLogs, has since been removed from
		// production code in favor of redact-before-format -- see helpers.go).
		ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "pfx_args", secretPassword)
		ctx = tflog.MaskAllFieldValuesStrings(ctx, secretPassword)
		ctx = tflog.MaskMessageStrings(ctx, secretPassword)

		tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))
		tflog.Debug(ctx, "Searching Keyfactor Command for a possibly-orphaned certificate")

		messages := strings.Join(decodedLogMessages(t, buf.String()), "\n")
		if !strings.Contains(messages, escapedSecret) {
			t.Fatalf(
				"expected substring masking to be bypassed by JSON escaping, but the escaped secret %q was not "+
					"found in output -- the reproduction no longer matches the documented bypass: %s",
				escapedSecret, messages,
			)
		}
	})

	t.Run("with redact-before-format the password never appears in logs, even JSON-escaped", func(t *testing.T) {
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		pfxArgs := buildPFXArgs()
		// Mirrors enrollPFXV2's fix: redact on a copy before marshaling for
		// logging; the original pfxArgs (with the real password) is left
		// untouched for the actual enrollment call.
		redactedPFXArgs := *pfxArgs
		redactedPFXArgs.Password = redactedSecretLogPlaceholder

		jsonData, err := json.Marshal(&redactedPFXArgs)
		if err != nil {
			t.Fatalf("json.Marshal() returned unexpected error: %v", err)
		}
		ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))

		tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))
		// Stands in for a downstream call (e.g. inside
		// recoverOrphanedPFXEnrollment / searchCertificatesForOrphanRecovery)
		// that reuses the same ctx without itself referencing the password.
		tflog.Debug(ctx, "Searching Keyfactor Command for a possibly-orphaned certificate")

		messages := strings.Join(decodedLogMessages(t, buf.String()), "\n")
		if strings.Contains(messages, secretPassword) {
			t.Fatalf("plaintext password leaked into log output: %s", messages)
		}
		if strings.Contains(messages, escapedSecret) {
			t.Fatalf("JSON-escaped plaintext password leaked into log output: %s", messages)
		}
		if pfxArgs.Password != secretPassword {
			t.Fatalf("redaction must not mutate the original pfxArgs.Password, got: %v", pfxArgs.Password)
		}
		if !strings.Contains(messages, redactedSecretLogPlaceholder) {
			t.Fatalf("expected redaction placeholder %q to appear in log output, got: %s", redactedSecretLogPlaceholder, messages)
		}
	})
}
