package keyfactor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-log/tflogtest"
)

// TestUnitCertificateStoreDataSourcePasswordNotLogged is a regression test
// for a CRITICAL-severity security bug:
// data_source_keyfactor_certificate_store.go's Read() used to log the
// plaintext store_password -- a declared Sensitive: true schema attribute --
// directly by name, unconditionally, on every data-source read:
//
//	password := state.StorePassword.Value
//	tflog.Trace(ctx, fmt.Sprintf("Password for store %s: %s", sResp.Id, password))
//
// Unlike the certificate-store resource's Update() response-logging finding
// (see certificate_store_credential_log_test.go /
// redactUpdateStoreResponseForLogging), there was no response-shape or
// JSON-escaping subtlety here -- this was a direct, literal log of the raw
// secret by name, reachable at Trace level on every read. The fix removed
// the line outright rather than attempting to redact it (there is no
// legitimate debugging value in logging a credential's value).
//
// This test has two parts:
//
//  1. It reproduces the exact vulnerable call inline to demonstrate the
//     leak it fixes (proving the reproduction is faithful to the reported
//     finding).
//  2. It statically guards against reintroduction by scanning the actual
//     production source file for the vulnerable pattern -- the log line
//     cannot be reached directly in a unit test without a live Keyfactor
//     Command client (dataSourceCertificateStore.Read's password variable is
//     only reachable after a real API round trip), so asserting its absence
//     from the source is the most direct regression guard available at the
//     unit-test tier.
func TestUnitCertificateStoreDataSourcePasswordNotLogged(t *testing.T) {
	const plaintextStorePassword = `S3cr3t-St0reP@ss"w0rd!`

	t.Run("reproduction: logging the raw password by name leaks it in plaintext", func(t *testing.T) {
		var buf bytes.Buffer
		ctx := tflogtest.RootLogger(context.Background(), &buf)

		// This is a direct reproduction of the removed vulnerable line.
		password := plaintextStorePassword
		tflog.Trace(ctx, fmt.Sprintf("Password for store %s: %s", "test-store-id", password))

		messages := strings.Join(decodedLogMessages(t, buf.String()), "\n")
		if !strings.Contains(messages, plaintextStorePassword) {
			t.Fatalf(
				"expected the reproduction of the removed vulnerable log line to leak the plaintext password, "+
					"but it did not appear in captured output -- the reproduction no longer matches the fixed "+
					"finding: %s", messages,
			)
		}
	})

	t.Run("regression guard: production source no longer logs store_password by value", func(t *testing.T) {
		path := filepath.Join(".", "data_source_keyfactor_certificate_store.go")
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("could not read %s: %v", path, err)
		}
		source := string(src)

		// The exact vulnerable format string/pattern that was removed.
		forbidden := []string{
			`"Password for store %s: %s"`,
			"password := state.StorePassword.Value",
		}
		for _, pattern := range forbidden {
			if strings.Contains(source, pattern) {
				t.Fatalf(
					"data_source_keyfactor_certificate_store.go contains %q -- the plaintext store_password "+
						"logging regression has been reintroduced", pattern,
				)
			}
		}
	})
}
