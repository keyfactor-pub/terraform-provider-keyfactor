package keyfactor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/stretchr/testify/assert"
)

// TestUnitCertificateStoreOmitsNilEntryPassword is a regression test for the
// bug where api.CertificateStore.EntryPassword lacked `omitempty`, so every
// add-certificate-to-store request marshaled an explicit `"EntryPassword": null`
// even though this resource never sets an entry password. The field now has
// `omitempty`, so a nil EntryPassword is omitted from the request body.
func TestUnitCertificateStoreOmitsNilEntryPassword(t *testing.T) {
	// Mirrors the request the deploy resource builds in addCertificateToStore.
	req := api.CertificateStore{
		CertificateStoreId: "f0cc1ede-3173-44b3-8368-ba1251ddb32e",
		Alias:              "alias",
		IncludePrivateKey:  true,
		Overwrite:          true,
		// EntryPassword deliberately left nil (not applicable).
	}

	b, err := json.Marshal(req)
	assert.NoError(t, err)
	assert.NotContains(t, string(b), "EntryPassword",
		"a nil EntryPassword must be omitted from the request, not marshaled as an explicit null")

	// Sanity: when an entry password IS set, it is still serialized.
	reqWith := api.CertificateStore{
		CertificateStoreId: "f0cc1ede-3173-44b3-8368-ba1251ddb32e",
		EntryPassword:      &api.EntryPassword{SecretValue: "s3cret"},
	}
	bWith, err := json.Marshal(reqWith)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(string(bWith), "EntryPassword"),
		"a set EntryPassword must still be sent")
}
