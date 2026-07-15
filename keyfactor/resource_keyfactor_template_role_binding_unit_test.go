package keyfactor

import (
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/stretchr/testify/assert"
)

// TestUnitTemplateRoleBindingUpdateArgPreservesUnrelatedFields is a regression
// test for the bug where the role attach/detach paths rebuilt the UpdateTemplate
// request with only a handful of fields and ran them through zero-collapsing
// pointer helpers. Because Command's UpdateTemplate is a full replacement, every
// omitted field was reset server-side — so attaching or detaching a role
// silently wiped template settings this resource does not even manage
// (RequiresApproval, KeyRetentionDays, KeyArchival, EnrollmentFields,
// MetadataFields, TemplateRegexes) along with any empty/zero FriendlyName /
// KeyRetention / AllowedEnrollmentTypes.
func TestUnitTemplateRoleBindingUpdateArgPreservesUnrelatedFields(t *testing.T) {
	template := &api.GetTemplateResponse{
		Id:                     42,
		CommonName:             "WebServer",
		TemplateName:           "WebServer",
		Oid:                    "1.2.3.4",
		KeySize:                "2048",
		KeyType:                "RSA",
		ForestRoot:             "example.com",
		FriendlyName:           "Web Server Template",
		KeyRetention:           "Indefinite",
		KeyRetentionDays:       365,
		KeyArchival:            true,
		AllowedEnrollmentTypes: 3,
		RFCEnforcement:         true,
		RequiresApproval:       true,
		AllowedRequesters:      []string{"Existing-Role"},
		EnrollmentFields:       []api.TemplateEnrollmentFields{{Id: 1, Name: "field-a"}},
		MetadataFields:         []api.TemplateMetadataFields{{Id: 2, MetadataId: 9}},
		TemplateRegexes:        []api.TemplateRegex{{TemplateId: 42, SubjectPart: "CN", RegEx: ".*"}},
	}

	assertPreserved := func(t *testing.T, arg *api.UpdateTemplateArg) {
		t.Helper()
		// Scalar settings this resource does not manage must round-trip.
		if assert.NotNil(t, arg.RequiresApproval) {
			assert.True(t, *arg.RequiresApproval, "RequiresApproval must be preserved, not reset")
		}
		if assert.NotNil(t, arg.KeyRetentionDays) {
			assert.Equal(t, 365, *arg.KeyRetentionDays, "KeyRetentionDays must be preserved")
		}
		if assert.NotNil(t, arg.KeyArchival) {
			assert.True(t, *arg.KeyArchival, "KeyArchival must be preserved")
		}
		if assert.NotNil(t, arg.RFCEnforcement) {
			assert.True(t, *arg.RFCEnforcement, "RFCEnforcement must be preserved")
		}
		if assert.NotNil(t, arg.FriendlyName) {
			assert.Equal(t, "Web Server Template", *arg.FriendlyName, "FriendlyName must be preserved")
		}
		if assert.NotNil(t, arg.KeyRetention) {
			assert.Equal(t, "Indefinite", *arg.KeyRetention, "KeyRetention must be preserved")
		}
		if assert.NotNil(t, arg.AllowedEnrollmentTypes) {
			assert.Equal(t, 3, *arg.AllowedEnrollmentTypes, "AllowedEnrollmentTypes must be preserved")
		}
		// Collection settings this resource does not manage must round-trip.
		assert.NotNil(t, arg.EnrollmentFields, "EnrollmentFields must be preserved, not reset")
		assert.NotNil(t, arg.MetadataFields, "MetadataFields must be preserved, not reset")
		assert.NotNil(t, arg.TemplateRegexes, "TemplateRegexes must be preserved, not reset")
		// Identity is preserved.
		assert.Equal(t, "WebServer", arg.CommonName)
		assert.Equal(t, 42, arg.Id)
	}

	t.Run("attach adds the role and preserves everything else", func(t *testing.T) {
		arg := buildTemplateRoleBindingUpdateArg(template, []string{"Existing-Role", "New-Role"})
		if assert.NotNil(t, arg.AllowedRequesters) {
			assert.ElementsMatch(t, []string{"Existing-Role", "New-Role"}, *arg.AllowedRequesters)
		}
		if assert.NotNil(t, arg.UseAllowedRequesters) {
			assert.True(t, *arg.UseAllowedRequesters)
		}
		assertPreserved(t, arg)
	})

	t.Run("detach removes the last role and preserves everything else", func(t *testing.T) {
		// Detaching the only role leaves an empty (but non-nil) requester list.
		arg := buildTemplateRoleBindingUpdateArg(template, []string{})
		if assert.NotNil(t, arg.AllowedRequesters, "an emptied requester list must be sent as [] not dropped") {
			assert.Len(t, *arg.AllowedRequesters, 0)
		}
		if assert.NotNil(t, arg.UseAllowedRequesters) {
			assert.False(t, *arg.UseAllowedRequesters)
		}
		assertPreserved(t, arg)
	})
}
