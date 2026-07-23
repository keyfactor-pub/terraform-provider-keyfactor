package keyfactor

import (
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// F9: auth certificate metadata else-null branch
// ---------------------------------------------------------------------------

// TestUnitCAReadAuthCertificateMetadataNullWhenAbsent is the red/green
// regression test for F9: caResponseToState only set
// auth_certificate_issued_dn/auth_certificate_issuer_dn/
// auth_certificate_thumbprint inside "if resp.AuthCertificate != nil", so a
// CA with no auth certificate configured left those three fields at the Go
// zero-value types.String{} -- a KNOWN empty string, not Null -- instead of
// explicit Null like every other pointer field in this function
// (boolPtrToTfBool/nullableStringToTfString/etc. all return Null on a nil
// pointer). Before the fix, the assertions below fail because
// newState.AuthCertificateIssuedDN.Null is false (Value == "").
func TestUnitCAReadAuthCertificateMetadataNullWhenAbsent(t *testing.T) {
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(47)
	resp.SetLogicalName("tf-unit-ca-no-auth-cert")
	resp.SetHostName("ca.lab.example.com")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	// resp.AuthCertificate intentionally left nil: no auth certificate configured.

	newState := caResponseToState(resp)

	assert.True(t, newState.AuthCertificateIssuedDN.Null,
		"auth_certificate_issued_dn must be Null (not a known empty string) when the CA has no auth certificate")
	assert.True(t, newState.AuthCertificateIssuerDN.Null,
		"auth_certificate_issuer_dn must be Null (not a known empty string) when the CA has no auth certificate")
	assert.True(t, newState.AuthCertificateThumbprint.Null,
		"auth_certificate_thumbprint must be Null (not a known empty string) when the CA has no auth certificate")
}
