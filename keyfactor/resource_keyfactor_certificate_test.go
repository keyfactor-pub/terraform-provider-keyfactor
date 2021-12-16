package keyfactor

import (
	"keyfactor-go-client/pkg/keyfactor"
	"reflect"
	"testing"
)

func TestFlattenEnrollResponse(t *testing.T) {
	cases := []struct {
		Input  *keyfactor.EnrollResponse
		Output []interface{}
	}{
		{
			Input: &keyfactor.EnrollResponse{
				Certificates: []string{
					"certificateBinary",
				},
				CertificateInformation: keyfactor.CertificateInformation{
					SerialNumber:       "2D000001F6B013D77F15D3A7BE0000000001F6",
					IssuerDN:           "CN=Keyfactor Demo Drive CA 1, O=Keyfactor Inc",
					Thumbprint:         "087AE0E5473781574AAC84ADD178B759A977DFB2",
					KeyfactorID:        2100,
					KeyfactorRequestID: 1533,
					PKCS12Blob:         "bruh",
					Certificates:       nil,
					RequestDisposition: "ISSUED",
					DispositionMessage: "The private key was successfully retained.",
					EnrollmentContext:  nil,
				},
			},
			Output: []interface{}{
				map[string]interface{}{
					"certificates": []interface{}{
						"certificateBinary",
					},
					"serial_number":        "2D000001F6B013D77F15D3A7BE0000000001F6",
					"issuer_dn":            "CN=Keyfactor Demo Drive CA 1, O=Keyfactor Inc",
					"thumbprint":           "087AE0E5473781574AAC84ADD178B759A977DFB2",
					"keyfactor_id":         2100,
					"keyfactor_request_id": 1533,
				},
			},
		},
	}
	for _, c := range cases {
		out := flattenCertificateItems(c.Input)
		if !reflect.DeepEqual(out, c.Output) {
			t.Fatalf("Error matching output and expected: %#v vs %#v", out, c.Output)
		}
	}
}
