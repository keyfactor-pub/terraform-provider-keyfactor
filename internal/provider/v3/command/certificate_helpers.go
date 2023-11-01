package command

import (
	"context"
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	kfc "github.com/Keyfactor/keyfactor-go-client-sdk/v2/api/command"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"io"
	"math/rand"
	"net/http"
	"software.sslmate.com/src/go-pkcs12"
	"sort"
	"strings"
)

var (
	lowerCharSet   = "abcdedfghijklmnopqrst"
	upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialCharSet = "!@#$%&*"
	numberSet      = "0123456789"
	allCharSet     = lowerCharSet + upperCharSet + specialCharSet + numberSet
)

func generatePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) string {
	var password strings.Builder

	//Set special character
	for i := 0; i < minSpecialChar; i++ {
		random := rand.Intn(len(specialCharSet))
		password.WriteString(string(specialCharSet[random]))
	}

	//Set numeric
	for i := 0; i < minNum; i++ {
		random := rand.Intn(len(numberSet))
		password.WriteString(string(numberSet[random]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random := rand.Intn(len(upperCharSet))
		password.WriteString(string(upperCharSet[random]))
	}

	remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
	for i := 0; i < remainingLength; i++ {
		random := rand.Intn(len(allCharSet))
		password.WriteString(string(allCharSet[random]))
	}
	inRune := []rune(password.String())
	rand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})
	return string(inRune)
}

//func flattenMetadata(metadata interface{}) types.Map {
//	data := make(map[string]string)
//	if metadata != nil {
//		for k, v := range metadata.(map[string]interface{}) {
//			data[k] = v.(string)
//		}
//	}
//
//	result := types.Map{
//		Elems:    map[string]attr.Value{},
//		ElemType: types.StringType,
//	}
//	for k, v := range data {
//		result.Elems[k] = types.String{Value: v}
//	}
//	return result
//}

func mapSanIDToName(sanID int) string {
	switch sanID {
	case 0:
		return "Other Name"
	case 1:
		return "RFC 822 Name"
	case 2:
		return "DNS Name"
	case 3:
		return "X400 Address"
	case 4:
		return "Directory Name"
	case 5:
		return "Ediparty Name"
	case 6:
		return "Uniform Resource Identifier"
	case 7:
		return "IP Address"
	case 8:
		return "Registered Id"
	case 100:
		return "MS_NTPrincipalName"
	case 101:
		return "MS_NTDSReplication"
	}
	return ""
}

func ParseCertificateBytes(certBytes *string) (string, []string, []string, []string, error) {
	// Parse the PEM block containing the certificate

	//convert string to []byte
	decoded, dErr := base64.StdEncoding.DecodeString(*certBytes)
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decoded,
	}
	if dErr != nil {
		return "", nil, nil, nil, fmt.Errorf("failed to decode PEM block containing certificate: %w", dErr)
	}

	pemString := string(pem.EncodeToMemory(&block))
	tflog.Trace(context.Background(), fmt.Sprintf("PEM String: %v", pemString))

	//// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract IP SANs
	ipSANs := make([]string, 0)
	for _, ip := range cert.IPAddresses {
		ipSANs = append(ipSANs, ip.String())
	}

	// Extract DNS SANs
	dnsSANs := cert.DNSNames

	// Extract URI SANs
	uriSANs := make([]string, 0)
	for _, uri := range cert.URIs {
		uriSANs = append(uriSANs, uri.String())
	}

	// Sort the SANs
	sort.Strings(ipSANs)
	sort.Strings(dnsSANs)
	sort.Strings(uriSANs)

	return pemString, ipSANs, dnsSANs, uriSANs, nil
}

func recoverPrivateKey(ctx context.Context, client *kfc.APIClient, id int64, thumbPrint string, sn string, dn string, password string, collectionId *int32) (interface{}, *x509.Certificate, []*x509.Certificate, error) {
	ctx = tflog.SetField(ctx, "CertId", id)
	tflog.Debug(ctx, fmt.Sprintf("Calling POST %s/Certificates/Recover", client.GetConfig().Host))

	if password == "" {
		tflog.Debug(ctx, "Password is required to recover private key and no password was supplied; using auto generated password.")
		password = generatePassword(DefaultPasswdLength, DefaultMinSpecialChar, DefaultMinNum, DefaultMinUpperCase)
	}
	tflog.Trace(ctx, fmt.Sprintf("PFX Password: %s", password))

	validInput := false
	if id != 0 {
		validInput = true
	} else if thumbPrint != "" {
		validInput = true
	} else if sn != "" && dn != "" {
		validInput = true
	}
	tflog.SetField(ctx, "valid_input", validInput)

	id32 := int32(id)

	if !validInput {
		return nil, nil, nil, fmt.Errorf("certID, thumbprint, or serial number AND issuer DN required to dowload certificate")
	}

	issuerDn := kfc.NullableString{}
	if dn != "" {
		issuerDn.Set(&dn)
	}

	request := kfc.ModelsCertificateRecoveryRequest{
		Password:             password,
		CertID:               &id32,
		SerialNumber:         &sn,
		IssuerDN:             issuerDn,
		Thumbprint:           &thumbPrint,
		IncludeChain:         convertBoolToPtr(true),
		AdditionalProperties: nil,
	}

	tflog.Info(ctx, "Attempting to recover private key from Keyfactor Command")
	cReq := client.CertificateApi.CertificateRecoverCertificateAsync(ctx).
		Rq(request).
		XCertificateformat("PFX")

	if collectionId != nil {
		cReq.CollectionId(*collectionId)
	}

	certsResp, httpResp, respErr := cReq.
		Execute()

	if respErr != nil {
		defer httpResp.Body.Close()
	}
	//logCommandAPIResponse(ctx, httpResp, respErr) // this is commented out because you can't read the body twice

	if httpResp.StatusCode == http.StatusOK && (certsResp == nil) {
		tflog.Warn(ctx, "Keyfactor SDK client returned a nil object and a 200 status code. This is likely a bug in SDK.")
		tflog.Info(ctx, "Attempting to parse HTTP response body as JSON")
		bodyBytes, err := io.ReadAll(httpResp.Body)
		bodyString := string(bodyBytes)
		if err != nil {
			tflog.Error(ctx, fmt.Sprintf("Unable to read HTTP response body: %v", err))
			return nil, nil, nil, err
		}
		tflog.Debug(ctx, fmt.Sprintf("Response body: %s", bodyString))

		var apiRespObj []kfc.ModelsCertificateRecoveryRequest // TODO: Remove this stuff
		var genericObj []map[string]interface{}
		gErr := json.Unmarshal(bodyBytes, &genericObj)
		if gErr != nil {
			tflog.Error(ctx, fmt.Sprintf("Unable to unmarshal JSON response body: %v", gErr))
		}
		aErr := json.Unmarshal(bodyBytes, &apiRespObj)
		if aErr != nil {
			tflog.Error(ctx, fmt.Sprintf("Unable to unmarshal JSON response body: %v", aErr))
			return nil, nil, nil, aErr
		}
	} else {
		if httpResp.StatusCode != http.StatusOK {
			return nil, nil, nil, fmt.Errorf("failed to recover certificate: %v", respErr)
		}

		pfxString := certsResp.PFX

		tflog.Trace(ctx, fmt.Sprintf("PFX String: %v", pfxString))
		tflog.Debug(ctx, "Decoding PFX to bytes")
		pfxDer, dErr := base64.StdEncoding.DecodeString(*certsResp.PFX)
		if dErr != nil {
			tflog.Error(ctx, fmt.Sprintf("Private key decode error: %s", dErr.Error()))
		}

		pkInterface, leaf, chain, err := pkcs12.DecodeChain(pfxDer, password)
		if err != nil {
			return nil, nil, nil, err
		}
		var pk string

		rsa, ok := pkInterface.(*rsa2.PrivateKey)
		if ok {
			tflog.Info(ctx, "Recovered RSA private key from Keyfactor Command:")
			buf := x509.MarshalPKCS1PrivateKey(rsa)
			if len(buf) > 0 {
				pk = string(pem.EncodeToMemory(&pem.Block{
					Bytes: buf,
					Type:  "RSA PRIVATE KEY",
				}))
				tflog.Trace(ctx, pk)
			} else {
				tflog.Warn(ctx, "Empty private key recovered from Keyfactor kfc.")
			}
		} else {
			tflog.Info(ctx, "Attempting ECC private key recovery")
			ecc, ok := pkInterface.(*ecdsa.PrivateKey)
			if ok {
				// We don't really care about the error here. An error just means that the key will be blank which isn't a
				// reason to fail
				tflog.Info(ctx, "Recovered ECC private key from Keyfactor Command")
				buf, _ := x509.MarshalECPrivateKey(ecc)
				if len(buf) > 0 {
					pk = string(pem.EncodeToMemory(&pem.Block{
						Bytes: buf,
						Type:  "EC PRIVATE KEY",
					}))
					tflog.Trace(ctx, pk)
				} else {
					tflog.Warn(ctx, "Empty private key returned from Keyfactor kfc.")
				}
			}
		}

		return pk, leaf, chain, nil
	}

	return "", nil, nil, fmt.Errorf("failed to recover private key for certificate")
}

func readCertificateById(ctx context.Context, cID int, client *kfc.APIClient) (*kfc.ModelsCertificateRetrievalResponse, *http.Response, error) {
	ctx = tflog.SetField(ctx, "certificate_id", cID)
	tflog.Debug(ctx, fmt.Sprintf("Calling GET %s/Certificate/%d", client.GetConfig().Host, cID))
	clientResp, httpResp, respErr := client.CertificateApi.CertificateGetCertificate(ctx, int32(cID)).
		IncludeMetadata(true).
		IncludeLocations(true).
		Execute()
	logCommandAPIResponse(ctx, httpResp, respErr)

	if httpResp.StatusCode == http.StatusNotFound {
		tflog.Warn(ctx, fmt.Sprintf("Unable to find certificate %d using Keyfactor Command certificate Id. Attempting to search as serial number.", cID))
		clientResp, httpResp, respErr = lookupCertificate(ctx, CertificateSNFieldName, fmt.Sprintf("%d", cID), client)
	}

	var (
		detailedClientResp *kfc.ModelsCertificateRetrievalResponse
		detailedHttpResp   *http.Response
		detailedRespErr    error
	)
	tp := clientResp.Thumbprint
	if tp != nil {
		detailedClientResp, detailedHttpResp, detailedRespErr = lookupCertificate(ctx, CertificateThumbprintFieldName, tp, client)
	} else {
		tflog.Warn(ctx, fmt.Sprintf("Thumbprint for certificate %d is nil. Attempting to search as serial number.", cID))
		sn := clientResp.SerialNumber
		if sn == nil {
			tflog.Warn(ctx, fmt.Sprintf("Serial number for certificate %d is nil. Attempting to search as Issuer DN.", cID))
			dn := clientResp.IssuedDN
			if dn.IsSet() {
				detailedClientResp, detailedHttpResp, detailedRespErr = lookupCertificate(ctx, CertificateDNFieldName, dn, client)
			} else {
				tflog.Warn(ctx, fmt.Sprintf("Unable to lookup locations, private key and metadata for %d", cID))
			}
		} else {
			detailedClientResp, detailedHttpResp, detailedRespErr = lookupCertificate(ctx, CertificateSNFieldName, sn, client)
		}
	}
	if detailedClientResp != nil && detailedRespErr == nil {
		//compare the IDs to make sure we have the same cert
		if *detailedClientResp.Id != *clientResp.Id {
			tflog.Warn(ctx, fmt.Sprintf("Certificate ID for certificate %d does not match certificate ID for certificate %d", detailedClientResp.Id, clientResp.Id))
		} else {
			return detailedClientResp, detailedHttpResp, detailedRespErr
		}
	}
	return clientResp, httpResp, respErr
}

func lookupCertificate(ctx context.Context, fieldName string, fieldValue interface{}, client *kfc.APIClient) (*kfc.ModelsCertificateRetrievalResponse, *http.Response, error) {
	var (
		q           string
		notFoundErr error
	)
	switch fieldValue.(type) {
	case string:
		q = fmt.Sprintf(`%s -eq "%s"`, fieldName, fieldValue.(string))
		notFoundErr = fmt.Errorf("unable to find certificate %s in Keyfactor Command", fieldValue.(string))
	case *string:
		q = fmt.Sprintf(`%s -eq "%s"`, fieldName, *fieldValue.(*string))
		notFoundErr = fmt.Errorf("unable to find certificate %s in Keyfactor Command", *fieldValue.(*string))
	case *kfc.NullableString:
		q = fmt.Sprintf(`%s -eq "%s"`, fieldName, *fieldValue.(*kfc.NullableString).Get())
		notFoundErr = fmt.Errorf("unable to find certificate %s in Keyfactor Command", *fieldValue.(*kfc.NullableString).Get())
	case int, int32, int64:
		q = fmt.Sprintf(`%s -eq %d`, fieldName, fieldValue)
		notFoundErr = fmt.Errorf("unable to find certificate %d in Keyfactor Command", fieldValue)
	case *int, *int32, *int64:
		q = fmt.Sprintf(`%s -eq %d`, fieldName, *fieldValue.(*int))
		notFoundErr = fmt.Errorf("unable to find certificate %d in Keyfactor Command", *fieldValue.(*int))
	case *kfc.NullableInt32, *kfc.NullableInt64:
		q = fmt.Sprintf(`%s -eq %d`, fieldName, fieldValue.(*kfc.NullableInt32).Get())
		notFoundErr = fmt.Errorf("unable to find certificate %d in Keyfactor Command", fieldValue.(*kfc.NullableInt32).Get())
	}
	ctx = tflog.SetField(ctx, fieldName, fieldValue)
	tflog.Info(ctx, fmt.Sprintf("Looking up cert by '%s'", fieldName))
	ctx = tflog.SetField(ctx, "query_string", q)
	tflog.Debug(ctx, fmt.Sprintf("Calling GET %s/Certificate?QueryString=%s", client.GetConfig().Host, q))
	certsResp, httpResp, respErr := client.CertificateApi.CertificateQueryCertificates(ctx).
		IncludeMetadata(true).
		IncludeLocations(true).
		IncludeHasPrivateKey(true).
		PqQueryString(q).
		Execute()
	logCommandAPIResponse(ctx, httpResp, respErr)

	if len(certsResp) > 0 {
		// find the newest cert by ImportDate
		var newestCert kfc.ModelsCertificateRetrievalResponse
		for _, cert := range certsResp { // Check if newestCert is empty, if it is set it to the first cert in the list
			if newestCert.ImportDate == nil {
				tflog.Debug(ctx, fmt.Sprintf("Setting newestCert to '%v(%v)'", cert.IssuedDN, cert.Thumbprint))
				newestCert = cert
				continue
			}

			if cert.ImportDate == nil || newestCert.ImportDate == nil {
				tflog.Error(ctx, fmt.Sprintf("Unable to compare %v(%v) and %v(%v)", cert.IssuedDN, cert.Thumbprint, newestCert.IssuedDN, newestCert.Thumbprint))
				continue
			}

			if cert.ImportDate.After(*newestCert.ImportDate) {
				tflog.Info(ctx, fmt.Sprintf("Multiple certs found, using most recently issued cert for %v", fieldValue))
				tflog.Debug(ctx, fmt.Sprintf("Setting newestCert to '%v(%v)'", cert.IssuedDN, cert.Thumbprint))
				newestCert = cert
			}
		}
		return &newestCert, httpResp, respErr
	} else if len(certsResp) <= 0 {
		tflog.Error(ctx, notFoundErr.Error())
		return nil, httpResp, notFoundErr
	}
	tflog.Error(ctx, fmt.Sprintf("Unable to find certificate by '%s'", fieldName))
	return nil, httpResp, respErr // no cert was found and an API error was returned
}
