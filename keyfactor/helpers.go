package keyfactor

import (
	"context"
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	rand.Shuffle(
		len(inRune), func(i, j int) {
			inRune[i], inRune[j] = inRune[j], inRune[i]
		},
	)
	return string(inRune)
}

func expandSubject(subject string) (
	types.String,
	types.String,
	types.String,
	types.String,
	types.String,
	types.String,
) {
	var (
		cn string
		ou string
		o  string
		l  string
		st string
		c  string
	)
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				cn = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				ou = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				c = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				l = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				st = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				o = strings.Replace(field, "O=", "", 1)
			}
		}
	}
	return types.String{Value: cn}, types.String{Value: ou}, types.String{Value: o}, types.String{Value: l}, types.String{Value: st}, types.String{Value: c}
}

func flattenSubject(subject string) types.Object {
	data := make(map[string]string) // Inner subject interface is a string mapped interface
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				data["subject_common_name"] = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				data["subject_organizational_unit"] = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				data["subject_country"] = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				data["subject_locality"] = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				data["subject_state"] = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				data["subject_organization"] = strings.Replace(field, "O=", "", 1)
			}
		}

	}
	result := types.Object{
		Attrs: map[string]attr.Value{
			"subject_common_name":         types.String{Value: data["subject_common_name"]},
			"subject_locality":            types.String{Value: data["subject_locality"]},
			"subject_organization":        types.String{Value: data["subject_organization"]},
			"subject_state":               types.String{Value: data["subject_state"]},
			"subject_country":             types.String{Value: data["subject_country"]},
			"subject_organizational_unit": types.String{Value: data["subject_organizational_unit"]},
		},
		AttrTypes: map[string]attr.Type{
			"subject_common_name":         types.StringType,
			"subject_locality":            types.StringType,
			"subject_organization":        types.StringType,
			"subject_state":               types.StringType,
			"subject_country":             types.StringType,
			"subject_organizational_unit": types.StringType,
		},
	}

	return result
}

func flattenMetadata(metadata interface{}) types.Map {
	data := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata.(map[string]interface{}) {
			data[k] = v.(string)
		}
	}

	result := types.Map{
		Elems:    map[string]attr.Value{},
		ElemType: types.StringType,
	}
	for k, v := range data {
		result.Elems[k] = types.String{Value: v}
	}

	//check if elems is empty
	if len(result.Elems) == 0 {
		result.Null = true
	}
	return result
}

func flattenSANs(
	sans []api.SubjectAltNameElements,
	tfDNSSANs types.List,
	tfIPSANs types.List,
	tfURISANs types.List,
) (types.List, types.List, types.List) {
	sanIP4Array := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     tfIPSANs.IsNull(),
	}
	sanDNSArray := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     tfDNSSANs.IsNull(),
	}
	sanURIArray := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     tfURISANs.IsNull(),
	}
	dnsSANs := []string{}
	ipSANs := []string{}
	uriSANs := []string{}
	if len(sans) > 0 {
		for _, san := range sans {
			sanName := mapSanIDToName(san.Type)
			if sanName == "IP Address" {
				ipSANs = append(ipSANs, san.Value)
				//sanIP4Array.Elems = append(sanIP4Array.Elems, types.String{Value: san.Value})
				//sanIP4Array.Null = false
			} else if sanName == "DNS Name" {
				dnsSANs = append(dnsSANs, san.Value)
				//sanDNSArray.Elems = append(sanDNSArray.Elems, types.String{Value: san.Value})
				//sanDNSArray.Null = false
			} else if sanName == "Uniform Resource Identifier" {
				uriSANs = append(uriSANs, san.Value)
				//sanURIArray.Elems = append(sanURIArray.Elems, types.String{Value: san.Value})
				//sanURIArray.Null = false
			}
		}
		// sort the arrays

		if len(tfDNSSANs.Elems) > 0 {
			var stateDNSSans []string
			_ = tfDNSSANs.ElementsAs(nil, &stateDNSSans, true)
			dnsSANs = sortInSameOrder(dnsSANs, stateDNSSans)
		} else {
			sort.Strings(dnsSANs)
		}
		if len(tfIPSANs.Elems) > 0 {
			var stateIPSans []string
			_ = tfIPSANs.ElementsAs(nil, &stateIPSans, true)
			ipSANs = sortInSameOrder(ipSANs, stateIPSans)
		} else {
			sort.Strings(ipSANs)
		}
		if len(tfURISANs.Elems) > 0 {
			var stateURISans []string
			_ = tfURISANs.ElementsAs(nil, &stateURISans, true)
			uriSANs = sortInSameOrder(uriSANs, stateURISans)
		} else {
			sort.Strings(uriSANs)
		}

		for _, san := range dnsSANs {
			sanDNSArray.Elems = append(sanDNSArray.Elems, types.String{Value: san})
			sanDNSArray.Null = false
		}
		for _, san := range ipSANs {
			sanIP4Array.Elems = append(sanIP4Array.Elems, types.String{Value: san})
			sanIP4Array.Null = false
		}
		for _, san := range uriSANs {
			sanURIArray.Elems = append(sanURIArray.Elems, types.String{Value: san})
			sanURIArray.Null = false
		}
	}

	return sanDNSArray, sanIP4Array, sanURIArray
}

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

func unescapeJSON(jsonData string) ([]byte, error) {
	unescapedJSON, err := strconv.Unquote(jsonData)
	if err != nil {
		return []byte(jsonData), err
	}
	return []byte(unescapedJSON), nil
}

func flattenEnrollmentFields(efs []api.TemplateEnrollmentFields) types.List {

	result := types.List{
		ElemType: types.MapType{},
		Elems:    []attr.Value{},
	}
	for _, ef := range efs {
		var options []attr.Value
		for _, op := range ef.Options {
			options = append(
				options, types.String{
					Value: op,
				},
			)
		}
		result.Elems = append(
			result.Elems, types.Map{
				ElemType: types.StringType,
				Elems: map[string]attr.Value{
					"id":   types.Int64{Value: int64(ef.Id)},
					"name": types.String{Value: ef.Name},
					"type": types.String{Value: strconv.Itoa(ef.DataType)},
					"options": types.List{
						Elems:    options,
						ElemType: types.StringType,
					},
				},
			},
		)
	}

	return result
}

func flattenTemplateRegexes(regexes []api.TemplateRegex) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	for _, regex := range regexes {
		result.Elems = append(result.Elems, types.String{Value: regex.RegEx})
	}
	return result
}

func flattenAllowedRequesters(requesters []string) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}

	if len(requesters) > 0 {
		for _, requester := range requesters {
			result.Elems = append(result.Elems, types.String{Value: requester})
		}
	}

	return result
}

func isNullString(s string) bool {
	switch s {
	case "", "null":
		return true
	default:
		return false
	}
}

func isNullId(i int) bool {
	if i <= 0 {
		return true
	}
	return false
}

// retryCertCollectionHandler is a helper function to retry downloading a certificate from a collection
// This is needed because the Keyfactor Command API may return an error if the certificate is not ready to be downloaded
// The function will retry a set number of times before returning an error.
func retryCertCollectionHandler(
	kfClient *api.Client,
	certID int,
	collectionID, maxSleep int, maxRetry int,
) (*api.GetCertificateResponse, error) {
	req := api.GetCertificateContextArgs{
		Id:           certID,
		CollectionId: intToPointer(collectionID),
	}

	totalSleep := 0
	for i := 0; i <= maxSleep; i++ {
		tflog.Debug(
			context.Background(),
			fmt.Sprintf("Attempting to download certificate with ID: %d from Collection ID: %d", certID, collectionID),
		)
		certificateContext, err := kfClient.GetCertificateContext(&req)
		if err != nil {
			if maxRetry > 0 && i >= maxRetry {
				tflog.Warn(context.Background(), fmt.Sprintf("Max retry attempts reached, returning error: %s", err))
				return nil, err
			}
			if totalSleep >= maxSleep {
				//log.Printf("[WARNING] Max retry attempts reached, returning error: %s", err)
				tflog.Warn(context.Background(), fmt.Sprintf("Max retry attempts reached, returning error: %s", err))
				return nil, err
			}
			if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(ERR_COLLECTION_WAIT)) {
				//log.Printf("[WARNING] Error downloading certificate: %s, will attempt to retry ", err)
				tflog.Warn(
					context.Background(),
					fmt.Sprintf("Error downloading certificate: %s, will attempt to retry ", err),
				)

				delay := time.Duration(i) * time.Second
				if maxRetry > 0 {
					tflog.Debug(
						context.Background(),
						fmt.Sprintf(
							"Max retry attempts set to %d, defaulting to %ss intervals",
							maxRetry,
							MAX_WAIT_SECONDS,
						),
					)
					delay = time.Duration(MAX_WAIT_SECONDS) * time.Second
				}
				if delay > time.Duration(MAX_WAIT_SECONDS)*time.Second {
					delay = time.Duration(MAX_WAIT_SECONDS) * time.Second
				}
				//log.Printf("[DEBUG] Sleeping for %s seconds before retrying", delay)
				tflog.Debug(context.Background(), fmt.Sprintf("Sleeping for %s seconds before retrying", delay))
				time.Sleep(delay)
				totalSleep += int(delay.Seconds())
				continue
			}
			tflog.Error(context.Background(), fmt.Sprintf("Error downloading certificate: %s", err))
			return nil, err
		}
		tflog.Debug(
			context.Background(),
			fmt.Sprintf("Successfully downloaded certificate with ID: %d from Collection ID: %d", certID, collectionID),
		)
		return certificateContext, nil
	}

	tflog.Warn(
		context.Background(),
		fmt.Sprintf(
			"This should be unreachable, attempting one last time to download certificate with ID: %d from Collection ID: %d",
			certID,
			collectionID,
		),
	)
	certificateContext, err := kfClient.GetCertificateContext(&req)
	if err != nil {
		tflog.Error(context.Background(), fmt.Sprintf("Error downloading certificate: %s", err))
		return nil, err
	}
	tflog.Debug(
		context.Background(),
		fmt.Sprintf("Successfully downloaded certificate with ID: %d from Collection ID: %d", certID, collectionID),
	)
	return certificateContext, nil
}

func downloadCertificate(
	id int,
	collectionId int,
	kfClient *api.Client,
	password string,
	csrEnrollment bool,
	maxCollectionEnrollWait int,
	maxCollectionEnrollWaitRetry int,
) (
	string,
	string,
	string,
	error,
) {
	//log.Printf("[DEBUG] enter downloadCertificate")
	//log.Printf("[INFO] Downloading certificate with ID: %d", id)
	tflog.Debug(context.Background(), fmt.Sprintf("Entered downloadCertificate for certificate ID: %d", id))

	req := api.GetCertificateContextArgs{
		Id: id,
	}
	var (
		certificateContext *api.GetCertificateResponse
		err                error
	)

	if collectionId > 0 {
		//log.Printf("[DEBUG] Downloading certificate '%d' from Collection ID: %d", id, collectionId)
		tflog.Debug(
			context.Background(),
			fmt.Sprintf("Downloading certificate '%d' from Collection ID: %d", id, collectionId),
		)
		req.CollectionId = &collectionId
		tflog.Debug(context.Background(), fmt.Sprintf("Calling retryCertCollectionHandler for certificate ID: %d", id))
		certificateContext, err = retryCertCollectionHandler(
			kfClient,
			id,
			collectionId,
			maxCollectionEnrollWait,
			maxCollectionEnrollWaitRetry,
		)
		if err != nil {
			return "", "", "", err
		}
	} else {
		//log.Printf("[INFO] Downloading certificate from Keyfactor Command")
		//log.Printf("[DEBUG] Request: %+v", req)
		tflog.Debug(context.Background(), fmt.Sprintf("Downloading certificate from Keyfactor Command"))
		certificateContext, err = kfClient.GetCertificateContext(&req)
		if err != nil {
			return "", "", "", err
		}
	}

	//log.Printf("[INFO] Looking up certificate template with ID: %d", certificateContext.TemplateId)
	tflog.Debug(
		context.Background(),
		fmt.Sprintf("Looking up certificate template with ID: %d", certificateContext.TemplateId),
	)
	template, err := kfClient.GetTemplate(certificateContext.TemplateId)
	if err != nil {
		log.Printf(
			"[ERROR] Error looking up certificate template: %s returning integer value rater than common name",
			err,
		)
		template = nil
	}

	recoverable := false

	if template == nil || template.KeyRetention != "None" {
		recoverable = true
	}

	var privPem []byte
	var leafPem []byte
	var chainPem []byte

	if recoverable && !csrEnrollment {
		//log.Printf("[INFO] Recovering certificate with ID: %d", id)
		tflog.Info(context.Background(), fmt.Sprintf("Recovering certificate with ID: %d", id))
		//priv, leaf, chain, rErr := kfClient.RecoverCertificate(id, "", "", "", password)
		priv, leaf, chain, rErr := kfClient.RecoverCertificate(id, "", "", "", password, collectionId)
		if rErr != nil {
			return "", "", "", rErr
		}

		// Encode DER to PEM
		tflog.Debug(context.Background(), fmt.Sprintf("Encoding certificate to PEM for certificate ID: %d", id))
		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		tflog.Debug(context.Background(), fmt.Sprintf("Encoding chain to PEM for certificate ID: %d", id))
		for _, i := range chain {
			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})...)
		}
		//log.Printf("[DEBUG] Chain PEM: %s", chainPem)
		tflog.Debug(context.Background(), fmt.Sprintf("Encoding private key to PEM for certificate ID: %d", id))

		//log.Printf("[DEBUG] Private Key Type: %T", priv)
		tflog.Debug(context.Background(), fmt.Sprintf("Private Key Type: %T", priv))
		rsa, ok := priv.(*rsa2.PrivateKey)
		if ok {
			//log.Printf("[INFO] Private Key is RSA for certificate ID: %d", id)
			tflog.Debug(context.Background(), fmt.Sprintf("Attempting to parse RSA key for certificate ID: %d", id))
			buf := x509.MarshalPKCS1PrivateKey(rsa)
			if len(buf) > 0 {
				tflog.Debug(
					context.Background(),
					fmt.Sprintf("RSA Private Key successfully parsed for certificate ID: %d", id),
				)
				tflog.Debug(
					context.Background(),
					fmt.Sprintf("Attempting to encode RSA private key to PEM for certificate ID: %d", id),
				)
				privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "RSA PRIVATE KEY"})
			}
		}

		if privPem == nil {
			//log.Printf("[INFO] Private Key is not RSA for certificate ID: %d attempting to parse ECC key", id)
			tflog.Debug(
				context.Background(),
				fmt.Sprintf("Private Key is not RSA for certificate ID: %d attempting to parse ECC key", id),
			)
			ecc, ok := priv.(*ecdsa.PrivateKey)
			if ok {
				tflog.Debug(
					context.Background(),
					fmt.Sprintf("Attempting to parse ECDSA key for certificate ID: %d", id),
				)
				buf, _ := x509.MarshalECPrivateKey(ecc)
				if len(buf) > 0 {
					tflog.Debug(
						context.Background(),
						fmt.Sprintf("ECDSA Private Key successfully parsed for certificate ID: %d", id),
					)
					tflog.Debug(
						context.Background(),
						fmt.Sprintf("Attempting to encode ECDSA private key to PEM for certificate ID: %d", id),
					)
					privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "EC PRIVATE KEY"})
				}
			}
		}
	} else {
		//log.Printf("[INFO] Downloading certificate with ID: %d", id)
		tflog.Debug(context.Background(), fmt.Sprintf("Calling DownloadCertificate for certificate ID: %d", id))
		leaf, chain, dlErr := kfClient.DownloadCertificate(id, "", "", "")
		if dlErr != nil {
			//log.Printf("[ERROR] Error downloading certificate: %s", dlErr)
			tflog.Error(context.Background(), fmt.Sprintf("Error downloading certificate: %s", dlErr))
			return "", "", "", err
		}

		// Encode DER to PEM
		//log.Printf("[DEBUG] Encoding certificate to PEM")
		tflog.Debug(context.Background(), fmt.Sprintf("Encoding certificate to PEM for certificate ID: %d", id))
		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		tflog.Trace(context.Background(), fmt.Sprintf("Certificate PEM: %s", leafPem))
		//log.Printf("[DEBUG] Certificate PEM: %s", leafPem)
		//log.Printf("[DEBUG] Encoding chain to PEM")
		tflog.Debug(context.Background(), fmt.Sprintf("Encoding chain to PEM for certificate ID: %d", id))
		// iterate through chain in reverse order
		for i := len(chain) - 1; i >= 0; i-- {
			// check if current cert is the leaf cert
			if chain[i].SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				continue
			}
			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[i].Raw})...)
		}
		//log.Printf("[DEBUG] Chain PEM: %s", chainPem)
		tflog.Trace(context.Background(), fmt.Sprintf("Chain PEM: %s", chainPem))
	}

	tflog.Debug(context.Background(), fmt.Sprintf("Successfully downloaded certificate with ID: %d", id))
	return string(leafPem), string(chainPem), string(privPem), nil
}

func terraformBoolToGoBool(tfBool string) (bool, error) {
	tfBool = strings.ToLower(tfBool)
	if tfBool == "true" {
		return true, nil
	} else if tfBool == "false" {
		return false, nil
	}
	return false, fmt.Errorf("invalid Terraform bool: %s", tfBool)
}

func parseProperties(properties string) (types.Map, types.String, types.String, types.Bool, diag.Diagnostics) {
	var (
		serverUsername types.String
		serverPassword types.String
		//storePassword  types.String
		serverUseSsl types.Bool
		diags        diag.Diagnostics
	)
	propElems := make(map[string]attr.Value)
	propsObj := make(map[string]interface{})
	if properties != "" {
		//convert JSON string to map
		unescapedJSON, _ := unescapeJSON(properties)
		jsonErr := json.Unmarshal(unescapedJSON, &propsObj)
		if jsonErr != nil {
			diags.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				"Error reading certificate store: %s"+jsonErr.Error(),
			)
			return types.Map{}, types.String{Value: ""}, types.String{Value: ""}, types.Bool{Value: false}, diags
		}
	}

	for k, v := range propsObj {
		switch k {
		case "ServerUsername":
			serverUsername = types.String{Value: v.(string)}
		case "ServerPassword":
			serverPassword = types.String{Value: v.(string)}
		case "ServerUseSsl":
			// Convert terraform True/False to bool true/false
			val, valErr := terraformBoolToGoBool(v.(string))
			if valErr != nil {
				val = true // Default to true if we can't convert
			}
			serverUseSsl = types.Bool{Value: val}
		//case "StorePassword":
		//	storePassword = types.String{Value: v.(string)} //TODO: Command doesn't seem to return anything for this as of 10.x
		default:
			propElems[k] = types.String{Value: v.(string)}
		}
	}

	return types.Map{ElemType: types.StringType, Elems: propElems}, serverUsername, serverPassword, serverUseSsl, diags
}

func parseStorePassword(sPassword *api.StorePasswordConfig) types.String {
	if sPassword == nil {
		return types.String{Value: ""}
	} else {
		if sPassword.Value != nil {
			return types.String{Value: *sPassword.Value}
		} else {
			return types.String{Value: ""}
		}
	}
}

func isGUID(input string) bool {
	guidPattern := `^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$`
	match, _ := regexp.MatchString(guidPattern, input)
	return match
}

func isNullList(input types.List) bool {
	if input.Elems == nil || len(input.Elems) == 0 {
		return true
	}
	return false
}

func checkListNull(tfList types.List, apiResponseList []interface{}) bool {
	if tfList.IsNull() && len(apiResponseList) == 0 {
		return true
	}
	return false
}

func sortInSameOrder(unsortedList, sortedList []string) []string {
	// Sort unsortedList in the same order as sortedList
	// This is needed because the API returns the list in a different order than the order we sent it in
	// This is needed for the terraform import command to work
	var sorted []string

	//if lists are not the same length don't waste the effort and return unsortedList
	if len(unsortedList) != len(sortedList) {
		return unsortedList
	}

	for _, v := range sortedList {
		for _, u := range unsortedList {
			if v == u {
				sorted = append(sorted, u)
			}
		}
	}
	return sorted
}

func parseDuration(duration string) (int, error) {
	totalSeconds := 0

	// check if is an integer
	if i, err := strconv.Atoi(duration); err == nil {
		return i, nil
	}

	// Split the original duration string by digits and non-digits
	durationParts := strings.Split(duration, "h")
	if len(durationParts) > 1 {
		// Process hours
		hoursPart := durationParts[0]
		hours, err := strconv.Atoi(hoursPart)
		if err != nil {
			return 0, err
		}
		totalSeconds += hours * 3600
		duration = durationParts[1]
	} else {
		durationParts = strings.Split(duration, "m")
		if len(durationParts) > 1 {
			// Process minutes
			minutesPart := durationParts[0]
			minutes, err := strconv.Atoi(minutesPart)
			if err != nil {
				return 0, err
			}
			totalSeconds += minutes * 60
			duration = durationParts[1]
		}
	}

	// Process seconds
	if strings.Contains(duration, "s") {
		secondsPart := strings.TrimSuffix(duration, "s")
		seconds, err := strconv.Atoi(secondsPart)
		if err != nil {
			return 0, err
		}
		totalSeconds += seconds
	}

	return totalSeconds, nil
}
