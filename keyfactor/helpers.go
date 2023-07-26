package keyfactor

import (
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"math/rand"
	"regexp"
	"strconv"
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

func expandSubject(subject string) (types.String, types.String, types.String, types.String, types.String, types.String) {
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
	return result
}

func flattenSANs(sans []api.SubjectAltNameElements) (types.List, types.List, types.List) {
	sanIP4Array := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	sanDNSArray := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	sanURIArray := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	if len(sans) > 0 {
		for _, san := range sans {
			sanName := mapSanIDToName(san.Type)
			if sanName == "IP Address" {
				sanIP4Array.Elems = append(sanIP4Array.Elems, types.String{Value: san.Value})
			} else if sanName == "DNS Name" {
				sanDNSArray.Elems = append(sanDNSArray.Elems, types.String{Value: san.Value})
			} else if sanName == "Uniform Resource Identifier" {
				sanURIArray.Elems = append(sanURIArray.Elems, types.String{Value: san.Value})
			}
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
			options = append(options, types.String{
				Value: op,
			})
		}
		result.Elems = append(result.Elems, types.Map{
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
		})
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

func downloadCertificate(id int, kfClient *api.Client, password string, csrEnrollment bool) (string, string, string, error) {
	certificateContext, err := kfClient.GetCertificateContext(&api.GetCertificateContextArgs{Id: id})
	if err != nil {
		return "", "", "", err
	}

	template, err := kfClient.GetTemplate(certificateContext.TemplateId)
	if err != nil {
		return "", "", "", err
	}

	recoverable := false

	if template.KeyRetention != "None" {
		recoverable = true
	}

	var privPem []byte
	var leafPem []byte
	var chainPem []byte

	if !recoverable || csrEnrollment {

		leaf, chain, err := kfClient.DownloadCertificate(id, "", "", "")
		if err != nil {
			return "", "", "", err
		}

		// Encode DER to PEM
		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		for _, i := range chain {
			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})...)
		}

	} else {

		priv, leaf, chain, err := kfClient.RecoverCertificate(id, "", "", "", password)
		if err != nil {
			return "", "", "", err
		}
		if err != nil {
			return "", "", "", err
		}

		// Encode DER to PEM
		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		for _, i := range chain {
			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})...)
		}

		// Figure out the format of the private key, then encode it to PEM
		rsa, ok := priv.(*rsa2.PrivateKey)
		if ok {
			buf := x509.MarshalPKCS1PrivateKey(rsa)
			if len(buf) > 0 {
				privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "RSA PRIVATE KEY"})
			}
		}

		ecc, ok := priv.(*ecdsa.PrivateKey)
		if ok {
			// We don't really care about the error here. An error just means that the key will be blank which isn't a
			// reason to fail
			buf, _ := x509.MarshalECPrivateKey(ecc)
			if len(buf) > 0 {
				privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "EC PRIVATE KEY"})
			}
		}
	}

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
				"Error reading certificate store",
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
