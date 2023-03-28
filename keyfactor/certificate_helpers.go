package keyfactor

import (
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"math/rand"
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
