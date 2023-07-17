package certrequest

import (
	"strings"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"gopkg.in/yaml.v3"
)

// CustomFieldType represents the different types a CustomField can be
type CustomFieldType int

const (
	// CFTypeUnknown represents an invalid option
	CFTypeUnknown CustomFieldType = iota
	// CFTypePlain represents an ordinary CustomField
	CFTypePlain
	// CFTypeOrigin represents a CustomField of type Origin
	CFTypeOrigin

	// String representations of the CustomFieldType types
	strCFTypeOrigin  = "origin"
	strCFTypePlain   = "plain"
	strCFTypeUnknown = "unknown"
)

// String returns a string representation of this object
func (cft *CustomFieldType) String() string {
	switch *cft {
	case CFTypeOrigin:
		return strCFTypeOrigin
	case CFTypePlain:
		return strCFTypePlain
	default:
		return strCFTypeUnknown
	}
}

func parseCustomFieldType(value string) (CustomFieldType, error) {
	switch strings.ToLower(value) {
	case strCFTypeOrigin:
		return CFTypeOrigin, nil
	case strCFTypePlain:
		return CFTypePlain, nil
	default:
		return CFTypeUnknown, nil
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (cft CustomFieldType) MarshalYAML() (interface{}, error) {
	return cft.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (cft *CustomFieldType) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*cft, err = parseCustomFieldType(strValue)
	if err != nil {
		return err
	}
	return nil
}

// ToVCert returns the representation in vcert of this value
func (cft *CustomFieldType) ToVCert() vcert.CustomFieldType {
	switch *cft {
	case CFTypeOrigin:
		return vcert.CustomFieldOrigin
	case CFTypePlain:
		return vcert.CustomFieldPlain
	default:
		return vcert.CustomFieldPlain
	}
}
