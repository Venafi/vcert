package certificate

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type CustomFieldType int

const (
	CustomFieldPlain CustomFieldType = 0 + iota
	CustomFieldOrigin
	CustomFieldUnknown

	// String representations of the CustomFieldType types
	strCFTypeOrigin  = "origin"
	strCFTypePlain   = "plain"
	strCFTypeUnknown = "unknown"
)

// String returns a string representation of this object
func (cft *CustomFieldType) String() string {
	switch *cft {
	case CustomFieldOrigin:
		return strCFTypeOrigin
	case CustomFieldPlain:
		return strCFTypePlain
	default:
		return strCFTypeUnknown
	}
}

func parseCustomFieldType(value string) CustomFieldType {
	switch strings.ToLower(value) {
	case strCFTypeOrigin:
		return CustomFieldOrigin
	case strCFTypePlain:
		return CustomFieldPlain
	default:
		return CustomFieldUnknown
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

	*cft = parseCustomFieldType(strValue)

	return nil
}
