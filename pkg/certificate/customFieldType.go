package certificate

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

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (cft CustomFieldType) MarshalYAML() (interface{}, error) {
	return cft.String(), nil
}
