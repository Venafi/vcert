package certificate

// CustomField can be used for adding additional information to certificate. For example: custom fields or Origin.
// By default, Type is CustomFieldPlain. For adding Origin set Type: CustomFieldOrigin
// For adding multiple values to a single custom field:
//
//	request.CustomFields = []CustomField{
//	  {Name: "name1", Value: "value1"}
//	  {Name: "name1", Value: "value2"}
//	}
type CustomField struct {
	Type  CustomFieldType `yaml:"-"`
	Name  string          `yaml:"name"`
	Value string          `yaml:"value"`
}
