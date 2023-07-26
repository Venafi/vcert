package certificate

// CustomField can be used for adding additional information to certificate. For example: custom fields or Origin.
// By default it's custom field. For adding Origin set Type: CustomFieldOrigin
// For adding custom field with one name and few values give to request:
//
//	request.CustomFields = []CustomField{
//	  {Name: "name1", Value: "value1"}
//	  {Name: "name1", Value: "value2"}
//	}
type CustomField struct {
	Type  CustomFieldType `yaml:"type"`
	Name  string          `yaml:"name"`
	Value string          `yaml:"value"`
}
