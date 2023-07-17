package certrequest

import (
	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
)

// CustomField can be used for adding additional information to certificate. For example: custom fields or Origin.
// By default, it's custom field. For adding Origin set Type: CFTypeOrigin
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

// ToVCert returns the representation in vcert of this value
func (cf *CustomField) ToVCert() vcert.CustomField {
	return vcert.CustomField{
		Type:  cf.Type.ToVCert(),
		Name:  cf.Name,
		Value: cf.Value,
	}
}

// CustomFields represents an array of CustomField objects
type CustomFields []CustomField

// ToVCert returns the representation in vcert of this value
func (cfs *CustomFields) ToVCert() []vcert.CustomField {
	if len(*cfs) == 0 {
		return nil
	}

	vcf := make([]vcert.CustomField, 0)
	for _, cf := range *cfs {
		vcf = append(vcf, cf.ToVCert())
	}

	return vcf
}
