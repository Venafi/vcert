package certrequest

import (
	"fmt"
	"testing"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type CustomFieldTypeSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		customFieldType CustomFieldType
		strValue        string
		vcertValue      vcert.CustomFieldType
	}
}

func (s *CustomFieldTypeSuite) SetupTest() {
	s.testCases = []struct {
		customFieldType CustomFieldType
		strValue        string
		vcertValue      vcert.CustomFieldType
	}{
		{customFieldType: CFTypePlain, strValue: strCFTypePlain, vcertValue: vcert.CustomFieldPlain},
		{customFieldType: CFTypeOrigin, strValue: strCFTypeOrigin, vcertValue: vcert.CustomFieldOrigin},
		{customFieldType: CFTypeUnknown, strValue: strCFTypeUnknown, vcertValue: vcert.CustomFieldPlain},
	}

	s.testYaml = `---
type: %s
name: foo
value: 123
`
}

func TestCustomFieldType(t *testing.T) {
	suite.Run(t, new(CustomFieldTypeSuite))
}

func (s *CustomFieldTypeSuite) TestCustomFieldType_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.customFieldType.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *CustomFieldTypeSuite) TestCustomFieldType_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.customFieldType.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *CustomFieldTypeSuite) TestCustomFieldType_ToVCert() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			vcertCft := tc.customFieldType.ToVCert()
			s.Equal(tc.vcertValue, vcertCft)
		})
	}
}

func (s *CustomFieldTypeSuite) TestCustomFieldType_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var cf CustomField
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &cf)

			s.Nil(err)
			s.Equal(tc.customFieldType, cf.Type)
		})
	}
}
