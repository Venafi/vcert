package certificate

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type CustomFieldTypeSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		customFieldType CustomFieldType
		strValue        string
		vcertValue      CustomFieldType
	}
}

func (s *CustomFieldTypeSuite) SetupTest() {
	s.testCases = []struct {
		customFieldType CustomFieldType
		strValue        string
		vcertValue      CustomFieldType
	}{
		{customFieldType: CustomFieldPlain, strValue: strCFTypePlain},
		{customFieldType: CustomFieldOrigin, strValue: strCFTypeOrigin},
		{customFieldType: CustomFieldUnknown, strValue: strCFTypeUnknown},
	}

	s.testYaml = `---
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
