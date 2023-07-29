package certificate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type CSROriginSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		csrOrigin CSrOriginOption
		strValue  string
	}
}

func (s *CSROriginSuite) SetupTest() {
	s.testCases = []struct {
		csrOrigin CSrOriginOption
		strValue  string
	}{
		{csrOrigin: LocalGeneratedCSR, strValue: StrLocalGeneratedCSR},
		{csrOrigin: ServiceGeneratedCSR, strValue: StrServiceGeneratedCSR},
		{csrOrigin: UserProvidedCSR, strValue: StrUserProvidedCSR},
		{csrOrigin: UnknownCSR, strValue: strUnknownCSR},
	}

	s.testYaml = `---
cn: foobar
csrOrigin: %s
`
}

func TestCSROrigin(t *testing.T) {
	suite.Run(t, new(CSROriginSuite))
}

func (s *CSROriginSuite) TestCSROrigin_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.csrOrigin.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *CSROriginSuite) TestCSROrigin_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.csrOrigin.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *CSROriginSuite) TestCSROrigin_UnmarshalYAML() {

	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			result := struct {
				Cn        string          `yaml:"cn"`
				CsrOrigin CSrOriginOption `yaml:"csrOrigin"`
			}{}
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &result)

			s.Nil(err)
			s.Equal(tc.csrOrigin, result.CsrOrigin)
		})
	}
}
