package certrequest

import (
	"fmt"
	"testing"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type CSROriginSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		csrOrigin  CsrOriginOption
		strValue   string
		vcertValue vcert.CSrOriginOption
	}
}

func (s *CSROriginSuite) SetupTest() {
	s.testCases = []struct {
		csrOrigin  CsrOriginOption
		strValue   string
		vcertValue vcert.CSrOriginOption
	}{
		{csrOrigin: CSRLocalGenerated, strValue: strCSRLocalGenerated, vcertValue: vcert.LocalGeneratedCSR},
		{csrOrigin: CSRServiceGenerated, strValue: strCSRServiceGenerated, vcertValue: vcert.ServiceGeneratedCSR},
		{csrOrigin: CSRUserProvided, strValue: strCSRUserProvided, vcertValue: vcert.UserProvidedCSR},
		{csrOrigin: CSRUnknown, strValue: strCSRUnknown, vcertValue: vcert.ServiceGeneratedCSR},
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

func (s *CSROriginSuite) TestCSROrigin_ToVCert() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			vcertCsro := tc.csrOrigin.ToVCert()
			s.Equal(tc.vcertValue, vcertCsro)
		})
	}
}

func (s *CSROriginSuite) TestCSROrigin_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var r Request
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &r)

			s.Nil(err)
			s.Equal(tc.csrOrigin, r.CsrOrigin)
		})
	}
}
