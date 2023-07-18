package domain

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type InstallationTypeSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		it       InstallationType
		strValue string
	}
}

func (s *InstallationTypeSuite) SetupTest() {
	s.testCases = []struct {
		it       InstallationType
		strValue string
	}{
		{it: TypeCAPI, strValue: stringCAPI},
		{it: TypeJKS, strValue: stringJKS},
		{it: TypePEM, strValue: stringPEM},
		{it: TypePKCS12, strValue: stringPKCS12},
		{it: TypeUnknown, strValue: stringUnknown},
	}

	s.testYaml = `---
type: %s
location: "my/folder"
afterAction: "foo bar kwan"
`
}

func TestInstallationType(t *testing.T) {
	suite.Run(t, new(InstallationTypeSuite))
}

func (s *InstallationTypeSuite) TestInstallationType_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.it.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *InstallationTypeSuite) TestInstallationType_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.it.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *InstallationTypeSuite) TestInstallationType_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var i Installation
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &i)

			s.Nil(err)
			s.Equal(tc.it, i.Type)
		})
	}
}
