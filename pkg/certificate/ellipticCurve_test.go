package certificate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type EllipticCurveSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		keyCurve EllipticCurve
		strValue string
	}
}

func (s *EllipticCurveSuite) SetupTest() {
	s.testCases = []struct {
		keyCurve EllipticCurve
		strValue string
	}{
		{keyCurve: EllipticCurveP256, strValue: strEccP256},
		{keyCurve: EllipticCurveP384, strValue: strEccP384},
		{keyCurve: EllipticCurveP521, strValue: strEccP521},
		{keyCurve: EllipticCurveED25519, strValue: strEccED25519},
	}

	s.testYaml = `---
cn: foobar
keyCurve: %s
`
}

func TestEllipticCurve(t *testing.T) {
	suite.Run(t, new(EllipticCurveSuite))
}

func (s *EllipticCurveSuite) TestEllipticCurve_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.keyCurve.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *EllipticCurveSuite) TestEllipticCurve_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.keyCurve.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *EllipticCurveSuite) TestEllipticCurve_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			result := struct {
				Cn       string        `yaml:"cn"`
				KeyCurve EllipticCurve `yaml:"keyCurve"`
			}{}
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &result)

			s.Nil(err)
			s.Equal(tc.keyCurve, result.KeyCurve)
		})
	}
}
