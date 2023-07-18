package certrequest

import (
	"fmt"
	"testing"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type EllipticCurveSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		keyCurve   EllipticCurve
		strValue   string
		vcertValue vcert.EllipticCurve
	}
}

func (s *EllipticCurveSuite) SetupTest() {
	s.testCases = []struct {
		keyCurve   EllipticCurve
		strValue   string
		vcertValue vcert.EllipticCurve
	}{
		{keyCurve: EccP256, strValue: strEccP256, vcertValue: vcert.EllipticCurveP256},
		{keyCurve: EccP384, strValue: strEccP384, vcertValue: vcert.EllipticCurveP384},
		{keyCurve: EccP521, strValue: strEccP521, vcertValue: vcert.EllipticCurveP521},
		{keyCurve: EccED25519, strValue: strEccED25519, vcertValue: vcert.EllipticCurveED25519},
		{keyCurve: EccUnknown, strValue: strEccUnknown, vcertValue: vcert.EllipticCurveDefault},
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

func (s *EllipticCurveSuite) TestEllipticCurve_ToVCert() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			vcertEcc := tc.keyCurve.ToVCert()
			s.Equal(tc.vcertValue, vcertEcc)
		})
	}
}

func (s *EllipticCurveSuite) TestEllipticCurve_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var r Request
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &r)

			s.Nil(err)
			s.Equal(tc.keyCurve, r.KeyCurve)
		})
	}
}
