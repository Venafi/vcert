package certrequest

import (
	"fmt"
	"testing"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type KeyTypeSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		keyType    KeyType
		strValue   string
		vcertValue vcert.KeyType
	}
}

func (s *KeyTypeSuite) SetupTest() {
	s.testCases = []struct {
		keyType    KeyType
		strValue   string
		vcertValue vcert.KeyType
	}{
		{keyType: KeyTypeECDSA, strValue: strKeyTypeECDSA, vcertValue: vcert.KeyTypeECDSA},
		{keyType: KeyTypeRSA, strValue: strKeyTypeRSA, vcertValue: vcert.KeyTypeRSA},
		{keyType: KeyTypeUnknown, strValue: strKeyTypeUnknown, vcertValue: vcert.KeyTypeRSA},
	}

	s.testYaml = `---
cn: foobar
keyType: %s
`
}

func TestKeyType(t *testing.T) {
	suite.Run(t, new(KeyTypeSuite))
}

func (s *KeyTypeSuite) TestKeyType_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.keyType.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *KeyTypeSuite) TestKeyType_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.keyType.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *KeyTypeSuite) TestEllipticCurve_ToVCert() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			vcertEcc := tc.keyType.ToVCert()
			s.Equal(tc.vcertValue, vcertEcc)
		})
	}
}

func (s *KeyTypeSuite) TestEllipticCurve_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var r Request
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &r)

			s.Nil(err)
			s.Equal(tc.keyType, r.KeyType)
		})
	}
}
