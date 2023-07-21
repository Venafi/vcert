package certificate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type KeyTypeSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		keyType  KeyType
		strValue string
	}
}

func (s *KeyTypeSuite) SetupTest() {
	s.testCases = []struct {
		keyType  KeyType
		strValue string
	}{
		{keyType: KeyTypeECDSA, strValue: strKeyTypeECDSA},
		{keyType: KeyTypeRSA, strValue: strKeyTypeRSA},
		{keyType: KeyTypeED25519, strValue: strKeyTypeED25519},
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

func (s *KeyTypeSuite) TestEllipticCurve_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			result := struct {
				Cn      string  `yaml:"cn"`
				KeyType KeyType `yaml:"keyType"`
			}{}
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &result)

			s.Nil(err)
			s.Equal(tc.keyType, result.KeyType)
		})
	}
}
