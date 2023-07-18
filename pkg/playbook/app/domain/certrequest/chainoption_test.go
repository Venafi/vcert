package certrequest

import (
	"fmt"
	"testing"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type ChainOptionSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		chainOption ChainOption
		strValue    string
		vcertValue  vcert.ChainOption
	}
}

func (s *ChainOptionSuite) SetupTest() {
	s.testCases = []struct {
		chainOption ChainOption
		strValue    string
		vcertValue  vcert.ChainOption
	}{
		{chainOption: ChainOptionIgnore, strValue: strChainOptionIgnore, vcertValue: vcert.ChainOptionIgnore},
		{chainOption: ChainOptionRootFirst, strValue: strChainOptionRootFirst, vcertValue: vcert.ChainOptionRootFirst},
		{chainOption: ChainOptionRootLast, strValue: strChainOptionRootLast, vcertValue: vcert.ChainOptionRootLast},
		{chainOption: ChainOptionUnknown, strValue: strChainOptionUnknown, vcertValue: vcert.ChainOptionRootLast},
	}

	s.testYaml = `---
cn: foobar
chainOption: %s
`
}

func TestChainOption(t *testing.T) {
	suite.Run(t, new(ChainOptionSuite))
}

func (s *ChainOptionSuite) TestChainOption_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.chainOption.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *ChainOptionSuite) TestChainOption_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.chainOption.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *ChainOptionSuite) TestChainOption_ToVCert() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			vcertCo := tc.chainOption.ToVCert()
			s.Equal(tc.vcertValue, vcertCo)
		})
	}
}

func (s *ChainOptionSuite) TestChainOption_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var r Request
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &r)

			s.Nil(err)
			s.Equal(tc.chainOption, r.ChainOption)
		})
	}
}
