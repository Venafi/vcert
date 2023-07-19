package certificate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type ChainOptionSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		chainOption ChainOption
		strValue    string
	}
}

func (s *ChainOptionSuite) SetupTest() {
	s.testCases = []struct {
		chainOption ChainOption
		strValue    string
	}{
		{chainOption: ChainOptionIgnore, strValue: strChainOptionIgnore},
		{chainOption: ChainOptionRootFirst, strValue: strChainOptionRootFirst},
		{chainOption: ChainOptionRootLast, strValue: strChainOptionRootLast},
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

func (s *ChainOptionSuite) TestChainOption_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			result := struct {
				Cn          string      `yaml:"cn"`
				ChainOption ChainOption `yaml:"chainOption"`
			}{}

			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &result)

			s.Nil(err)
			s.Equal(tc.chainOption, result.ChainOption)
		})
	}
}
