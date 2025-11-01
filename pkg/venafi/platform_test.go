/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package venafi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type PlatformSuite struct {
	suite.Suite
	testYaml  string
	testCases []struct {
		ct       Platform
		strValue string
	}
}

func (s *PlatformSuite) SetupTest() {
	s.testCases = []struct {
		ct       Platform
		strValue string
	}{
		{ct: Undefined, strValue: strPlatformUnknown},
		{ct: TPP, strValue: strPlatformTPP},
		{ct: TLSPCloud, strValue: strPlatformVaaS},
		{ct: Firefly, strValue: strPlatformFirefly},
	}

	s.testYaml = `---
platform: %s
url: https://something.com
`
}

func TestConnectionType(t *testing.T) {
	suite.Run(t, new(PlatformSuite))
}

func (s *PlatformSuite) TestConnectionType_MarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			data, err := tc.ct.MarshalYAML()
			s.Nil(err)
			s.Equal(tc.strValue, data.(string))
		})
	}
}

func (s *PlatformSuite) TestConnectionType_String() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			str := tc.ct.String()
			s.Equal(tc.strValue, str)
		})
	}
}

func (s *PlatformSuite) TestConnectionType_UnmarshalYAML() {
	for _, tc := range s.testCases {
		s.Run(tc.strValue, func() {
			var c struct {
				Platform Platform `yaml:"platform,omitempty"`
				Url      string   `yaml:"url,omitempty"`
			}
			parsedYaml := fmt.Sprintf(s.testYaml, tc.strValue)
			err := yaml.Unmarshal([]byte(parsedYaml), &c)

			s.Nil(err)
			s.Equal(tc.ct, c.Platform)
		})
	}
}
