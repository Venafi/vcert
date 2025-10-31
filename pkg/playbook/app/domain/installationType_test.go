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
		it       InstallationFormat
		strValue string
	}
}

func (s *InstallationTypeSuite) SetupTest() {
	s.testCases = []struct {
		it       InstallationFormat
		strValue string
	}{
		{it: FormatCAPI, strValue: stringCAPI},
		{it: FormatJKS, strValue: stringJKS},
		{it: FormatPEM, strValue: stringPEM},
		{it: FormatPKCS12, strValue: stringPKCS12},
		{it: FormatUnknown, strValue: stringUnknown},
	}

	s.testYaml = `---
format: %s
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
