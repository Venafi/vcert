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
	"testing"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

const examplePlaybook = `certificateTasks:
    - name: foo
config:
    connection:
        credentials:
            accessToken: "123456"
            apiKey: xyz789
            clientId: clientID
            clientSecret: clientSecret
            externalJWT: tokenJWT
            idP:
                audience: some audience
                tokenURL: some.token.url
            p12Task: foo
            refreshToken: abcdef
            scope: noScope
            tokenURL: venafi.com/tokenurl
        insecure: true
        platform: VAAS
        trustBundle: some/path.txt
        url: foo.bar.com
`

type AuthenticationSuite struct {
	suite.Suite
}

func (s *AuthenticationSuite) SetupTest() {}

func TestAuthentication(t *testing.T) {
	suite.Run(t, new(AuthenticationSuite))
}

func (s *AuthenticationSuite) TestAuthentication_MarshalIdentityProvider() {
	p := Playbook{
		CertificateTasks: CertificateTasks{
			CertificateTask{
				Name: "foo",
			},
		},
		Config: Config{
			Connection: Connection{
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						AccessToken:  "123456",
						RefreshToken: "abcdef",
						APIKey:       "xyz789",
						ExternalJWT:  "tokenJWT",
						ClientId:     "clientID",
						ClientSecret: "clientSecret",
						Scope:        "noScope",
						TokenURL:     "venafi.com/tokenurl",
						IdentityProvider: &endpoint.OAuthProvider{
							TokenURL: "some.token.url",
							Audience: "some audience",
						},
					},
					P12Task: "foo",
				},
				Insecure:        true,
				Platform:        venafi.TLSPCloud,
				TrustBundlePath: "some/path.txt",
				URL:             "foo.bar.com",
			},
		},
	}

	data, err := yaml.Marshal(p)
	s.NoError(err)
	s.NotNil(data)
	s.Equal([]byte(examplePlaybook), data)
}

func (s *AuthenticationSuite) TestAuthentication_UnmarshalIdentityProvider() {
	playbook := NewPlaybook()
	err := yaml.Unmarshal([]byte(examplePlaybook), &playbook)
	s.NoError(err)
	s.Equal(1, len(playbook.CertificateTasks))
	s.Equal("foo", playbook.CertificateTasks[0].Name)

	s.NotNil(playbook.Config.Connection)
	s.True(playbook.Config.Connection.Insecure)
	s.Equal(venafi.TLSPCloud, playbook.Config.Connection.Platform)
	s.Equal("some/path.txt", playbook.Config.Connection.TrustBundlePath)
	s.Equal("foo.bar.com", playbook.Config.Connection.URL)

	s.NotNil(playbook.Config.Connection.Credentials)
	s.Equal("foo", playbook.Config.Connection.Credentials.P12Task)
	s.Equal("123456", playbook.Config.Connection.Credentials.AccessToken)
	s.Equal("abcdef", playbook.Config.Connection.Credentials.RefreshToken)
	s.Equal("xyz789", playbook.Config.Connection.Credentials.APIKey)
	s.Equal("tokenJWT", playbook.Config.Connection.Credentials.ExternalJWT)
	s.Equal("venafi.com/tokenurl", playbook.Config.Connection.Credentials.TokenURL)
	s.Equal("clientID", playbook.Config.Connection.Credentials.ClientId)
	s.Equal("clientSecret", playbook.Config.Connection.Credentials.ClientSecret)
	s.Equal("noScope", playbook.Config.Connection.Credentials.Scope)
	s.NotNil(playbook.Config.Connection.Credentials.IdentityProvider)
	s.Equal("some.token.url", playbook.Config.Connection.Credentials.IdentityProvider.TokenURL)
	s.Equal("some audience", playbook.Config.Connection.Credentials.IdentityProvider.Audience)
}
