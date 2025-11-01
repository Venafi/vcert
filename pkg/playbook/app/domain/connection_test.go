/*
 * Copyright 2023 Venafi, Inc.
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

	"github.com/Venafi/vcert/v5/pkg/venafi"
	"github.com/stretchr/testify/suite"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

type ConnectionSuite struct {
	suite.Suite
	testCases []struct {
		name          string
		c             Connection
		expectedCType endpoint.ConnectorType
		expectedValid bool
		expectedErr   error
	}
}

func (s *ConnectionSuite) SetupTest() {
	s.testCases = []struct {
		name          string
		c             Connection
		expectedCType endpoint.ConnectorType
		expectedValid bool
		expectedErr   error
	}{
		// FIREFLY USE CASES
		{
			name: "Firefly_valid_secret",
			c: Connection{
				Platform: venafi.Firefly,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						ClientSecret: "mySecret",
						ClientId:     "myClientID",
						IdentityProvider: &endpoint.OAuthProvider{
							TokenURL: "https://my.okta.instance.com/token",
						},
					},
				},
				URL: "https://my.firefly.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: true,
		},
		{
			name: "Firefly_valid_password",
			c: Connection{
				Platform: venafi.Firefly,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						User:     "myUser",
						Password: "myPassword",
						ClientId: "myClientID",
						IdentityProvider: &endpoint.OAuthProvider{
							TokenURL: "https://my.okta.instance.com/token",
						},
					},
				},
				URL: "https://my.firefly.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: true,
		},
		{
			name: "Firefly_valid_token",
			c: Connection{
				Platform: venafi.Firefly,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						AccessToken: "foo123Token",
					},
				},
				URL: "https://my.firefly.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: true,
		},
		{
			name: "Firefly_invalid_no_url",
			c: Connection{
				Platform:    venafi.Firefly,
				Credentials: Authentication{},
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: false,
			expectedErr:   ErrNoFireflyURL,
		},
		{
			name: "Firefly_invalid_empty_credentials",
			c: Connection{
				Platform:    venafi.Firefly,
				Credentials: Authentication{},
				URL:         "https://my.firefly.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: false,
			expectedErr:   ErrNoCredentials,
		},
		{
			name: "Firefly_invalid_no_clientID",
			c: Connection{
				Platform: venafi.Firefly,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						ClientSecret: "mySecret",
					},
				},
				URL: "https://my.firefly.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: false,
			expectedErr:   ErrNoClientId,
		},
		{
			name: "Firefly_invalid_no_IdP",
			c: Connection{
				Platform: venafi.Firefly,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						ClientSecret: "mySecret",
						ClientId:     "myClientID",
					},
				},
				URL: "https://my.firefly.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeFirefly,
			expectedValid: false,
			expectedErr:   ErrNoIdentityProviderURL,
		},
		// CyberArk Certificate Manager, Self-Hosted USE CASES
		{
			name: "TPP_valid",
			c: Connection{
				Platform: venafi.TPP,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						AccessToken: "123abc###",
					},
				},
				URL:             "https://my.tpp.instance.com",
				TrustBundlePath: "",
				Insecure:        false,
			},
			expectedCType: endpoint.ConnectorTypeTPP,
			expectedValid: true,
		},
		{
			name: "TPP_invalid_empty_credentials",
			c: Connection{
				Platform:    venafi.TPP,
				Credentials: Authentication{},
				URL:         "https://my.tpp.instance.com",
			},
			expectedCType: endpoint.ConnectorTypeTPP,
			expectedValid: false,
			expectedErr:   ErrNoCredentials,
		},
		{
			name: "TPP_invalid_no_url",
			c: Connection{
				Platform: venafi.TPP,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						AccessToken: "123abc###",
					},
				},
			},
			expectedCType: endpoint.ConnectorTypeTPP,
			expectedValid: false,
			expectedErr:   ErrNoTPPURL,
		},
		{
			name: "TPP_invalid_trustbundle_not_exist",
			c: Connection{
				Platform: venafi.TPP,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						AccessToken: "123abc###",
					},
				},
				URL:             "https://my.tpp.instance.com",
				TrustBundlePath: "/foo/bar/trustbundle.pem",
			},
			expectedCType: endpoint.ConnectorTypeTPP,
			expectedValid: false,
			expectedErr:   ErrTrustBundleNotExist,
		},
		// CyberArk Certificate Manager, SaaS USE CASES
		{
			name: "VaaS_valid",
			c: Connection{
				Platform: venafi.TLSPCloud,
				Credentials: Authentication{
					Authentication: endpoint.Authentication{
						APIKey: "xxx-XXX-xxx",
					},
				},
			},
			expectedCType: endpoint.ConnectorTypeCloud,
			expectedValid: true,
		},
		{
			name: "VaaS_invalid_empty_credentials",
			c: Connection{
				Platform:    venafi.TLSPCloud,
				Credentials: Authentication{},
			},
			expectedCType: endpoint.ConnectorTypeCloud,
			expectedValid: false,
			expectedErr:   ErrNoCredentials,
		},
		// UNKNOWN USE CASES
		{
			name: "Unknown_invalid",
			c: Connection{
				Platform: venafi.Undefined,
			},
			expectedCType: endpoint.ConnectorTypeFake,
			expectedValid: false,
			expectedErr:   fmt.Errorf("invalid connection type %v", venafi.Undefined),
		},
	}
}

func TestConnection(t *testing.T) {
	suite.Run(t, new(ConnectionSuite))
}

func (s *ConnectionSuite) TestConnection_GetConnectorType() {
	for _, tc := range s.testCases {
		s.Run(tc.name, func() {
			currentType := tc.c.GetConnectorType()
			s.Equal(tc.expectedCType, currentType)
		})
	}
}

func (s *ConnectionSuite) TestConnection_IsValid() {
	for _, tc := range s.testCases {
		s.Run(tc.name, func() {
			result, err := tc.c.IsValid()
			s.Equal(tc.expectedValid, result)

			if tc.expectedValid {
				s.Nil(err)
			} else {
				s.NotNil(err)
				s.Error(err)
				s.Contains(err.Error(), tc.expectedErr.Error())
			}
		})
	}
}
