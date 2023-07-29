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

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/stretchr/testify/suite"
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
		//TODO: Update this test once vcert supports Firefly
		{
			name: "Firefly_valid",
			c: Connection{
				Platform: CTypeFirefly,
				Credentials: Authentication{
					Apikey: "asdasdadsd",
				},
			},
			expectedCType: endpoint.ConnectorTypeFake,
			expectedValid: true,
		},
		{
			name: "Firefly_invalid_empty_credentials",
			c: Connection{
				Platform:    CTypeFirefly,
				Credentials: Authentication{},
			},
			expectedCType: endpoint.ConnectorTypeFake,
			expectedValid: false,
			expectedErr:   ErrNoCredentials,
		},
		{
			name: "TPP_valid",
			c: Connection{
				Platform: CTypeTPP,
				Credentials: Authentication{
					AccessToken: "123abc###",
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
				Platform:    CTypeTPP,
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
				Platform: CTypeTPP,
				Credentials: Authentication{
					AccessToken: "123abc###",
				},
			},
			expectedCType: endpoint.ConnectorTypeTPP,
			expectedValid: false,
			expectedErr:   ErrNoTPPURL,
		},
		{
			name: "TPP_invalid_trustbundle_not_exist",
			c: Connection{
				Platform: CTypeTPP,
				Credentials: Authentication{
					AccessToken: "123abc###",
				},
				URL:             "https://my.tpp.instance.com",
				TrustBundlePath: "/foo/bar/trustbundle.pem",
			},
			expectedCType: endpoint.ConnectorTypeTPP,
			expectedValid: false,
			expectedErr:   ErrTrustBundleNotExist,
		},
		{
			name: "VaaS_valid",
			c: Connection{
				Platform: CTypeVaaS,
				Credentials: Authentication{
					Apikey: "xxx-XXX-xxx",
				},
			},
			expectedCType: endpoint.ConnectorTypeCloud,
			expectedValid: true,
		},
		{
			name: "VaaS_invalid_empty_credentials",
			c: Connection{
				Platform:    CTypeVaaS,
				Credentials: Authentication{},
			},
			expectedCType: endpoint.ConnectorTypeCloud,
			expectedValid: false,
			expectedErr:   ErrNoCredentials,
		},
		{
			name: "Unknown_invalid",
			c: Connection{
				Platform: CTypeUnknown,
			},
			expectedCType: endpoint.ConnectorTypeFake,
			expectedValid: false,
			expectedErr:   fmt.Errorf("invalid connection type %v", CTypeUnknown),
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
