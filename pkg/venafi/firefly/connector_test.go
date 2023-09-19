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

package firefly

import (
	"fmt"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ConnectorSuite struct {
	suite.Suite
	idpServer *IdentityProviderServer
}

func (s *ConnectorSuite) SetupSuite() {
	fmt.Println("mocking server")
	s.idpServer = newIdentityProviderServer()
}

func (s *ConnectorSuite) createCredFlowAuth() *endpoint.Authentication {
	return &endpoint.Authentication{
		Scope:        TestingScope,
		ClientId:     TestingClientID,
		ClientSecret: TestingClientSecret,
		IdentityProvider: &endpoint.OAuthProvider{
			TokenURL: s.idpServer.idpURL + s.idpServer.tokenPath,
			Audience: TestingAudience,
		},
	}
}

func (s *ConnectorSuite) createPasswordFlowAuth() *endpoint.Authentication {
	return &endpoint.Authentication{
		User:     TestingUserName,
		Password: TestingUserPassword,
		Scope:    TestingScope,
		ClientId: TestingClientID,
		IdentityProvider: &endpoint.OAuthProvider{
			TokenURL: s.idpServer.idpURL + s.idpServer.tokenPath,
			Audience: TestingAudience,
		},
	}
}

func (s *ConnectorSuite) createDevFlowAuth() *endpoint.Authentication {
	return &endpoint.Authentication{
		Scope:    TestingScope,
		ClientId: TestingClientID,
		IdentityProvider: &endpoint.OAuthProvider{
			DeviceURL: s.idpServer.idpURL + s.idpServer.devicePath,
			TokenURL:  s.idpServer.idpURL + s.idpServer.tokenPath,
			Audience:  TestingAudience,
		},
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestConnectorSuite(t *testing.T) {
	suite.Run(t, new(ConnectorSuite))
}

func (s *ConnectorSuite) TestNewConnector() {

	s.Run("Success", func() {
		fireflyConnector, err := NewConnector("my.firefly:8080", "", false, nil)

		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), fireflyConnector)
		assert.Equal(s.T(), "https://my.firefly:8080/", fireflyConnector.baseURL)
	})
}

func (s *ConnectorSuite) TestGetType() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())
	assert.Equal(s.T(), endpoint.ConnectorTypeFirefly, fireflyConnector.GetType())
}

func (s *ConnectorSuite) TestAuthenticate() {
	s.Run("AuthenticationConfNotProvided", func() {
		fireflyConnector, err := NewConnector("", "", false, nil)
		assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

		err = fireflyConnector.Authenticate(nil)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the access_token") {
			assert.Equal(s.T(), "failed to authenticate: no credentials provided", err.Error())
		}
		assert.Equal(s.T(), "", fireflyConnector.accessToken)
	})

	s.Run("Success", func() {
		fireflyConnector, err := NewConnector("", "", false, nil)
		assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

		err = fireflyConnector.Authenticate(s.createCredFlowAuth())

		assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
		assert.NotNil(s.T(), fireflyConnector.accessToken)
	})
}

func (s *ConnectorSuite) TestClientCredentialFlow() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	oauthToken, err := fireflyConnector.Authorize(s.createCredFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestClientCredentialFlow_Unauthorized() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	auth := s.createCredFlowAuth()
	//changing the clientId
	auth.ClientId = "unauthorized"

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.NotNil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestClientPasswordFlow() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	oauthToken, err := fireflyConnector.Authorize(s.createPasswordFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestClientPasswordFlow_Unauthorized() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	auth := s.createPasswordFlowAuth()
	auth.ClientId = "unauthorized"

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.NotNil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	oauthToken, err := fireflyConnector.Authorize(s.createDevFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_AuthPending() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDAuthPending

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_SlowDown() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDSlowDown

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_AccessDenied() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDAccessDenied

	oauthToken, err := fireflyConnector.Authorize(auth)

	if assert.Errorf(s.T(), err, "expected to get an error but was gotten the access_token") {
		assert.Equal(s.T(), "vcert error: your data contains problems: auth error: the access from device was denied by the user", err.Error())
	}
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_ExpiredToken() {
	fireflyConnector, err := NewConnector("", "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDExpiredToken

	oauthToken, err := fireflyConnector.Authorize(auth)

	if assert.Errorf(s.T(), err, "expected to get an error but was gotten the access_token") {
		assert.Equal(s.T(), "vcert error: your data contains problems: auth error: the device code expired", err.Error())
	}
	assert.Nil(s.T(), oauthToken)
}
