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

	"gopkg.in/yaml.v3"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const (
	accessToken  = "accessToken"
	apiKey       = "apiKey"
	clientID     = "clientId"
	clientSecret = "clientSecret"
	refreshToken = "refreshToken"
	p12Task      = "p12Task"
	scope        = "scope"
	idPTokenURL  = "tokenURL"
	idPAudience  = "audience"
)

// Authentication holds the credentials to connect to Venafi platforms: TPP and TLSPC
type Authentication struct {
	endpoint.Authentication `yaml:"-"`
	P12Task                 string `yaml:"p12Task,omitempty"`
}

// IsEmpty returns true if not credentials are set
func (a Authentication) IsEmpty() bool {
	// TODO: This is very hacky.. need specifics based on connection type
	if a.APIKey == "" && a.AccessToken == "" && a.RefreshToken == "" && a.P12Task == "" {
		return true
	}
	return false
}

// MarshalYAML customizes the behavior of Authentication when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (a Authentication) MarshalYAML() (interface{}, error) {
	values := make(map[string]interface{})

	if a.AccessToken != "" {
		values[accessToken] = a.AccessToken
	}
	if a.APIKey != "" {
		values[apiKey] = a.APIKey
	}
	if a.ClientId != "" {
		values[clientID] = a.ClientId
	}
	if a.ClientSecret != "" {
		values[clientSecret] = a.ClientSecret
	}
	if a.IdentityProvider != nil {
		if a.IdentityProvider.TokenURL != "" {
			values[idPTokenURL] = a.IdentityProvider.TokenURL
		}
		if a.IdentityProvider.Audience != "" {
			values[idPAudience] = a.IdentityProvider.Audience
		}
		//values[idP] = a.IdentityProvider
	}
	if a.RefreshToken != "" {
		values[refreshToken] = a.RefreshToken
	}
	if a.P12Task != "" {
		values[p12Task] = a.P12Task
	}
	if a.Scope != "" {
		values[scope] = a.Scope
	}

	return values, nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (a *Authentication) UnmarshalYAML(value *yaml.Node) error {
	var authMap map[string]interface{}
	err := value.Decode(&authMap)
	if err != nil {
		return err
	}

	if val, found := authMap[accessToken]; found {
		a.AccessToken = val.(string)
	}
	if val, found := authMap[apiKey]; found {
		a.APIKey = val.(string)
	}
	if val, found := authMap[clientID]; found {
		a.ClientId = val.(string)
	}
	if val, found := authMap[clientSecret]; found {
		a.ClientSecret = val.(string)
	}
	if val, found := authMap[refreshToken]; found {
		a.RefreshToken = val.(string)
	}
	if val, found := authMap[p12Task]; found {
		a.P12Task = val.(string)
	}
	if val, found := authMap[scope]; found {
		a.Scope = val.(string)
	}

	provider, err := unmarshallIdP(authMap)
	if err != nil {
		return err
	}
	a.IdentityProvider = provider

	return nil
}

func unmarshallIdP(value interface{}) (*endpoint.OAuthProvider, error) {
	if value == nil {
		return nil, fmt.Errorf("authentication map value is nil")
	}
	authMap, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map but got %v", value)
	}

	tokenURL, tokenURLFound := authMap[idPTokenURL]
	audience, audienceFound := authMap[idPAudience]

	if !tokenURLFound && !audienceFound {
		return nil, nil
	}

	provider := &endpoint.OAuthProvider{}
	if tokenURLFound {
		provider.TokenURL = tokenURL.(string)
	}
	if audienceFound {
		provider.Audience = audience.(string)
	}

	return provider, nil
}
