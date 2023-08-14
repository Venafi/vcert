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
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"gopkg.in/yaml.v3"
)

const (
	accessToken  = "accessToken"
	apiKey       = "apiKey"
	clientID     = "clientId"
	clientSecret = "clientSecret"
	idP          = "idP"
	refreshToken = "refreshToken"
	p12Task      = "p12Task"
	scope        = "scope"
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
		values[idP] = a.IdentityProvider
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

	if _, found := authMap[accessToken]; found {
		a.AccessToken = authMap[accessToken].(string)
	}
	if _, found := authMap[apiKey]; found {
		a.APIKey = authMap[apiKey].(string)
	}
	if _, found := authMap[clientID]; found {
		a.ClientId = authMap[clientID].(string)
	}
	if _, found := authMap[clientSecret]; found {
		a.ClientSecret = authMap[clientSecret].(string)
	}
	if _, found := authMap[idP]; found {
		//a.IdentityProvider = authMap[].(string)
	}
	if _, found := authMap[refreshToken]; found {
		a.RefreshToken = authMap[refreshToken].(string)
	}
	if _, found := authMap[p12Task]; found {
		a.P12Task = authMap[p12Task].(string)
	}
	if _, found := authMap[scope]; found {
		a.Scope = authMap[scope].(string)
	}

	return nil
}
