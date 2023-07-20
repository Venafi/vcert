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

// Authentication holds the credentials to connect to Venafi platforms: TPP and TLSPC
type Authentication struct {
	AccessToken  string `yaml:"accessToken,omitempty"`
	Apikey       string `yaml:"apikey,omitempty"`
	ClientID     string `yaml:"clientId,omitempty"`
	RefreshToken string `yaml:"refreshToken,omitempty"`
	Scope        string `yaml:"scope,omitempty"`
	PKCS12       string `yaml:"pkcs12,omitempty"`
}

// IsEmpty returns true if not credentials are set
func (a Authentication) IsEmpty() bool {
	// TODO: This is very hacky.. need specifics based on connection type
	if a.Apikey == "" && a.AccessToken == "" && a.RefreshToken == "" && a.PKCS12 == "" {
		return true
	}
	return false
}
