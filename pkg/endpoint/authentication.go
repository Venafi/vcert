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

package endpoint

// Authentication provides a struct for authentication data. Either specify User and Password for CyberArk Certificate Manager, Self-Hosted
// or CyberArk Workload Identity Manager or ClientId and ClientSecret for CyberArk Workload Identity Manager or specify an APIKey for CyberArk Certificate Manager, SaaS.
type Authentication struct {
	// CyberArk Certificate Manager, Self-Hosted Auth methods
	// user and password
	User     string `yaml:"user,omitempty"`     //**DEPRECATED** Use access/refresh token or client certificate instead
	Password string `yaml:"password,omitempty"` //**DEPRECATED** Use access/refresh token or client certificate instead
	// tokens
	AccessToken  string `yaml:"accessToken,omitempty"`
	RefreshToken string `yaml:"refreshToken,omitempty"`
	// client certificate
	ClientPKCS12 bool `yaml:"-"`

	// CyberArk Certificate Manager, SaaS Auth methods
	// API key
	APIKey string `yaml:"apiKey,omitempty"`
	// Service account
	TokenURL    string `yaml:"tokenURL,omitempty"`
	ExternalJWT string `yaml:"externalJWT,omitempty"`

	// OIDC Auth methods
	ClientId     string `yaml:"clientId,omitempty"`
	ClientSecret string `yaml:"clientSecret,omitempty"`
	Scope        string `yaml:"scope,omitempty"`
	// IdentityProvider specify the OAuth 2.0 which VCert will be working for authorization purposes
	IdentityProvider *OAuthProvider `yaml:"idP,omitempty"`
}

// OAuthProvider provides a struct for the OAuth 2.0 providers information
type OAuthProvider struct {
	// OIDC Auth methods
	DeviceURL string `yaml:"-"`
	TokenURL  string `yaml:"tokenURL,omitempty"`
	Audience  string `yaml:"audience,omitempty"`
}
