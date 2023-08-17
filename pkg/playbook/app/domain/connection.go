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
	"errors"
	"fmt"
	"os"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

// Connection represents the issuer that vCert will connect to
// in order to issue certificates
type Connection struct {
	Credentials     Authentication  `yaml:"credentials,omitempty"`
	Insecure        bool            `yaml:"insecure,omitempty"`
	Platform        venafi.Platform `yaml:"platform,omitempty"`
	TrustBundlePath string          `yaml:"trustBundle,omitempty"`
	URL             string          `yaml:"url,omitempty"`
}

// GetConnectorType returns the type of vcert Connector this config will create
func (c Connection) GetConnectorType() endpoint.ConnectorType {
	switch c.Platform {
	case venafi.Firefly:
		return endpoint.ConnectorTypeFirefly
	case venafi.TPP:
		return endpoint.ConnectorTypeTPP
	case venafi.TLSPCloud:
		return endpoint.ConnectorTypeCloud
	default:
		return endpoint.ConnectorTypeFake
	}
}

func (c Connection) validateTrustBundle() error {
	_, err := os.Stat(c.TrustBundlePath)
	if err != nil {
		// TrustBundle does not exist in location
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrTrustBundleNotExist, c.TrustBundlePath)
		}
	}
	return nil
}

// IsValid returns true if the Connection is supported by vcert
// and has the necessary values to connect to the given platform
func (c Connection) IsValid() (bool, error) {
	switch c.Platform {
	case venafi.TPP:
		return isValidTpp(c)
	case venafi.TLSPCloud:
		return isValidVaaS(c)
	case venafi.Firefly:
		return isValidFirefly(c)
	default:
		return false, fmt.Errorf("invalid connection type %v", c.Platform)
	}
}

func isValidTpp(c Connection) (bool, error) {
	var rErr error = nil
	rValid := true

	// Credentials are not empty
	if c.Credentials.IsEmpty() {
		rValid = false
		rErr = errors.Join(rErr, ErrNoCredentials)
	}

	// TPP connector requires a url
	if c.URL == "" {
		rValid = false
		rErr = errors.Join(rErr, ErrNoTPPURL)
	}

	// If specified, ensure TrustBundle exists
	if c.TrustBundlePath != "" {
		err := c.validateTrustBundle()
		if err != nil {
			rValid = false
			rErr = errors.Join(rErr, err)
		}
	}

	return rValid, rErr
}

func isValidVaaS(c Connection) (bool, error) {
	// Credentials are not empty
	if c.Credentials.APIKey == "" {
		return false, ErrNoCredentials
	}

	return true, nil
}

func isValidFirefly(c Connection) (bool, error) {

	if c.URL == "" {
		return false, ErrNoFireflyURL
	}

	// Auth method: User-Password
	userPassword := false
	if c.Credentials.User != "" && c.Credentials.Password != "" {
		userPassword = true
	}

	//Auth method: Client Secret
	cSecret := false
	if c.Credentials.ClientSecret != "" {
		cSecret = true
	}

	//Auth method: Access Token
	token := false
	if c.Credentials.AccessToken != "" {
		token = true
	}

	if !userPassword && !cSecret && !token {
		return false, ErrNoCredentials
	}

	// Auth method is AccessToken, no further validations required
	if token {
		return true, nil
	}

	//Validate ClientId
	if c.Credentials.ClientId == "" {
		return false, ErrNoClientId
	}

	// Validate Identity Provider values
	if c.Credentials.IdentityProvider == nil || c.Credentials.IdentityProvider.TokenURL == "" {
		return false, ErrNoIdentityProviderURL
	}

	return true, nil
}
