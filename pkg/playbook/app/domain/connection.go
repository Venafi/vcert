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
	if c.Credentials.AccessToken == "" && c.Credentials.RefreshToken == "" && c.Credentials.P12Task == "" {
		rValid = false
		rErr = errors.Join(rErr, ErrNoCredentials)
	}

	// CyberArk Certificate Manager, Self-Hosted connector requires a url
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
	// Check if an API key has been provided
	apikey := false
	if c.Credentials.APIKey != "" {
		apikey = true
	}

	accesstoken := false
	if c.Credentials.AccessToken != "" {
		accesstoken = true
	}

	// Check if an TokenURL has been provided
	tokenurl := false
	if c.Credentials.TokenURL != "" {
		tokenurl = true
	}

	// Check if externalJWT has been provided
	externaljwt := false
	if c.Credentials.ExternalJWT != "" {
		externaljwt = true
	}

	// There's a valid service account IF both externalJWT and tokenURL provided
	svcaccount := false
	if externaljwt && tokenurl {
		svcaccount = true
	} else if externaljwt && !tokenurl {
		// JWT Provided without token URL
		return false, ErrNoVCPTokenURL
	} else if tokenurl && !externaljwt {
		// Token URL without an external JWT
		return false, ErrNoExternalJWT
	}

	// At this point, there are no valid credentials. Figure out why.
	if !apikey && !svcaccount && !accesstoken {
		return false, ErrNoCredentials
	}

	// if we got here then at least one of the credential options was provided
	if (svcaccount && apikey) || (svcaccount && accesstoken) || (apikey && accesstoken) {
		// more than one credential option is not acceptable
		return false, ErrAmbiguousVCPCreds
	}

	// if we got here then only one credential option was provided (which is what we want)
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
