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

	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

// Connection represents the issuer that vCert will connect to
// in order to issue certificates
type Connection struct {
	Type            ConnectionType `yaml:"type,omitempty"`
	Credentials     Authentication `yaml:"credentials,omitempty"`
	URL             string         `yaml:"url,omitempty"`
	TrustBundlePath string         `yaml:"trustBundle,omitempty"`
	Insecure        bool           `yaml:"insecure,omitempty"`
}

// GetConnectorType returns the type of vcert Connector this config will create
func (c Connection) GetConnectorType() endpoint.ConnectorType {
	if c.Type == CTypeVaaS {
		return endpoint.ConnectorTypeCloud
	} else if c.Type == CTypeTPP {
		return endpoint.ConnectorTypeTPP
	} else if c.Type == CTypeFirefly {
		// This is not implemented in vCertSDK yet
		return endpoint.ConnectorTypeFake
	} else {
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
	switch c.Type {
	case CTypeTPP:
		return isValidTpp(c)
	case CTypeVaaS:
		return isValidVaaS(c)
	case CTypeFirefly:
		return isValidFirefly(c)
	default:
		return false, fmt.Errorf("invalid connection type %v", c.Type)
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
	if c.Credentials.IsEmpty() {
		return false, ErrNoCredentials
	}

	return true, nil
}

func isValidFirefly(c Connection) (bool, error) {
	// Credentials are not empty
	if c.Credentials.IsEmpty() {
		return false, ErrNoCredentials
	}

	return true, nil
}

// IsEmpty returns true if no URL, TrustBundlePath and Credentials are defined
func (c Connection) IsEmpty() bool {
	return c.Credentials.IsEmpty() && c.URL == "" && c.TrustBundlePath == ""
}
