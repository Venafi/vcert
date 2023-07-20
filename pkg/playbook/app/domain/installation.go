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
	"runtime"
	"strings"
)

const (
	// JKSMinPasswordLength represents the minimum length a JKS password must have per the JKS specification
	JKSMinPasswordLength = 6

	capiLocationCurrentUser  = "currentuser"
	capiLocationLocalMachine = "localmachine"
)

var validStoreNames = []string{"addressbook", "authroot", "certificateauthority", "disallowed", "my", "root",
	"trustedpeople", "trustedpublisher"}

// Installation represents a location in which a certificate will be installed,
// along with the format in which it will be installed
type Installation struct {
	AfterAction         string           `yaml:"afterInstallAction,omitempty"`
	BackupFiles         bool             `yaml:"backupFiles,omitempty"`
	CAPIIsNonExportable bool             `yaml:"capiIsNonExportable,omitempty"`
	InstallValidation   string           `yaml:"installValidationAction,omitempty"`
	JKSAlias            string           `yaml:"jksAlias,omitempty"`
	JKSPassword         string           `yaml:"jksPassword,omitempty"`
	Location            string           `yaml:"location,omitempty"`
	PEMCertFilename     string           `yaml:"pemCertFilename,omitempty"`
	PEMChainFilename    string           `yaml:"pemChainFilename,omitempty"`
	PEMKeyFilename      string           `yaml:"pemKeyFilename,omitempty"`
	Type                InstallationType `yaml:"type,omitempty"`
}

// Installations is a slice of Installation
type Installations []Installation

// IsValid returns true if the Installation type is supported by vcert
func (installation Installation) IsValid() (bool, error) {
	switch installation.Type {
	case TypeJKS:
		if err := validateJKS(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypePEM:
		if err := validatePEM(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypePKCS12:
		if err := validateP12(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypeCAPI:
		if err := validateCAPI(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypeUnknown:
		fallthrough
	default:
		return false, fmt.Errorf("\t\t\t%w", ErrUndefinedInstallationType)
	}

	return true, nil
}

func validateCAPI(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}

	if runtime.GOOS != "windows" {
		return ErrCAPIOnNonWindows
	}

	// Ensure proper location specified
	segments := strings.Split(installation.Location, "\\")

	// CAPI Location must be in form of <string>\<string>
	if len(segments) != 2 {
		return ErrMalformedCAPILocation
	}

	location := strings.ToLower(segments[0])
	if location != capiLocationCurrentUser && location != capiLocationLocalMachine {
		return ErrInvalidCAPILocation
	}

	// valid store names from https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename?view=net-7.0
	// Although it is unlikely that you'd want to install a certificate and private key in anything but "my", here for completeness
	isValidStoreName := false
	for _, v := range validStoreNames {
		if v == strings.ToLower(segments[1]) {
			isValidStoreName = true
			break
		}
	}

	if !isValidStoreName {
		return ErrInvalidCAPIStoreName
	}

	return nil
}

func validateJKS(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}

	if installation.JKSAlias == "" {
		return ErrNoJKSAlias
	}
	if installation.JKSPassword == "" {
		return ErrNoJKSPassword
	}
	if len(installation.JKSPassword) < JKSMinPasswordLength {
		return ErrJKSPasswordLength
	}
	return nil
}

func validatePEM(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}

	if installation.PEMCertFilename == "" {
		return ErrNoPEMCertFilename
	}
	if installation.PEMChainFilename == "" {
		return ErrNoPEMChainFilename
	}
	if installation.PEMKeyFilename == "" {
		return ErrNoPEMKeyFilename
	}
	return nil
}

func validateP12(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}
	return nil
}
