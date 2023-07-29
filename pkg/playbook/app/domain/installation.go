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
	AfterAction         string             `yaml:"afterInstallAction,omitempty"`
	BackupFiles         bool               `yaml:"backupFiles,omitempty"`
	CAPIIsNonExportable bool               `yaml:"capiIsNonExportable,omitempty"`
	ChainFile           string             `yaml:"chainFile,omitempty"`
	File                string             `yaml:"file,omitempty"`
	InstallValidation   string             `yaml:"installValidationAction,omitempty"`
	JKSAlias            string             `yaml:"jksAlias,omitempty"`
	JKSPassword         string             `yaml:"jksPassword,omitempty"`
	KeyFile             string             `yaml:"keyFile,omitempty"`
	Location            string             `yaml:"location,omitempty"`
	Type                InstallationFormat `yaml:"format,omitempty"`
}

// Installations is a slice of Installation
type Installations []Installation

// IsValid returns true if the Installation type is supported by vcert
func (installation Installation) IsValid() (bool, error) {
	switch installation.Type {
	case FormatJKS:
		if err := validateJKS(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case FormatPEM:
		if err := validatePEM(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case FormatPKCS12:
		if err := validateP12(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case FormatCAPI:
		if err := validateCAPI(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case FormatUnknown:
		fallthrough
	default:
		return false, fmt.Errorf("\t\t\t%w", ErrUndefinedInstallationFormat)
	}

	return true, nil
}

func validateCAPI(installation Installation) error {
	if installation.Location == "" {
		return ErrNoCAPILocation
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
	if installation.File == "" {
		return ErrNoInstallationFile
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
	if installation.File == "" {
		return ErrNoInstallationFile
	}

	if installation.ChainFile == "" {
		return ErrNoChainFile
	}
	if installation.KeyFile == "" {
		return ErrNoKeyFile
	}
	return nil
}

func validateP12(installation Installation) error {
	if installation.File == "" {
		return ErrNoInstallationFile
	}
	return nil
}
