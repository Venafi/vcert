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
	"strings"

	"gopkg.in/yaml.v3"
)

// InstallationFormat represents the type of installation to be done:
// PEM, PKCS12, JKS or CAPI (only on Windows environments)
type InstallationFormat int64

const (
	// FormatUnknown represents an invalid InstallationFormat
	FormatUnknown InstallationFormat = iota
	// FormatCAPI represents an installation in CAPI store
	FormatCAPI
	// FormatJKS represents an installation with the Java KeyStore format
	FormatJKS
	// FormatPEM represents an installation with PEM format
	FormatPEM
	// FormatPKCS12 represents an installation with the PKCS12 format
	FormatPKCS12

	// String representations of the InstallationFormat types
	stringCAPI    = "CAPI"
	stringJKS     = "JKS"
	stringPEM     = "PEM"
	stringPKCS12  = "PKCS12"
	stringUnknown = "Unknown"
)

// String returns a string representation of this object
func (it *InstallationFormat) String() string {
	switch *it {
	case FormatPEM:
		return stringPEM
	case FormatPKCS12:
		return stringPKCS12
	case FormatJKS:
		return stringJKS
	case FormatCAPI:
		return stringCAPI
	default:
		return stringUnknown
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (it InstallationFormat) MarshalYAML() (interface{}, error) {
	return it.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (it *InstallationFormat) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*it, err = parseInstallationType(strValue)
	if err != nil {
		return err
	}
	return nil
}

func parseInstallationType(installationType string) (InstallationFormat, error) {
	switch strings.ToUpper(installationType) {
	case stringCAPI:
		return FormatCAPI, nil
	case stringJKS:
		return FormatJKS, nil
	case stringPEM:
		return FormatPEM, nil
	case stringPKCS12:
		return FormatPKCS12, nil
	default:
		return FormatUnknown, nil
	}
}
