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

// InstallationType represents the type of installation to be done:
// PEM, PKCS12, JKS or CAPI (only on Windows environments)
type InstallationType int64

const (
	// TypeUnknown represents an invalid InstallationType
	TypeUnknown InstallationType = iota
	// TypeCAPI represents an installation in CAPI store
	TypeCAPI
	// TypeJKS represents an installation with the Java KeyStore format
	TypeJKS
	// TypePEM represents an installation with PEM format
	TypePEM
	// TypePKCS12 represents an installation with the PKCS12 format
	TypePKCS12

	// String representations of the InstallationType types
	stringCAPI    = "CAPI"
	stringJKS     = "JKS"
	stringPEM     = "PEM"
	stringPKCS12  = "PKCS12"
	stringUnknown = "Unknown"
)

// String returns a string representation of this object
func (it *InstallationType) String() string {
	switch *it {
	case TypePEM:
		return stringPEM
	case TypePKCS12:
		return stringPKCS12
	case TypeJKS:
		return stringJKS
	case TypeCAPI:
		return stringCAPI
	default:
		return stringUnknown
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (it InstallationType) MarshalYAML() (interface{}, error) {
	return it.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (it *InstallationType) UnmarshalYAML(value *yaml.Node) error {
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

func parseInstallationType(installationType string) (InstallationType, error) {
	switch strings.ToUpper(installationType) {
	case stringCAPI:
		return TypeCAPI, nil
	case stringJKS:
		return TypeJKS, nil
	case stringPEM:
		return TypePEM, nil
	case stringPKCS12:
		return TypePKCS12, nil
	default:
		return TypeUnknown, nil
	}
}
