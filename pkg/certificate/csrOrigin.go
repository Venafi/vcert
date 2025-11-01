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

package certificate

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type CSrOriginOption int

const (
	// LocalGeneratedCSR - this vcert library generates CSR internally based on Request data
	LocalGeneratedCSR CSrOriginOption = iota // local generation is default.
	// ServiceGeneratedCSR - server generate CSR internally based on zone configuration and data from Request
	ServiceGeneratedCSR
	// UserProvidedCSR - client provides CSR from external resource and vcert library just check and send this CSR to server
	UserProvidedCSR
	UnknownCSR

	// StrLocalGeneratedCSR is the string representations of the LocalGeneratedCSR constant
	StrLocalGeneratedCSR = "local"
	// StrServiceGeneratedCSR is the string representations of the ServiceGeneratedCSR constant
	StrServiceGeneratedCSR = "service"
	// StrUserProvidedCSR is the string representations of the UserProvidedCSR constant
	StrUserProvidedCSR = "file"
	strUnknownCSR      = "unknown"
)

// String returns a string representation of this object
func (csr *CSrOriginOption) String() string {
	switch *csr {
	case LocalGeneratedCSR:
		return StrLocalGeneratedCSR
	case ServiceGeneratedCSR:
		return StrServiceGeneratedCSR
	case UserProvidedCSR:
		return StrUserProvidedCSR
	default:
		return strUnknownCSR
	}
}

// ParseCSROrigin returns a CSrOriginOption from a valid string representation
func ParseCSROrigin(value string) CSrOriginOption {
	switch strings.ToLower(value) {
	case StrLocalGeneratedCSR:
		return LocalGeneratedCSR
	case StrServiceGeneratedCSR:
		return ServiceGeneratedCSR
	case StrUserProvidedCSR:
		return UserProvidedCSR
	default:
		return UnknownCSR
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (csr CSrOriginOption) MarshalYAML() (interface{}, error) {
	return csr.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (csr *CSrOriginOption) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*csr = ParseCSROrigin(strValue)
	if err != nil {
		return err
	}
	return nil
}
