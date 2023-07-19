/*
 * Copyright 2018 Venafi, Inc.
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

	// String representations of the CSrOriginOption types
	strLocalGeneratedCSR   = "local"
	strServiceGeneratedCSR = "service"
	strUserProvidedCSR     = "user"
	strUnknownCSR          = "unknown"
)

// String returns a string representation of this object
func (csr *CSrOriginOption) String() string {
	switch *csr {
	case LocalGeneratedCSR:
		return strLocalGeneratedCSR
	case ServiceGeneratedCSR:
		return strServiceGeneratedCSR
	case UserProvidedCSR:
		return strUserProvidedCSR
	default:
		return strUnknownCSR
	}
}

func parseCSROrigin(value string) CSrOriginOption {
	switch strings.ToLower(value) {
	case strLocalGeneratedCSR:
		return LocalGeneratedCSR
	case strServiceGeneratedCSR:
		return ServiceGeneratedCSR
	case strUserProvidedCSR:
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
	*csr = parseCSROrigin(strValue)
	if err != nil {
		return err
	}
	return nil
}
