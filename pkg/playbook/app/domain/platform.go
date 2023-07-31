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

// Platform represents the type of connection for certificate issuance:
// TPP, TLSPC, Firefly, etc.
type Platform int64

const (
	// CTypeUnknown represents an invalid Platform
	CTypeUnknown Platform = iota
	// CTypeTPP represents a connection to TPP
	CTypeTPP
	// CTypeVaaS represents a connection to VaaS
	CTypeVaaS
	// CTypeFirefly represents a connection to Firefly
	CTypeFirefly

	// String representations of the Platform types
	stringCTypeTPP     = "TPP"
	stringCTypeVaaS    = "VAAS"
	stringCTypeFirefly = "FIREFLY"
	stringCTypeUnknown = "Unknown"

	// Some alias names for TPP & VaaS
	stringCTypeTLSPDC = "TLSPDC"
	stringCTypeTLSPC  = "TLSPC"
)

// String returns a string representation of this object
func (ct *Platform) String() string {
	switch *ct {
	case CTypeTPP:
		return stringCTypeTPP
	case CTypeVaaS:
		return stringCTypeVaaS
	case CTypeFirefly:
		return stringCTypeFirefly
	default:
		return stringCTypeUnknown
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (ct Platform) MarshalYAML() (interface{}, error) {
	return ct.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (ct *Platform) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*ct, err = parseConnectionType(strValue)
	if err != nil {
		return err
	}
	return nil
}

func parseConnectionType(strConnectionType string) (Platform, error) {
	switch strings.ToUpper(strConnectionType) {
	case stringCTypeTPP, stringCTypeTLSPDC:
		return CTypeTPP, nil
	case stringCTypeVaaS, stringCTypeTLSPC:
		return CTypeVaaS, nil
	case stringCTypeFirefly:
		return CTypeFirefly, nil
	default:
		return CTypeUnknown, nil
	}
}
