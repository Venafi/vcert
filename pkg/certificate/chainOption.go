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

// ChainOption represents the options to be used with the certificate chain
type ChainOption int

const (
	//ChainOptionRootLast specifies the root certificate should be in the last position of the chain
	ChainOptionRootLast ChainOption = iota
	//ChainOptionRootFirst specifies the root certificate should be in the first position of the chain
	ChainOptionRootFirst
	//ChainOptionIgnore specifies the chain should be ignored
	ChainOptionIgnore

	// String representations of the ChainOption types
	strChainOptionIgnore    = "ignore"
	strChainOptionRootFirst = "root-first"
	strChainOptionRootLast  = "root-last"
	strChainOptionUnknown   = "unknown"
)

// String returns a string representation of this object
func (co *ChainOption) String() string {
	switch *co {
	case ChainOptionIgnore:
		return strChainOptionIgnore
	case ChainOptionRootFirst:
		return strChainOptionRootFirst
	case ChainOptionRootLast:
		return strChainOptionRootLast
	default:
		return strChainOptionUnknown
	}
}

// ChainOptionFromString converts the string to the corresponding ChainOption
func ChainOptionFromString(order string) ChainOption {
	switch strings.ToLower(order) {
	case strChainOptionRootFirst:
		return ChainOptionRootFirst
	case strChainOptionIgnore:
		return ChainOptionIgnore
	default:
		return ChainOptionRootLast
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (co ChainOption) MarshalYAML() (interface{}, error) {
	return co.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (co *ChainOption) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*co = ChainOptionFromString(strValue)
	return nil
}
