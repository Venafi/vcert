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

package util

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type IssuerHint int

const (
	IssuerHintGeneric IssuerHint = iota
	IssuerHintMicrosoft
	IssuerHintDigicert
	IssuerHintEntrust
	IssuerHintAllIssuers

	strIssuerHintMicrosoft = "MICROSOFT"
	strIssuerHintDigicert  = "DIGICERT"
	strIssuerHintEntrust   = "ENTRUST"
	strIssuerHintAll       = "ALL_ISSUERS"
)

// String returns a string representation of this object
func (i *IssuerHint) String() string {
	switch *i {
	case IssuerHintMicrosoft:
		return strIssuerHintMicrosoft
	case IssuerHintDigicert:
		return strIssuerHintDigicert
	case IssuerHintEntrust:
		return strIssuerHintEntrust
	case IssuerHintAllIssuers:
		return strIssuerHintAll
	default:
		return ""
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (i IssuerHint) MarshalYAML() (interface{}, error) {
	return i.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (i *IssuerHint) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*i, err = parseInstallationType(strValue)
	if err != nil {
		return err
	}
	return nil
}

func parseInstallationType(issuerHint string) (IssuerHint, error) {
	switch strings.ToUpper(issuerHint) {
	case strIssuerHintMicrosoft:
		return IssuerHintMicrosoft, nil
	case strIssuerHintDigicert:
		return IssuerHintDigicert, nil
	case strIssuerHintEntrust:
		return IssuerHintEntrust, nil
	case strIssuerHintAll:
		return IssuerHintAllIssuers, nil
	default:
		return IssuerHintGeneric, nil
	}
}
