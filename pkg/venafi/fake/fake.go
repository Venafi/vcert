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

package fake

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
)

//GenerateRequest creates a new certificate request, based on the zone/policy configuration and the user data
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		err = req.GeneratePrivateKey()
		if err != nil {
			return err
		}
		err = req.GenerateCSR()
		if err != nil {
			return err
		}

	case certificate.UserProvidedCSR:
		if req.GetCSR() == nil {
			return fmt.Errorf("CSR was supposed to be provided by user, but it's empty")
		}

	case certificate.ServiceGeneratedCSR:
		return nil

	default:
		return fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	return nil
}

type RevocationReason int

var RevocationReasonsMap = map[string]RevocationReason{
	"":                       0, // NoReason
	"none":                   0, //
	"key-compromise":         1, // UserKeyCompromised
	"ca-compromise":          2, // CAKeyCompromised
	"affiliation-changed":    3, // UserChangedAffiliation
	"superseded":             4, // CertificateSuperseded
	"cessation-of-operation": 5, // OriginalUseNoLongerValid
}
