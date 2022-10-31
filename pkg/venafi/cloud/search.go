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

package cloud

import (
	"log"
	"math"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

func certificateToCertificateInfo(c *cloud_structs.Certificate) certificate.CertificateInfo {
	var cn string
	if len(c.SubjectCN) > 0 {
		cn = c.SubjectCN[0]
	}

	start, err := time.Parse(time.RFC3339, c.ValidityStart)
	if err != nil { //we just print the error, and let the user know.
		log.Println(err)
	}

	end, err := time.Parse(time.RFC3339, c.ValidityEnd)
	if err != nil { //we just print the error, and let the user know.
		log.Println(err)
	}

	return certificate.CertificateInfo{
		ID: c.Id,
		CN: cn,
		SANS: certificate.Sans{
			DNS:   c.SubjectAlternativeNamesByType["dNSName"],
			Email: c.SubjectAlternativeNamesByType["rfc822Name"],
			IP:    c.SubjectAlternativeNamesByType["iPAddress"],
			URI:   c.SubjectAlternativeNamesByType["uniformResourceIdentifier"],
			// currently not supported on VaaS
			// UPN: cert.SubjectAlternativeNamesByType["x400Address"],
		},
		Serial:     c.SerialNumber,
		Thumbprint: c.Fingerprint,
		ValidFrom:  start,
		ValidTo:    end,
	}
}

// returns everything up to the last slash (if any)
//
// example:
// Just The App Name
// -> Just The App Name
//
// The application\\With Cit
// -> The application
//
// The complex application\\name\\and the cit
// -> The complex application\\name
func getAppNameFromZone(zone string) string {
	lastSlash := strings.LastIndex(zone, "\\")

	// there is no backslash in zone, meaning it's just the application name,
	// return it
	if lastSlash == -1 {
		return zone
	}

	return zone[:lastSlash]
}

// TODO: test this function
func formatSearchCertificateArguments(cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) *cloud_structs.SearchRequest {
	// convert a time.Duration to days
	certMinTimeDays := math.Floor(certMinTimeLeft.Hours() / 24)

	// generate base request
	req := &cloud_structs.SearchRequest{
		Expression: &cloud_structs.Expression{
			Operator: cloud_structs.AND,
			Operands: []cloud_structs.Operand{
				{
					Field:    "validityPeriodDays",
					Operator: cloud_structs.GTE,
					Value:    certMinTimeDays,
				},
			},
		},
	}

	if sans != nil && sans.DNS != nil {
		addOperand(req, cloud_structs.Operand{
			Field:    "subjectAlternativeNameDns",
			Operator: cloud_structs.IN,
			Values:   sans.DNS,
		})
	}

	// only if a CN is provided, we add the field to the search request
	if cn != "" {
		addOperand(req, cloud_structs.Operand{
			Field:    "subjectCN",
			Operator: cloud_structs.EQ,
			Value:    cn,
		})
	}

	return req
}

func addOperand(req *cloud_structs.SearchRequest, o cloud_structs.Operand) *cloud_structs.SearchRequest {
	req.Expression.Operands = append(req.Expression.Operands, o)
	return req
}
