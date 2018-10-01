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

package tpp

import (
	"testing"
)

func TestParseCertificateSearchResponse(t *testing.T) {
	body := `
		{
		  "Certificates": [
			{
			  "CreatedOn": "2018-06-06T12:49:11.4795797Z",
			  "DN": "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com",
			  "Guid": "{f32c5cd0-9b77-47ab-bf27-65a1159ff98e}",
			  "Name": "renx3.venafi.example.com",
			  "ParentDn": "\\VED\\Policy\\devops\\vcert",
			  "SchemaClass": "X509 Server Certificate",
			  "_links": [
				{
				  "Details": "/vedsdk/certificates/%7bf32c5cd0-9b77-47ab-bf27-65a1159ff98e%7d"
				}
			  ]
			}
		  ],
		  "DataRange": "Certificates 1 - 1",
		  "TotalCount": 1
		}`

	res, err := ParseCertificateSearchResponse(200, []byte(body))
	if err != nil {
		t.Fatal(err)
	}

	if res.Certificates[0].CertificateRequestId != "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com" {
		t.Fatal("failed to parse cert DN")
	}
}
