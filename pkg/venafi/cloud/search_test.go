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
	"encoding/json"
	"testing"
)

func TestSearchRequest(t *testing.T) {

	// encoding to JSON
	req := &SearchRequest{
		Expression: &Expression{
			Operands: []Operand{
				{
					"fingerprint",
					MATCH,
					"A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6",
				},
			},
		},
		Paging: &Paging{10, 10},
	}
	var expectedJson = `{"expression":{"operands":[{"field":"fingerprint","operator":"MATCH","value":"A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6"}]},"paging":{"pageNumber":10,"pageSize":10}}`

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expectedJson {
		t.Fatalf("expected different JSON:\nhave:     %s\nexpected: %s", data, expectedJson)
	}
	t.Logf("%s\n", data)

	// decoding from JSON
	var req2 = &SearchRequest{}
	err = json.Unmarshal(data, req2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v\n", req2)
	data2, err := json.Marshal(req2)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(data2) {
		t.Fatalf("one expected to be the same as another:\none:   %s\nother: %s", data, data2)
	}

	// if Paging is not specified, it should not be included to JSON
	req = &SearchRequest{
		Expression: &Expression{
			Operands: []Operand{
				{
					"fingerprint",
					MATCH,
					"A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6",
				},
			},
		},
	}
	expectedJson = `{"expression":{"operands":[{"field":"fingerprint","operator":"MATCH","value":"A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6"}]}}`

	data, err = json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expectedJson {
		t.Fatalf("expected different JSON:\nhave:     %s\nexpected: %s", data, expectedJson)
	}
}

func TestParseCertificateSearchResponse(t *testing.T) {
	var code int
	var body []byte
	var searchResult *CertificateSearchResponse
	var err error

	code = 200
	body = []byte(`
		{"count":1,"certificates":[
			{"id":"ab239880-5de9-11e8-bb9b-8d6e819a14f1","companyId":"b5ed6d60-22c4-11e7-ac27-035f0608fd2c","managedCertificateId":"ab239881-5de9-11e8-bb9b-8d6e819a14f1","fingerprint":"73CF2CC98C7DEC4045EDB93151750F5B9609FF44","issuerCertificateIds":["828a2b70-22ce-11e7-ba19-0da4a5ff6335","82734810-22ce-11e7-ba19-0da4a5ff6335"],"certificateRequestId":"8ceb8ad0-5de9-11e8-9c7a-e596bbf80f56","certificateSource":"USER_PROVIDED","certificateStatuses":["NONE"],"certificateType":"END_ENTITY","ownerUsername":"alexander.tarasenko@venafi.com","creationDate":"2018-05-22T17:58:01.480+0000","modificationDate":"2018-05-22T17:58:01.480+0000","totalInstanceCount":0,"validityStart":"2018-05-22T00:00:00.000+0000","validityEnd":"2018-08-20T12:00:00.000+0000","validityPeriodDays":90,"validityPeriodRange":"GT_30_DAYS_LTE_2_YEARS","selfSigned":false,"signatureAlgorithm":"SHA256_WITH_RSA_ENCRYPTION","signatureHashAlgorithm":"SHA256","encryptionType":"RSA","keyStrength":2048,"publicKeyHash":"0048AA1D7E2F0017F9CA2E687D8776A1A340553D","subjectKeyIdentifierHash":"C6E7C18CADE684CB420CA4764A6469086536D08E","authorityKeyIdentifierHash":"AC90A22B9320CE93369173BC3074121005D7F909","serialNumber":"07F3FE39F4E1A4B6075633ECFB748D84","subjectCN":["renew-test.venafi.example.com"],"subjectOU":["SerialNumber"],"subjectST":"California","subjectL":"Palo Alto","subjectC":"US","subjectAlternativeNamesByType":{"otherName":[],"rfc822Name":[],"dNSName":["renew-test.venafi.example.com"],"x400Address":[],"directoryName":[],"ediPartyName":[],"uniformResourceIdentifier":[],"iPAddress":[],"registeredID":[]},"subjectAlternativeNameDns":["renew-test.venafi.example.com"],"issuerCN":["DigiCert Test SHA2 Intermediate CA-1"],"issuerC":"US","keyUsage":["digitalSignature","keyEncipherment"],"ocspNoCheck":false,"compliance":{"score":0.8728395061728398},"instances":[{"id":"ab28c8a0-5de9-11e8-bb9b-8d6e819a14f1","certificateId":"ab239880-5de9-11e8-bb9b-8d6e819a14f1","managedCertificateId":"ab239881-5de9-11e8-bb9b-8d6e819a14f1","companyId":"b5ed6d60-22c4-11e7-ac27-035f0608fd2c","zoneId":"b5f69520-22c4-11e7-ac27-035f0608fd2c","fingerprint":"73CF2CC98C7DEC4045EDB93151750F5B9609FF44","certificateSource":"USER_PROVIDED","certificateStatuses":["NONE"],"ownerUsername":"alexander.tarasenko@venafi.com","creationDate":"2018-05-22T17:58:01.514+0000","modificationDate":"2018-05-22T17:58:01.514+0000","ipAddress":"254.254.254.254","ipAddressAsLong":4278124286,"hostname":" ","port":-1,"sslProtocolsSecurityStatus":"UNKNOWN","cipherSuitesSecurityStatus":"UNKNOWN","compliance":{"score":0.0}}]}
		]}
	`)

	searchResult, err = ParseCertificateSearchResponse(code, body)
	if err != nil {
		t.Fatal(err)
	}
	if searchResult.Count != 1 {
		t.Fatal("wrong count field")
	}
	if len(searchResult.Certificates) != 1 {
		t.Fatal("wrong count")
	}
	if searchResult.Certificates[0].ManagedCertificateId != "ab239881-5de9-11e8-bb9b-8d6e819a14f1" {
		t.Fatal("wrong ManagedCertificateId value")
	}

	code = 400
	body = []byte("")
	searchResult, err = ParseCertificateSearchResponse(code, body)
	if err == nil {
		t.Fatal("should trigger error")
	}
	t.Log(err)

	code = 400
	body = []byte(`
		{	
		  "errors": [
		    {
		      "code": 1004,
		      "message": "Invalid or missing request header [SESSION, tppl-api-key]",
		      "args": [
		        [
		          "SESSION",
		          "tppl-api-key"
		        ]
		      ]
		    },
		    {
		      "code": 1005,
		      "message": "Something else was wrong"
		    }
		  ]
		}
	`)
	searchResult, err = ParseCertificateSearchResponse(code, body)
	if err == nil {
		t.Fatal("JSON body should trigger error")
	}
}
