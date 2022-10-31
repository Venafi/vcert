/*
 * Copyright 2022 Venafi, Inc.
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

package cloud_api

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

var (
	successGetUserAccount     = []byte("{\"user\": {\"username\": \"ben.skolmoski@venafi.com\",\"id\": \"aa4a4ee0-efaf-11e5-b223-d96cf8021ce5\",\"companyId\": \"a94d5140-efaf-11e5-b223-d96cf8021ce5\",\"userType\": \"EXTERNAL\",\"userAccountType\": \"API\",\"userStatus\": \"ACTIVE\",\"creationDate\": \"2016-03-21T21:55:45.998+0000\"},\"company\": {\"id\": \"a94d5140-efaf-11e5-b223-d96cf8021ce5\",\"companyType\": \"TPP_CUSTOMER\",\"active\": true,\"creationDate\": \"2016-03-21T21:55:44.326+0000\",\"domains\": [\"venafi.com\"]},\"apiKey\": {\"username\": \"ben.skolmoski@venafi.com\",\"apiType\": \"ALL\",\"apiVersion\": \"ALL\",\"apiKeyStatus\": \"ACTIVE\",\"creationDate\": \"2016-03-21T21:55:45.998+0000\"}}")
	errorGetUserAccount       = []byte("{\"errors\": [{\"code\": 10501,\"message\": \"Unable to find api key for key cec682ba-f409-40c0-9b00-aeb67876b7a1\",\"args\": [\"cec682ba-f409-40c0-9b00-aeb67876b7a1\"]}]}")
	successGetZoneByTag       = []byte("{\"id\": \"700e6820-0a60-11e7-a0e2-77cf2c42e000\",\"companyId\": \"700c4540-0a60-11e7-a0e2-77cf2c42e000\",\"tag\": \"Default\",\"zoneType\": \"OTHER\",\"certificatePolicyIds\": {\"CERTIFICATE_IDENTITY\": [\"700df2f0-0a60-11e7-a0e2-77cf2c42e000\"],\"CERTIFICATE_USE\": [\"700df2f1-0a60-11e7-a0e2-77cf2c42e000\"]},\"defaultCertificateIdentityPolicyId\": \"700df2f0-0a60-11e7-a0e2-77cf2c42e000\",  \"defaultCertificateUsePolicyId\": \"700df2f1-0a60-11e7-a0e2-77cf2c42e000\",\"systemGenerated\": true,\"creationDate\": \"2017-03-16T15:51:37.108+0000\"}")
	errorGetZoneByTag         = []byte("{\"errors\": [{\"code\": 10803,\"message\": \"Unable to find zone with tag Defaultwer for companyId 700c4540-0a60-11e7-a0e2-77cf2c42e000\",\"args\": [\"Defaultwer\",\"700c4540-0a60-11e7-a0e2-77cf2c42e000\"]}]}")
	successRequestCertificate = []byte("{\"certificateRequests\": [{\"id\": \"04c051d0-f118-11e5-8b33-d96cf8021ce5\",\"zoneId\": \"a94d9f60-efaf-11e5-b223-d96cf8021ce5\",\"status\": \"ISSUED\",\"subjectDN\": \"cn=vcert.test.vfidev.com,ou=Automated Tests,o=Venafi, Inc.\",\"generatedKey\": false,\"defaultKeyPassword\": true,\"certificateInstanceIds\": [\"04bad390-f118-11e5-8b33-d96cf8021ce5\",\"04bcf670-f118-11e5-8b33-d96cf8021ce5\",\"04bf4060-f118-11e5-8b33-d96cf8021ce5\"],\"creationDate\": \"2016-03-23T16:55:16.589+0000\",\"pem\": \"-----BEGIN CERTIFICATE-----\\nMIIEkDCCA3igAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBjTELMAkGA1UEBhMCQVUx\\nKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNV\\nBAsMGkJvdW5jeSBQcmltYXJ5IENlcnRpZmljYXRlMS8wLQYJKoZIhvcNAQkBFiBm\\nZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0xNTEyMjQxNjU1MTVa\\nFw0xNjA2MjExNjU1MTVaMIGSMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExl\\nZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTEoMCYGA1UECwwfQm91bmN5IEludGVy\\nbWVkaWF0ZSBDZXJ0aWZpY2F0ZTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5\\ncHRvQGJvdW5jeWNhc3RsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\\nAoIBAQDXmXlWdmym4BrYAGiwjf4lpZCuAa1trEoYZpoYbBrbSxTTc9YJPbZTdwf2\\nGfpu5Gtu6Aa4jBoLSB+hNqs9ViHMPvWelhfwR16EL4Zquz9O0RrigzDyEr0xTkhd\\no/1B8izZRzyEkfvHCi0j8fUtI/zS8XX5dXw+SJfHhdc8qTT7Hduczrio4QK2Y+bE\\nVSYUuie/RODVFRNNEUarBfnIChVyPM+ea+1AuGQaH1dw2Wjkkh90dFZYxNqg/DNF\\nMUsNLglLwIcKIjT5vQQg0ICcljXsrxYRCf2Cpw03GqVMARakSzbQTdrW7jKgue8T\\nqDD9BZaJhL4Vx3VwVGl5KYP2fsDjAgMBAAGjgfMwgfAwHQYDVR0OBBYEFMvG5bA8\\npPyoQq727jNHLkmbpecBMIG6BgNVHSMEgbIwga+AFMvG5bA8pPyoQq727jNHLkmb\\npecBoYGTpIGQMIGNMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBv\\nZiB0aGUgQm91bmN5IENhc3RsZTEjMCEGA1UECwwaQm91bmN5IFByaW1hcnkgQ2Vy\\ndGlmaWNhdGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3lj\\nYXN0bGUub3JnggEBMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQAD\\nggEBAJK16ApH7IU+nJ0gWNNncEWV8BBqTdsYPix1sKiMlNZzXG8l9M2DzVSbUBoF\\nZ63QDqp1VUlUX1N11b074tGr2JBmZNSRDaj61qRLKqWbcKlSeWAOwrzyeBUJWR5N\\nfMl/pE19uGcf4L0/SMPDboTiytTDGV/AszhAnsXVm/J4H27C4fPQVl3z0NY1VxnN\\nvbuD+qNRIYEbHpmpRzwpVDPIL3Qsp5AGq2Zeci9tr2F8aEl5EAxMcbT5FBZ6R9+B\\nhGAAId1NZgE3Xndt41KcgLPitNJ5ClSDecFU+gW0l3yv8/xBPBcAzoxUWW8Q32jJ\\ncneyJVzgKNLi7RBAMufyvql+6P8=\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIDkDCCAngCAQEwDQYJKoZIhvcNAQELBQAwgY0xCzAJBgNVBAYTAkFVMSgwJgYD\\nVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMSMwIQYDVQQLDBpC\\nb3VuY3kgUHJpbWFyeSBDZXJ0aWZpY2F0ZTEvMC0GCSqGSIb3DQEJARYgZmVlZGJh\\nY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwHhcNMTUxMjI0MTY1NTE1WhcNMTYw\\nNjIxMTY1NTE1WjCBjTELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24g\\nb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNVBAsMGkJvdW5jeSBQcmltYXJ5IENl\\ncnRpZmljYXRlMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5\\nY2FzdGxlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANeZeVZ2\\nbKbgGtgAaLCN/iWlkK4BrW2sShhmmhhsGttLFNNz1gk9tlN3B/YZ+m7ka27oBriM\\nGgtIH6E2qz1WIcw+9Z6WF/BHXoQvhmq7P07RGuKDMPISvTFOSF2j/UHyLNlHPISR\\n+8cKLSPx9S0j/NLxdfl1fD5Il8eF1zypNPsd25zOuKjhArZj5sRVJhS6J79E4NUV\\nE00RRqsF+cgKFXI8z55r7UC4ZBofV3DZaOSSH3R0VljE2qD8M0UxSw0uCUvAhwoi\\nNPm9BCDQgJyWNeyvFhEJ/YKnDTcapUwBFqRLNtBN2tbuMqC57xOoMP0FlomEvhXH\\ndXBUaXkpg/Z+wOMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAC39Y+ODklhaI4fLY\\noGUiCHgJqejn1wKeUhqua1NA/urChdYUenSUdwEcy2x9+gNNXAdg+XGJG3MNycaY\\nes24zvc2848QWwESOZ/hI/747JVNgnmfgF4DcIFlvDljN57B5nduYpE/1VwdIq5p\\n5/P+jEkY9rjWvEujm0t/hbaYdkkayXQJMaMQNV57AhnwaecPpqzBuhzZxL6vZjtl\\nGPBd6++GNe93+xRUyhWueVGUg5k+TupMZQXWrWfngh5lWfNqqUuvtgT+0U2Isgk+\\njYODaZA5rEOxqnyUrawuWaYUmf03ezPKssRb0fVE3GjM+dx2PhSuIPBnY3YkEaPo\\njwBAww==\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIDxDCCAqygAwIBAgIFAOQPMskwDQYJKoZIhvcNAQELBQAwgZIxLzAtBgkqhkiG\\n9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMSgwJgYDVQQL\\nDB9Cb3VuY3kgSW50ZXJtZWRpYXRlIENlcnRpZmljYXRlMSgwJgYDVQQKDB9UaGUg\\nTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAeFw0xNjAz\\nMjMxNjU1MTZaFw0xNjA2MjExNjU1MTZaMHAxDzANBgNVBAgTBk5ldmFkYTESMBAG\\nA1UEBxMJTGFzIFZlZ2FzMRUwEwYDVQQKEwxWZW5hZmksIEluYy4xGDAWBgNVBAsT\\nD0F1dG9tYXRlZCBUZXN0czEYMBYGA1UEAxMPdGVzdC52ZW5hZmkuY29tMIIBIjAN\\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo9YR84fN1hiTaHjKH2ZKrTHYgJOS\\nSc9/mWw7eCbT7yYxs1TG97UnxngOUh7lIRRpUVpWZNXfWuam76GA6NfhQk75pQRi\\na24KV20z4v2ZDho785WxlvjXLTBu86XgQAZZ4DAjqit2LVcaJNgqxGK8R9fWmmUA\\noNyQRoPy2fRd5vPdZhbK37V+JsdF3KHSHUHkciNzKtJmVcCL1mO1FkiKkaHOo49x\\nzkjJM2ZbS4RjH5LAeJv/+gYCIhTkhjpeSM35dM4kp2xGQiIrAf8xrvfJpklAWtcS\\nZnfUTH6sRiSlOfZz09JvHUQhjZzwGvtcuetP7FASAeCgH5QWSZKNYVfsywIDAQAB\\no0IwQDAdBgNVHQ4EFgQUFTjuG78m12WBgi4Kzl/4QXu0x+IwHwYDVR0jBBgwFoAU\\ny8blsDyk/KhCrvbuM0cuSZul5wEwDQYJKoZIhvcNAQELBQADggEBAATw1x9+c3RY\\nFE1cxvGIr6hud324qVIW3mo2J/L6QoJns5ESxSoe+f6VjWxHsBGvSvhJxuQsLgUp\\nSnZvB86HxY/imUluBouP6ov+6yPet4E22N+AGPVYk0yddca9GguJQsIqZC1bEEHm\\nLLGYl1APJ8DuGQ0fos6q55seFVGBQAPlrod18wIutJYDKetnxYHv/4ZLELQKojF1\\n7s2i4LiVhTrIGjTH9sWiybup8vXY7iBcqPQOuop3Him7ODpPAm+RSx9//8wGyI9X\\n5Xchl8p8KStjxFkk6zGBTcqrY2HbRyZW8vu+Uqa+NITPAcnmYy9dVI00c2oodCtl\\n7fsDMneM/PI=\\n-----END CERTIFICATE-----\\n\"}]}")
	errorRequestCertificate   = []byte("{\"errors\": [{\"code\": 10702,\"message\": \"Unable to parse bytes of certificate signing request\",\"args\": [\"\"]}]}")
)

type fakeClient struct {
	statusCode int
	body       []byte
}

func (fc *fakeClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: fc.statusCode,
		Body:       io.NopCloser(bytes.NewBuffer(fc.body)),
	}, nil
}

func fakeRawClient(statusCode int, body []byte) *RawClient {
	return &RawClient{
		Authenticator: func(r *http.Request) error { return nil },
		HttpClient: &fakeClient{
			statusCode: statusCode,
			body:       body,
		},
	}
}

func TestParseGetUserAccountData(t *testing.T) {
	reg, err := fakeRawClient(http.StatusOK, successGetUserAccount).GetUserAccounts()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if reg.User.Username != "ben.skolmoski@venafi.com" {
		t.Fatalf("Registration username did not match expected value of ben.skolmoski@venafi.com, actual: %s", reg.User.Username)
	}
}

func TestParseBadAPIKeyError(t *testing.T) {
	_, err := fakeRawClient(http.StatusPreconditionFailed, errorGetUserAccount).GetUserAccounts()
	if err == nil {
		t.Fatalf("err nil, expected error back")
	}
}

func TestParseZoneResponse(t *testing.T) {
	_, err := fakeRawClient(http.StatusOK, successGetZoneByTag).GetCertificateIssuingTemplateByApplicationAndId("unused", "unused")
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	_, err = fakeRawClient(http.StatusNotFound, errorGetZoneByTag).GetCertificateIssuingTemplateByApplicationAndId("unused", "unused")
	if err == nil {
		t.Fatalf("err nil, expected error back")
	}
}

func TestParseCertificateRequestResponse(t *testing.T) {
	_, err := fakeRawClient(http.StatusCreated, successRequestCertificate).PostCertificateRequest(nil)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	_, err = fakeRawClient(http.StatusBadRequest, errorRequestCertificate).PostCertificateRequest(nil)
	if err == nil {
		t.Fatalf("err nil, expected error back")
	}

	_, err = fakeRawClient(http.StatusGone, errorRequestCertificate).PostCertificateRequest(nil)
	if err == nil {
		t.Fatalf("err nil, expected error back")
	}
}

func TestParseCertificateSearchResponse(t *testing.T) {
	var code int
	var body []byte
	var searchResult *cloud_structs.CertificateSearchResponse
	var err error

	code = 200
	body = []byte(`
{
  "count": 1,
  "certificates": [
    {
      "id": "ab239880-5de9-11e8-bb9b-8d6e819a14f1",
      "companyId": "b5ed6d60-22c4-11e7-ac27-035f0608fd2c",
      "managedCertificateId": "ab239881-5de9-11e8-bb9b-8d6e819a14f1",
      "fingerprint": "73CF2CC98C7DEC4045EDB93151750F5B9609FF44",
      "issuerCertificateIds": [
        "828a2b70-22ce-11e7-ba19-0da4a5ff6335",
        "82734810-22ce-11e7-ba19-0da4a5ff6335"
      ],
      "certificateRequestId": "8ceb8ad0-5de9-11e8-9c7a-e596bbf80f56",
      "certificateSource": "USER_PROVIDED",
      "certificateStatuses": [
        "NONE"
      ],
      "certificateType": "END_ENTITY",
      "ownerUsername": "alexander.tarasenko@venafi.com",
      "creationDate": "2018-05-22T17:58:01.480+00:00",
      "modificationDate": "2018-05-22T17:58:01.480+00:00",
      "totalInstanceCount": 0,
      "validityStart": "2018-05-22T00:00:00.000+00:00",
      "validityEnd": "2018-08-20T12:00:00.000+00:00",
      "validityPeriodDays": 90,
      "validityPeriodRange": "GT_30_DAYS_LTE_2_YEARS",
      "selfSigned": false,
      "signatureAlgorithm": "SHA256_WITH_RSA_ENCRYPTION",
      "signatureHashAlgorithm": "SHA256",
      "encryptionType": "RSA",
      "keyStrength": 2048,
      "publicKeyHash": "0048AA1D7E2F0017F9CA2E687D8776A1A340553D",
      "subjectKeyIdentifierHash": "C6E7C18CADE684CB420CA4764A6469086536D08E",
      "authorityKeyIdentifierHash": "AC90A22B9320CE93369173BC3074121005D7F909",
      "serialNumber": "07F3FE39F4E1A4B6075633ECFB748D84",
      "subjectCN": [
        "renew-test.venafi.example.com"
      ],
      "subjectOU": [
        "SerialNumber"
      ],
      "subjectST": "California",
      "subjectL": "Palo Alto",
      "subjectC": "US",
      "subjectAlternativeNamesByType": {
        "otherName": [],
        "rfc822Name": [],
        "dNSName": [
          "renew-test.venafi.example.com"
        ],
        "x400Address": [],
        "directoryName": [],
        "ediPartyName": [],
        "uniformResourceIdentifier": [],
        "iPAddress": [],
        "registeredID": []
      },
      "subjectAlternativeNameDns": [
        "renew-test.venafi.example.com"
      ],
      "issuerCN": [
        "DigiCert Test SHA2 Intermediate CA-1"
      ],
      "issuerC": "US",
      "keyUsage": [
        "digitalSignature",
        "keyEncipherment"
      ],
      "ocspNoCheck": false,
      "compliance": {
        "score": 0.8728395061728398
      },
      "instances": [
        {
	  	"id": "ab28c8a0-5de9-11e8-bb9b-8d6e819a14f1",
	  	"certificateId": "ab239880-5de9-11e8-bb9b-8d6e819a14f1",
	  	"managedCertificateId": "ab239881-5de9-11e8-bb9b-8d6e819a14f1",
	  	"companyId": "b5ed6d60-22c4-11e7-ac27-035f0608fd2c",
	  	"zoneId": "b5f69520-22c4-11e7-ac27-035f0608fd2c",
	  	"fingerprint": "73CF2CC98C7DEC4045EDB93151750F5B9609FF44",
	  	"certificateSource": "USER_PROVIDED",
	  	"certificateStatuses": [
	  		"NONE"
	  	],
	  	"ownerUsername": "alexander.tarasenko@venafi.com",
	  	"creationDate": "2018-05-22T17:58:01.514+00:00",
	  	"modificationDate": "2018-05-22T17:58:01.514+00:00",
	  	"ipAddress": "254.254.254.254",
	  	"ipAddressAsLong": 4278124286,
	  	"hostname": " ",
	  	"port": -1,
	  	"sslProtocolsSecurityStatus": "UNKNOWN",
	  	"cipherSuitesSecurityStatus": "UNKNOWN",
	  	"compliance": {
	  		"score": 0.0
	  	}
        }
      ],
      "applicationIds": []
    }
  ]
}
`)

	searchResult, err = fakeRawClient(code, body).PostCertificateSearch(nil)
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
	_, err = fakeRawClient(code, body).PostCertificateSearch(nil)
	if err == nil {
		t.Fatal("should trigger error")
	}

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
	_, err = fakeRawClient(code, body).PostCertificateSearch(nil)
	if err == nil {
		t.Fatal("JSON body should trigger error")
	}
}
