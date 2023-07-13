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
	"regexp"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/certificate"
)

var (
	successRetrieveCertificate = []byte("-----BEGIN CERTIFICATE-----\nMIIEkDCCA3igAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBjTELMAkGA1UEBhMCQVUx\nKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNV\nBAsMGkJvdW5jeSBQcmltYXJ5IENlcnRpZmljYXRlMS8wLQYJKoZIhvcNAQkBFiBm\nZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0xNTEyMjQyMDQ4MzJa\nFw0xNjA2MjEyMDQ4MzJaMIGSMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExl\nZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTEoMCYGA1UECwwfQm91bmN5IEludGVy\nbWVkaWF0ZSBDZXJ0aWZpY2F0ZTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5\ncHRvQGJvdW5jeWNhc3RsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDXmXlWdmym4BrYAGiwjf4lpZCuAa1trEoYZpoYbBrbSxTTc9YJPbZTdwf2\nGfpu5Gtu6Aa4jBoLSB+hNqs9ViHMPvWelhfwR16EL4Zquz9O0RrigzDyEr0xTkhd\no/1B8izZRzyEkfvHCi0j8fUtI/zS8XX5dXw+SJfHhdc8qTT7Hduczrio4QK2Y+bE\nVSYUuie/RODVFRNNEUarBfnIChVyPM+ea+1AuGQaH1dw2Wjkkh90dFZYxNqg/DNF\nMUsNLglLwIcKIjT5vQQg0ICcljXsrxYRCf2Cpw03GqVMARakSzbQTdrW7jKgue8T\nqDD9BZaJhL4Vx3VwVGl5KYP2fsDjAgMBAAGjgfMwgfAwHQYDVR0OBBYEFMvG5bA8\npPyoQq727jNHLkmbpecBMIG6BgNVHSMEgbIwga+AFMvG5bA8pPyoQq727jNHLkmb\npecBoYGTpIGQMIGNMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBv\nZiB0aGUgQm91bmN5IENhc3RsZTEjMCEGA1UECwwaQm91bmN5IFByaW1hcnkgQ2Vy\ndGlmaWNhdGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3lj\nYXN0bGUub3JnggEBMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQAD\nggEBANAkqjVJZKQ8mxgbicKKHuVPoVohaRsIAW6LnDVVITYqtACpdbCRb0EruaCy\n6lH188gAMXVmEpCrjW4wplhikFYdGJVdz5q/sR/hlYKTSuLq33f+GlMWUy0p3MwX\nQQC73IEv0gwAp9PVf8bI7zICzy1qzmvRY4PZTWnzq8zupyz1Srfwuj3YiQA0orr7\nMGvISJjLShfW65HvEqvH65TGOMCQrLERELBHyyVRJNh/6snU6ZHiWKHsUmMgclA7\nYzVMYjAopRTBQp171d3m7RPkj7OnxNDAiIlgW8jwVhZ+RRlmGGL64pz4EBzXQ51f\nnPeVyjisi4ewoFl4kPdW1OVvLUk=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDkDCCAngCAQEwDQYJKoZIhvcNAQELBQAwgY0xCzAJBgNVBAYTAkFVMSgwJgYD\nVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMSMwIQYDVQQLDBpC\nb3VuY3kgUHJpbWFyeSBDZXJ0aWZpY2F0ZTEvMC0GCSqGSIb3DQEJARYgZmVlZGJh\nY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwHhcNMTUxMjI0MjA0ODMyWhcNMTYw\nNjIxMjA0ODMyWjCBjTELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24g\nb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNVBAsMGkJvdW5jeSBQcmltYXJ5IENl\ncnRpZmljYXRlMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5\nY2FzdGxlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANeZeVZ2\nbKbgGtgAaLCN/iWlkK4BrW2sShhmmhhsGttLFNNz1gk9tlN3B/YZ+m7ka27oBriM\nGgtIH6E2qz1WIcw+9Z6WF/BHXoQvhmq7P07RGuKDMPISvTFOSF2j/UHyLNlHPISR\n+8cKLSPx9S0j/NLxdfl1fD5Il8eF1zypNPsd25zOuKjhArZj5sRVJhS6J79E4NUV\nE00RRqsF+cgKFXI8z55r7UC4ZBofV3DZaOSSH3R0VljE2qD8M0UxSw0uCUvAhwoi\nNPm9BCDQgJyWNeyvFhEJ/YKnDTcapUwBFqRLNtBN2tbuMqC57xOoMP0FlomEvhXH\ndXBUaXkpg/Z+wOMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA0qoqGT/iiNufZGyg\nusTCEQkLETXvzeQNnTP3ZOo33zuTrkNzLXB7wufwSUCpJ4A7iJudfejCNF0PW0Tp\nMxI7ImhJrTDkrJrTSS2nrXmqiy73aNAt8yCF8w9yGA0tBbmsenh1vPweZkYT9vt/\nqaDuOzEtxgAW0pLTwO1VO3V0FebMtXVZqWebJYCR4MTwV87p/dYcU12d5DBvV0FX\n57f+e3yqk8hqNC0m7yPwQmwvwu6qrjhQf9u92otUr0wnJ+TPAXg3gN0dJWvmT8F6\nGOSSVqoWgUz7ma3+tI+D5z1s6NYqNljAAUQsXgC8s/7uek7b2eeFsewq692ZBawO\nE5bWEQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDqDCCApCgAwIBAgIEWPizGTANBgkqhkiG9w0BAQsFADCBkjEvMC0GCSqGSIb3\nDQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcxKDAmBgNVBAsM\nH0JvdW5jeSBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUxKDAmBgNVBAoMH1RoZSBM\nZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVMB4XDTE2MDMy\nMzIwNDgzM1oXDTE2MDYyMTIwNDgzM1owVTEVMBMGA1UEChMMVmVuYWZpLCBJbmMu\nMRgwFgYDVQQLEw9BdXRvbWF0ZWQgVGVzdHMxIjAgBgNVBAMTGWNlcnRhZmkudGVz\ndDMyLnZlbmFmaS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDu\nFIDROdRJkw2gsE1YjyWy4s17PGNZpaXchpKq6eAmbK+O83ckE5tNT+pT+PbZA74D\nGQECiEIHIhazEm4Vq7H/fDVxvFAxpOU8SQ4tITJIvMhZaNIm1+luc8+YeSMEC8FG\n9BM/IloKPP5e7cjz6R0QRXh+SqMHpYzPcTakqnjXKoIYXnYafJylNVzH7hS7VNWC\nQv5lnKRy41gCxDwzF/rD101zHSs+5tmMNNr1UrBFs7ePpEnnTNIQP47zpSJewo5r\n2taRFp8ydyY3uTaf8pWkl+1iEyxvdNVDK6fyBGSdg1FQ3SifqIa8MrXlZeQv1FmN\nQpovuYA2sIbC3pD5JkhhAgMBAAGjQjBAMB0GA1UdDgQWBBSFtgPoILigM4FCd79u\nT7T1RhcZmTAfBgNVHSMEGDAWgBTLxuWwPKT8qEKu9u4zRy5Jm6XnATANBgkqhkiG\n9w0BAQsFAAOCAQEAmaJZKQ5VnDO4bwn5XofN+1OQ/5lwyXsUopRJ8ARy+p2gUqrX\nw4Xunznd1ZJsvSsUrDgMZvzqpVfR0NFCunHdhwl+peRRG+5U2JFleYq8UlK02Jil\nnvl3buyHD2Ejt0VbSPzWMSAiqTRM/qVRf9odOubXshxKz7S+JPjl2TmvtOEvNg9I\nJbI+qo8gm1LGQ6p3iVeG2UsMYzK4eF8eN/7YaVGf9LQ1SmdJKp6ZX1NA4OQA9D94\n1vh+hciO1LGIm1UgNAeas+/osN4ClAagA1HFmQ7aC6KY5PtfYjvfmvbCg+LZRomp\ncvLklAkilVvNX83ZnKL+trHpNCH2oe+3FnaV1w==\n-----END CERTIFICATE-----")
)

const (
	expectedURL = "https://api2.projectc.venafi.com/"
)

func TestUpdateRequest(t *testing.T) {
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}

	zoneConfig := getZoneConfiguration(nil)

	zoneConfig.UpdateCertificateRequest(&req)
}

func TestGenerateRequest(t *testing.T) {

	keyTypeRSA := certificate.KeyTypeRSA
	keyTypeEC := certificate.KeyTypeECDSA
	keyTypeED25519 := certificate.KeyTypeED25519
	csrOriginServiceGenerated := certificate.ServiceGeneratedCSR

	cases := []struct {
		name          string
		keyType       *certificate.KeyType
		csrOrigin     *certificate.CSrOriginOption
		request       *certificate.Request
		expectedError string
	}{
		{
			"GenerateRequest-RSA-NotProvided",
			nil,
			nil,
			&certificate.Request{},
			"",
		},
		{
			"GenerateRequest-RSA",
			&keyTypeRSA,
			nil,
			&certificate.Request{},
			"",
		},
		{
			"GenerateRequest-EC",
			&keyTypeEC,
			nil,
			&certificate.Request{},
			"",
		},
		{
			"GenerateRequest-ED25519",
			&keyTypeED25519,
			nil,
			&certificate.Request{},
			"",
		},
		{
			"GenerateRequest-ED25519",
			&keyTypeED25519,
			&csrOriginServiceGenerated,
			&certificate.Request{},
			"ED25519 keys are not yet supported for Service Generated CSR",
		},
	}

	// filling every request
	for _, testCase := range cases {
		testCase.request.Subject.CommonName = "vcert.test.vfidev.com"
		testCase.request.Subject.Organization = []string{"Venafi, Inc."}
		testCase.request.Subject.OrganizationalUnit = []string{"Automated Tests"}
		testCase.request.Subject.Locality = []string{"Las Vegas"}
		testCase.request.Subject.Province = []string{"Nevada"}
		testCase.request.Subject.Country = []string{"US"}

		if testCase.keyType != nil {
			testCase.request.KeyType = *testCase.keyType
		}

		if testCase.csrOrigin != nil {
			testCase.request.CsrOrigin = *testCase.csrOrigin
		}
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {

			zoneConfig := getZoneConfiguration(nil)

			req := c.request
			zoneConfig.UpdateCertificateRequest(req)

			conn := Connector{}
			err := conn.GenerateRequest(zoneConfig, req)
			if err != nil {
				if c.expectedError != "" {
					regexErr := regexp.MustCompile(c.expectedError)
					if !regexErr.MatchString(err.Error()) {
						t.Fatalf("didn't get expected error, expected: %s, got: %s", c.expectedError, err.Error())
					}
				} else {
					t.Fatalf("err is not nil, err: %s", err)
				}
			} else {
				if c.expectedError != "" {
					t.Fatalf("got nil error, expected: %s", c.expectedError)
				}
			}
		})
	}
}

func TestParseCertificateRetrieveResponse(t *testing.T) {
	_, err := newPEMCollectionFromResponse(successRetrieveCertificate, certificate.ChainOptionRootFirst)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
}
