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
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"net/http"
	"strings"
	"testing"
)

const (
	expectedURL = "https://localhost/vedsdk/"
)

func TestParseAuthorizeData(t *testing.T) {
	data := []byte("{\"APIKey\":\"3561721a-4a0a-a441-8a80-655a736c3d76\",\"ValidUntil\":\"/Date(1455728250931)/\"}")
	apiKey, err := parseAuthorizeResult(http.StatusOK, "", data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if apiKey != "3561721a-4a0a-a441-8a80-655a736c3d76" {
		t.Fatalf("Parsed API Key did not match expected value. Expected: 3561721a-4a0a-a441-8a80-655a736c3d76 Actual: %s", apiKey)
	}
}

func TestSetBaseURL(t *testing.T) {
	tpp := Connector{}
	url := "http://localhost/vedsdk/"
	err := tpp.SetBaseURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(tpp.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, tpp.baseURL)
	}

	url = "http://localhost"
	tpp.baseURL = ""
	err = tpp.SetBaseURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(tpp.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, tpp.baseURL)
	}

	url = "http://localhost/vedsdk"
	tpp.baseURL = ""
	err = tpp.SetBaseURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(tpp.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, tpp.baseURL)
	}

	url = "localhost/vedsdk"
	tpp.baseURL = ""
	err = tpp.SetBaseURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(tpp.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, tpp.baseURL)
	}

	url = "ftp://wrongurlformat.com"
	tpp.baseURL = ""
	err = tpp.SetBaseURL(url)
	if err == nil {
		t.Fatalf("err was not expected to be nil. url: %s", url)
	}
	if strings.EqualFold(tpp.baseURL, expectedURL) {
		t.Fatalf("Base URL should not match expected value. Expected: %s Actual: %s", expectedURL, tpp.baseURL)
	}
}

func TestGetURL(t *testing.T) {
	tpp := Connector{}
	url := "http://localhost/vedsdk/"
	tpp.baseURL = ""
	err := tpp.SetBaseURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(tpp.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, tpp.baseURL)
	}

	url, err = tpp.getURL(urlResourceAuthorize)
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", expectedURL, urlResourceAuthorize)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", expectedURL, urlResourceAuthorize), url)
	}

	url, err = tpp.getURL(urlResourceCertificateRequest)
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRequest)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRequest), url)
	}

	url, err = tpp.getURL(urlResourceCertificateRetrieve)
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRetrieve)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRetrieve), url)
	}
	tpp.baseURL = ""
	url, err = tpp.getURL(urlResourceAuthorize)
	if err == nil {
		t.Fatalf("Get URL did not return an error when the base url had not been set.")
	}
}

func TestParseConfigFindPolicyData(t *testing.T) {
	data := []byte("{\"Locked\":false,\"PolicyDN\":\"\\\\VED\\\\Policy\\\\Web SDK Testing\",\"Result\":1,\"Values\":[\"Engineering\",\"Quality Assurance\"]}")
	tppData, err := parseConfigResult(http.StatusOK, "", data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if len(tppData.Values) != 2 {
		t.Fatalf("Values count was not expected count of 2 actual count is %d", len(tppData.Values))
	}

	tppData, err = parseConfigResult(http.StatusBadRequest, "Bad Request", data)
	if err == nil {
		t.Fatalf("err is nil when expected to not be")
	}

	if !strings.Contains(err.Error(), "Bad Request") {
		t.Fatalf("Parse Certificate error response did not include expected string: Bad Request -- Actual: %s", err)
	}

	data = []byte("bad data")
	tppData, err = parseConfigData(data)
	if err == nil {
		t.Fatalf("ParseConfigData with bad data did not return an error")
	}
}

func TestParseCertificateRequestData(t *testing.T) {
	data := []byte("{\"CertificateDN\":\"\\\\VED\\\\Policy\\\\Web SDK Testing\\\\bonjoTest 33\"}")

	requestDN, err := parseRequestResult(http.StatusOK, "", data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if !strings.EqualFold(requestDN, "\\VED\\Policy\\Web SDK Testing\\bonjoTest 33") {
		t.Fatalf("Parse Certificate retrieve response did not include expected CertificateDN: \\VED\\Policy\\Web SDK Testing\\bonjoTest 33 -- Actual: %s", requestDN)
	}

	requestDN, err = parseRequestResult(http.StatusBadRequest, "Bad Request", data)
	if err == nil {
		t.Fatalf("err is nil when expected to not be")
	}

	if !strings.Contains(err.Error(), "Bad Request") {
		t.Fatalf("Parse Certificate error response did not include expected string: Bad Request -- Actual: %s", err)
	}

	data = []byte("bad data")
	_, err = parseRequestData(data)
	if err == nil {
		t.Fatalf("ParseRequestData with bad data did not return an error")
	}
}

func TestParseCertificateRetrieveData(t *testing.T) {
	data := []byte("{\"CertificateData\":\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlHYWpDQ0JWS2dBd0lCQWdJS0hyT1Z5d0FBQUNxNHp6QU5CZ2txaGtpRzl3MEJBUVVGQURCWE1STXdFUVlLDQpDWkltaVpQeUxHUUJHUllEWTI5dE1SWXdGQVlLQ1pJbWlaUHlMR1FCR1JZR2RtVnVZV1pwTVJVd0V3WUtDWkltDQppWlB5TEdRQkdSWUZkbVZ1Y1dFeEVUQVBCZ05WQkFNVENGWmxibEZCSUVOQk1CNFhEVEUyTURJeE9ESXlNRFl3DQpNMW9YRFRFM01URXdPVEl5TlRnek1sb3dnWXd4Q3pBSkJnTlZCQVlUQWxWVE1RMHdDd1lEVlFRSUV3UlZkR0ZvDQpNUXd3Q2dZRFZRUUhFd05UVEVNeEZUQVRCZ05WQkFvVERGWmxibUZtYVN3Z1NXNWpMakVVTUJJR0ExVUVDeE1MDQpSVzVuYVc1bFpYSnBibWN4R2pBWUJnTlZCQXNURVZGMVlXeHBkSGtnUVhOemRYSmhibU5sTVJjd0ZRWURWUVFEDQpFdzUwWlhOMExtSnZibXB2TG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCDQpBTXcwR2RrNm1CeUt0WHJBcXpQQ3pmVzV0V2lTZFFDTzhycHJadStRQXZwYXlUSjBJbFBBbE5QZEt5M3JlRUM1DQowMWxjUlpvYSt0aUpuazVKNWRqcU9oaXErdkhNKzRJYkJWb3lPODNPdmxYd045a1gyc0NuTGJ1MkFTeUJGZmVwDQpVWDJuNmJ5aGVKS3FJSUw1ZXd3TFlMWndYYUhHa1pZL2Q0ZXFSVmM5UTN3Nzh4SkJSbXdCNzhad1lQeVdYd0ZXDQpRTUVyRitMdkRZTnhQeGRtWXVSdFRWRTkvUHBpaWNKUnpVWWUzV25KcEhNRzQ0cDJDR3gvVHJQcDZkUHVoNlUxDQpET2J2UEt0UHAyR25JZy9aaWovL3ZDMU94eFNKMXdFdzdXMFE1N3JpMWl0QkxmTFg3MS9WOEpHMUFEN0t6cFQwDQp6ZGM1OERvVWxHTHg0cXd4dWFmaDR0c0NBd0VBQWFPQ0F3QXdnZ0w4TUIwR0ExVWREZ1FXQkJTTU5XK2Z4ZDZFDQphQ0tkaHk3dG11WS9YSnh4UmpBZkJnTlZIU01FR0RBV2dCUkdWbzIzMkxKRzA5OGg2RVFTUEZBVFFTdzdBVENDDQpBVnNHQTFVZEh3U0NBVkl3Z2dGT01JSUJTcUNDQVVhZ2dnRkNoajlvZEhSd09pOHZNbXM0TFhabGJuRmhMWEJrDQpZeTUyWlc1eFlTNTJaVzVoWm1rdVkyOXRMME5sY25SRmJuSnZiR3d2Vm1WdVVVRWxNakJEUVM1amNteUdnYjlzDQpaR0Z3T2k4dkwwTk9QVlpsYmxGQkpUSXdRMEVzUTA0OU1tczRMWFpsYm5GaExYQmtZeXhEVGoxRFJGQXNRMDQ5DQpVSFZpYkdsakpUSXdTMlY1SlRJd1UyVnlkbWxqWlhNc1EwNDlVMlZ5ZG1salpYTXNRMDQ5UTI5dVptbG5kWEpoDQpkR2x2Yml4RVF6MTJaVzV4WVN4RVF6MTJaVzVoWm1rc1JFTTlZMjl0UDJObGNuUnBabWxqWVhSbFVtVjJiMk5oDQpkR2x2Ymt4cGMzUS9ZbUZ6WlQ5dlltcGxZM1JEYkdGemN6MWpVa3hFYVhOMGNtbGlkWFJwYjI1UWIybHVkSVk5DQpabWxzWlRvdkx6SnJPQzEyWlc1eFlTMXdaR011ZG1WdWNXRXVkbVZ1WVdacExtTnZiUzlEWlhKMFJXNXliMnhzDQpMMVpsYmxGQklFTkJMbU55YkRDQnhBWUlLd1lCQlFVSEFRRUVnYmN3Z2JRd2diRUdDQ3NHQVFVRkJ6QUNob0drDQpiR1JoY0Rvdkx5OURUajFXWlc1UlFTVXlNRU5CTEVOT1BVRkpRU3hEVGoxUWRXSnNhV01sTWpCTFpYa2xNakJUDQpaWEoyYVdObGN5eERUajFUWlhKMmFXTmxjeXhEVGoxRGIyNW1hV2QxY21GMGFXOXVMRVJEUFhabGJuRmhMRVJEDQpQWFpsYm1GbWFTeEVRejFqYjIwL1kwRkRaWEowYVdacFkyRjBaVDlpWVhObFAyOWlhbVZqZEVOc1lYTnpQV05sDQpjblJwWm1sallYUnBiMjVCZFhSb2IzSnBkSGt3Q3dZRFZSMFBCQVFEQWdXZ01Eb0dDU3NHQVFRQmdqY1ZCd1F0DQpNQ3NHSXlzR0FRUUJnamNWQ0lHUGlYS0VoTEJxOVowUWg1Yi9mTVNKRldDYzZFT0Z1NlJkQWdGa0FnRUpNQk1HDQpBMVVkSlFRTU1Bb0dDQ3NHQVFVRkJ3TUJNQnNHQ1NzR0FRUUJnamNWQ2dRT01Bd3dDZ1lJS3dZQkJRVUhBd0V3DQpHUVlEVlIwUkJCSXdFSUlPZEdWemRDNWliMjVxYnk1amIyMHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBSFhSDQpIZXZSTnZhL3l3YVU3VHJTMUlTb2ZqcUVtT1MwVDB2ZWlDenVFZkhwTitZWGg2SzhZVXViODFWTHF2aTJxSmJUDQp0bExwSmNVTytBVHBrYWV5K2RQU1B2WVNUejVKY3BaWjU3MCsrUTg0RFFPcnEvcmJjamFHMHBsNDk1Sk1nQzVRDQo4VUlZa0JTMndEWWhJRVdpYmZZVU91S2c3Y3RVRTV2eVI3eFkvU1JhaFBwUUNVS1o0QmJqNnhnV2VmOW5IVjVVDQpuVWZqQzVjdXJ3TUE5RGVweFBHWGtwVm5FK1RzK1k4ZlFwSmdVUUtmNHRoWklwbVB1d044NU1BVXJxTW9YbkNyDQpIM0Y4NzJJNnF4RlkzUzhyNk1TZUdMdUtyb3h4TEErQk9scDV2cXRqRlo0SWlDcUNmLzA1UzZFbFhaa1V1K1ZpDQpZaUkyQ1VValVEWkdVU2lrMUFBPQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ0K\",\"Filename\":\"test.bonjo.com.cer\",\"Format\":\"base64\"}")

	resp, err := parseRetrieveResult(http.StatusOK, "", data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if !strings.EqualFold(resp.Filename, "test.bonjo.com.cer") {
		t.Fatalf("Parse Certificate retrieve response did not include expected filename: test.bonjo.com.cer -- Actual: %s", resp.Filename)
	}

	resp, err = parseRetrieveResult(http.StatusBadRequest, "Bad Request", data)
	if err == nil {
		t.Fatalf("err is nil when expected to not be")
	}

	if !strings.Contains(err.Error(), "Bad Request") {
		t.Fatalf("Parse Certificate error response did not include expected string: Bad Request -- Actual: %s", err)
	}

	data = []byte("bad data")
	_, err = parseRetrieveData(data)
	if err == nil {
		t.Fatalf("ParseRetrieveData with bad data did not return an error")
	}
}

func getBaseZoneConfiguration() *endpoint.ZoneConfiguration {
	z := endpoint.NewZoneConfiguration()
	z.Organization = "Venafi"
	z.OrganizationLocked = false
	z.OrganizationalUnit = []string{"Engineering", "Automated Tests"}
	z.Country = "US"
	z.CountryLocked = false
	z.Province = "Utah"
	z.ProvinceLocked = true
	z.Locality = "SLC"
	z.LocalityLocked = true
	z.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{endpoint.AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{4096}}}
	z.KeySizeLocked = true
	z.HashAlgorithm = x509.SHA512WithRSA
	return z
}

func TestGetPolicyDN(t *testing.T) {
	const expectedPolicy = "\\VED\\Policy\\One\\Level 2\\This is level Three"

	actualPolicy := getPolicyDN("One\\Level 2\\This is level Three")
	if len(expectedPolicy) != len(actualPolicy) {
		t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
	}
	for i := 0; i < len(expectedPolicy); i++ {
		if expectedPolicy[i] != actualPolicy[i] {
			t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
		}
	}

	actualPolicy = getPolicyDN("\\One\\Level 2\\This is level Three")
	if len(expectedPolicy) != len(actualPolicy) {
		t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
	}
	for i := 0; i < len(expectedPolicy); i++ {
		if expectedPolicy[i] != actualPolicy[i] {
			t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
		}
	}

	actualPolicy = getPolicyDN(expectedPolicy)
	if len(expectedPolicy) != len(actualPolicy) {
		t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
	}
	for i := 0; i < len(expectedPolicy); i++ {
		if expectedPolicy[i] != actualPolicy[i] {
			t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
		}
	}
}

func TestRetrieveChainOptionFromString(t *testing.T) {
	co := retrieveChainOptionFromString("RoOt-fIrSt")
	if co != retrieveChainOptionRootFirst {
		t.Fatalf("retrieveChainOptionFromString did not return the expected value of %v -- Actual value %v", retrieveChainOptionRootFirst, co)
	}
	co = retrieveChainOptionFromString("IGNORE")
	if co != retrieveChainOptionIgnore {
		t.Fatalf("retrieveChainOptionFromString did not return the expected value of %v -- Actual value %v", retrieveChainOptionIgnore, co)
	}
	co = retrieveChainOptionFromString("RoOt-LaSt")
	if co != retrieveChainOptionRootLast {
		t.Fatalf("retrieveChainOptionFromString did not return the expected value of %v -- Actual value %v", retrieveChainOptionRootLast, co)
	}
	co = retrieveChainOptionFromString("some value")
	if co != retrieveChainOptionRootLast {
		t.Fatalf("retrieveChainOptionFromString did not return the expected value of %v -- Actual value %v", retrieveChainOptionRootLast, co)
	}
}

func TestNewPEMCertificateCollectionFromResponse(t *testing.T) {
	var (
		tppResponse = "c3ViamVjdD1DTj1jZXJ0YWZpLWJvbmpvLnZlbmFmaS5jb20sIE9VPVF1YWxpdHkgQXNzdXJhbmNlLCBPVT1FbmdpbmVlcmluZywgTz0iVmVuYWZpLCBJbmMuIiwgTD1TTEMsIFM9VXRhaCwgQz1VUw0KaXNzdWVyPUNOPVZlblFBIENsYXNzIEcgQ0EsIERDPXZlbnFhLCBEQz12ZW5hZmksIERDPWNvbQ0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlHbWpDQ0JZS2dBd0lCQWdJS1ZPQkRWQUFCQUFCUXl6QU5CZ2txaGtpRzl3MEJBUVVGQURCZk1STXdFUVlLDQpDWkltaVpQeUxHUUJHUllEWTI5dE1SWXdGQVlLQ1pJbWlaUHlMR1FCR1JZR2RtVnVZV1pwTVJVd0V3WUtDWkltDQppWlB5TEdRQkdSWUZkbVZ1Y1dFeEdUQVhCZ05WQkFNVEVGWmxibEZCSUVOc1lYTnpJRWNnUTBFd0hoY05NVFl3DQpNakkyTWpFek56TXpXaGNOTVRZd016QXlNakV6TnpNeldqQ0JsakVMTUFrR0ExVUVCaE1DVlZNeERUQUxCZ05WDQpCQWdUQkZWMFlXZ3hEREFLQmdOVkJBY1RBMU5NUXpFVk1CTUdBMVVFQ2hNTVZtVnVZV1pwTENCSmJtTXVNUlF3DQpFZ1lEVlFRTEV3dEZibWRwYm1WbGNtbHVaekVhTUJnR0ExVUVDeE1SVVhWaGJHbDBlU0JCYzNOMWNtRnVZMlV4DQpJVEFmQmdOVkJBTVRHR05sY25SaFpta3RZbTl1YW04dWRtVnVZV1pwTG1OdmJUQ0NBU0l3RFFZSktvWklodmNODQpBUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBUEZnbVl1LzRBV0p3SHNtdTRFS3c5Z3Y2bXZweU9DdG5UbjAxNEp2DQpyanV3MStybVJpOXZIUGFoM3hmL255aUZpaFlvSEl5aEZ1RXIrVGZLSE5QQTRiTkE4ZkFvN2lBK012aFRpaU0zDQpDakZJenZYVTlZT3IydmU5MmRKMjM3TDF0Z3FUeGhiZXdOQ0hBdEFrWW00V2RVbUlFZlhMclplUk9oQ1QvQkJSDQpiUDYraTQzWTFxRkw3VnhxWjE0WjBudXhHdDYzdkg4TUx0VitHeWR5T05kdVk2eldOM3FpRmhjeWlValJDMjJyDQprTWlQaWEwQ0dlS0lOWDRNc2lWQ0JmRVdYYTZTVjViSE1ZeE5vUzNkdVRtTUdoQmdsdi9uVlVlR0pKL2tjWkNQDQo5VFREU25qc3BjZFI5SStFVUtYTTBObEs4Z084b1NGZ2lGdWlKdnlQeXFtZjNlTUNBd0VBQWFPQ0F4NHdnZ01hDQpNQjBHQTFVZERnUVdCQlF5UmR3MVZmWU5wMVNZV2ZoRlBqaEw0UjE0b2pBZkJnTlZIU01FR0RBV2dCVHpmaUpXDQp4SGsrNUZJN1JjaCtvcFZjb2xoYWVEQ0JzQVlEVlIwZkJJR29NSUdsTUlHaW9JR2ZvSUdjaGs5b2RIUndPaTh2DQpkbVZ1Y1dFdE1tczRMV2xqWVRFdWRtVnVjV0V1ZG1WdVlXWnBMbU52YlM5RFpYSjBSVzV5YjJ4c0wxWmxibEZCDQpKVEl3UTJ4aGMzTWxNakJISlRJd1EwRW9NU2t1WTNKc2hrbG1hV3hsT2k4dlZtVnVVVUV0TW1zNExVbERRVEV1DQpkbVZ1Y1dFdWRtVnVZV1pwTG1OdmJTOURaWEowUlc1eWIyeHNMMVpsYmxGQklFTnNZWE56SUVjZ1EwRW9NU2t1DQpZM0pzTUlJQmdnWUlLd1lCQlFVSEFRRUVnZ0YwTUlJQmNEQ0J2UVlJS3dZQkJRVUhNQUtHZ2JCc1pHRndPaTh2DQpMME5PUFZabGJsRkJKVEl3UTJ4aGMzTWxNakJISlRJd1EwRXNRMDQ5UVVsQkxFTk9QVkIxWW14cFl5VXlNRXRsDQplU1V5TUZObGNuWnBZMlZ6TEVOT1BWTmxjblpwWTJWekxFTk9QVU52Ym1acFozVnlZWFJwYjI0c1JFTTlkbVZ1DQpjV0VzUkVNOWRtVnVZV1pwTEVSRFBXTnZiVDlqUVVObGNuUnBabWxqWVhSbFAySmhjMlUvYjJKcVpXTjBRMnhoDQpjM005WTJWeWRHbG1hV05oZEdsdmJrRjFkR2h2Y21sMGVUQjFCZ2dyQmdFRkJRY3dBb1pwWm1sc1pUb3ZMMVpsDQpibEZCTFRKck9DMUpRMEV4TG5abGJuRmhMblpsYm1GbWFTNWpiMjB2UTJWeWRFVnVjbTlzYkM5V1pXNVJRUzB5DQphemd0U1VOQk1TNTJaVzV4WVM1MlpXNWhabWt1WTI5dFgxWmxibEZCSUVOc1lYTnpJRWNnUTBFb01Ta3VZM0owDQpNRGNHQ0NzR0FRVUZCekFCaGl0b2RIUndPaTh2ZG1WdWNXRXRNbXM0TFdsallURXVkbVZ1Y1dFdWRtVnVZV1pwDQpMbU52YlM5dlkzTndNQXNHQTFVZER3UUVBd0lGb0RBN0Jna3JCZ0VFQVlJM0ZRY0VMakFzQmlRckJnRUVBWUkzDQpGUWlCajRseWhJU3dhdldkRUllVy8zekVpUlZnZ3FUSFJvZjd2eXNDQVdRQ0FSY3dFd1lEVlIwbEJBd3dDZ1lJDQpLd1lCQlFVSEF3RXdHd1lKS3dZQkJBR0NOeFVLQkE0d0REQUtCZ2dyQmdFRkJRY0RBVEFqQmdOVkhSRUVIREFhDQpnaGhqWlhKMFlXWnBMV0p2Ym1wdkxuWmxibUZtYVM1amIyMHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRHNKDQpCaG1hTE5CbnZ0dWNHSHFJbXQ5dUhlSDBWUngwVHF5cEh2N21LTE10YTZubG1iTEMvVzdFV3hrenFlanFPall1DQp1eUIxSU1DOENyNUliTFo0elc3eW5QN1E0ZmNJMldPbFdWQVJTYkRzSVhXaml2SmV0dTBjL2xIMzBuaFNLQWk4DQpDV1JVZVBSckdsT3RZY1BrQnM1RlNxbzdMQjdoNmtXak9wRGR2bVpaK015OTdDSURNOTdTUjRjaGpQUFZxNkhDDQpCc3NoWTk3Y05rekxYbjBsTTRtZTBYZzNkMzM5SVBQam5qYm9FeWFoNjVqa2FpeGtVNVRIbUt5ei9JYlZjTjB2DQpjWWNBZVBFZ2FFdm9WdU1oNzgzS1R3K1ZrTERQQ0Z3Z3F5d0h3aEdxNVBkWmdXazZJbk9CTDQzciszNjNiVlFFDQpjSG92SFQ5Z0hIUUFmdGo5TVdjPQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ0KDQpzdWJqZWN0PUNOPVZlblFBIENsYXNzIEcgQ0EsIERDPXZlbnFhLCBEQz12ZW5hZmksIERDPWNvbQ0KaXNzdWVyPUNOPVZlblFBIENBLCBEQz12ZW5xYSwgREM9dmVuYWZpLCBEQz1jb20NCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQ0KTUlJR0d6Q0NCUU9nQXdJQkFnSUtLMGtqSFFBQUFDYUhXakFOQmdrcWhraUc5dzBCQVFVRkFEQlhNUk13RVFZSw0KQ1pJbWlaUHlMR1FCR1JZRFkyOXRNUll3RkFZS0NaSW1pWlB5TEdRQkdSWUdkbVZ1WVdacE1SVXdFd1lLQ1pJbQ0KaVpQeUxHUUJHUllGZG1WdWNXRXhFVEFQQmdOVkJBTVRDRlpsYmxGQklFTkJNQjRYRFRFME1ETXdPVEEzTXpJdw0KTjFvWERURTJNRE13T1RBM05ESXdOMW93WHpFVE1CRUdDZ21TSm9tVDhpeGtBUmtXQTJOdmJURVdNQlFHQ2dtUw0KSm9tVDhpeGtBUmtXQm5abGJtRm1hVEVWTUJNR0NnbVNKb21UOGl4a0FSa1dCWFpsYm5GaE1Sa3dGd1lEVlFRRA0KRXhCV1pXNVJRU0JEYkdGemN5QkhJRU5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQw0KQVFFQXJSTVBUcndYUmFENzFTenkwNzBKUUMxbHcrazlMZmhEN3RMcW43bHI4T2cyNDIrbHhGRVJGb2xRZFlXNg0KdjB1dmNuWnJKeEdqK2MzQkp2N0pMU2RMdW1ONCtOOXorQ09sSGoyaElFbVp1SC8vYTNpS0E1K1krNDZ3c1dxTQ0KTU5GeG9uTVVZRFJ0SC9jb2N4L1ltN3lFKzhEeXVUWGM0elozOGhnRml1c0RyQ0g5ZDR6S0VkUXJQaUxjNUVnSQ0Kb2V3YTBKRml1ZG03S3BoMnRoNzVvK0t3eVVYRW1mQVVqSW9HbENDN0YvMEdSRVBpajd0T2ZnWEtvZE5WWHozSw0KemZ1Y2cwcDh2ZjN3ZDVLNnhuekcxRm8vMG8zR2xIWm1NNVRmTER1cngvbWdtZGU4TGZ0QzZCSHRkQkMrcHdwMA0KcHZ5TVVKYWIwQnI2QWxaZVpHMDRJclZQQndJREFRQUJvNElDM3pDQ0F0c3dFZ1lKS3dZQkJBR0NOeFVCQkFVQw0KQXdFQUFUQWpCZ2tyQmdFRUFZSTNGUUlFRmdRVWpSL1VHc3lCeWlZYlVSZWIxSnpyOVRrNURtY3dIUVlEVlIwTw0KQkJZRUZQTitJbGJFZVQ3a1VqdEZ5SDZpbFZ5aVdGcDRNQmtHQ1NzR0FRUUJnamNVQWdRTUhnb0FVd0IxQUdJQQ0KUXdCQk1Bc0dBMVVkRHdRRUF3SUJoakFTQmdOVkhSTUJBZjhFQ0RBR0FRSC9BZ0VBTUI4R0ExVWRJd1FZTUJhQQ0KRkVaV2piZllza2JUM3lIb1JCSThVQk5CTERzQk1JSUJXd1lEVlIwZkJJSUJVakNDQVU0d2dnRktvSUlCUnFDQw0KQVVLR1AyaDBkSEE2THk4eWF6Z3RkbVZ1Y1dFdGNHUmpMblpsYm5GaExuWmxibUZtYVM1amIyMHZRMlZ5ZEVWdQ0KY205c2JDOVdaVzVSUVNVeU1FTkJMbU55YklhQnYyeGtZWEE2THk4dlEwNDlWbVZ1VVVFbE1qQkRRU3hEVGoweQ0KYXpndGRtVnVjV0V0Y0dSakxFTk9QVU5FVUN4RFRqMVFkV0pzYVdNbE1qQkxaWGtsTWpCVFpYSjJhV05sY3l4RA0KVGoxVFpYSjJhV05sY3l4RFRqMURiMjVtYVdkMWNtRjBhVzl1TEVSRFBYWmxibkZoTEVSRFBYWmxibUZtYVN4RQ0KUXoxamIyMC9ZMlZ5ZEdsbWFXTmhkR1ZTWlhadlkyRjBhVzl1VEdsemREOWlZWE5sUDI5aWFtVmpkRU5zWVhOeg0KUFdOU1RFUnBjM1J5YVdKMWRHbHZibEJ2YVc1MGhqMW1hV3hsT2k4dk1tczRMWFpsYm5GaExYQmtZeTUyWlc1eA0KWVM1MlpXNWhabWt1WTI5dEwwTmxjblJGYm5KdmJHd3ZWbVZ1VVVFZ1EwRXVZM0pzTUlIRUJnZ3JCZ0VGQlFjQg0KQVFTQnR6Q0J0RENCc1FZSUt3WUJCUVVITUFLR2dhUnNaR0Z3T2k4dkwwTk9QVlpsYmxGQkpUSXdRMEVzUTA0OQ0KUVVsQkxFTk9QVkIxWW14cFl5VXlNRXRsZVNVeU1GTmxjblpwWTJWekxFTk9QVk5sY25acFkyVnpMRU5PUFVOdg0KYm1acFozVnlZWFJwYjI0c1JFTTlkbVZ1Y1dFc1JFTTlkbVZ1WVdacExFUkRQV052YlQ5alFVTmxjblJwWm1sag0KWVhSbFAySmhjMlUvYjJKcVpXTjBRMnhoYzNNOVkyVnlkR2xtYVdOaGRHbHZia0YxZEdodmNtbDBlVEFOQmdrcQ0KaGtpRzl3MEJBUVVGQUFPQ0FRRUFUTkE4Q3d1bDFVQlFKSGQrNTBiOWc0am5YWDdLZitiVVVtRTlpSkdPcjJhQg0KRTcvTUFIR2RqZnR2ZEpZMFgrbDFoOFhTM09hcXVvOHRyZEdseGg5ZEJyUUVZUDJZbFhuSGdtWTJ4ckk5MmJ6ZA0KaWkzQjlaekxOS2JNTVBqb3d1alplQjNHbXl0ZE5adksrZ2hXWlJaOUEyd05nWUs0T1RWSmpsTURkOUw4NTU4VA0KeURuRXhlaW5JMjRYK3o4Q0YxYllSNWRYMU5KVGhjd0x3UlBRZDdFT1FxWXJmSlYvN2hza2xiQXlwTEFxZVBYdA0KUDlCK0RRNWJ3RmFqZ2VMNWVuOVVPZmtKdjM0WTZ4aVp3NXVaRnVKRDNRRnF3cGM1VTZTdGFGZmt0WXNLZFluSw0KMnlrdE5IQ2l1UmpGanpZMjdUMlNzMmtuRUliTGpPSlJaK0dSVnhQbTBRPT0NCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg0Kc3ViamVjdD1DTj1WZW5RQSBDQSwgREM9dmVucWEsIERDPXZlbmFmaSwgREM9Y29tDQppc3N1ZXI9Q049VmVuUUEgQ0EsIERDPXZlbnFhLCBEQz12ZW5hZmksIERDPWNvbQ0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlEbmpDQ0FvYWdBd0lCQWdJUVNUSEl5LzVKdEo1RDJJb3BHell1MnpBTkJna3Foa2lHOXcwQkFRVUZBREJYDQpNUk13RVFZS0NaSW1pWlB5TEdRQkdSWURZMjl0TVJZd0ZBWUtDWkltaVpQeUxHUUJHUllHZG1WdVlXWnBNUlV3DQpFd1lLQ1pJbWlaUHlMR1FCR1JZRmRtVnVjV0V4RVRBUEJnTlZCQU1UQ0ZabGJsRkJJRU5CTUI0WERURXlNVEV3DQpPVEl5TkRrd00xb1hEVEUzTVRFd09USXlOVGd6TWxvd1Z6RVRNQkVHQ2dtU0pvbVQ4aXhrQVJrV0EyTnZiVEVXDQpNQlFHQ2dtU0pvbVQ4aXhrQVJrV0JuWmxibUZtYVRFVk1CTUdDZ21TSm9tVDhpeGtBUmtXQlhabGJuRmhNUkV3DQpEd1lEVlFRREV3aFdaVzVSUVNCRFFUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCDQpBSmJyUlUwYUp3cGRpdGx3NGM4UGxMRWM0dmh0TXVUSVZDRTJlR21RM296U0J5by9yZ2ZibnlYalRJWFI5T3lmDQpmYkwvMXdNUTN3aWVaNitvUG1yZCs2NXJEK3lLWmMralpQU3p1WkNrbExnVG1uNVBoS3EzcUc2QS9nOUFrNnY4DQpVYmhoZjVvaGNkdjhneldvMjJoMEtYK1BMMFJCWlMrWm8rSGZDOGRWdUIzdWxUQkFjeG9PSmNWVzJCTTBBNUI2DQpWZkF6K0hhZjJXM2lxM3FPcTY4WGFSSmgxL3VsN2VjZXVmSC9XSElUTldYT0xuZXVkcldFbG00aVU4MkRiS1ZSDQp4VkNrY2tUT3RQM01ZNkY3aUcxTnhZYURDbXY0MTJhclpUd3FhR09hVnQ2YTBmdkY5Uy9mczRVK1M1QThxUmtODQo4QUY4dktGM3RXQXJGbk9maVorckhoc0NBd0VBQWFObU1HUXdFd1lKS3dZQkJBR0NOeFFDQkFZZUJBQkRBRUV3DQpDd1lEVlIwUEJBUURBZ0dHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkVaV2piZllza2JUDQozeUhvUkJJOFVCTkJMRHNCTUJBR0NTc0dBUVFCZ2pjVkFRUURBZ0VBTUEwR0NTcUdTSWIzRFFFQkJRVUFBNElCDQpBUUFWdXkyemR1Qkc2WFhVVHg1Z25aUWxBYStmdVB2LzdHMzMyWE9VcWN0NkQ1UmRVTjlVZDlRM2MxR2NVcmR4DQp0NzFvbS9xV3cxSmhnbnZIWTJJbG9wcTFFdHdZY3JwZitWcThGR0swZVpLa1Q3MEFLRWdTTTYrODZhczdzcVFzDQozbklvSkZCWU9CTG0xRHo0em1zNTFWZ2k3NXFDbDRzVzBUa3NJUHFGNlpGUnNIVHlmYU5wKzZ0RG5jaXZoZkowDQovNzJvdHVyZzdUMlgyVm9qMkY3NG1PMyt1bHpkWEgwNnhiZDFORlJvemFZZ0VCMjFVNVMwc2hTcmRPR0hCMVI4DQp0Z0tidU1XUGplVnZqR3k0NU5LNVhUSURRTHpyOWZiTE0zKzdPRGZiajBxdHZ2dnBxclV3bGhLbjMwNTJSZ05MDQoycERqY1NyazBZTVU1L1ZYNElXcjd2cloNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg0K"
	)

	col, err := newPEMCollectionFromResponse(tppResponse, certificate.ChainOptionRootLast)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if len(col.Chain) != 2 {
		t.Fatalf("PEM Chain did not contain the expected number of elements 2, actual count %d", len(col.Chain))
	}
}

func TestGenerateRequest(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
}

func TestGenerateRequestWithLockedMgmtType(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	zoneConfig.CustomAttributeValues[tppAttributeManagementType] = "Monitoring"
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err == nil {
		t.Fatalf("Error expected, request should not be generated with mgmt type set to Monitoring")
	}
}

func TestGenerateRequestWithNoUserProvidedCSRAllowed(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	zoneConfig.CustomAttributeValues[tppAttributeManualCSR] = "0"
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err == nil {
		t.Fatalf("Error expected, request should not be generated with Manual CSR set to 0")
	}
}

func TestGenerateRequestWithLockedKeyConfiguration(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	zoneConfig.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{endpoint.AllowedKeyConfiguration{KeyType: certificate.KeyTypeECDSA, KeyCurves: []certificate.EllipticCurve{certificate.EllipticCurveP384}}}
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.KeyType = certificate.KeyTypeRSA
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err == nil {
		t.Fatalf("Error expected, request should not be generated with key type set to RSA")
	}
}

func TestGetHttpClient(t *testing.T) {
	tpp := Connector{}
	if tpp.getHTTPClient() == nil {
		t.Fatalf("Failed to get http client")
	}
}
