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
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/test"
	"net/url"
	"strings"
	"testing"
	"time"
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

func TestParseCertificateDetailsResponse(t *testing.T) {
	body := `
		{
		  "CertificateAuthorityDN": "\\VED\\Policy\\devops\\msca_template",
		  "CertificateDetails": {
			"AIACAIssuerURL": [
			  "0:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt",
			  "1:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority"
			],
			"AIAKeyIdentifier": "3CAC9CA60DA130D456A73D78BC231BECB47B4D75",
			"C": "US",
			"CDPURI": "0::False:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl",
			"CN": "t1579099443-xiel.venafi.example.com",
			"EnhancedKeyUsage": "Server Authentication(1.3.6.1.5.5.7.3.1)",
			"Issuer": "CN=QA Venafi CA, DC=venqa, DC=venafi, DC=com",
			"KeyAlgorithm": "RSA",
			"KeySize": 8192,
			"KeyUsage": "KeyEncipherment, DigitalSignature",
			"L": "Las Vegas",
			"O": "Venafi, Inc.",
			"OU": [
			  "Automated Tests"
			],
			"PublicKeyHash": "8637C052479F9C4A01CC0CEE600769597DF69DA8",
			"S": "Nevada",
			"SKIKeyIdentifier": "C65C994B38A5B17841C536A8C8189C6613B02C44",
			"Serial": "6D007AAF80B115C1BE51B6F94E0000007AAF80",
			"SignatureAlgorithm": "sha256RSA",
			"SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
			"StoreAdded": "2020-01-15T14:47:02.0862587Z",
			"Subject": "CN=t1579099443-xiel.venafi.example.com, OU=Automated Tests, O=\"Venafi, Inc.\", L=Las Vegas, S=Nevada, C=US",
			"SubjectAltNameDNS": [
			  "t1579099443-xiel.venafi.example.com"
			],
			"SubjectAltNameURI": [
			  "https://example.com/test"
			],
			"TemplateMajorVersion": "100",
			"TemplateMinorVersion": "4",
			"TemplateName": "WebServer-2008(8years)",
			"TemplateOID": "1.3.6.1.4.1.311.21.8.2344178.8460394.1920656.15056892.1115285.96.9686371.12506947",
			"Thumbprint": "D9F8A14D6687824D2F25D1BE1C2A24697B84CF68",
			"ValidFrom": "2020-01-15T14:36:29.0000000Z",
			"ValidTo": "2028-01-13T14:36:29.0000000Z"
		  },
		  "Contact": [
			"local:{f47ab62f-65d4-4a7f-8a8a-cd5440ce2d60}"
		  ],
		  "CreatedBy": [
			"Web SDK"
		  ],
		  "CreatedOn": "2020-01-15T14:46:53.2296661Z",
		  "CustomFields": [
			{
			  "Name": "custom",
			  "Type": "Text",
			  "Value": [
				"2019-10-10"
			  ]
			}
		  ],
		  "DN": "\\VED\\Policy\\devops\\vcert\\t1579099443-xiel.venafi.example.com",
		  "Guid": "{d1542a81-9268-4c62-af7e-8090fac5194d}",
		  "ManagementType": "Enrollment",
		  "Name": "t1579099443-xiel.venafi.example.com",
		  "ParentDn": "\\VED\\Policy\\devops\\vcert",
		  "ProcessingDetails": {},
		  "RenewalDetails": {
			"City": "Las Vegas",
			"Country": "US",
			"KeySize": 8192,
			"Organization": "Venafi, Inc.",
			"OrganizationalUnit": [
			  "Automated Tests"
			],
			"State": "Nevada",
			"Subject": "t1579099443-xiel.venafi.example.com",
			"SubjectAltNameURI": [
			  "https://example.com/test"
			]
		  },
		  "SchemaClass": "X509 Server Certificate",
		  "ValidationDetails": {
			"LastValidationStateUpdate": "0001-01-01T00:00:00.0000000Z"
		  }
		}`

	res, err := parseCertificateDetailsResponse(200, []byte(body))
	if err != nil {
		t.Fatal(err)
	}

	if res.CustomFields[0].Value[0] != "2019-10-10" {
		t.Fatal("invalid custom field value")
	}
}

func TestRequestAndSearchCertificate(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	config, err := tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	cn := test.RandCN()
	appInfo := "APP Info " + cn
	workload := fmt.Sprintf("workload-%d", time.Now().Unix())
	instance := "devops-instance"
	cfValue := cn
	req := &certificate.Request{Timeout: time.Second * 30}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	u := url.URL{Scheme: "https", Host: "example.com", Path: "/test"}
	req.URIs = []*url.URL{&u}
	req.FriendlyName = cn
	req.CustomFields = []certificate.CustomField{
		{Name: "custom", Value: cfValue},
		{Type: certificate.CustomFieldOrigin, Value: appInfo},
	}
	req.Location = &certificate.Location{
		Instance:   instance,
		Workload:   workload,
		TLSAddress: "wwww.example.com:443",
	}

	req.KeyLength = 1024

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	certCollections, err := tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode([]byte(certCollections.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if cert.Subject.CommonName != cn {
		t.Fatalf("mismatched common names: %v and %v", cn, cert.Subject.CommonName)
	}
	if cert.URIs[0].String() != u.String() {
		t.Fatalf("mismatched URIs: %v and %v", u.String(), cert.URIs[0].String())
	}

	thumbprint := calcThumbprint(certCollections.Certificate)
	searchResult, err := tpp.searchCertificatesByFingerprint(thumbprint)
	if err != nil {
		t.Fatal(err)
	}

	guid := searchResult.Certificates[0].CertificateRequestGuid
	details, err := tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatal(err)
	}

	//check custom fields
	if details.CustomFields[0].Value[0] != cfValue {
		t.Fatalf("mismtached custom field valud: want %s but got %s", details.CustomFields[0].Value[0], cfValue)
	}

	//check installed location device
	if !strings.HasSuffix(details.Consumers[0], instance+"\\"+workload) {
		t.Fatalf("Consumer %s should end on %s", details.Consumers[0], instance+"\\"+workload)
	}

	configReq := ConfigReadDNRequest{
		ObjectDN:      getCertificateDN(ctx.TPPZone, cn),
		AttributeName: "Origin",
	}

	configResp, err := tpp.configReadDN(configReq)
	if err != nil {
		t.Fatal(err)
	}
	if configResp.Values[0] != appInfo {
		t.Fatalf("Origin attribute value should be %s, but it is %s", appInfo, configResp.Values[0])
	}

	//add one more device
	req.Location = &certificate.Location{
		Instance:   instance,
		Workload:   workload + "-1",
		TLSAddress: "wwww.example.com:443",
	}

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	//to wait until cert will be aprooved so we can check list of devices
	_, err = tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}

	details, err = tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatal(err)
	}

	if len(details.Consumers) < 1 {
		t.Fatal("There should be at least two devices in consumers")
	}
	//check installed location device
	if !strings.HasSuffix(details.Consumers[1], instance+"\\"+workload+"-1") {
		t.Fatalf("Consumer %s should end on %s", details.Consumers[1], instance+"\\"+workload+"-1")
	}

	//replace first device, second must be kept
	req.Location = &certificate.Location{
		Instance:   instance,
		Workload:   workload,
		TLSAddress: "wwww.example.com:443",
		Replace:    true,
	}

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	//to wait until cert will be aprooved so we can check list of devices
	_, err = tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}

	details, err = tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatal(err)
	}

	if len(details.Consumers) < 1 {
		t.Fatal("There should be at least two devices in consumers")
	}

	//check installed location device
	if !strings.HasSuffix(details.Consumers[0], instance+"\\"+workload+"-1") {
		t.Fatalf("Consumer %s should end on %s", details.Consumers[0], instance+"\\"+workload+"-1")
	}
}

func TestSearchDevice(t *testing.T) {
	t.Skip() //we don't use this method now, keep this test for future usage

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	authResp, err := tpp.GetRefreshToken(&endpoint.Authentication{
		User: ctx.TPPuser, Password: ctx.TPPPassword,
		Scope: "configuration:read"})
	if err != nil {
		panic(err)
	}

	err = tpp.Authenticate(&endpoint.Authentication{
		AccessToken: authResp.Access_token,
	})

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req := ConfigReadDNRequest{
		ObjectDN:      "\\VED\\Policy\\devops\\vcert\\kube-worker-1\\nginx_246",
		AttributeName: "Certificate",
	}

	resp, err := tpp.configReadDN(req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(resp)
}
