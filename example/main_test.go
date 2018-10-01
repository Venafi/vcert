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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/test"
	"net/http"
	"testing"
	"time"
)

var effectiveConfig = tppConfig

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func TestRequestCertificate(t *testing.T) {
	//
	// 0. get client instance based on connection config
	//
	c, err := vcert.NewClient(effectiveConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}

	//
	// 1. compose request object
	//
	req := &certificate.Request{
		Subject: pkix.Name{
			CommonName:         "client.venafi.example.com",
			Organization:       []string{"Venafi.com"},
			OrganizationalUnit: []string{"Integration Team"},
			Locality:           []string{"Salt Lake"},
			Province:           []string{"Salt Lake"},
			Country:            []string{"US"},
		},
		DNSNames: []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
		//EmailAddresses: []string{"e1@venafi.example.com", "e2@venafi.example.com"},
		//IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)},
		CsrOrigin:   certificate.LocalGeneratedCSR,
		KeyType:     certificate.KeyTypeRSA,
		KeyLength:   2048,
		ChainOption: certificate.ChainOptionRootLast,
		KeyPassword: "newPassw0rd!",
	}

	//
	// 2. generate private key and certificate request (CSR) based on request's options
	//
	err = c.GenerateRequest(nil, req)
	if err != nil {
		t.Fatalf("could not generate certificate request: %s", err)
	}

	//
	// 3. submit certificate request, get request ID as a response
	//
	requestID, err := c.RequestCertificate(req, "")
	if err != nil {
		t.Fatalf("could not submit certificate request: %s", err)
	}

	//
	// 4. retrieve certificate using request ID obtained on previous step, get PEM collection as a response
	//
	req.PickupID = requestID
	req.Timeout = 180 * time.Second
	pcc, err := c.RetrieveCertificate(req)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}

	//
	// 5. (optional) add certificate's private key to PEM collection
	//
	pcc.AddPrivateKey(req.PrivateKey, []byte(req.KeyPassword))

	//
	// 6. Done!
	//
	pp(requestID)
	pp(pcc)
}

func TestRevokeCertificate(t *testing.T) {
	//
	// 0. get client instance based on connection config
	//
	c, err := vcert.NewClient(effectiveConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}

	//
	// 1. compose revocation object
	//
	req := &certificate.RevocationRequest{
		CertificateDN: `\VED\Policy\` + effectiveConfig.Zone + `\client.venafi.example.com`,
		Reason:        "key-compromise",
		Comments:      "revocation comment below",
		Disable:       false,
	}

	//
	// 2. submit revocation request
	//
	err = c.RevokeCertificate(req)
	if err != nil {
		t.Fatalf("could not submit certificate revocation request: %s", err)
	}

	//
	// 3. Done!
	//
}

func TestRenewCertificate(t *testing.T) {
	//
	// 0. get client instance based on connection config
	//
	c, err := vcert.NewClient(effectiveConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}

	//
	// 1. compose renewal object
	//
	renewReq := &certificate.RenewalRequest{
		// certificate is identified using DN
		CertificateDN: `\VED\Policy\` + effectiveConfig.Zone + `\client.venafi.example.com`,
		// ..or SHA1 Thumbprint
		// Thumbprint: "",
		//CertificateRequest: certificate.Request{}
	}

	//
	// 2. submit renewal request
	//
	requestID, err := c.RenewCertificate(renewReq)
	if err != nil {
		t.Fatalf("could not submit certificate renewal request: %s", err)
	}

	//
	// 4. retrieve certificate using request ID obtained on previous step, get PEM collection as a response
	//
	req := &certificate.Request{
		PickupID: requestID,
		Timeout:  180 * time.Second,
	}
	pcc, err := c.RetrieveCertificate(req)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}

	//
	// 3. Done!
	//
	pp(requestID)
	pp(pcc)

	// decoding renewed certificate
	block, _ := pem.Decode([]byte(pcc.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("could not get PEM certificate block")
	}
	cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		t.Fatalf("could not parse x509 certificate: %s", err)
	}

	// renewed certificate serial number
	pp(cert.SerialNumber)

}

func TestImportCertificate(t *testing.T) {
	//
	// 0. get client instance based on connection config
	//
	c, err := vcert.NewClient(effectiveConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}

	//
	// 1. compose, generate, submit request and retrieve certificate
	//
	req := &certificate.Request{
		Subject: pkix.Name{
			CommonName:         "client.venafi.example.com",
			Organization:       []string{"Venafi.com"},
			OrganizationalUnit: []string{"Integration Team"},
			Locality:           []string{"Salt Lake"},
			Province:           []string{"Salt Lake"},
			Country:            []string{"US"},
		},
		DNSNames:    []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
		CsrOrigin:   certificate.LocalGeneratedCSR,
		KeyType:     certificate.KeyTypeRSA,
		KeyLength:   2048,
		ChainOption: certificate.ChainOptionRootLast,
		KeyPassword: "newPassw0rd!",
	}

	err = c.GenerateRequest(nil, req)
	if err != nil {
		t.Fatalf("could not generate certificate request: %s", err)
	}

	requestID, err := c.RequestCertificate(req, "")
	if err != nil {
		t.Fatalf("could not submit certificate request: %s", err)
	}

	req.PickupID = requestID
	req.Timeout = 180 * time.Second
	pcc, err := c.RetrieveCertificate(req)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}

	pcc.AddPrivateKey(req.PrivateKey, []byte(req.KeyPassword))

	pp(requestID)
	pp(pcc)

	//
	// 2. Import certificate to another object of the same Zone
	//
	importCertDN := test.RandCN()
	importReq := &certificate.ImportRequest{
		// if PolicyDN is empty, it is taken from cfg.Zone
		ObjectName:      importCertDN,
		CertificateData: pcc.Certificate,
		PrivateKeyData:  pcc.PrivateKey,
		Password:        "newPassw0rd!",
		Reconcile:       false,
	}
	importResp, err := c.ImportCertificate(importReq)
	if err != nil {
		t.Fatalf("could not import certificate: %s", err)
	}
	pp(importReq)
	pp(importResp)

	//
	// 3. retrieve certificate & key from new object
	//
	req = &certificate.Request{
		PickupID:        importResp.CertificateDN,
		Timeout:         180 * time.Second,
		KeyPassword:     "newPassw0rd!",
		FetchPrivateKey: true,
	}
	pcc2, err := c.RetrieveCertificate(req)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}
	pp(pcc2)
}
