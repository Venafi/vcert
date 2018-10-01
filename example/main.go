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
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	t "log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if len(os.Args) != 2 || os.Args[1] == "" {
		t.Fatalf("Usage: ./$0 common.name.venafi.example.com")
	}
	var commonName = os.Args[1]

	//
	// 0. get client instance based on connection config
	//
	c, err := vcert.NewClient(tppConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}

	//
	// 1.1. compose request object
	//
	enrollReq := &certificate.Request{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"Venafi.com"},
			OrganizationalUnit: []string{"Integration Team"},
			Locality:           []string{"Salt Lake"},
			Province:           []string{"Salt Lake"},
			Country:            []string{"US"},
		},
		DNSNames:       []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
		EmailAddresses: []string{"e1@venafi.example.com", "e2@venafi.example.com"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)},
		CsrOrigin:      certificate.LocalGeneratedCSR,
		KeyType:        certificate.KeyTypeRSA,
		KeyLength:      2048,
		ChainOption:    certificate.ChainOptionRootLast,
		KeyPassword:    "newPassw0rd!",
	}

	//
	// 1.2. generate private key and certificate request (CSR) based on request's options
	//
	err = c.GenerateRequest(nil, enrollReq)
	if err != nil {
		t.Fatalf("could not generate certificate request: %s", err)
	}

	//
	// 1.3. submit certificate request, get request ID as a response
	//
	requestID, err := c.RequestCertificate(enrollReq, "")
	if err != nil {
		t.Fatalf("could not submit certificate request: %s", err)
	}
	t.Printf("Successfully submitted certificate request. Will pickup certificate by ID %s", requestID)

	//
	// 1.4. retrieve certificate using request ID obtained on previous step, get PEM collection as a response
	//
	pickupReq := &certificate.Request{
		PickupID: requestID,
		Timeout:  180 * time.Second,
	}
	pcc, err := c.RetrieveCertificate(pickupReq)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}

	//
	// 1.5. (optional) add certificate's private key to PEM collection
	//
	pcc.AddPrivateKey(enrollReq.PrivateKey, []byte(enrollReq.KeyPassword))

	t.Printf("Successfully picked up certificate for %s", commonName)
	pp(pcc)

	//
	// 2.1. compose renewal object
	//
	renewReq := &certificate.RenewalRequest{
		// certificate is identified using DN
		CertificateDN: requestID,
		// ..or SHA1 Thumbprint
		// Thumbprint: "",
		//CertificateRequest: certificate.Request{}
	}

	//
	// 2.2. submit renewal request
	//
	newRequestID, err := c.RenewCertificate(renewReq)
	if err != nil {
		t.Fatalf("could not submit certificate renewal request: %s", err)
	}
	t.Printf("Successfully submitted certificate renewal request. Will pickup certificate by ID %s", newRequestID)

	//
	// 2.3. retrieve certificate using request ID obtained on previous step, get PEM collection as a response
	//
	renewRetrieveReq := &certificate.Request{
		PickupID: newRequestID,
		Timeout:  180 * time.Second,
	}
	pcc2, err := c.RetrieveCertificate(renewRetrieveReq)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}

	t.Printf("Successfully retrieved renewed certificate for %s", commonName)
	t.Printf("Old serial number %s", getSerial(pcc.Certificate))
	t.Printf("New serial number %s", getSerial(pcc2.Certificate))

	//
	// 3.1. compose revocation object
	//
	revokeReq := &certificate.RevocationRequest{
		CertificateDN: requestID,
		Reason:        "key-compromise",
		Comments:      "revocation comment below",
		Disable:       false,
	}

	//
	// 3.2. submit revocation request
	//
	err = c.RevokeCertificate(revokeReq)
	if err != nil {
		t.Fatalf("could not submit certificate revocation request: %s", err)
	}
	t.Printf("Successfully submitted revocation request for %s", requestID)

	//
	// 2. Import certificate to another object of the same Zone
	//
	importObjectName := fmt.Sprintf("%s-imported", commonName)
	importReq := &certificate.ImportRequest{
		// if PolicyDN is empty, it is taken from cfg.Zone
		ObjectName:      importObjectName,
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
	t.Printf("Successfully imported certificate to %s", importResp.CertificateDN)

	//
	// 3. retrieve certificate & key from new object
	//
	importedRetriveReq := &certificate.Request{
		PickupID:        importResp.CertificateDN,
		Timeout:         180 * time.Second,
		KeyPassword:     "newPassw0rd!",
		FetchPrivateKey: true,
	}
	pcc3, err := c.RetrieveCertificate(importedRetriveReq)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}
	t.Printf("Successfully retrieved imported certificate from %s", importResp.CertificateDN)
	pp(pcc3)
}

func getSerial(crt string) *big.Int {
	block, _ := pem.Decode([]byte(crt))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("could not get PEM certificate block")
	}
	newCert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		t.Fatalf("could not parse x509 certificate: %s", err)
	}
	return newCert.SerialNumber
}
