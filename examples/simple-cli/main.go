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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	"io/ioutil"
	t "log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {

	if len(os.Args) != 2 || os.Args[1] == "" {
		t.Fatalf("Usage: ./$0 common.name.venafi.example.com")
	}
	var commonName = os.Args[1]

	//
	// 0. Get client instance based on connection config
	//
	config := tppConfig
	//config := cloudConfig
	//config := mockConfig
	c, err := vcert.NewClient(config)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}

	//
	// 1.1. Compose request object
	//
	//Not all Venafi Cloud providers support IPAddress and EmailAddresses extensions.
	var enrollReq = &certificate.Request{}
	switch {
	case config.ConnectorType == endpoint.ConnectorTypeTPP || config.ConnectorType == endpoint.ConnectorTypeFake:
		enrollReq = &certificate.Request{
			Subject: pkix.Name{
				CommonName:         commonName,
				Organization:       []string{"Venafi.com"},
				OrganizationalUnit: []string{"Integration Team"},
				Locality:           []string{"Salt Lake"},
				Province:           []string{"Salt Lake"},
				Country:            []string{"US"},
			},
			DNSNames: []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},

			EmailAddresses: []string{"e1@venafi.example.com", "e2@venafi.example.com"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)},
			CsrOrigin:      certificate.LocalGeneratedCSR,
			KeyType:        certificate.KeyTypeRSA,
			KeyLength:      2048,
			ChainOption:    certificate.ChainOptionRootLast,
			KeyPassword:    "newPassw0rd!",
			//Before setting custom field in request you need to configure custom field on TPP
			CustomFields: []certificate.CustomField{
				{Name: "custom", Value: "2019-12-10"},
			},
		}
	case config.ConnectorType == endpoint.ConnectorTypeCloud:
		enrollReq = &certificate.Request{
			Subject: pkix.Name{
				CommonName:         commonName,
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

	}

	//
	// 1.2. Generate private key and certificate request (CSR) based on request's options
	//
	err = c.GenerateRequest(nil, enrollReq)
	if err != nil {
		t.Fatalf("could not generate certificate request: %s", err)
	}

	//
	// 1.3. Submit certificate request, get request ID as a response
	//
	requestID, err := c.RequestCertificate(enrollReq)
	if err != nil {
		t.Fatalf("could not submit certificate request: %s", err)
	}
	t.Printf("Successfully submitted certificate request. Will pickup certificate by ID %s", requestID)

	//
	// 1.4. Retrieve certificate using request ID obtained on previous step, get PEM collection as a response
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
	// 1.5. (optional) Add certificate's private key to PEM collection
	//
	_ = pcc.AddPrivateKey(enrollReq.PrivateKey, []byte(enrollReq.KeyPassword))

	t.Printf("Successfully picked up certificate for %s", commonName)
	pp(pcc)

	//
	// 2.1. Compose renewal object
	//
	renewReq := &certificate.RenewalRequest{
		// certificate is identified using DN
		CertificateDN: requestID,
		// ..or SHA1 Thumbprint
		// Thumbprint: "",
		//CertificateRequest: certificate.Request{}
	}

	//
	// 2.2. Submit renewal request
	//
	newRequestID, err := c.RenewCertificate(renewReq)
	if err != nil {
		t.Fatalf("could not submit certificate renewal request: %s", err)
	}
	t.Printf("Successfully submitted certificate renewal request. Will pickup certificate by ID %s", newRequestID)

	//
	// 2.3. Retrieve certificate using request ID obtained on previous step, get PEM collection as a response
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
	// 3.1. Compose revocation object
	//
	revokeReq := &certificate.RevocationRequest{
		CertificateDN: requestID,
		Reason:        "key-compromise",
		Comments:      "revocation comment below",
		Disable:       false,
	}

	//
	// 3.2. Submit revocation request (not supported in Venafi Cloud)
	//
	if config.ConnectorType != endpoint.ConnectorTypeCloud {
		err = c.RevokeCertificate(revokeReq)
		if err != nil {
			t.Fatalf("could not submit certificate revocation request: %s", err)
		}
		t.Printf("Successfully submitted revocation request for %s", requestID)
	}
	//
	// 4. Import certificate to another object of the same Zone
	//
	var importReq = &certificate.ImportRequest{}
	switch {
	case config.ConnectorType == endpoint.ConnectorTypeTPP || config.ConnectorType == endpoint.ConnectorTypeFake:
		importObjectName := fmt.Sprintf("%s-imported", commonName)
		importReq = &certificate.ImportRequest{
			// if PolicyDN is empty, it is taken from cfg.Zone
			ObjectName:      importObjectName,
			CertificateData: pcc.Certificate,
			PrivateKeyData:  pcc.PrivateKey,
			Password:        "newPassw0rd!",
			Reconcile:       false,
		}
	case config.ConnectorType == endpoint.ConnectorTypeCloud:
		importObjectName := fmt.Sprintf("%s-imported", commonName)
		importReq = &certificate.ImportRequest{
			// if PolicyDN is empty, it is taken from cfg.Zone
			ObjectName:      importObjectName,
			CertificateData: pcc.Certificate,
			PrivateKeyData:  "",
			Reconcile:       false,
		}
	}
	importResp, err := c.ImportCertificate(importReq)
	if err != nil {
		t.Fatalf("could not import certificate: %s", err)
	}
	pp(importReq)
	pp(importResp)
	t.Printf("Successfully imported certificate to %s", importResp.CertificateDN)

	//
	// 5. Retrieve certificate & key from new object
	//
	var importedRetriveReq = &certificate.Request{}
	switch {
	case config.ConnectorType == endpoint.ConnectorTypeTPP || config.ConnectorType == endpoint.ConnectorTypeFake:
		importedRetriveReq = &certificate.Request{
			PickupID:        importResp.CertificateDN,
			Timeout:         180 * time.Second,
			KeyPassword:     "newPassw0rd!",
			FetchPrivateKey: true,
		}
	case config.ConnectorType == endpoint.ConnectorTypeCloud:
		//You can retrieve imported certificate by thumbprint or certificate Id.
		thumbprint := calcThumbprint(pcc.Certificate)
		importedRetriveReq = &certificate.Request{
			Thumbprint: thumbprint,
			//CertID: importResp.CertId,
			Timeout: 180 * time.Second,
		}
	}

	pcc3, err := c.RetrieveCertificate(importedRetriveReq)
	if err != nil {
		t.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}
	t.Printf("Successfully retrieved imported certificate from %s", importResp.CertificateDN)
	pp(pcc3)

	//
	// 6. Get refresh token and refresh access token
	//
	if config.ConnectorType == endpoint.ConnectorTypeTPP {
		var connectionTrustBundle *x509.CertPool
		trustBundleFilePath := os.Getenv("TRUST_BUNDLE_PATH")
		if trustBundleFilePath != "" {
			buf, err := ioutil.ReadFile(trustBundleFilePath)
			if err != nil {
				panic(err)
			}
			connectionTrustBundle = x509.NewCertPool()
			if !connectionTrustBundle.AppendCertsFromPEM(buf) {
				panic("Failed to parse PEM trust bundle")
			}
		}
		tppConnector, err := tpp.NewConnector(config.BaseUrl, "", false, connectionTrustBundle)
		if err != nil {
			t.Fatalf("could not create TPP connector: %s", err)
		}

		resp, err := tppConnector.GetRefreshToken(&endpoint.Authentication{
			User:     os.Getenv("TPP_USER"),
			Password: os.Getenv("TPP_PASSWORD"),
			Scope:    "certificate:manage,revoke;", ClientId: "websdk"})
		if err != nil {
			panic(err)
		}
		fmt.Printf("Refresh token is %s", resp.Refresh_token)

		auth := &endpoint.Authentication{RefreshToken: resp.Refresh_token, ClientId: "websdk"}
		err = tppConnector.Authenticate(auth)
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}

	}

	//
	// 7. Audit certificates list in zone
	//

	_l := 10
	certList, err := c.ListCertificates(endpoint.Filter{Limit: &_l})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ID             Common Name              Expire")
	for _, cert := range certList {
		validTo := cert.ValidTo.String()
		if cert.ValidTo.Before(time.Now()) {
			validTo = fmt.Sprintf("\033[1;31m%s\033[0m", validTo)
		}
		fmt.Printf("%v    %v     %v\n", cert.ID, cert.CN, validTo)
	}
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

func calcThumbprint(cert string) string {
	p, _ := pem.Decode([]byte(cert))
	h := sha1.New()
	h.Write(p.Bytes)
	buf := h.Sum(nil)
	return strings.ToUpper(fmt.Sprintf("%x", buf))
}
