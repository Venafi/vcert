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
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/cmd/vcert/output"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
)

var (
	logger = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
	logf   = logger.Printf
	exit   = os.Exit
)

func init() {
	setupGenCsrCommandFlags()
	setupEnrollCommandFlags()
	setupRetrieveCommandFlags()
	setupRevokeCommandFlags()
	setupRenewCommandFlags()

	flag.BoolVar(&showVersion, "version", false, "Displays the running version of the "+UtilityShortName+" utility.")
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			// logger.Fatalf() does immediately os.Exit(1)
			// so we use logger.Panic() and do recover() here to hide stacktrace
			// exit() is a function to decide what to do

			exit(1)  // it's os.Exit() by default, but can be overridden
			panic(r) // so that panic() bubbling continues (it's needed when we call main() from cli_test.go)

		}
	}()

	co, cf, _ := parseArgs()
	var tlsConfig tls.Config

	if cf.insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if cf.clientP12 != "" {
		// Load client PKCS#12 archive
		p12, err := ioutil.ReadFile(cf.clientP12)
		if err != nil {
			logger.Panicf("Error reading PKCS#12 archive file: %s", err)
		}

		blocks, err := pkcs12.ToPEM(p12, cf.clientP12PW)
		if err != nil {
			logger.Panicf("Error converting PKCS#12 archive file to PEM blocks: %s", err)
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		// Construct TLS certificate from PEM data
		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			logger.Panicf("Error reading PEM data to build X.509 certificate: %s", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(pemData)

		// Setup HTTPS client
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig

	if err := readPasswordsFromInputFlags(co, cf); err != nil {
		log.Fatal(err)
	}

	if co == commandGenCSR {
		doGenCSR(cf)
		return
	}

	cfg, err := buildConfig(cf)
	if err != nil {
		logger.Panicf("Failed to build vcert config: %s", err)
	}

	if cf.zone == "" && cfg.Zone != "" {
		cf.zone = cfg.Zone
	}

	connector, err := vcert.NewClient(cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	if co == commandRevoke {
		doRevoke(connector, cf)
		return
	}

	if co == commandEnroll {
		var req = &certificate.Request{}
		var pcc = &certificate.PEMCollection{}

		zoneConfig, err := connector.ReadZoneConfiguration(cf.zone)

		if err != nil {
			logger.Panicf("%s", err)
		}
		logf("Successfully read zone configuration for %s", cf.zone)
		req = fillCertificateRequest(req, cf)
		err = connector.GenerateRequest(zoneConfig, req)
		if err != nil {
			logger.Panicf("%s", err)
		}

		var requestedFor string
		if req.Subject.CommonName != "" {
			requestedFor = req.Subject.CommonName
		} else {
			requestedFor = cf.csrOption
		}

		logf("Successfully created request for %s", requestedFor)
		cf.pickupID, err = connector.RequestCertificate(req, cf.zone)
		if err != nil {
			logger.Panicf("%s", err)
		}
		logf("Successfully posted request for %s, will pick up by %s", requestedFor, cf.pickupID)

		if cf.noPickup {
			pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(cf.keyPassword))
			if err != nil {
				logger.Panicf("%s", err)
			}
		} else {
			req.PickupID = cf.pickupID
			req.ChainOption = certificate.ChainOptionFromString(cf.chainOption)
			req.KeyPassword = cf.keyPassword

			pcc, err = retrieveCertificate(connector, req, time.Duration(cf.timeout)*time.Second)
			if err != nil {
				logger.Panicf("%s", err)
			}
			logf("Successfully retrieved request for %s", cf.pickupID)

			if req.CsrOrigin == certificate.LocalGeneratedCSR {
				// otherwise private key can be taken from *req
				err := pcc.AddPrivateKey(req.PrivateKey, []byte(cf.keyPassword))
				if err != nil {
					log.Fatal(err)
				}
			}
		}

		result := &output.Result{
			Pcc:      pcc,
			PickupId: cf.pickupID,
			Config: &output.Config{
				Command:      int(co),
				Format:       cf.format,
				ChainOption:  certificate.ChainOptionFromString(cf.chainOption),
				AllFile:      cf.file,
				KeyFile:      cf.keyFile,
				CertFile:     cf.certFile,
				ChainFile:    cf.chainFile,
				PickupIdFile: cf.pickupIDFile,
				KeyPassword:  cf.keyPassword,
			},
		}
		err = result.Flush()

		if err != nil {
			logger.Panicf("Failed to output the results: %s", err)
		}
		return
	}

	if co == commandPickup {
		if cf.pickupIDFile != "" {
			bytes, err := ioutil.ReadFile(cf.pickupIDFile)
			if err != nil {
				logger.Panicf("Failed to read Pickup ID value: %s", err)
			}
			cf.pickupID = strings.TrimSpace(string(bytes))
		}
		var req = &certificate.Request{
			PickupID:    cf.pickupID,
			ChainOption: certificate.ChainOptionFromString(cf.chainOption),
		}
		if cf.keyPassword != "" {
			// key password is provided, which means will be requesting private key
			req.KeyPassword = cf.keyPassword
			req.FetchPrivateKey = true
		}
		var pcc *certificate.PEMCollection
		pcc, err = retrieveCertificate(connector, req, time.Duration(cf.timeout)*time.Second)
		if err != nil {
			logger.Panicf("Failed to retrieve certificate: %s", err)
		}
		logf("Successfully retrieved request for %s", cf.pickupID)

		result := &output.Result{
			Pcc:      pcc,
			PickupId: cf.pickupID,
			Config: &output.Config{
				Command:      int(co),
				Format:       cf.format,
				ChainOption:  certificate.ChainOptionFromString(cf.chainOption),
				AllFile:      cf.file,
				KeyFile:      cf.keyFile,
				CertFile:     cf.certFile,
				ChainFile:    cf.chainFile,
				PickupIdFile: cf.pickupIDFile,
				KeyPassword:  cf.keyPassword,
			},
		}
		err = result.Flush()

		if err != nil {
			logger.Panicf("Failed to output the results: %s", err)
		}
		return
	}

	if co == commandRenew {
		var req = &certificate.Request{}
		var pcc = &certificate.PEMCollection{}

		searchReq := &certificate.Request{
			PickupID:   cf.distinguishedName,
			Thumbprint: cf.thumbprint,
		}

		// here we fetch old cert anyway
		oldPcc, err := connector.RetrieveCertificate(searchReq)
		if err != nil {
			logger.Panicf("Failed to fetch old certificate by id %s: %s", cf.distinguishedName, err)
		}
		oldCertBlock, _ := pem.Decode([]byte(oldPcc.Certificate))
		if oldCertBlock == nil || oldCertBlock.Type != "CERTIFICATE" {
			logger.Panicf("Failed to fetch old certificate by id %s: PEM parse error", cf.distinguishedName)
		}
		oldCert, err := x509.ParseCertificate([]byte(oldCertBlock.Bytes))
		if err != nil {
			logger.Panicf("Failed to fetch old certificate by id %s: %s", cf.distinguishedName, err)
		}
		// now we have old one
		logf("Fetched the latest certificate. Serial: %x, NotAfter: %s", oldCert.SerialNumber, oldCert.NotAfter)

		switch true {
		case 0 == strings.Index(cf.csrOption, "file:"):
			// will be just sending CSR to backend
			req = fillCertificateRequest(req, cf)

		case "local" == cf.csrOption || "" == cf.csrOption:
			// restore certificate request from old certificate
			req = certificate.NewRequest(oldCert)
			// override values with those from command line flags
			req = fillCertificateRequest(req, cf)

		case "service" == cf.csrOption:
			// logger.Panic("service side renewal is not implemented")
			req = fillCertificateRequest(req, cf)

		default:
			logger.Panicf("unexpected -csr option: %s", cf.csrOption)
		}

		// here we ignore zone for Renew action, however, API still needs it
		zoneConfig := &endpoint.ZoneConfiguration{}

		err = connector.GenerateRequest(zoneConfig, req)
		if err != nil {
			logger.Panicf("%s", err)
		}

		requestedFor := func() string {
			if cf.distinguishedName != "" {
				return cf.distinguishedName
			}
			if cf.thumbprint != "" {
				return cf.thumbprint
			}
			return ""
		}()

		logf("Successfully created request for %s", requestedFor)

		renewReq := generateRenewalRequest(cf, req)

		cf.pickupID, err = connector.RenewCertificate(renewReq)

		if err != nil {
			logger.Panicf("%s", err)
		}
		logf("Successfully posted renewal request for %s, will pick up by %s", requestedFor, cf.pickupID)

		if cf.noPickup {
			pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(cf.keyPassword))
			if err != nil {
				logger.Panicf("%s", err)
			}
		} else {
			req.PickupID = cf.pickupID
			req.ChainOption = certificate.ChainOptionFromString(cf.chainOption)
			req.KeyPassword = cf.keyPassword

			pcc, err = retrieveCertificate(connector, req, time.Duration(cf.timeout)*time.Second)
			if err != nil {
				logger.Panicf("%s", err)
			}
			logf("Successfully retrieved request for %s", cf.pickupID)

			if req.CsrOrigin == certificate.LocalGeneratedCSR {
				// otherwise private key can be taken from *req
				err = pcc.AddPrivateKey(req.PrivateKey, []byte(cf.keyPassword))
				if err != nil {
					logger.Fatal(err)
				}
			}
		}

		// check if previous and renewed certificates are of the same private key
		newCertBlock, _ := pem.Decode([]byte(pcc.Certificate))
		if newCertBlock != nil && newCertBlock.Type == "CERTIFICATE" {
			newCert, err := x509.ParseCertificate([]byte(newCertBlock.Bytes))
			if err == nil {
				old, _ := json.Marshal(oldCert.PublicKey)
				new, _ := json.Marshal(newCert.PublicKey)
				if len(old) > 0 && string(old) == string(new) {
					logf("WARNING: private key reused")
				}
			}
		}

		result := &output.Result{
			Pcc:      pcc,
			PickupId: cf.pickupID,
			Config: &output.Config{
				Command:      int(co),
				Format:       cf.format,
				ChainOption:  certificate.ChainOptionFromString(cf.chainOption),
				AllFile:      cf.file,
				KeyFile:      cf.keyFile,
				CertFile:     cf.certFile,
				ChainFile:    cf.chainFile,
				PickupIdFile: cf.pickupIDFile,
				KeyPassword:  cf.keyPassword,
			},
		}
		err = result.Flush()

		if err != nil {
			logger.Panicf("Failed to output the results: %s", err)
		}
		return
	}

}

func doGenCSR(cf *commandFlags) {
	key, csr, err := generateCsrForCommandGenCsr(cf, []byte(cf.keyPassword))
	if err != nil {
		logger.Panicf("%s", err)
	}
	err = writeOutKeyAndCsr(cf, key, csr)
	if err != nil {
		logger.Panicf("%s", err)
	}
}

func doRevoke(connector endpoint.Connector, cf *commandFlags) {
	var revReq = &certificate.RevocationRequest{}
	switch true {
	case cf.distinguishedName != "":
		revReq.CertificateDN = cf.distinguishedName
		revReq.Disable = !cf.revocationNoRetire
	case cf.thumbprint != "":
		revReq.Thumbprint = cf.thumbprint
		revReq.Disable = false
	default:
		logger.Panicf("Certificate DN or Thumbprint is required")
		return
	}

	requestedFor := func() string {
		if cf.distinguishedName != "" {
			return cf.distinguishedName
		}
		if cf.thumbprint != "" {
			return cf.thumbprint
		}
		return ""
	}()

	revReq.Reason = cf.revocationReason
	revReq.Comments = "revocation request from command line utility"

	err := connector.RevokeCertificate(revReq)
	if err != nil {
		logger.Panicf("Failed to revoke certificate: %s", err)
	}
	logf("Successfully created revocation request for %s", requestedFor)
}
