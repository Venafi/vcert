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
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/cmd/vcert/output"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	logger = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
	logf   = logger.Printf
	exit   = os.Exit
)

func init() {
	setupRegistrationFlags()
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

			exit(1)  // it's os.Exit() by default, but can be overridden,
			panic(r) // so that panic() bubbling continues (it's needed when we call main() from cli_test.go)

		}
	}()

	co, cf, _ := parseArgs()

	if cf.insecure {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	readPasswordsFromInputFlags(co, cf)

	if co == commandGenCSR {
		doGenCSR(cf)
		return
	}

	cfg, err := buildConfig(cf)
	if err != nil {
		logger.Panicf("failed to build vcert config: %s", err)
	}

	if cf.zone == "" && cfg.Zone != "" {
		cf.zone = cfg.Zone
	}

	connector, err := vcert.NewClient(cfg) // the rest requires endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	if co == commandRegister {
		doRegister(connector, cf)
		return
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

		if cf.noPickup == true {
			pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(cf.keyPassword))
		} else {
			req.PickupID = cf.pickupID
			req.ChainOption = certificate.ChainOptionFromString(cf.chainOption)
			req.KeyPassword = cf.keyPassword

			pcc, err = retrieveCertificate(connector, req, time.Duration(cf.timeout)*time.Second)
			if err != nil {
				logger.Panicf("%s", err)
			}
			logf("Successfully retrieved request for %s", cf.pickupID)

			if cf.csrOption == "service" {
				// pcc.PrivateKey should be already encrypted by endpoint
				// so nothing to do here
			} else {
				// otherwise private key can be taken from *req
				pcc.AddPrivateKey(req.PrivateKey, []byte(cf.keyPassword))
			}
		}

		result := &output.Result{
			pcc,
			cf.pickupID,
			&output.Config{
				int(co),
				cf.format,
				certificate.ChainOptionFromString(cf.chainOption),
				cf.file,
				cf.keyFile,
				cf.certFile,
				cf.chainFile,
				cf.pickupIdFile,
				cf.keyPassword,
			},
		}
		err = result.Flush()

		if err != nil {
			logger.Panicf("Failed to output the results: %s", err)
		}
		return
	}

	if co == commandPickup {
		if cf.pickupIdFile != "" {
			bytes, err := ioutil.ReadFile(cf.pickupIdFile)
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
			pcc,
			cf.pickupID,
			&output.Config{
				int(co),
				cf.format,
				certificate.ChainOptionFromString(cf.chainOption),
				cf.file,
				cf.keyFile,
				cf.certFile,
				cf.chainFile,
				cf.pickupIdFile,
				cf.keyPassword,
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
			// override values with from command line flags
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

		if cf.noPickup == true {
			pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(cf.keyPassword))
		} else {
			req.PickupID = cf.pickupID
			req.ChainOption = certificate.ChainOptionFromString(cf.chainOption)
			req.KeyPassword = cf.keyPassword

			pcc, err = retrieveCertificate(connector, req, time.Duration(cf.timeout)*time.Second)
			if err != nil {
				logger.Panicf("%s", err)
			}
			logf("Successfully retrieved request for %s", cf.pickupID)

			if cf.csrOption == "service" {
				// pcc.PrivateKey should be already encrypted by endpoint
				// so nothing to do here
			} else {
				// otherwise private key can be taken from *req
				pcc.AddPrivateKey(req.PrivateKey, []byte(cf.keyPassword))
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
			pcc,
			cf.pickupID,
			&output.Config{
				int(co),
				cf.format,
				certificate.ChainOptionFromString(cf.chainOption),
				cf.file,
				cf.keyFile,
				cf.certFile,
				cf.chainFile,
				cf.pickupIdFile,
				cf.keyPassword,
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

func doRegister(connector endpoint.Connector, cf *commandFlags) {
	if cf.email == "" {
		input, err := getEmailForRegistration(bufio.NewWriter(os.Stdout), bufio.NewReader(os.Stdin))
		if err != nil {
			logger.Panicf("%s", err)
		}
		cf.email = input
		if !isValidEmailAddress(cf.email) {
			logger.Panicf("Email address validation failed.  Please use a valid email address")
		}
	}
	err := connector.Register(cf.email)
	if err != nil {
		logger.Panicf("Failed to register: %s", err)
	}
	logf("Registration complete, please check your email for further instructions.")
}

func p(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}
