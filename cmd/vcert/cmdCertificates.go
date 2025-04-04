/*
 * Copyright 2020-2024 Venafi, Inc.
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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

var (
	commandEnroll = &cli.Command{
		Before: runBeforeCommand,
		Flags:  enrollFlags,
		Action: doCommandEnroll1,
		Name:   commandEnrollName,
		Usage:  "To enroll a certificate",
		UsageText: ` vcert enroll <Required Venafi Control Plane -OR- Trust Protection Platform Config> <Options>

		vcert enroll -k <VCP API key> -z "<app name>\<CIT alias>" --cn <common name>
		vcert enroll -k <VCP API key> -z "<app name>\<CIT alias>" --cn <common name> --key-type rsa --key-size 4096 --san-dns <alt name> --san-dns <alt name2>
		vcert enroll -p vcp -t <VCP access token> -z "<app name>\<CIT alias>" --cn <common name>

		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name>
		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name> --key-size 4096 --san-dns <alt name> --san-dns <alt name2>
		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name> --key-type ecdsa --key-curve p384 --san-dns <alt name> -san-dns <alt name2>
		vcert enroll -u https://tpp.example.com -z "<policy folder DN>" --p12-file <PKCS#12 client cert> --p12-password <PKCS#12 password> --cn <common name>
		vcert enroll -p tpp -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name>

		vcert enroll -p firefly -u <Firefly instance url> -t <OIDC access token> -z "<policy folder DN>" --cn <common name>`,
	}

	commandPickup = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandPickupName,
		Flags:  pickupFlags,
		Action: doCommandPickup1,
		Usage:  "To download a certificate",
		UsageText: ` vcert pickup <Required Venafi Control Plane -OR- Trust Protection Platform Config> <Options>

		 vcert pickup -k <VCP API key> [--pickup-id <ID value> | --pickup-id-file <file containing ID value>]
		 vcert pickup -p vcp -t <VCP access token> [--pickup-id <ID value> | --pickup-id-file <file containing ID value>]

		 vcert pickup -u https://tpp.example.com -t <TPP access token> --pickup-id <ID value>
		 vcert pickup -p tpp -u https://tpp.example.com -t <TPP access token> --pickup-id <ID value>`,
	}

	commandRevoke = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRevokeName,
		Flags:  revokeFlags,
		Action: doCommandRevoke1,
		Usage:  "To revoke a certificate",
		UsageText: ` vcert revoke <Required Trust Protection Platform Config> <Options>

		 vcert revoke -u https://tpp.example.com -t <TPP access token> --thumbprint <cert SHA1 thumbprint>
		 vcert revoke -u https://tpp.example.com -t <TPP access token> --id <ID value>
		 vcert revoke -p tpp -u https://tpp.example.com -t <TPP access token> --id <ID value>`,
	}

	commandRenew = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRenewName,
		Flags:  renewFlags,
		Action: doCommandRenew1,
		Usage:  "To renew a certificate",
		UsageText: ` vcert renew <Required Venafi Control Plane -OR- Trust Protection Platform Config> <Options>

		vcert renew -k <VCP API key> --thumbprint <cert SHA1 fingerprint>
		vcert renew -p vcp -t <VCP access token> --thumbprint <cert SHA1 fingerprint>

        vcert renew -u https://tpp.example.com -t <TPP access token> --id <ID value>`,
	}

	commandRetire = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRetireName,
		Flags:  retireFlags,
		Action: doCommandRetire,
		Usage:  "To retire a certificate",
		UsageText: ` vcert retire <Required Venafi Control Plane -OR- Trust Protection Platform Config> <Options>

		 vcert retire -k <VCP API key> --thumbprint <cert SHA1 fingerprint>
		 vcert retire -p vcp -t <VCP access token> --thumbprint <cert SHA1 fingerprint>

		 vcert retire -u https://tpp.example.com -t <TPP access token> --id <ID value>`,
	}

	commandGenCSR = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGenCSRName,
		Flags:  genCsrFlags,
		Action: doCommandGenCSR1,
		Usage:  "To generate a certificate signing request (CSR)",
		UsageText: ` vcert gencsr --cn <common name> -o <organization> --ou <organizational unit> -l <locality> --st <state> -c <country> --key-file <key output file> --csr-file <csr output file>
		 vcert gencsr --cn <common name> -o <organization> --ou <organizational unit> --ou <organizational unit2> -l <locality> --st <state> -c <country> --key-file <key output file> --csr-file <csr output file>`,
	}
)

func doCommandEnroll1(c *cli.Context) error {
	err := validateEnrollFlags(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg)
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}
	var req = &certificate.Request{}
	var pcc = &certificate.PEMCollection{}

	zoneConfig, err := connector.ReadZoneConfiguration()

	if err != nil {
		return err
	}
	logf("Successfully read zone configuration for %s", flags.zone)
	req = fillCertificateRequest(req, &flags)
	err = connector.GenerateRequest(zoneConfig, req)
	if err != nil {
		return err
	}

	var requestedFor string
	if req.Subject.CommonName != "" {
		requestedFor = req.Subject.CommonName
	} else {
		requestedFor = flags.csrOption
	}

	logf("Successfully created request for %s", requestedFor)
	passwordAutogenerated := false

	if connector.SupportSynchronousRequestCertificate() {
		pcc, err = connector.SynchronousRequestCertificate(req)
		if err != nil {
			return err
		}
		logf("Successfully requested certificate for %s", requestedFor)
	} else {
		flags.pickupID, err = connector.RequestCertificate(req)
		if err != nil {
			return err
		}

		logf("Successfully posted request for %s, will pick up by %s", requestedFor, flags.pickupID)

		if flags.noPickup {
			pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(flags.keyPassword), flags.format)
			if err != nil {
				return err
			}
		} else {
			req.PickupID = flags.pickupID
			req.ChainOption = certificate.ChainOptionFromString(flags.chainOption)
			req.KeyPassword = flags.keyPassword

			// Creates a temporary password for service generated csr if following validation is fulfilled.
			// Analyzing validation assuming that pkcs12, legacy-pkcs12, jks and service flags are true
			//+-------------+----------------+----------------------------------------------------------------------+
			//| --no-prompt | --key-password |                    What happens in validation?                       |
			//|-------------|----------------|----------------------------------------------------------------------|
			//|    true     |      true      |VCert will ignore prompt and create a certificate with given password |
			//|-------------|----------------|----------------------------------------------------------------------|
			//|    false    |      true      |VCert will ignore prompt and create a certificate with given password |
			//|-------------|----------------|----------------------------------------------------------------------|
			//|    true     |     false      |VCert will ignore prompt and create a certificate with NO password set|
			//|-------------|----------------|----------------------------------------------------------------------|
			//|    false    |     false      |VCert will prompt to enter password and process will not be completed |
			//|             |                |until password is provided by user                                    |
			//+-------------+----------------+----------------------------------------------------------------------+
			if flags.noPrompt && flags.keyPassword == "" && flags.format != P12Format && flags.format != LegacyP12Format && flags.format != JKSFormat && flags.csrOption == "service" {
				flags.keyPassword = fmt.Sprintf("t%d-%s.tem.pwd", time.Now().Unix(), randRunes(4))
				req.KeyPassword = flags.keyPassword
				passwordAutogenerated = true
			}

			req.Timeout = time.Duration(180) * time.Second
			pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
			if err != nil {
				return err
			}
			logf("Successfully retrieved request for %s", flags.pickupID)

			if req.CsrOrigin == certificate.LocalGeneratedCSR {
				// otherwise private key can be taken from *req
				err := pcc.AddPrivateKey(req.PrivateKey, []byte(flags.keyPassword), flags.format)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}

	if (pcc.PrivateKey != "" && (flags.format == P12Format || flags.format == LegacyP12Format || flags.format == JKSFormat)) || (flags.format == util.LegacyPem && flags.csrOption == "service") || flags.noPrompt && passwordAutogenerated {
		privKey, err := util.DecryptPkcs8PrivateKey(pcc.PrivateKey, flags.keyPassword)
		if err != nil {
			if err.Error() == "pkcs8: only PBES2 supported" && connector.GetType() == endpoint.ConnectorTypeTPP {
				return fmt.Errorf("ERROR: To continue, you must select either the SHA1 3DES or SHA256 AES256 private key PBE algorithm. In a web browser, log in to TLS Protect and go to Configuration > Folders, select your zone, then click Certificate Policy and expand Show Advanced Options to make the change.")
			}
			return err
		}
		pcc.PrivateKey = privKey
	}

	if flags.csrOption == "service" && flags.format == util.LegacyPem && !passwordAutogenerated {
		pcc.PrivateKey, err = util.EncryptPkcs1PrivateKey(pcc.PrivateKey, flags.keyPassword)
		if err != nil {
			return nil
		}
	}

	// removing temporary password if it was set
	if passwordAutogenerated {
		flags.keyPassword = ""
	}
	result := &Result{
		Pcc:      pcc,
		PickupId: flags.pickupID,
		Config: &Config{
			Command:      c.Command.Name,
			Format:       flags.format,
			JKSAlias:     flags.jksAlias,
			JKSPassword:  flags.jksPassword,
			ChainOption:  certificate.ChainOptionFromString(flags.chainOption),
			AllFile:      flags.file,
			KeyFile:      flags.keyFile,
			CertFile:     flags.certFile,
			ChainFile:    flags.chainFile,
			PickupIdFile: flags.pickupIDFile,
			KeyPassword:  flags.keyPassword,
		},
	}

	err = result.Flush()

	if err != nil {
		return fmt.Errorf("Failed to output the results: %s", err)
	}
	return nil
}

func doCommandPickup1(c *cli.Context) error {

	isServiceGen := IsCSRServiceVaaSGenerated(c.Command.Name)
	wasPasswordEmpty := false
	if flags.noPrompt && flags.keyPassword == "" && flags.format != P12Format && flags.format != LegacyP12Format && flags.format != JKSFormat && (isServiceGen || isTppConnector(c.Command.Name)) {
		flags.keyPassword = fmt.Sprintf("t%d-%s.tem.pwd", time.Now().Unix(), randRunes(4))
		wasPasswordEmpty = true
	}

	err := validatePickupFlags1(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	if flags.pickupIDFile != "" {
		bytes, err := os.ReadFile(flags.pickupIDFile)
		if err != nil {
			return fmt.Errorf("Failed to read Pickup ID value: %s", err)
		}
		flags.pickupID = strings.TrimSpace(string(bytes))
	}
	var req = &certificate.Request{
		PickupID:    flags.pickupID,
		ChainOption: certificate.ChainOptionFromString(flags.chainOption),
	}
	if flags.keyPassword != "" {
		// key password is provided, which means will be requesting private key
		req.KeyPassword = flags.keyPassword
		req.FetchPrivateKey = true
	}
	var pcc *certificate.PEMCollection
	pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
	if err != nil {
		errStr := err.Error()
		sliceString := strings.Split(errStr, ":")
		size := len(sliceString)
		errToValidate := sliceString[size-1]
		if strings.TrimSpace(errToValidate) == "Failed to lookup private key vault id" && wasPasswordEmpty {
			req.KeyPassword = ""
			req.FetchPrivateKey = false
			pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)

			if err != nil {
				return fmt.Errorf("Failed to retrieve certificate: %s", err)
			}

		} else {
			return fmt.Errorf("Failed to retrieve certificate: %s", err)
		}
	}
	logf("Successfully retrieved request for %s", flags.pickupID)

	if pcc.PrivateKey != "" && (flags.format == P12Format || flags.format == LegacyP12Format || flags.format == JKSFormat || flags.format == util.LegacyPem) || (flags.noPrompt && wasPasswordEmpty && pcc.PrivateKey != "") {
		privKey, err := util.DecryptPkcs8PrivateKey(pcc.PrivateKey, flags.keyPassword)
		if err != nil {
			if err.Error() == "pkcs8: only PBES2 supported" && connector.GetType() == endpoint.ConnectorTypeTPP {
				return fmt.Errorf("ERROR: To continue, you must select either the SHA1 3DES or SHA256 AES256 private key PBE algorithm. In a web browser, log in to TLS Protect and go to Configuration > Folders, select your zone, then click Certificate Policy and expand Show Advanced Options to make the change.")
			}
			return err
		}
		pcc.PrivateKey = privKey
	}

	if pcc.PrivateKey != "" && flags.format == util.LegacyPem && !wasPasswordEmpty {
		pcc.PrivateKey, err = util.EncryptPkcs1PrivateKey(pcc.PrivateKey, flags.keyPassword)
		if err != nil {
			return err
		}
	}

	if wasPasswordEmpty {
		flags.keyPassword = ""
	}

	result := &Result{
		Pcc:      pcc,
		PickupId: flags.pickupID,
		Config: &Config{
			Command:      c.Command.Name,
			Format:       flags.format,
			JKSAlias:     flags.jksAlias,
			JKSPassword:  flags.jksPassword,
			ChainOption:  certificate.ChainOptionFromString(flags.chainOption),
			AllFile:      flags.file,
			KeyFile:      flags.keyFile,
			CertFile:     flags.certFile,
			ChainFile:    flags.chainFile,
			PickupIdFile: flags.pickupIDFile,
			KeyPassword:  flags.keyPassword,
		},
	}
	err = result.Flush()

	if err != nil {
		return fmt.Errorf("Failed to output the results: %s", err)
	}
	return nil
}

func doCommandRevoke1(c *cli.Context) error {
	err := validateRevokeFlags1(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	var revReq = &certificate.RevocationRequest{}
	switch true {
	case flags.distinguishedName != "":
		revReq.CertificateDN = flags.distinguishedName
		revReq.Disable = !flags.noRetire
	case flags.thumbprint != "":
		revReq.Thumbprint = flags.thumbprint
		revReq.Disable = false
	default:
		return fmt.Errorf("Certificate DN or Thumbprint is required")
	}

	requestedFor := func() string {
		if flags.distinguishedName != "" {
			return flags.distinguishedName
		}
		if flags.thumbprint != "" {
			return flags.thumbprint
		}
		return ""
	}()

	revReq.Reason = flags.revocationReason
	revReq.Comments = "revocation request from command line utility"

	err = connector.RevokeCertificate(revReq)
	if err != nil {
		return fmt.Errorf("Failed to revoke certificate: %s", err)
	}
	logf("Successfully created revocation request for %s", requestedFor)

	return nil
}

func doCommandRenew1(c *cli.Context) error {
	err := validateRenewFlags1(c.Command.Name)
	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	var req = &certificate.Request{}
	var pcc = &certificate.PEMCollection{}

	searchReq := &certificate.Request{
		PickupID:   flags.distinguishedName,
		Thumbprint: flags.thumbprint,
	}

	// here we fetch old cert anyway
	oldPcc, err := connector.RetrieveCertificate(searchReq)
	if err != nil {
		return fmt.Errorf("Failed to fetch old certificate by id %s: %s", flags.distinguishedName, err)
	}
	oldCertBlock, _ := pem.Decode([]byte(oldPcc.Certificate))
	if oldCertBlock == nil || oldCertBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("Failed to fetch old certificate by id %s: PEM parse error", flags.distinguishedName)
	}
	oldCert, err := x509.ParseCertificate(oldCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to fetch old certificate by id %s: %s", flags.distinguishedName, err)
	}
	// now we have old one
	logf("Fetched the latest certificate. Serial: %x, NotAfter: %s", oldCert.SerialNumber, oldCert.NotAfter)

	switch true {
	case strings.HasPrefix(flags.csrOption, "file:"):
		// will be just sending CSR to backend
		req = fillCertificateRequest(req, &flags)

	case "local" == flags.csrOption || "" == flags.csrOption:
		// restore certificate request from old certificate
		req = certificate.NewRequest(oldCert)
		// override values with those from command line flags
		req = fillCertificateRequest(req, &flags)

	case "service" == flags.csrOption:
		// logger.Panic("service side renewal is not implemented")
		req = fillCertificateRequest(req, &flags)

	default:
		return fmt.Errorf("unexpected -csr option: %s", flags.csrOption)
	}

	// here we ignore zone for Renew action, however, API still needs it
	zoneConfig := &endpoint.ZoneConfiguration{}

	err = connector.GenerateRequest(zoneConfig, req)
	if err != nil {
		return err
	}

	requestedFor := func() string {
		if flags.distinguishedName != "" {
			return flags.distinguishedName
		}
		if flags.thumbprint != "" {
			return flags.thumbprint
		}
		return ""
	}()

	logf("Successfully created request for %s", requestedFor)

	renewReq := generateRenewalRequest(&flags, req)

	flags.pickupID, err = connector.RenewCertificate(renewReq)

	if err != nil {
		return err
	}
	logf("Successfully posted renewal request for %s, will pick up by %s", requestedFor, flags.pickupID)

	passwordAutogenerated := false
	if flags.noPickup {
		pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(flags.keyPassword), flags.format)
		if err != nil {
			return err
		}
	} else {
		req.PickupID = flags.pickupID
		req.ChainOption = certificate.ChainOptionFromString(flags.chainOption)
		req.KeyPassword = flags.keyPassword

		if flags.noPrompt && flags.keyPassword == "" && flags.format != P12Format && flags.format != LegacyP12Format && flags.format != JKSFormat && flags.csrOption == "service" {
			flags.keyPassword = fmt.Sprintf("t%d-%s.tem.pwd", time.Now().Unix(), randRunes(4))
			req.KeyPassword = flags.keyPassword
			passwordAutogenerated = true
		}

		req.Timeout = time.Duration(180) * time.Second
		pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
		if err != nil {
			return err
		}
		logf("Successfully retrieved request for %s", flags.pickupID)

		if req.CsrOrigin == certificate.LocalGeneratedCSR {
			// otherwise private key can be taken from *req
			err := pcc.AddPrivateKey(req.PrivateKey, []byte(flags.keyPassword), flags.format)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// Creates a temporary password for service generated csr if following validation is fulfilled.
	// Analyzing validation assuming that pkcs12, legacy-pkcs12, jks and service flags are true
	//+-------------+----------------+----------------------------------------------------------------------+
	//| --no-prompt | --key-password |                    What happens in validation?                       |
	//|-------------|----------------|----------------------------------------------------------------------|
	//|    true     |      true      |VCert will ignore prompt and create a certificate with given password |
	//|-------------|----------------|----------------------------------------------------------------------|
	//|    false    |      true      |VCert will ignore prompt and create a certificate with given password |
	//|-------------|----------------|----------------------------------------------------------------------|
	//|    true     |     false      |VCert will ignore prompt and create a certificate with NO password set|
	//|-------------|----------------|----------------------------------------------------------------------|
	//|    false    |     false      |VCert will prompt to enter password and process will not be completed |
	//|             |                |until password is provided by user                                    |
	//+-------------+----------------+----------------------------------------------------------------------+
	if (pcc.PrivateKey != "" && (flags.format == P12Format || flags.format == LegacyP12Format || flags.format == JKSFormat)) || (flags.format == util.LegacyPem && flags.csrOption == "service") || flags.noPrompt && passwordAutogenerated {
		privKey, err := util.DecryptPkcs8PrivateKey(pcc.PrivateKey, flags.keyPassword)
		if err != nil {
			if err.Error() == "pkcs8: only PBES2 supported" && connector.GetType() == endpoint.ConnectorTypeTPP {
				return fmt.Errorf("ERROR: To continue, you must select either the SHA1 3DES or SHA256 AES256 private key PBE algorithm. In a web browser, log in to TLS Protect and go to Configuration > Folders, select your zone, then click Certificate Policy and expand Show Advanced Options to make the change.")
			}
			return err
		}
		pcc.PrivateKey = privKey
	}

	if flags.csrOption == "service" && flags.format == util.LegacyPem && !passwordAutogenerated {
		pcc.PrivateKey, err = util.EncryptPkcs1PrivateKey(pcc.PrivateKey, flags.keyPassword)
		if err != nil {
			return nil
		}
	}

	// removing temporary password if it was set
	if passwordAutogenerated {
		flags.keyPassword = ""
	}

	// check if previous and renewed certificates are of the same private key
	newCertBlock, _ := pem.Decode([]byte(pcc.Certificate))
	if newCertBlock != nil && newCertBlock.Type == "CERTIFICATE" {
		newCert, err := x509.ParseCertificate(newCertBlock.Bytes)
		if err == nil {
			old, _ := json.Marshal(oldCert.PublicKey)
			newCrt, _ := json.Marshal(newCert.PublicKey)
			if len(old) > 0 && string(old) == string(newCrt) {
				logf("WARNING: private key reused")
			}
		}
	}

	result := &Result{
		Pcc:      pcc,
		PickupId: flags.pickupID,
		Config: &Config{
			Command:      c.Command.Name,
			Format:       flags.format,
			JKSAlias:     flags.jksAlias,
			JKSPassword:  flags.jksPassword,
			ChainOption:  certificate.ChainOptionFromString(flags.chainOption),
			AllFile:      flags.file,
			KeyFile:      flags.keyFile,
			CertFile:     flags.certFile,
			ChainFile:    flags.chainFile,
			PickupIdFile: flags.pickupIDFile,
			KeyPassword:  flags.keyPassword,
		},
	}
	err = result.Flush()

	if err != nil {
		return fmt.Errorf("Failed to output the results: %s", err)
	}
	return nil
}

func doCommandRetire(c *cli.Context) error {
	err := validateRetireFlags(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	var retReq = &certificate.RetireRequest{}
	switch true {
	case flags.distinguishedName != "":
		retReq.CertificateDN = flags.distinguishedName
	case flags.thumbprint != "":
		retReq.Thumbprint = flags.thumbprint
	default:
		return fmt.Errorf("Certificate DN or Thumbprint is required")
	}

	requestedFor := func() string {
		if flags.distinguishedName != "" {
			return flags.distinguishedName
		}
		if flags.thumbprint != "" {
			return flags.thumbprint
		}
		return ""
	}()

	err = connector.RetireCertificate(retReq)
	if err != nil {
		return fmt.Errorf("Failed to retire certificate: %s", err)
	}
	logf("Successfully retired certificate for %s", requestedFor)

	return nil
}

func doCommandGenCSR1(c *cli.Context) error {
	err := validateGenerateFlags1(c.Command.Name)
	if err != nil {
		return err
	}
	key, csr, err := generateCsrForCommandGenCsr(&flags, []byte(flags.keyPassword))
	if err != nil {
		return err
	}
	err = writeOutKeyAndCsr(c.Command.Name, &flags, key, csr)
	if err != nil {
		return err
	}

	return nil
}
