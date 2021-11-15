/*
 * Copyright 2020-2021 Venafi, Inc.
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
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"gopkg.in/yaml.v2"

	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/pkcs12"
)

var (
	tlsConfig      tls.Config
	connectionType endpoint.ConnectorType
	commandEnroll  = &cli.Command{
		Before: runBeforeCommand,
		Flags:  enrollFlags,
		Action: doCommandEnroll1,
		Name:   commandEnrollName,
		Usage:  "To enroll a certificate",
		UsageText: ` vcert enroll <Required Venafi as a Service -OR- Trust Protection Platform Config> <Options>
		vcert enroll -k <VaaS API key> -z "<app name>\<CIT alias>" --cn <common name>
		vcert enroll -k <VaaS API key> -z "<app name>\<CIT alias>" --cn <common name> --key-type rsa --key-size 4096 --san-dns <alt name> --san-dns <alt name2>
		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name>
		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name> --key-size 4096 --san-dns <alt name> --san-dns <alt name2>
		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --cn <common name> --key-type ecdsa --key-curve p384 --san-dns <alt name> -san-dns <alt name2>
		vcert enroll -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --p12-file <PKCS#12 client cert> --p12-password <PKCS#12 password> --cn <common name>`,
	}
	commandGetCred = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGetCredName,
		Flags:  getCredFlags,
		Action: doCommandCredMgmt1,
		Usage:  "To obtain a new credential (token) for authentication",
		UsageText: ` vcert getcred -u https://tpp.example.com --username <TPP user> --password <TPP user password>
		vcert getcred -u https://tpp.example.com --p12-file <PKCS#12 client cert> --p12-password <PKCS#12 password> --trust-bundle /path-to/bundle.pem
		vcert getcred -u https://tpp.example.com -t <TPP refresh token>
		vcert getcred -u https://tpp.example.com -t <TPP refresh token> --scope <scopes and restrictions>`,
	}
	commandCheckCred = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandCheckCredName,
		Flags:     checkCredFlags,
		Action:    doCommandCredMgmt1,
		Usage:     "To verify whether a credential (token) is valid and view its attributes",
		UsageText: " vcert checkcred -u https://tpp.example.com -t <TPP access token> --trust-bundle /path-to/bundle.pem",
	}
	commandVoidCred = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandVoidCredName,
		Flags:     voidCredFlags,
		Action:    doCommandCredMgmt1,
		Usage:     "To invalidate an authentication credential (token)",
		UsageText: " vcert voidcred -u https://tpp.example.com -t <TPP access token> --trust-bundle /path-to/bundle.pem",
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
	commandPickup = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandPickupName,
		Flags:  pickupFlags,
		Action: doCommandPickup1,
		Usage:  "To download a certificate",
		UsageText: ` vcert pickup <Required Venafi as a Service -OR- Trust Protection Platform Config> <Options>
		vcert pickup -k <VaaS API key> [--pickup-id <ID value> | --pickup-id-file <file containing ID value>]
		vcert pickup -u https://tpp.example.com -t <TPP access token> --pickup-id <ID value>`,
	}
	commandRevoke = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRevokeName,
		Flags:  revokeFlags,
		Action: doCommandRevoke1,
		Usage:  "To revoke a certificate",
		UsageText: ` vcert revoke <Required Trust Protection Platform Config> <Options>
		vcert revoke -u https://tpp.example.com -t <TPP access token> --thumbprint <cert SHA1 thumbprint>
		vcert revoke -u https://tpp.example.com -t <TPP access token> --id <ID value>`,
	}
	commandRenew = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRenewName,
		Flags:  renewFlags,
		Action: doCommandRenew1,
		Usage:  "To renew a certificate",
		UsageText: ` vcert renew <Required Venafi as a Service -OR- Trust Protection Platform Config> <Options>
		vcert renew -u https://tpp.example.com -t <TPP access token> --id <ID value>
		vcert renew -k <VaaS API key> --thumbprint <cert SHA1 fingerprint>`,
	}

	commandCreatePolicy = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandCreatePolicyName,
		Flags:  createPolicyFlags,
		Action: doCommandCreatePolicy,
		Usage:  "To apply a certificate policy specification to a zone",
		UsageText: ` vcert setpolicy <Required Venafi as a Service -OR- Trust Protection Platform Config> <Options>
		vcert setpolicy -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>" --file /path-to/policy.spec
		vcert setpolicy -k <VaaS API key> -z "<app name>\<CIT alias>" --file /path-to/policy.spec`,
	}

	commandGetPolicy = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGetePolicyName,
		Flags:  getPolicyFlags,
		Action: doCommandGetPolicy,
		Usage:  "To retrieve the certificate policy of a zone",
		UsageText: ` vcert getpolicy <Required Venafi as a Service -OR- Trust Protection Platform Config> <Options>
		vcert getpolicy -u https://tpp.example.com -t <TPP access token> -z "<policy folder DN>"
		vcert getpolicy -k <VaaS API key> -z "<app name>\<CIT alias>"`,
	}

	commandSshPickup = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandSshPickupName,
		Flags:     sshPickupFlags,
		Action:    doCommandSshPickup,
		Usage:     "To retrieve a SSH Certificate",
		UsageText: `vcert sshpickup -u https://tpp.example.com -t <TPP access token> --pickup-id <ssh cert DN>`,
	}

	commandSshEnroll = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandSshEnrollName,
		Flags:     sshEnrollFlags,
		Action:    doCommandEnrollSshCert,
		Usage:     "To enroll a SSH Certificate",
		UsageText: `vcert sshenroll -u https://tpp.example.com -t <TPP access token> --template <val> --id <val> --principal bob --principal alice --valid-hours 1`,
	}

	commandSshGetConfig = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandSshGetConfigName,
		Flags:     sshGetConfigFlags,
		Action:    doCommandSshGetConfig,
		Usage:     "To get the SSH CA public key and default principals",
		UsageText: `vcert sshgetconfig -u https://tpp.example.com -t <TPP access token> --template <val>`,
	}
)

func runBeforeCommand(c *cli.Context) error {
	//TODO: move all flag validations here
	flags.orgUnits = c.StringSlice("ou")
	flags.dnsSans = c.StringSlice("san-dns")
	flags.emailSans = c.StringSlice("san-email")
	flags.upnSans = c.StringSlice("san-upn")
	flags.customFields = c.StringSlice("field")
	flags.sshCertExtension = c.StringSlice("extension")
	flags.sshCertPrincipal = c.StringSlice("principal")
	flags.sshCertSourceAddrs = c.StringSlice("source-address")
	flags.sshCertDestAddrs = c.StringSlice("destination-address")

	noDuplicatedFlags := []string{"instance", "tls-address", "app-info"}
	for _, f := range noDuplicatedFlags {
		if len(c.StringSlice(f)) > 1 {
			return fmt.Errorf("flag %s can not be duplicated", f)
		} else if len(c.StringSlice(f)) == 1 {
			switch f {
			case "instance":
				flags.instance = c.StringSlice(f)[0]
			case "tls-address":
				flags.tlsAddress = c.StringSlice(f)[0]
			case "app-info":
				flags.appInfo = c.StringSlice(f)[0]
			}

		}
	}

	for _, stringIP := range c.StringSlice("san-ip") {
		ip := net.ParseIP(stringIP)
		flags.ipSans = append(flags.ipSans, ip)
	}
	for _, stringURI := range c.StringSlice("san-uri") {
		uri, _ := url.Parse(stringURI)
		flags.uriSans = append(flags.uriSans, uri)
	}

	return nil
}

func setTLSConfig() error {
	//Set RenegotiateFreelyAsClient in case of we're communicating with MTLS TPP server with only user\password
	if flags.apiKey == "" {
		tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	if flags.insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if flags.clientP12 != "" {
		// Load client PKCS#12 archive
		p12, err := ioutil.ReadFile(flags.clientP12)
		if err != nil {
			return fmt.Errorf("Error reading PKCS#12 archive file: %s", err)
		}

		blocks, err := pkcs12.ToPEM(p12, flags.clientP12PW)
		if err != nil {
			return fmt.Errorf("Error converting PKCS#12 archive file to PEM blocks: %s", err)
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		// Construct TLS certificate from PEM data
		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			return fmt.Errorf("Error reading PEM data to build X.509 certificate: %s", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(pemData)

		// Setup HTTPS client
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.RootCAs = caCertPool
		// nolint:staticcheck
		tlsConfig.BuildNameToCertificate()
	}

	//Setting TLS configuration
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig

	return nil
}

func doCommandEnroll1(c *cli.Context) error {
	err := validateEnrollFlags(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	validateOverWritingEnviromentVariables()

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
	flags.pickupID, err = connector.RequestCertificate(req)
	if err != nil {
		return err
	}
	logf("Successfully posted request for %s, will pick up by %s", requestedFor, flags.pickupID)

	if flags.noPickup {
		pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(flags.keyPassword))
		if err != nil {
			return err
		}
	} else {
		req.PickupID = flags.pickupID
		req.ChainOption = certificate.ChainOptionFromString(flags.chainOption)
		req.KeyPassword = flags.keyPassword

		pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
		if err != nil {
			return err
		}
		logf("Successfully retrieved request for %s", flags.pickupID)

		if req.CsrOrigin == certificate.LocalGeneratedCSR {
			// otherwise private key can be taken from *req
			err := pcc.AddPrivateKey(req.PrivateKey, []byte(flags.keyPassword))
			if err != nil {
				log.Fatal(err)
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

func doCommandEnrollSshCert(c *cli.Context) error {

	err := validateSshEnrollFlags(c.Command.Name)

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
		logf("Unable to build connector for %s: %s", cfg.ConnectorType, err)
	} else {
		if flags.verbose {
			logf("Successfully built connector for %s", cfg.ConnectorType)
		}
	}

	err = connector.Ping()

	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		if flags.verbose {
			logf("Successfully connected to %s", cfg.ConnectorType)
		}
	}

	var req = &certificate.SshCertRequest{}

	req = fillSshCertificateRequest(req, &flags)

	if flags.sshCertKeyPassphrase != "" {
		flags.keyPassword = flags.sshCertKeyPassphrase
	}

	var privateKey, publicKey []byte
	sPubKey := ""
	//support for local generated keypair or provided public key
	if flags.sshCertPubKey == SshCertPubKeyLocal {

		keySize := flags.sshCertKeySize
		if keySize <= 0 {
			keySize = 3072
		}

		privateKey, publicKey, err = util.GenerateSshKeyPair(keySize, flags.keyPassword, flags.sshCertKeyId)

		if err != nil {
			return err
		}

		sPubKey = string(publicKey)
		req.PublicKeyData = sPubKey
	}

	if isPubKeyInFile() {
		pubKeyS, err := getSshPubKeyFromFile()

		if err != nil {
			return err
		}

		if pubKeyS == "" {
			return fmt.Errorf("specified public key in %s is empty", flags.sshCertPubKey)
		}

		req.PublicKeyData = pubKeyS
	}

	req.Timeout = time.Duration(flags.timeout) * time.Second
	data, err := connector.RequestSSHCertificate(req)

	if err != nil {
		return err
	}

	// 'Rejected' status is handled in the connector
	if (data.ProcessingDetails.Status == "Pending Issue") || (data.ProcessingDetails.Status == "Issued" && data.CertificateData == "") {
		logf("SSH certificate was successfully requested. Retrieving the certificate data.")

		flags.pickupID = data.DN
		retReq := certificate.SshCertRequest{
			PickupID:                  flags.pickupID,
			IncludeCertificateDetails: true,
		}
		if flags.keyPassword != "" {
			retReq.PrivateKeyPassphrase = flags.keyPassword
		}

		retReq.Timeout = time.Duration(10) * time.Second
		data, err = connector.RetrieveSSHCertificate(&retReq)
		if err != nil {
			return fmt.Errorf("Failed to retrieve SSH certificate '%s'. Error: %s", flags.pickupID, err)
		}
	} else {
		logf("Successfully issued SSH certificate with Key ID '%s'", data.CertificateDetails.KeyID)
	}

	//this case is when the keypair is local generated
	if data.PrivateKeyData == "" {
		data.PrivateKeyData = string(privateKey)
	}
	if sPubKey != "" {
		data.PublicKeyData = sPubKey
	}

	printSshMetadata(data)
	privateKeyS := data.PrivateKeyData
	if isServiceGenerated() {
		privateKeyS = AddLineEnding(privateKeyS)
	}

	privateKeyFileName := flags.sshFileCertEnroll
	if privateKeyFileName == "" {
		privateKeyFileName = data.CertificateDetails.KeyID
	}

	// Check if the files already exist and prompt the user to overwrite
	if !flags.noPrompt {
		err = validateExistingFile(privateKeyFileName)
		if err != nil {
			return err
		}
	}

	err = writeSshFiles(privateKeyFileName, []byte(privateKeyS), []byte(data.PublicKeyData), []byte(data.CertificateData))
	if err != nil {
		return err
	}

	return nil
}

func fillSshCertificateRequest(req *certificate.SshCertRequest, cf *commandFlags) *certificate.SshCertRequest {

	if cf.sshCertTemplate != "" {
		req.Template = cf.sshCertTemplate
	}

	if cf.sshCertKeyId != "" {
		req.KeyId = cf.sshCertKeyId
	}

	if cf.sshCertObjectName != "" {
		req.ObjectName = cf.sshCertObjectName
	}

	if cf.sshCertValidHours > 0 {
		req.ValidityPeriod = strconv.Itoa(cf.sshCertValidHours) + "h"
	}

	if cf.sshCertFolder != "" {
		req.PolicyDN = cf.sshCertFolder
	}

	if len(cf.sshCertDestAddrs) > 0 {
		req.DestinationAddresses = cf.sshCertDestAddrs
	}

	if len(cf.sshCertPrincipal) > 0 {
		req.Principals = cf.sshCertPrincipal
	}

	if len(cf.sshCertExtension) > 0 {
		req.Extensions = cf.sshCertExtension
	}

	if len(cf.sshCertSourceAddrs) > 0 {
		req.SourceAddresses = cf.sshCertSourceAddrs
	}

	if cf.sshCertPubKeyData != "" {
		req.PublicKeyData = cf.sshCertPubKeyData
	}

	if cf.sshCertForceCommand != "" {
		req.ForceCommand = cf.sshCertForceCommand
	}

	return req
}

func doCommandCredMgmt1(c *cli.Context) error {
	err := validateCredMgmtFlags1(c.Command.Name)
	if err != nil {
		return err
	}
	validateOverWritingEnviromentVariables()

	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	var clientP12 bool
	if flags.clientP12 != "" {
		clientP12 = true
	}
	var connectionTrustBundle *x509.CertPool
	if cfg.ConnectionTrust != "" {
		logf("You specified a trust bundle.")
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return fmt.Errorf("Failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		return fmt.Errorf("could not create TPP connector: %s", err)
	}

	switch c.Command.Name {
	case commandGetCredName:
		//TODO: quick workaround to supress logs when output is in JSON.
		if flags.credFormat != "json" {
			logf("Getting credentials...")
		}

		if cfg.Credentials.RefreshToken != "" {
			resp, err := tppConnector.RefreshAccessToken(&endpoint.Authentication{
				RefreshToken: cfg.Credentials.RefreshToken,
				ClientId:     flags.clientId,
				Scope:        flags.scope,
			})
			if err != nil {
				return err
			}
			if flags.credFormat == "json" {
				if err := outputJSON(resp); err != nil {
					return err
				}
			} else {
				tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
				fmt.Println("access_token: ", resp.Access_token)
				fmt.Println("access_token_expires: ", tm)
				fmt.Println("refresh_token: ", resp.Refresh_token)
			}
		} else if cfg.Credentials.User != "" && cfg.Credentials.Password != "" {

			auth := &endpoint.Authentication{
				User:     cfg.Credentials.User,
				Password: cfg.Credentials.Password,
				Scope:    flags.scope,
				ClientId: flags.clientId}

			if flags.sshCred {
				auth.Scope = "ssh:manage"
			} else if flags.pmCred {
				auth.Scope = "certificate:manage,revoke;configuration:manage"
			}

			resp, err := tppConnector.GetRefreshToken(auth)
			if err != nil {
				return err
			}
			if flags.credFormat == "json" {
				if err := outputJSON(resp); err != nil {
					return err
				}
			} else {
				tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
				fmt.Println("access_token: ", resp.Access_token)
				fmt.Println("access_token_expires: ", tm)
				if resp.Refresh_token != "" {
					fmt.Println("refresh_token: ", resp.Refresh_token)
				}
			}
		} else if clientP12 {
			resp, err := tppConnector.GetRefreshToken(&endpoint.Authentication{
				ClientPKCS12: clientP12,
				Scope:        flags.scope,
				ClientId:     flags.clientId})
			if err != nil {
				return err
			}
			if flags.credFormat == "json" {
				if err := outputJSON(resp); err != nil {
					return err
				}
			} else {
				tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
				fmt.Println("access_token: ", resp.Access_token)
				fmt.Println("access_token_expires: ", tm)
				if resp.Refresh_token != "" {
					fmt.Println("refresh_token: ", resp.Refresh_token)
				}
			}
		} else {
			return fmt.Errorf("Failed to determine credentials set")
		}
	case commandCheckCredName:
		//TODO: quick workaround to supress logs when output is in JSON.
		if flags.credFormat != "json" {
			logf("Checking credentials...")
		}

		if cfg.Credentials.AccessToken != "" {
			resp, err := tppConnector.VerifyAccessToken(&endpoint.Authentication{
				AccessToken: cfg.Credentials.AccessToken,
			})
			if err != nil {
				return err
			}
			if flags.credFormat == "json" {
				if err := outputJSON(resp); err != nil {
					return err
				}
			} else {
				iso8601fmt := "2006-01-02T15:04:05Z"
				tm, _ := time.Parse(iso8601fmt, resp.AccessIssuedOn)
				accessExpires := tm.Add(time.Duration(resp.ValidFor) * time.Second).Format(iso8601fmt)
				fmt.Println("access_token_expires: ", accessExpires)
				fmt.Println("grant_expires: ", resp.Expires)
				fmt.Println("client_id: ", resp.ClientID)
				fmt.Println("scope: ", resp.Scope)
			}
		} else {
			return fmt.Errorf("Failed to determine credentials set")
		}
	case commandVoidCredName:
		if cfg.Credentials.AccessToken != "" {
			err := tppConnector.RevokeAccessToken(&endpoint.Authentication{
				AccessToken: cfg.Credentials.AccessToken,
			})
			if err != nil {
				return err
			}
			logf("Access token grant successfully revoked")
		} else {
			return fmt.Errorf("Failed to determine credentials set")
		}
	default:
		return fmt.Errorf("Unexpected credential operation %s", c.Command.Name)
	}

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

func doCommandPickup1(c *cli.Context) error {
	err := validatePickupFlags1(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	validateOverWritingEnviromentVariables()

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
		bytes, err := ioutil.ReadFile(flags.pickupIDFile)
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
		return fmt.Errorf("Failed to retrieve certificate: %s", err)
	}
	logf("Successfully retrieved request for %s", flags.pickupID)

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

	validateOverWritingEnviromentVariables()

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

func doCommandCreatePolicy(c *cli.Context) error {

	err := validateSetPolicyFlags(c.Command.Name)

	if err != nil {
		return err
	}

	policyName := flags.policyName
	policySpecLocation := flags.policySpecLocation

	logf("Loading policy specification from %s", policySpecLocation)

	file, bytes, err := getFileAndBytes(policySpecLocation)

	if err != nil {
		return err
	}

	if flags.verbose {
		logf("Policy specification file was successfully opened")
	}

	fileExt := policy.GetFileType(policySpecLocation)
	fileExt = strings.ToLower(fileExt)

	if flags.verifyPolicyConfig {
		err = verifyPolicySpec(bytes, fileExt)
		if err != nil {
			err = fmt.Errorf("policy specification file is not valid: %s", err)
			return err
		} else {
			logf("policy specification %s is valid", policySpecLocation)
			return nil
		}
	}

	//based on the extension call the appropriate method to feed the policySpecification
	//structure.
	var policySpecification policy.PolicySpecification
	if fileExt == policy.JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else if fileExt == policy.YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("the specified file is not supported")
	}

	cfg, err := buildConfig(c, &flags)

	if err != nil {
		return fmt.Errorf("failed to build vcert config: %s", err)
	}
	connector, err := vcert.NewClient(&cfg)

	if err != nil {
		return err
	}

	_, err = connector.SetPolicy(policyName, &policySpecification)

	defer file.Close()

	return err
}

func doCommandGetPolicy(c *cli.Context) error {

	err := validateGetPolicyFlags(c.Command.Name)

	if err != nil {
		return err
	}

	policyName := flags.policyName

	policySpecLocation := flags.policySpecLocation

	var ps *policy.PolicySpecification

	if !flags.policyConfigStarter {

		cfg, err := buildConfig(c, &flags)
		if err != nil {
			return fmt.Errorf("failed to build vcert config: %s", err)
		}

		connector, err := vcert.NewClient(&cfg)

		if err != nil {

			return err

		}

		ps, err = connector.GetPolicy(policyName)

		if err != nil {
			return err
		}

	} else {

		ps = getEmptyPolicySpec()

	}

	var byte []byte

	if policySpecLocation != "" {

		fileExt := policy.GetFileType(policySpecLocation)
		fileExt = strings.ToLower(fileExt)
		if fileExt == policy.JsonExtension {
			byte, _ = json.MarshalIndent(ps, "", "  ")
			if err != nil {
				return err
			}
		} else if fileExt == policy.YamlExtension {
			byte, _ = yaml.Marshal(ps)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("the specified byte is not supported")
		}

		err = ioutil.WriteFile(policySpecLocation, byte, 0600)
		if err != nil {
			return err
		}
		log.Printf("policy was written in: %s", policySpecLocation)

	} else {

		byte, _ = json.MarshalIndent(ps, "", "  ")

		if err != nil {
			return err
		}
		log.Println("Policy is:")
		fmt.Println(string(byte))
	}

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

	validateOverWritingEnviromentVariables()
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
	oldCert, err := x509.ParseCertificate([]byte(oldCertBlock.Bytes))
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

	if flags.noPickup {
		pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(flags.keyPassword))
		if err != nil {
			return err
		}
	} else {
		req.PickupID = flags.pickupID
		req.ChainOption = certificate.ChainOptionFromString(flags.chainOption)
		req.KeyPassword = flags.keyPassword

		pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
		if err != nil {
			return err
		}
		logf("Successfully retrieved request for %s", flags.pickupID)

		if req.CsrOrigin == certificate.LocalGeneratedCSR {
			// otherwise private key can be taken from *req
			err = pcc.AddPrivateKey(req.PrivateKey, []byte(flags.keyPassword))
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

func doCommandSshGetConfig(c *cli.Context) error {

	err := validateGetSshConfigFlags(c.Command.Name)

	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg)

	if err != nil {
		strErr := (err).Error()
		if strErr != "vcert error: your data contains problems: auth error: failed to authenticate: can't determine valid credentials set" {
			logf("Unable to build connector for %s: %s", cfg.ConnectorType, err)
		} else {
			logf("Successfully built connector for %s", cfg.ConnectorType)
		}
	} else {
		logf("Successfully built connector for %s", cfg.ConnectorType)
	}

	err = connector.Ping()

	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	req := &certificate.SshCaTemplateRequest{}
	if flags.sshCertTemplate != "" {
		req.Template = flags.sshCertTemplate
	}
	if flags.sshCertGuid != "" {
		req.Guid = flags.sshCertGuid
	}

	conf, err := connector.RetrieveSshConfig(req)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("CA public key:")
	fmt.Println(conf.CaPublicKey)

	if len(conf.Principals) > 0 {
		fmt.Println()
		fmt.Println("Principals:")
		for _, v := range conf.Principals {
			fmt.Println(v)
		}
	}

	if flags.sshFileGetConfig != "" {
		// Check if the file already exists and prompt the user to overwrite
		if !flags.noPrompt {
			err = validateExistingFile(flags.sshFileGetConfig)
			if err != nil {
				return err
			}
		}

		err = writeToFile([]byte(conf.CaPublicKey), flags.sshFileGetConfig, 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func generateCsrForCommandGenCsr(cf *commandFlags, privateKeyPass []byte) (privateKey []byte, csr []byte, err error) {
	certReq := &certificate.Request{}
	if cf.keyType != nil {
		certReq.KeyType = *cf.keyType
	}
	certReq.KeyLength = cf.keySize
	if cf.keyCurve != certificate.EllipticCurveNotSet {
		certReq.KeyCurve = cf.keyCurve
	}
	err = certReq.GeneratePrivateKey()
	if err != nil {
		return
	}

	var pBlock *pem.Block
	if len(privateKeyPass) == 0 {
		pBlock, err = certificate.GetPrivateKeyPEMBock(certReq.PrivateKey)
		if err != nil {
			return
		}
		privateKey = pem.EncodeToMemory(pBlock)
	} else {
		pBlock, err = certificate.GetEncryptedPrivateKeyPEMBock(certReq.PrivateKey, privateKeyPass)
		if err != nil {
			return
		}
		privateKey = pem.EncodeToMemory(pBlock)
	}
	certReq = fillCertificateRequest(certReq, cf)
	err = certReq.GenerateCSR()
	if err != nil {
		return
	}
	err = certReq.GeneratePrivateKey()
	if err != nil {
		return
	}
	csr = certReq.GetCSR()

	return
}

func writeOutKeyAndCsr(commandName string, cf *commandFlags, key []byte, csr []byte) (err error) {
	pcc := &certificate.PEMCollection{}
	pcc.CSR = string(csr[:])
	pcc.PrivateKey = string(key[:])

	result := &Result{
		Pcc:      pcc,
		PickupId: "",
		Config: &Config{
			Command:      commandName,
			Format:       cf.csrFormat,
			ChainOption:  certificate.ChainOptionFromString(cf.chainOption),
			AllFile:      cf.file,
			KeyFile:      cf.keyFile,
			CSRFile:      cf.csrFile,
			ChainFile:    "",
			PickupIdFile: "",
			KeyPassword:  cf.keyPassword,
		},
	}

	err = result.Flush()
	return
}

func doCommandSshPickup(c *cli.Context) error {

	err := validateSshRetrieveFlags(c.Command.Name)

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

	var req certificate.SshCertRequest

	req = buildSshCertRequest(req, &flags)

	req.Timeout = time.Duration(10) * time.Second
	data, err := connector.RetrieveSSHCertificate(&req)

	if err != nil {
		return fmt.Errorf("failed to retrieve certificate: %s", err)
	}
	logf("Successfully retrieved request for %s", data.DN)

	printSshMetadata(data)
	privateKeyS := data.PrivateKeyData
	if privateKeyS != "" {
		privateKeyS = AddLineEnding(privateKeyS)
	}

	// If --file is not set, use Key ID as filename
	privateKeyFileName := flags.sshFileCertEnroll
	if privateKeyFileName == "" {
		privateKeyFileName = data.CertificateDetails.KeyID
	}

	// Check if the files already exist and prompt the user to overwrite
	if !flags.noPrompt {
		err = validateExistingFile(privateKeyFileName)
		if err != nil {
			return err
		}
	}

	err = writeSshFiles(privateKeyFileName, []byte(privateKeyS), []byte(data.PublicKeyData), []byte(data.CertificateData))
	if err != nil {
		return err
	}

	return nil
}

func buildSshCertRequest(r certificate.SshCertRequest, cf *commandFlags) certificate.SshCertRequest {

	if cf.sshCertKeyPassphrase != "" {
		cf.keyPassword = cf.sshCertKeyPassphrase
	}

	if cf.sshCertPickupId != "" {
		r.PickupID = cf.sshCertPickupId
	}

	if cf.sshCertGuid != "" {
		r.Guid = cf.sshCertGuid
	}

	if cf.keyPassword != "" {
		r.PrivateKeyPassphrase = cf.keyPassword
	}

	r.IncludeCertificateDetails = true

	return r
}
