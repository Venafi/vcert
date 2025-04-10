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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/pkcs12"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/firefly"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
)

var tlsConfig tls.Config

func runBeforeCommand(c *cli.Context) error {
	//TODO: refactor flags to specified command. If command doesn't use it, flag should be ignored.
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
	for _, stringExtKeyUsage := range c.StringSlice("eku") {
		eku, _ := certificate.ParseExtKeyUsage(stringExtKeyUsage)
		flags.extKeyUsage.Add(eku)
	}

	if flags.platformString != "" {
		flags.platform = venafi.GetPlatformType(flags.platformString)
	}

	if flags.platform == venafi.Firefly {
		if flags.scope != "" {
			//The separator in scope flag is ";" but Firefly use " " as separator
			flags.scope = strings.ReplaceAll(flags.scope, ";", " ")
		}

		if flags.csrOption == "" {
			flags.csrOption = "service"
		}
	}

	return nil
}

func runBeforeProvisionCommand(c *cli.Context) error {
	if flags.platformString != "" {
		flags.platform = venafi.GetPlatformType(flags.platformString)
	}
	return nil
}

func setTLSConfig() error {
	//Set RenegotiateFreelyAsClient in case of we're communicating with MTLS TPP server with only user\password
	if flags.apiKey == "" {
		tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	if flags.insecure {
		// We are ignoring the following from the linter, since from:
		// golangci-lint version 1.51.2 built from 3e8facb4 on 2023-02-19T21:43:54Z
		// it started failing due to error in this version of the linter
		// #nosec G402: Look for bad TLS connection settings
		tlsConfig.InsecureSkipVerify = true
	}

	if flags.clientP12 != "" {
		// Load client PKCS#12 archive
		p12, err := os.ReadFile(flags.clientP12)
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

func getTppCredentials(tppConnector *tpp.Connector, cfg *vcert.Config, clientP12 bool) error {
	//TODO: quick workaround to suppress logs when output is in JSON.
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
			fmt.Println("refresh_until: ", time.Unix(int64(resp.Refresh_until), 0).UTC().Format(time.RFC3339))
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
				fmt.Println("refresh_until: ", time.Unix(int64(resp.Refresh_until), 0).UTC().Format(time.RFC3339))
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
				fmt.Println("refresh_until: ", time.Unix(int64(resp.Refresh_until), 0).UTC().Format(time.RFC3339))
			}
		}
	} else {
		return fmt.Errorf("failed to determine credentials set")
	}

	return nil
}

func getVaaSCredentials(vaasConnector *cloud.Connector, cfg *vcert.Config) error {
	//TODO: quick workaround to suppress logs when output is in JSON.
	if flags.credFormat != "json" {
		logf("Getting credentials...")
	}

	// Register new account to VaaS
	if cfg.Credentials.User != "" {

		statusCode, userDetails, err := vaasConnector.CreateAPIUserAccount(cfg.Credentials.User, cfg.Credentials.Password)
		if err != nil {
			return fmt.Errorf("failed to create a User Account/rotate API Key in VaaS: %s", err)
		}

		apiKey := userDetails.APIKey

		if flags.credFormat == "json" {
			return outputJSON(apiKey)
		} else {
			var headerMessage string
			if statusCode == http.StatusCreated {
				headerMessage = "the user account was created successfully. To complete the registration please review your email account and follow the link."
			} else if statusCode == http.StatusAccepted {
				headerMessage = "the user account already exists therefore the API Key was rotated. To complete the activation of the rotated API Key," +
					" please review your email account and follow the link."
			} else { // only is expected that the status code returned is 201 or 202
				return fmt.Errorf("unexpected http status code when the useraccount is tried to be created or api key rotated: %d", statusCode)
			}

			fmt.Println(headerMessage)
			fmt.Println("api_key: ", apiKey.Key)
			fmt.Println("api_key_expires: ", apiKey.ValidityEndDateString)
		}
		// Request access token
	} else if cfg.Credentials.ExternalJWT != "" && cfg.Credentials.TokenURL != "" {
		// Request access token from VaaS service account
		tokenResponse, err := vaasConnector.GetAccessToken(cfg.Credentials)
		if err != nil {
			return fmt.Errorf("failed to request access token from VCP: %w", err)
		}

		if flags.credFormat == "json" {
			return outputJSON(tokenResponse)
		} else {
			validityPeriod := time.Duration(tokenResponse.ExpiresIn) * time.Second
			expirationDate := time.Now().Add(validityPeriod)
			t := expirationDate.UTC().Format(time.RFC3339)
			fmt.Println("access_token: ", tokenResponse.AccessToken)
			fmt.Println("expires_in: ", t)
		}
	} else {
		return fmt.Errorf("failed to determine credentials set")
	}

	return nil
}

func getFireflyCredentials(fireflyConnector *firefly.Connector, cfg *vcert.Config) error {
	//TODO: quick workaround to suppress logs when output is in JSON.
	if flags.credFormat != "json" {
		logf("Getting credentials...")
	}

	token, err := fireflyConnector.Authorize(cfg.Credentials)

	if err != nil {
		return err
	}
	if flags.credFormat == "json" {
		if err := outputJSON(token); err != nil {
			return err
		}
	} else {
		fmt.Println("access_token: ", token.AccessToken)
		fmt.Println("refresh_token: ", token.RefreshToken)
		fmt.Println("token_type: ", token.TokenType)
		fmt.Println("access_token_expires: ", token.Expiry)
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
