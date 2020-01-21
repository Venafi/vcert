package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/cmd/vcert/output"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/pkg/venafi/tpp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	tlsConfig      tls.Config
	err            error
	commandEnroll1 = &cli.Command{
		Flags: enrollFlags1,
		Action: func(c *cli.Context) error {
			err = doCommandEnroll1(c)
			return err
		},
		Name:  commandEnrollName,
		Usage: "To enroll a certificate,",
	}
	commandGetcred1 = &cli.Command{
		Name:  commandGetcredName,
		Flags: getcredFlags1,
		Action: func(c *cli.Context) error {
			err = doCommandGetcred1(c)
			return err
		},
		Usage: "To obtain a new token for authentication",
	}
	commandGenCSR1 = &cli.Command{
		Name:  commandGenCSRName,
		Flags: genCsrFlags1,
		Action: func(c *cli.Context) error {
			err = doCommandGenCSR1(c)
			return err
		},
		Usage: "To generate a certificate signing request (CSR)",
	}
	commandPickup1 = &cli.Command{
		Name:  commandPickupName,
		Flags: pickupFlags1,
		Action: func(c *cli.Context) error {
			err = doCommandPickup1(c)
			return err
		},
		Usage: "To retrieve a certificate",
	}
	commandRevoke1 = &cli.Command{
		Name:  commandRevokeName,
		Flags: revokeFlags1,
		Action: func(c *cli.Context) error {
			err = doCommandRevoke1(c)
			return err
		},
		Usage: "To revoke a certificate",
	}
	commandRenew1 = &cli.Command{
		Name:  commandRenewName,
		Flags: renewFlags1,
		Action: func(c *cli.Context) error {
			err = doCommandRenew1(c)
			return err
		},
		Usage: "To renew a certificate",
	}
)

func setTLSConfig() {
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
			logger.Panicf("Error reading PKCS#12 archive file: %s", err)
		}

		blocks, err := pkcs12.ToPEM(p12, flags.clientP12PW)
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
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	}

	//Setting TLS configuration
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
}

func doCommandEnroll1(c *cli.Context) error {

	setTLSConfig()

	cfg, err := buildConfig(commandEnroll, &flags)
	if err != nil {
		logger.Panicf("Failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}
	var req = &certificate.Request{}
	var pcc = &certificate.PEMCollection{}

	zoneConfig, err := connector.ReadZoneConfiguration()

	if err != nil {
		logger.Panicf("%s", err)
	}
	logf("Successfully read zone configuration for %s", flags.zone)
	req = fillCertificateRequest(req, &flags)
	err = connector.GenerateRequest(zoneConfig, req)
	if err != nil {
		logger.Panicf("%s", err)
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
		logger.Panicf("%s", err)
	}
	logf("Successfully posted request for %s, will pick up by %s", requestedFor, flags.pickupID)

	if flags.noPickup {
		pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(flags.keyPassword))
		if err != nil {
			logger.Panicf("%s", err)
		}
	} else {
		req.PickupID = flags.pickupID
		req.ChainOption = certificate.ChainOptionFromString(flags.chainOption)
		req.KeyPassword = flags.keyPassword

		pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
		if err != nil {
			logger.Panicf("%s", err)
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

	result := &output.Result{
		Pcc:      pcc,
		PickupId: flags.pickupID,
		Config: &output.Config{
			Command:      int(commandEnroll),
			Format:       flags.format,
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
		logger.Panicf("Failed to output the results: %s", err)
	}
	return nil
}

func doCommandGetcred1(c *cli.Context) error {

	setTLSConfig()

	cfg, err := buildConfig(commandGetcred, &flags)
	if err != nil {
		logger.Panicf("Failed to build vcert config: %s", err)
	}

	//TODO: quick workaround to supress logs when output is in JSON.
	if flags.format != "json" {
		logf("Getting credentials")
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
			logger.Panicf("Failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		logger.Panicf("could not create TPP connector: %s", err)
	}

	if cfg.Credentials.RefreshToken != "" {
		resp, err := tppConnector.RefreshAccessToken(&endpoint.Authentication{
			RefreshToken: cfg.Credentials.RefreshToken,
			ClientId:     flags.clientId,
			Scope:        flags.scope,
		})
		if err != nil {
			logger.Panicf("%s", err)
		}
		if flags.format == "json" {
			jsonData, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				logger.Panicf("%s", err)
			}
			fmt.Println(string(jsonData))
		} else {
			tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
			fmt.Println("access_token: ", resp.Access_token)
			fmt.Println("access_token_expires: ", tm)
			fmt.Println("refresh_token: ", resp.Refresh_token)
		}
	} else if cfg.Credentials.User != "" && cfg.Credentials.Password != "" {
		resp, err := tppConnector.GetRefreshToken(&endpoint.Authentication{
			User:     cfg.Credentials.User,
			Password: cfg.Credentials.Password,
			Scope:    flags.scope,
			ClientId: flags.clientId})
		if err != nil {
			logger.Panicf("%s", err)
		}
		if flags.format == "json" {
			jsonData, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				logger.Panicf("%s", err)
			}
			fmt.Println(string(jsonData))
		} else {
			tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
			fmt.Println("access_token: ", resp.Access_token)
			fmt.Println("access_token_expires: ", tm)
			fmt.Println("refresh_token: ", resp.Refresh_token)

		}
	} else if clientP12 {
		resp, err := tppConnector.GetRefreshToken(&endpoint.Authentication{
			ClientPKCS12: clientP12,
			Scope:        flags.scope,
			ClientId:     flags.clientId})
		if err != nil {
			logger.Panicf("%s", err)
		}
		if flags.format == "json" {
			jsonData, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				logger.Panicf("%s", err)
			}
			fmt.Println(string(jsonData))
		} else {
			tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
			fmt.Println("access_token: ", resp.Access_token)
			fmt.Println("access_token_expires: ", tm)
			fmt.Println("refresh_token: ", resp.Refresh_token)

		}
	} else {
		logger.Panicf("Failed to determine credentials set")
	}

	return nil
}

func doCommandGenCSR1(c *cli.Context) error {

	key, csr, err := generateCsrForCommandGenCsr(&flags, []byte(flags.keyPassword))
	if err != nil {
		logger.Panicf("%s", err)
	}
	err = writeOutKeyAndCsr(&flags, key, csr)
	if err != nil {
		logger.Panicf("%s", err)
	}

	return nil
}

func doCommandPickup1(c *cli.Context) error {

	setTLSConfig()

	cfg, err := buildConfig(commandPickup, &flags)
	if err != nil {
		logger.Panicf("Failed to build vcert config: %s", err)
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
			logger.Panicf("Failed to read Pickup ID value: %s", err)
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
		logger.Panicf("Failed to retrieve certificate: %s", err)
	}
	logf("Successfully retrieved request for %s", flags.pickupID)

	result := &output.Result{
		Pcc:      pcc,
		PickupId: flags.pickupID,
		Config: &output.Config{
			Command:      int(commandPickup),
			Format:       flags.format,
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
		logger.Panicf("Failed to output the results: %s", err)
	}
	return nil
}

func doCommandRevoke1(c *cli.Context) error {

	setTLSConfig()

	cfg, err := buildConfig(commandPickup, &flags)
	if err != nil {
		logger.Panicf("Failed to build vcert config: %s", err)
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
		revReq.Disable = !flags.revocationNoRetire
	case flags.thumbprint != "":
		revReq.Thumbprint = flags.thumbprint
		revReq.Disable = false
	default:
		logger.Panicf("Certificate DN or Thumbprint is required")
		return nil
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
		logger.Panicf("Failed to revoke certificate: %s", err)
	}
	logf("Successfully created revocation request for %s", requestedFor)

	return nil
}

func doCommandRenew1(c *cli.Context) error {

	setTLSConfig()

	cfg, err := buildConfig(commandPickup, &flags)
	if err != nil {
		logger.Panicf("Failed to build vcert config: %s", err)
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
		logger.Panicf("Failed to fetch old certificate by id %s: %s", flags.distinguishedName, err)
	}
	oldCertBlock, _ := pem.Decode([]byte(oldPcc.Certificate))
	if oldCertBlock == nil || oldCertBlock.Type != "CERTIFICATE" {
		logger.Panicf("Failed to fetch old certificate by id %s: PEM parse error", flags.distinguishedName)
	}
	oldCert, err := x509.ParseCertificate([]byte(oldCertBlock.Bytes))
	if err != nil {
		logger.Panicf("Failed to fetch old certificate by id %s: %s", flags.distinguishedName, err)
	}
	// now we have old one
	logf("Fetched the latest certificate. Serial: %x, NotAfter: %s", oldCert.SerialNumber, oldCert.NotAfter)

	switch true {
	case 0 == strings.Index(flags.csrOption, "file:"):
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
		logger.Panicf("unexpected -csr option: %s", flags.csrOption)
	}

	// here we ignore zone for Renew action, however, API still needs it
	zoneConfig := &endpoint.ZoneConfiguration{}

	err = connector.GenerateRequest(zoneConfig, req)
	if err != nil {
		logger.Panicf("%s", err)
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
		logger.Panicf("%s", err)
	}
	logf("Successfully posted renewal request for %s, will pick up by %s", requestedFor, flags.pickupID)

	if flags.noPickup {
		pcc, err = certificate.NewPEMCollection(nil, req.PrivateKey, []byte(flags.keyPassword))
		if err != nil {
			logger.Panicf("%s", err)
		}
	} else {
		req.PickupID = flags.pickupID
		req.ChainOption = certificate.ChainOptionFromString(flags.chainOption)
		req.KeyPassword = flags.keyPassword

		pcc, err = retrieveCertificate(connector, req, time.Duration(flags.timeout)*time.Second)
		if err != nil {
			logger.Panicf("%s", err)
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

	result := &output.Result{
		Pcc:      pcc,
		PickupId: flags.pickupID,
		Config: &output.Config{
			Command:      int(commandRenew),
			Format:       flags.format,
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
		logger.Panicf("Failed to output the results: %s", err)
	}
	return nil
}
