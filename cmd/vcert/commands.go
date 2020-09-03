package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	tlsConfig      tls.Config
	connectionType endpoint.ConnectorType
	commandEnroll  = &cli.Command{
		Before: runBeforeCommand,
		Flags:  enrollFlags,
		Action: doCommandEnroll1,
		Name:   commandEnrollName,
		Usage:  "To enroll a certificate,",
		UsageText: ` vcert enroll <Required Venafi Cloud Config> OR <Required Trust Protection Platform Config> <Options>
		vcert enroll -k <api key> -cn <common name> -z <zone>
		vcert enroll -k <api key> -cn <common name> -z <zone> -key-type rsa -key-size 4096 -san-dns <alt common name> -san-dns <alt common name2>
		vcert enroll -u <https://tpp.example.com> -t <tpp access token> -cn <common name> -z <zone>
		vcert enroll -u <https://tpp.example.com> -t <tpp access token> -cn <common name> -z <zone> -key-size 4096 -san-dns <alt common name> -san-dns <alt common name2>
		vcert enroll -u <https://tpp.example.com> -t <tpp access token> -cn <common name> -z <zone> -key-type ecdsa -key-curve p384 -san-dns <alt common name> -san-dns <alt common name2>
		vcert enroll -u <https://tpp.example.com> -t <tpp access token> -cn <common name> -z <zone> -client-pkcs12 <client PKCS#12 archive> -client-pkcs12-pw <PKCS#12 archive password>
`,
	}
	commandGetcred = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGetcredName,
		Flags:  getcredFlags,
		Action: doCommandGetcred1,
		Usage:  "To obtain a new token for authentication",
		UsageText: ` vcert getcred -u https://tpp.example.com -username <TPP user> -password <TPP user password>
		vcert getcred -u https://tpp.example.com -p12-file <PKCS#12 client certificate> -p12-password <PKCS#12 password> -trust-bundle /path-to/bundle.pem
		vcert getcred -u https://tpp.example.com -t <refresh token>
		vcert getcred -u https://tpp.example.com -t <refresh token> -scope <scopes and restrictions>
`,
	}
	commandGenCSR = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGenCSRName,
		Flags:  genCsrFlags,
		Action: doCommandGenCSR1,
		Usage:  "To generate a certificate signing request (CSR)",
		UsageText: ` vcert gencsr -cn <common name> -o <organization> -ou <organizational unit> -c <country> -st <state> -l <locality> -key-file <key output file> -csr-file <csr output file>
		vcert gencsr -cn <common name> -o <organization> -ou <organizational unit> -ou <organizational unit2> -c <country> -st <state> -l <locality> -key-file <key output file> -csr-file <csr output file>
`,
	}
	commandPickup = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandPickupName,
		Flags:  pickupFlags,
		Action: doCommandPickup1,
		Usage:  "To retrieve a certificate",
		UsageText: ` vcert pickup <Required Venafi Cloud Config> OR <Required Trust Protection Platform Config> <Options>
		vcert pickup -k <api key> -pickup-id <request id> OR -pickup-id-file <file with Pickup ID value>
		vcert pickup -u <https://tpp.example.com> -t <tpp access token> -pickup-id <request id>
`,
	}
	commandRevoke = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRevokeName,
		Flags:  revokeFlags,
		Action: doCommandRevoke1,
		Usage:  "To revoke a certificate",
		UsageText: ` vcert revoke <Required Trust Protection Platform Config> <Options>
	vcert revoke -u <https://tpp.example.com> -t <tpp access token> -thumbprint <certificate thumbprint>
	vcert revoke -u <https://tpp.example.com> -t <tpp access token> -id <certificate DN>`,
	}
	commandRenew = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandRenewName,
		Flags:  renewFlags,
		Action: doCommandRenew1,
		Usage:  "To renew a certificate",
		UsageText: ` vcert renew <Required Venafi Cloud Config> OR <Required Trust Protection Platform Config> <Options>
		vcert renew -t <tpp access token> -id <certificate DN>
		vcert renew -k <api key> -thumbprint <certificate SHA1 fingerprint>
`,
	}
)

func runBeforeCommand(c *cli.Context) error {
	//TODO: move all flag validations here
	flags.orgUnits = c.StringSlice("ou")
	flags.dnsSans = c.StringSlice("san-dns")
	flags.emailSans = c.StringSlice("san-email")
	flags.upnSans = c.StringSlice("san-upn")
	flags.customFields = c.StringSlice("field")

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

func doCommandGetcred1(c *cli.Context) error {
	err := validateGetcredFlags1(c.Command.Name)
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
			return fmt.Errorf("Failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		return fmt.Errorf("could not create TPP connector: %s", err)
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
		if flags.format == "json" {
			jsonData, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				return err
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
			return err
		}
		if flags.format == "json" {
			jsonData, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				return err
			}
			fmt.Println(string(jsonData))
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
		if flags.format == "json" {
			jsonData, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				return err
			}
			fmt.Println(string(jsonData))
		} else {
			tm := time.Unix(int64(resp.Expires), 0).UTC().Format(time.RFC3339)
			fmt.Println("access_token: ", resp.Access_token)
			fmt.Println("access_token_expires: ", tm)
			fmt.Println("refresh_token: ", resp.Refresh_token)

		}
	} else {
		return fmt.Errorf("Failed to determine credentials set")
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
