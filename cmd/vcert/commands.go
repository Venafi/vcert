package main

import (
	"crypto/tls"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/cmd/vcert/output"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/urfave/cli/v2"
	"log"
	"net/http"
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
	return nil
}

func doCommandGenCSR1(c *cli.Context) error {

	setTLSConfig()

	return nil
}

func doCommandPickup1(c *cli.Context) error {

	setTLSConfig()

	return nil
}

func doCommandRevoke1(c *cli.Context) error {

	setTLSConfig()

	return nil
}

func doCommandRenew1(c *cli.Context) error {

	setTLSConfig()

	return nil
}
