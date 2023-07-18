package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/crypto/pkcs12"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/parser"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/service"
	"github.com/Venafi/vcert/v4/pkg/playbook/options"
	"github.com/Venafi/vcert/v4/pkg/playbook/util"
)

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVarP(&runOptions.Filepath, "file", "f", options.DefaultFilepath, "the path to the playbook file to be run")
	runCmd.Flags().BoolVar(&runOptions.Force, "force-renew", false, "forces certificate renewal regardless of expiration date or renew window")
}

var (
	// vcert already defines tls.Config on each command, this will need to be considered
	//  when incorporating into vcert.. we'll use the same style here to make porting easier later (justin)
	tlsConfig tls.Config

	playbook   domain.Playbook
	runOptions = options.NewRunOptions()
	runCmd     = &cobra.Command{
		Use:   "run",
		Short: "Runs the tasks specified on the config file",
		Long: `run takes a YAML config file as input and will request, 
retrieve and/or renew the specified certificates. Then run the specified post-install instructions`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := run()
			if err != nil {
				return err
			}
			return nil
		},
	}
)

func run() error {
	err := util.ConfigureLogger(globalOptions.Debug)
	if err != nil {
		return err
	}
	zap.L().Info(fmt.Sprintf("running with playbook file at %s", runOptions.Filepath))
	zap.L().Debug("debug is enabled")

	playbook, err = parser.ReadPlaybook(runOptions.Filepath)
	if err != nil {
		zap.L().Error(fmt.Errorf("%w", err).Error())
		os.Exit(1)
	}

	_, err = playbook.IsValid()
	if err != nil {
		zap.L().Error(fmt.Errorf("playbook '%v' is invalid: \n%w", runOptions.Filepath, err).Error())
		os.Exit(1)
	}

	//Set the forceRenew variable
	playbook.Config.ForceRenew = runOptions.Force

	if len(playbook.CertificateTasks) == 0 {
		zap.L().Info("no tasks in the playbook. Nothing to do")
		return nil
	}

	// emulate the setTLSConfig from vcert
	err = setTLSConfig()
	if err != nil {
		zap.L().Error(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	if playbook.Config.Connection.Type == domain.CTypeTPP {
		err = service.ValidateTPPCredentials(&playbook)
		if err != nil {
			zap.L().Error(fmt.Sprintf("%v", err))
			os.Exit(1)
		}
	}

	for _, certTask := range playbook.CertificateTasks {
		zap.L().Info(fmt.Sprintf("running task: %s", certTask.Name))
		errors := service.Execute(playbook.Config, certTask)
		if len(errors) > 0 {
			for _, err2 := range errors {
				zap.L().Error(fmt.Sprintf("error running task '%s': %v", certTask.Name, err2))
			}
			os.Exit(1)
		}
	}

	zap.L().Info("playbook run finished")
	return nil
}

func setTLSConfig() error {
	// NOTE: This should use the standard setTLSConfig from vCert once incorporated into vCert
	//  added here mostly to deal with TPP servers that are enabled for certificate authentication
	//  and to enable certificate authentication

	// Set RenegotiateFreelyAsClient in case of we're communicating with MTLS enabled TPP server
	if playbook.Config.Connection.Type == domain.CTypeTPP {
		tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	if playbook.Config.Connection.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	// Try to setup certificate authentication if enabled
	if playbook.Config.Connection.Type == domain.CTypeTPP && playbook.Config.Connection.Credentials.PKCS12 != "" {
		zap.L().Info("attempting to enable certificate authentication to TPP")
		var p12FileLocation string
		var p12Password string

		// Figure out which certificate task in the playbook the PKCS12 authentication should use
		for _, task := range playbook.CertificateTasks {
			if task.Name == playbook.Config.Connection.Credentials.PKCS12 {
				for _, inst := range task.Installations {
					// Find the first installation that is of type P12
					if inst.Type == domain.TypePKCS12 {
						p12FileLocation = inst.Location
						p12Password = task.Request.KeyPassword
						break
					}
				}
			}

			// If we found a correct association, stop looking
			if p12FileLocation != "" && p12Password != "" {
				break
			}
		}

		// Load client PKCS#12 archive
		p12, err := ioutil.ReadFile(p12FileLocation)
		if err != nil {
			// This is a warning only.. our playbook may define a PKCS12 to use for authentication
			//  but use an access_token / refresh_token to get it for the first time
			zap.L().Warn(fmt.Sprintf("unable to read PKCS#12 file: %s", err))
		} else {
			// We have a PKCS12 file to use, set it up for cert authentication
			blocks, err := pkcs12.ToPEM(p12, p12Password)
			if err != nil {
				return fmt.Errorf("failed converting PKCS#12 archive file to PEM blocks: %s", err)
			}

			var pemData []byte
			for _, b := range blocks {
				pemData = append(pemData, pem.EncodeToMemory(b)...)
			}

			// Construct TLS certificate from PEM data
			cert, err := tls.X509KeyPair(pemData, pemData)
			if err != nil {
				return fmt.Errorf("failed reading PEM data to build X.509 certificate: %s", err)
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(pemData)

			// Setup HTTPS client
			tlsConfig.Certificates = []tls.Certificate{cert}
			tlsConfig.RootCAs = caCertPool
			// nolint:staticcheck
			tlsConfig.BuildNameToCertificate()
		}

	}

	//Setting TLS configuration
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig

	return nil
}
