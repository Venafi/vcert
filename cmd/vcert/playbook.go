/*
 * Copyright 2023 Venafi, Inc.
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
	"net/http"
	"os"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/pkcs12"

	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/parser"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/service"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

const (
	commandRunPlaybookName = "run"
)

var commandRunPlaybook = &cli.Command{
	Name: commandRunPlaybookName,
	Usage: `Enables users to request and retrieve one or more certificates, 
	install them as either CAPI, JKS, PEM, or PKCS#12, run after-install operations 
	(script, command-line instruction, etc.), and monitor certificate(s) for renewal 
	on subsequent runs.`,
	UsageText: `vcert run
   vcert run -f /path/to/my/file.yml
   vcert run -f ./myFile.yaml --force-renew
   vcert run -f ./myFile.yaml --debug`,
	Action: doRunPlaybook,
	Flags:  playbookFlags,
}

type runOptions struct {
	debug    bool
	filepath string
	force    bool
}

var (
	playbookOptions = runOptions{}

	PBFlagDebug = &cli.BoolFlag{
		Name:        "debug",
		Aliases:     []string{"d"},
		Usage:       "Enables debug log messages",
		Required:    false,
		Value:       false,
		Destination: &playbookOptions.debug,
	}

	PBFlagFilepath = &cli.StringFlag{
		Name:        "file",
		Aliases:     []string{"f"},
		Usage:       "the path to the playbook file to be run",
		Required:    true,
		Value:       domain.DefaultFilepath,
		Destination: &playbookOptions.filepath,
	}

	PBFlagForce = &cli.BoolFlag{
		Name:        "force-renew",
		Aliases:     nil,
		Usage:       "forces certificate renewal regardless of expiration date or renew window",
		Required:    false,
		Value:       false,
		Destination: &playbookOptions.force,
	}

	playbookFlags = flagsApppend(
		PBFlagDebug,
		PBFlagFilepath,
		PBFlagForce,
	)
)

func doRunPlaybook(_ *cli.Context) error {
	err := util.ConfigureLogger(playbookOptions.debug)
	if err != nil {
		return err
	}
	zap.L().Info("running playbook file", zap.String("file", playbookOptions.filepath))
	zap.L().Debug("debug is enabled")

	playbook, err := parser.ReadPlaybook(playbookOptions.filepath)
	if err != nil {
		zap.L().Error(fmt.Errorf("%w", err).Error())
		os.Exit(1)
	}

	_, err = playbook.IsValid()
	if err != nil {
		zap.L().Error("invalid playbook file", zap.String("file", playbookOptions.filepath), zap.Error(err))
		os.Exit(1)
	}

	//Set the forceRenew variable
	playbook.Config.ForceRenew = playbookOptions.force

	if len(playbook.CertificateTasks) == 0 {
		zap.L().Info("no tasks in the playbook. Nothing to do")
		return nil
	}

	// emulate the setTLSConfig from vcert
	err = setPlaybookTLSConfig(playbook)
	if err != nil {
		zap.L().Error("tls config error", zap.Error(err))
		os.Exit(1)
	}

	zap.L().Info("using Venafi Platform", zap.String("platform", playbook.Config.Connection.Platform.String()))

	if playbook.Config.Connection.Platform == venafi.TPP {
		err = service.ValidateTPPCredentials(&playbook)
		if err != nil {
			zap.L().Error("invalid tpp credentials", zap.Error(err))
			os.Exit(1)
		}
	}

	var taskErrors []string

	for _, certTask := range playbook.CertificateTasks {
		zap.L().Info("running playbook task", zap.String("task", certTask.Name))
		errors := service.Execute(playbook.Config, certTask)
		if len(errors) > 0 {
			taskErrors = append(taskErrors, certTask.Name)
			for _, err2 := range errors {
				zap.L().Error("error running task", zap.String("task", certTask.Name), zap.Error(err2))
			}
		}
	}
	if len(taskErrors) > 0 {
		os.Exit(1)
	}

	zap.L().Info("playbook run finished")
	return nil
}

func setPlaybookTLSConfig(playbook domain.Playbook) error {
	// NOTE: This should use the standard setTLSConfig from vCert once incorporated into vCert
	//  added here mostly to deal with TPP servers that are enabled for certificate authentication
	//  and to enable certificate authentication

	// Set RenegotiateFreelyAsClient in case of we're communicating with MTLS enabled TPP server
	if playbook.Config.Connection.Platform == venafi.TPP {
		tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	if playbook.Config.Connection.Insecure {
		tlsConfig.InsecureSkipVerify = true // #nosec G402
	}

	// Try to set up certificate authentication if enabled
	if playbook.Config.Connection.Platform == venafi.TPP && playbook.Config.Connection.Credentials.P12Task != "" {
		zap.L().Info("attempting to enable certificate authentication to TPP")
		var p12FileLocation string
		var p12Password string

		// Figure out which certificate task in the playbook the PKCS12 authentication should use
		for _, task := range playbook.CertificateTasks {
			if task.Name == playbook.Config.Connection.Credentials.P12Task {
				for _, inst := range task.Installations {
					// Find the first installation that is of type P12
					if inst.Type == domain.FormatPKCS12 {
						p12FileLocation = inst.File
						p12Password = inst.P12Password
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
		p12, err := os.ReadFile(p12FileLocation)
		if err != nil {
			// This is a warning only... our playbook may define a PKCS12 to use for authentication
			//  but use an access_token / refresh_token to get it for the first time
			zap.L().Warn("unable to read PKCS#12 file", zap.String("file", p12FileLocation), zap.Error(err))
		} else {
			// We have a PKCS12 file to use, set it up for cert authentication
			blocks, err := pkcs12.ToPEM(p12, p12Password)
			if err != nil {
				return fmt.Errorf("failed converting PKCS#12 archive file to PEM blocks: %w", err)
			}

			var pemData []byte
			for _, b := range blocks {
				pemData = append(pemData, pem.EncodeToMemory(b)...)
			}

			// Construct TLS certificate from PEM data
			cert, err := tls.X509KeyPair(pemData, pemData)
			if err != nil {
				return fmt.Errorf("failed reading PEM data to build X.509 certificate: %w", err)
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(pemData)

			// Setup HTTPS client
			tlsConfig.Certificates = []tls.Certificate{cert}
			tlsConfig.RootCAs = caCertPool
			tlsConfig.BuildNameToCertificate() // nolint:staticcheck
		}

	}

	// Create own Transport to allow HTTP1.1 connections
	transport := &http.Transport{
		// Only one request is made with a client
		DisableKeepAlives: true,
		// This is to allow for http1.1 connections
		ForceAttemptHTTP2: false,
		TLSClientConfig:   &tlsConfig,
	}

	//Setting Default HTTP Transport
	http.DefaultTransport = transport

	return nil
}
