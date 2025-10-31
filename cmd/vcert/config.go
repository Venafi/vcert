/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

func buildConfig(c *cli.Context, flags *commandFlags) (cfg vcert.Config, err error) {
	if flags.config != "" {
		// Loading configuration from file
		cfg, err = vcert.LoadConfigFromFile(flags.config, flags.profile)
		if err != nil {
			return cfg, err
		}
	} else {
		// Get values from Env Vars and set it to flags before building the config object
		// Only do these when values are not loaded from config file
		assignEnvVarsToFlags()

		//build configuration from CLI flags
		flagsCfg, err := buildConfigFromFlags(c.Command.Name, flags)
		if err != nil {
			return cfg, err
		}
		cfg = *flagsCfg
	}

	//verbosity
	cfg.LogVerbose = flags.verbose

	// trust bundle may be overridden by CLI flag
	if flags.trustBundle != "" {
		logf("Detected trust bundle...")
		if cfg.ConnectionTrust != "" {
			logf("Overriding trust bundle in configuration")
		}
		data, err := os.ReadFile(flags.trustBundle)
		if err != nil {
			return cfg, fmt.Errorf("failed to read trust bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	}

	// zone may be overridden by CLI flag
	if flags.zone != "" {
		if cfg.Zone != "" {
			logf("Overriding zone based on command line flag.")
		}
		cfg.Zone = flags.zone
	}

	if c.Command.Name == commandEnrollName || c.Command.Name == commandPickupName {
		if cfg.Zone == "" && cfg.ConnectorType != endpoint.ConnectorTypeFake && !(flags.pickupID != "" || flags.pickupIDFile != "") {
			return cfg, fmt.Errorf("zone cannot be empty. Use -z option")
		}
	}

	return cfg, nil
}

func buildConfigFromFlags(commandName string, flags *commandFlags) (*vcert.Config, error) {
	// Configuration for fake connector
	if flags.testMode {
		cfg, err := buildConfigFake(flags)
		if err != nil {
			return nil, err
		}
		if flags.testModeDelay > 0 {
			logf("Running in --test-mode with emulating endpoint delay.")
			delay, _ := rand.Int(rand.Reader, big.NewInt(int64(flags.testModeDelay)))
			for i := int64(0); i < delay.Int64(); i++ {
				time.Sleep(1 * time.Second)
			}
		}
		return cfg, nil
	}

	switch flags.platform {
	case venafi.TPP:
		return buildConfigTPP(commandName, flags)
	case venafi.TLSPCloud:
		return buildConfigVaaS(flags)
	case venafi.Firefly:
		return buildConfigFirefly(flags)
	}

	log.Printf("Warning: --platform not set. Attempting to best-guess platform from connection flags")

	//Guessing the platform by checking flags
	//	- Firefly not present here as it is required to pass the platform flag
	//	- Token empty is considered to mean Cloud connector to keep previous behavior where token was exclusive to Certificate Manager, Self-Hosted
	//	- To use token with CyberArk Certificate Manager, SaaS, the platform flag is required.
	//	- If the platform flag is set we would not be guessing here
	if flags.userName == "" && flags.token == "" {
		// should be CyberArk Certificate Manager, SaaS endpoint
		return buildConfigVaaS(flags)
	} else {
		// should be CyberArk Certificate Manager, Self-Hosted service
		return buildConfigTPP(commandName, flags)
	}
}

func buildConfigFake(_ *commandFlags) (*vcert.Config, error) {
	return &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeFake,
		Credentials:   &endpoint.Authentication{},
	}, nil
}

func buildConfigTPP(commandName string, flags *commandFlags) (*vcert.Config, error) {

	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       flags.url,
		Credentials: &endpoint.Authentication{
			User:     flags.userName,
			Password: flags.password,
		},
		ConnectionTrust: "",
		LogVerbose:      false,
		Client:          nil,
	}

	if commandName == commandGetCredName {
		config.Credentials.RefreshToken = flags.token
	} else {
		config.Credentials.AccessToken = flags.token
	}

	return config, nil
}

func buildConfigVaaS(flags *commandFlags) (*vcert.Config, error) {
	return &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       flags.url,
		Credentials: &endpoint.Authentication{
			User:        flags.email,
			Password:    flags.password,
			AccessToken: flags.token,
			APIKey:      flags.apiKey,
			ExternalJWT: flags.externalJWT,
			TokenURL:    flags.tokenURL,
		},
	}, nil
}

func buildConfigFirefly(flags *commandFlags) (*vcert.Config, error) {
	return &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeFirefly,
		BaseUrl:       flags.url,
		Credentials: &endpoint.Authentication{
			User:         flags.userName,
			Password:     flags.password,
			AccessToken:  flags.token,
			ClientId:     flags.clientId,
			ClientSecret: flags.clientSecret,
			Scope:        flags.scope,
			IdentityProvider: &endpoint.OAuthProvider{
				DeviceURL: flags.deviceURL,
				TokenURL:  flags.url,
				Audience:  flags.audience,
			},
		},
	}, nil
}
