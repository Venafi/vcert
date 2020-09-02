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
	"fmt"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

func buildConfig(c *cli.Context, flags *commandFlags) (cfg vcert.Config, err error) {
	cfg.LogVerbose = flags.verbose

	if flags.config != "" {
		// Loading configuration from file
		cfg, err = vcert.LoadConfigFromFile(flags.config, flags.profile)
		if err != nil {
			return cfg, err
		}
	} else {
		// Loading configuration from CLI flags
		var connectorType endpoint.ConnectorType
		var baseURL string
		var auth = &endpoint.Authentication{}

		//case when access token can come from enviroment variable.
		tppTokenS := flags.tppToken

		if tppTokenS == "" {
			tppTokenS = getPropertyFromEnvironment(vCertToken)
		}

		if flags.testMode {
			connectorType = endpoint.ConnectorTypeFake
			if flags.testModeDelay > 0 {
				logf("Running in -test-mode with emulating endpoint delay.")
				/* #nosec */
				var delay = rand.Intn(flags.testModeDelay)
				for i := 0; i < delay; i++ {
					time.Sleep(1 * time.Second)
				}
			}
		} else if flags.tppUser != "" || tppTokenS != "" || flags.clientP12 != "" {
			connectorType = endpoint.ConnectorTypeTPP

			//add support for using enviroment variables begins
			baseURL = flags.url
			if baseURL == "" {
				baseURL = getPropertyFromEnvironment(vCertURL)
			}
			//add support for using enviroment variables ends

			if tppTokenS == "" && flags.tppPassword == "" && flags.clientP12 == "" {
				return cfg, fmt.Errorf("A password is required to communicate with TPP")
			}

			if flags.tppToken != "" {
				if c.Command.Name == commandGetcredName {
					auth.RefreshToken = flags.tppToken
				} else {
					auth.AccessToken = flags.tppToken
				}
			} else if flags.tppUser != "" && flags.tppPassword != "" {
				auth.User = flags.tppUser
				auth.Password = flags.tppPassword
			} else {
				tokenS := getPropertyFromEnvironment(vCertToken)
				if tokenS != "" {
					if c.Command.Name == commandGetcredName {
						auth.RefreshToken = tokenS
					} else {
						auth.AccessToken = tokenS
					}
				}
			}
		} else {
			apiKey := flags.apiKey
			if apiKey == "" {
				apiKey = getPropertyFromEnvironment(vCertApiKey)
			}
			connectorType = endpoint.ConnectorTypeCloud
			baseURL = flags.url
			auth.APIKey = apiKey
		}
		cfg.ConnectorType = connectorType
		cfg.Credentials = auth
		cfg.BaseUrl = baseURL
	}

	// trust bundle may be overridden by CLI flag
	if flags.trustBundle != "" {
		logf("Detected trust bundle flag at CLI.")
		if cfg.ConnectionTrust != "" {
			logf("Overriding trust bundle based on command line flag.")
		}
		data, err := ioutil.ReadFile(flags.trustBundle)
		if err != nil {
			return cfg, fmt.Errorf("Failed to read trust bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	} else {
		trustBundleSrc := getPropertyFromEnvironment(vCertTrustBundle)
		if trustBundleSrc != "" {
			logf("Detected trust bundle in environment properties.")
			if cfg.ConnectionTrust != "" {
				logf("Overriding trust bundle based on environment property")
			}
			data, err := ioutil.ReadFile(trustBundleSrc)
			if err != nil {
				return cfg, fmt.Errorf("Failed to read trust bundle: %s", err)
			}
			cfg.ConnectionTrust = string(data)
		}
	}

	// zone may be overridden by CLI flag
	if flags.zone != "" {
		if cfg.Zone != "" {
			logf("Overriding zone based on command line flag.")
		}
		cfg.Zone = flags.zone
	}

	zone := getPropertyFromEnvironment(vCertZone)
	if cfg.Zone == "" && zone != "" {
		cfg.Zone = zone
	}

	if c.Command.Name == commandEnrollName || c.Command.Name == commandPickupName {
		if cfg.Zone == "" && cfg.ConnectorType != endpoint.ConnectorTypeFake && !(flags.pickupID != "" || flags.pickupIDFile != "") {
			return cfg, fmt.Errorf("Zone cannot be empty. Use -z option")
		}
	}

	return cfg, nil
}
