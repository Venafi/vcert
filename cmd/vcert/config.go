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
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
)

func buildConfig(cf *commandFlags) (cfg vcert.Config, err error) {
	cfg.LogVerbose = cf.verbose

	if cf.config != "" {
		// Loading configuration from file
		cfg, err = vcert.LoadConfigFromFile(cf.config, cf.profile)
		if err != nil {
			return cfg, err
		}
	} else {
		// Loading configuration from CLI flags
		var connectorType endpoint.ConnectorType
		var baseURL string
		var auth = &endpoint.Authentication{}
		if cf.testMode {
			connectorType = endpoint.ConnectorTypeFake
			if cf.testModeDelay > 0 {
				logger.Println("Running in -test-mode with emulating endpoint delay.")
				var delay = rand.Intn(cf.testModeDelay)
				for i := 0; i < delay; i++ {
					time.Sleep(1 * time.Second)
				}
			}
		} else if cf.tppURL != "" {
			connectorType = endpoint.ConnectorTypeTPP
			baseURL = cf.tppURL
			if cf.tppPassword == "" {
				logger.Panicf("A password is required to communicate with TPP")
			}
			auth.User = cf.tppUser
			auth.Password = cf.tppPassword
		} else {
			connectorType = endpoint.ConnectorTypeCloud
			baseURL = cf.cloudURL
			auth.APIKey = cf.apiKey
		}
		cfg.ConnectorType = connectorType
		cfg.Credentials = auth
		cfg.BaseUrl = baseURL
	}

	// trust bundle may be overridden by CLI flag
	if cf.trustBundle != "" {
		logger.Println("Detected trust bundle flag at CLI.")
		if cfg.ConnectionTrust != "" {
			logf("Overriding trust bundle based on command line flag.")
		}
		data, err := ioutil.ReadFile(cf.trustBundle)
		if err != nil {
			logger.Panicf("Failed to read trust bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	}

	// zone may be overridden by CLI flag
	if cf.zone != "" {
		if cfg.Zone != "" {
			logf("Overriding zone based on command line flag.")
		}
		cfg.Zone = cf.zone
	}

	if cfg.Zone == "" && cfg.ConnectorType != endpoint.ConnectorTypeFake && !(cf.pickupID != "" || cf.pickupIDFile != "") {
		return cfg, fmt.Errorf("Zone cannot be empty. Use -z option")
	}

	return cfg, nil
}
