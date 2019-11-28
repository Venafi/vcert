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
	"github.com/Venafi/vcert"
)

func setupGetcredCommandFlags() {
	getcredFlags.StringVar(&getcredParams.url, "u", "", "")
	getcredFlags.StringVar(&getcredParams.tppUser, "tpp-user", "", "")
	getcredFlags.StringVar(&getcredParams.tppPassword, "tpp-password", "", "")
	getcredFlags.StringVar(&getcredParams.tppToken, "t", "", "")
	getcredFlags.StringVar(&getcredParams.trustBundle, "trust-bundle", "", "")
	getcredFlags.StringVar(&getcredParams.scope, "scope", "", "")
	getcredFlags.StringVar(&getcredParams.clientId, "client-id", "", "")
	getcredFlags.StringVar(&getcredParams.config, "config", "", "")
	getcredFlags.StringVar(&getcredParams.profile, "profile", "", "")
	getcredFlags.StringVar(&getcredParams.clientP12, "client-pkcs12", "", "")
	getcredFlags.StringVar(&getcredParams.clientP12PW, "client-pkcs12-pw", "", "")
	getcredFlags.StringVar(&getcredParams.format, "format", "", "")

	getcredFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showGetcredUsage()
	}
}

func showGetcredUsage() {
	fmt.Printf("Getting credentials usage:\n")
	fmt.Println("  -format")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the output format. If not specified will be plain text. Options include: json ."))
	//TODO
	fmt.Println()
}

// validateGetcredFlags valdiates the combination of command flags specified in an getcredment request
func validateGetcredFlags() error {
	if enrollParams.config != "" {
		if enrollParams.apiKey != "" ||
			enrollParams.cloudURL != "" ||
			enrollParams.tppURL != "" ||
			enrollParams.tppUser != "" ||
			enrollParams.tppPassword != "" ||
			enrollParams.tppToken != "" ||
			enrollParams.url != "" ||
			enrollParams.testMode {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if enrollParams.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}
	}
	//TODO
	return nil
}
