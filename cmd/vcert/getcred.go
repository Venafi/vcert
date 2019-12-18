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
	getcredFlags.StringVar(&getcredParams.tppUser, "username", "", "")
	getcredFlags.StringVar(&getcredParams.tppPassword, "password", "", "")
	getcredFlags.StringVar(&getcredParams.tppToken, "t", "", "")
	getcredFlags.StringVar(&getcredParams.trustBundle, "trust-bundle", "", "")
	getcredFlags.StringVar(&getcredParams.scope, "scope", "certificates:manage,revoke", "")
	getcredFlags.StringVar(&getcredParams.clientId, "client-id", "vedsdk", "")
	getcredFlags.StringVar(&getcredParams.config, "config", "", "")
	getcredFlags.StringVar(&getcredParams.profile, "profile", "", "")
	getcredFlags.StringVar(&getcredParams.clientP12, "p12-file", "", "")
	getcredFlags.StringVar(&getcredParams.clientP12PW, "p12-password", "", "")
	getcredFlags.StringVar(&getcredParams.format, "format", "", "")
	getcredFlags.BoolVar(&getcredParams.verbose, "verbose", false, "")
	getcredFlags.BoolVar(&getcredParams.insecure, "insecure", false, "")

	getcredFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showGetcredUsage()
	}
}

func showGetcredUsage() {
	fmt.Printf("Getting credentials usage:\n")
	fmt.Println("  -u")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify TPP url."))
	fmt.Println("  -username")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify TPP user."))
	fmt.Println("  -password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify TPP password."))
	fmt.Println("  -p12-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify TPP PKSC12 file if using MTLS connection."))
	fmt.Println("  -p12-file-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify TPP PKSC12 file password if using MTLS connection."))
	fmt.Println("  -t")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the refresh token."))
	fmt.Println("  -format")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the output format. If not specified will be plain text. Options include: json ."))
	fmt.Println("  -verbose")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to increase the level of logging detail, which is helpful when troubleshooting issues."))
	fmt.Printf("Getting credentials examples:\n")
	fmt.Println("Get refresh token:\n")
	fmt.Printf("vcert getcred -u https:/venafi.example.com/vedsdk -trust-bundle /opt/venafi/bundle.pem -t 3rlybZwAdV1qo/KpNJ5FWg==\n")
	fmt.Println("Refresh access token:\n")
	fmt.Printf("vcert getcred -u https:/venafi.example.com/vedsdk -trust-bundle /opt/venafi/bundle.pem -t 3rlybZwAdV1qo/KpNJ5FWg==\n")
	fmt.Println("Get refresh token using MTLS:\n")
	fmt.Printf("vcert getcred -u https:/venafi.example.com/vedsdk -trust-bundle /opt/venafi/bundle.pem --p12-file venafi.p12 -p12-password secretPass\n")

}

// validateGetcredFlags valdiates the combination of command flags specified in an getcredment request
func validateGetcredFlags() error {
	if getcredParams.config != "" {
		if getcredParams.apiKey != "" ||
			getcredParams.cloudURL != "" ||
			getcredParams.tppURL != "" ||
			getcredParams.tppUser != "" ||
			getcredParams.tppPassword != "" ||
			getcredParams.tppToken != "" ||
			getcredParams.url != "" ||
			getcredParams.testMode {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if getcredParams.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}
	}

	if getcredParams.url == "" && getcredParams.tppURL == "" {
		return fmt.Errorf("Missing url parameter.")
	}

	if getcredParams.tppToken == "" && getcredParams.tppUser == "" && getcredParams.clientP12 == "" {
		return fmt.Errorf("Refresh token of username must be specified")
	}
	return nil
}
