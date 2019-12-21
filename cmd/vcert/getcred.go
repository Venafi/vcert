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
	getcredFlags.StringVar(&getcredParams.scope, "scope", "", "")
	getcredFlags.StringVar(&getcredParams.clientId, "client-id", "vcert-cli", "")
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
	fmt.Printf("Get Credentials Usage:\n")
	fmt.Printf("vcert getcred -u https://tpp.example.com -username <TPP user> -password <TPP user password>\n")
	fmt.Printf("vcert getcred -u https://tpp.example.com -p12-file <PKCS#12 client certificate> -p12-password <PKCS#12 password> -trust-bundle /path-to/bundle.pem\n")
	fmt.Printf("vcert getcred -u https://tpp.example.com -t <refresh token>\n")
	fmt.Printf("vcert getcred -u https://tpp.example.com -t <refresh token> -scope <scopes and restrictions>\n")

	fmt.Printf("\nRequired:\n")
	fmt.Println("  -u")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the URL of the Trust Protection Platform WebSDK server. Example: -u https://tpp.example.com"))
	fmt.Println("  -username")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the username of a Trust Protection Platform user. Required if -p12-file or -t is not present and may not be combined with either."))
	fmt.Println("  -password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the Trust Protection Platform user's password."))
	fmt.Println("  -p12-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a PKCS#12 file containing a client certificate (and private key) of a Trust Protection Platform user to be used for mutual TLS. Required if -username or -t is not present and may not be combined with either. Must specify -trust-bundle if the chain for the client certificate is not in the PKCS#12 file."))
	fmt.Println("  -p12-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the password of the PKCS#12 file containing the client certificate."))
	fmt.Println("  -t")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a refresh token for a Trust Protection Platform user. Required if -username or -p12-file is not present and may not be combined with either."))

	fmt.Printf("\nOptions:\n")
	fmt.Println("  -client-id")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the application that will be using the token. \"vcert-cli\" is the default."))
	fmt.Println("  -format")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Specify \"json\" to get JSON formatted output instead of the plain text default."))
	fmt.Println("  -scope")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to request specific scopes and restrictions. \"certificate:manage,revoke;\" is the default."))
	fmt.Println("  -trust-bundle")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a PEM file name to be used as trust anchors when communicating with the remote server."))
	fmt.Println("  -verbose")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to increase the level of logging detail, which is helpful when troubleshooting issues."))
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
		return fmt.Errorf("missing -u (URL) parameter")
	}

	if getcredParams.tppToken == "" && getcredParams.tppUser == "" && getcredParams.clientP12 == "" {
		return fmt.Errorf("either -username, -p12-file, or -t must be specified")
	}
	return nil
}
