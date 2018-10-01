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
	"os"
)

var RevocationReasonOptions = []string{
	"none",
	"key-compromise",
	"ca-compromise",
	"affiliation-changed",
	"superseded",
	"cessation-of-operation",
}

func setupRevokeCommandFlags() {
	revokeFlags.StringVar(&revokeParams.distinguishedName, "id", "", "")
	revokeFlags.StringVar(&revokeParams.thumbprint, "thumbprint", "", "")
	revokeFlags.StringVar(&revokeParams.revocationReason, "reason", "", "")
	revokeFlags.BoolVar(&revokeParams.revocationNoRetire, "no-retire", false, "")
	revokeFlags.StringVar(&revokeParams.tppURL, "tpp-url", "", "")
	revokeFlags.StringVar(&revokeParams.tppUser, "tpp-user", "", "")
	revokeFlags.StringVar(&revokeParams.tppPassword, "tpp-password", "", "")
	revokeFlags.StringVar(&revokeParams.trustBundle, "trust-bundle", "", "")
	revokeFlags.StringVar(&revokeParams.file, "file", "", "")
	revokeFlags.BoolVar(&revokeParams.verbose, "verbose", false, "")
	revokeFlags.BoolVar(&revokeParams.noPrompt, "no-prevokerompt", false, "")
	revokeFlags.BoolVar(&revokeParams.testMode, "test-mode", false, "")
	revokeFlags.IntVar(&revokeParams.testModeDelay, "test-mode-delay", 15, "")
	revokeFlags.BoolVar(&revokeParams.insecure, "insecure", false, "")
	// Zone is not needed by `revoke` so it's ignored here,
	// it's only needed for consistency with `enroll` command when user runs `revoke` with the same connection string
	revokeFlags.StringVar(&revokeParams.zone, "z", "", "")
	revokeFlags.StringVar(&revokeParams.config, "config", "", "")
	revokeFlags.StringVar(&revokeParams.profile, "profile", "", "")

	revokeFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showRevokeUsage()
	}
}

func showRevokeUsage() {
	fmt.Printf("Revoke Usage:\n")
	fmt.Printf("  %s revoke <Required Trust Protection Platform><Options>\n", os.Args[0])
	fmt.Printf("  %s revoke -id <certificate DN>\n", os.Args[0])
	fmt.Printf("  %s revoke -thumbprint <certificate thumbprint>\n", os.Args[0])
	fmt.Printf("  %s revoke -tpp-url <https://tpp.example.com> -tpp-user <username> -tpp-password <password> -id <certificate DN>\n", os.Args[0])

	fmt.Printf("\nRequired for Trust Protection Platform:\n")

	fmt.Println("  -id")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText(
		"Use to specify the ID of the certificate to revoke. Required unless -thumbprint is specified. "+
			"Marks the certificate as disabled and no new certificate will be enrolled to replace the revoked one. "+
			"If a replacement certificate is necessary, also specify -no-retire=true."))

	fmt.Println("  -thumbprint")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the SHA1 thumbprint of the certificate to renew."+
		" Value may be specified as a string or read from the certificate file using the file: prefix. "+
		"Implies -no-retire=true"))

	fmt.Println("  -tpp-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the password required to authenticate with Trust Protection Platform."))
	fmt.Println("  -tpp-url")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the URL of the Trust Protection Platform Server. Example: -tpp-url https://tpp.example.com"))
	fmt.Println("  -tpp-user")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the username required to authenticate with Trust Protection Platform."))

	fmt.Printf("\nOptions:\n")

	fmt.Println("  -config")
	fmt.Printf("\t%s\n", ("Use to specify INI configuration file containing connection details\n" +
		"\t\tFor TPP: tpp_url, tpp_user, tpp_password, tpp_zone\n" +
		"\t\tFor Cloud: cloud_url, cloud_apikey, cloud_zone\n" +
		"\t\tTPP & Cloud: trust_bundle, test_mode"))

	fmt.Println("  -no-prompt")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to exclude the authentication prompt. If you enable the prompt and you enter incorrect information, an error is displayed. This is useful with scripting."))

	fmt.Println("  -no-retire")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Do not disable certificate object. Works only with -id <certificate DN>)"))

	fmt.Println("  -profile")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify effective section in ini-configuration file specified by -config option"))

	fmt.Println("  -reason")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Revocation reason. One of the following values: "+fmt.Sprintf("%v", RevocationReasonOptions)))

	fmt.Println("  -test-mode")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to test enrollment without a connection to a real endpoint. Options include: true | false (default false uses a real connection for enrollment)."))

	fmt.Println("  -test-mode-delay")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the maximum, random seconds for a test-mode connection delay (default 15)."))

	fmt.Println("  -trust-bundle")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with the remote server."))

	fmt.Println("  -verbose")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to increase the level of logging detail, which is helpful when troubleshooting issues."))

	fmt.Println("  -h")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to show the help text."))
	fmt.Println()
}

func validateRevokeFlags() error {

	if revokeParams.config != "" {
		if revokeParams.apiKey != "" ||
			revokeParams.cloudURL != "" ||
			revokeParams.tppURL != "" ||
			revokeParams.tppUser != "" ||
			revokeParams.tppPassword != "" ||
			revokeParams.testMode == true {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if revokeParams.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}
		if revokeParams.testMode == false {
			if revokeParams.tppURL == "" {
				return fmt.Errorf("missing required data for certificate revocation. Please check the help to see available command arguments")
			} else {
				if revokeParams.tppUser == "" {
					return fmt.Errorf("username is required for communicating with TPP")
				}
				if revokeParams.noPrompt && revokeParams.tppPassword == "" {
					return fmt.Errorf("password is required for communicating with TPP")
				}
			}
		}
	}

	if revokeParams.distinguishedName == "" {
		if revokeParams.thumbprint == "" {
			return fmt.Errorf("certificate DN or Thumbprint is required to revoke the certificate")
		}
	}
	if revokeParams.distinguishedName != "" && revokeParams.thumbprint != "" {
		return fmt.Errorf("either -id or -thumbprint can be used")
	}
	if revokeParams.revocationReason != "" {

		isValidReason := func(reason string) bool {
			for _, v := range RevocationReasonOptions {
				if v == reason {
					return true
				}
			}
			return false
		}(revokeParams.revocationReason)

		if !isValidReason {
			return fmt.Errorf("%s is not valid revocation reason. it should be one of %v", revokeParams.revocationReason, RevocationReasonOptions)
		}
	}
	return nil
}
