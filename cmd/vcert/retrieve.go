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

func setupRetrieveCommandFlags() {
	pickupFlags.StringVar(&pickParams.cloudURL, "venafi-saas-url", "", "")
	pickupFlags.StringVar(&pickParams.pickupID, "pickup-id", "", "")
	pickupFlags.StringVar(&pickParams.apiKey, "k", "", "")
	pickupFlags.StringVar(&pickParams.tppURL, "tpp-url", "", "")
	pickupFlags.StringVar(&pickParams.tppUser, "tpp-user", "", "")
	pickupFlags.StringVar(&pickParams.tppPassword, "tpp-password", "", "")
	pickupFlags.StringVar(&pickParams.trustBundle, "trust-bundle", "", "")
	pickupFlags.StringVar(&pickParams.format, "format", "pem", "")
	pickupFlags.StringVar(&pickParams.file, "file", "", "")
	pickupFlags.StringVar(&pickParams.certFile, "cert-file", "", "")
	pickupFlags.StringVar(&pickParams.chainFile, "chain-file", "", "")
	pickupFlags.StringVar(&pickParams.chainOption, "chain", "root-last", "")
	pickupFlags.BoolVar(&pickParams.verbose, "verbose", false, "")
	pickupFlags.BoolVar(&pickParams.noPrompt, "no-prompt", false, "")
	pickupFlags.BoolVar(&pickParams.testMode, "test-mode", false, "")
	pickupFlags.IntVar(&pickParams.testModeDelay, "test-mode-delay", 15, "")
	pickupFlags.StringVar(&pickParams.keyPassword, "key-password", "", "")
	pickupFlags.StringVar(&pickParams.zone, "z", "", "")
	pickupFlags.IntVar(&pickParams.timeout, "timeout", 0, "")
	pickupFlags.BoolVar(&pickParams.insecure, "insecure", false, "")
	pickupFlags.StringVar(&pickParams.pickupIdFile, "pickup-id-file", "", "")
	pickupFlags.StringVar(&pickParams.keyFile, "key-file", "", "")
	pickupFlags.StringVar(&pickParams.config, "config", "", "")
	pickupFlags.StringVar(&pickParams.profile, "profile", "", "")

	pickupFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showPickupUsage()
	}
}

func showPickupUsage() {
	fmt.Printf("Pickup Usage:\n")
	fmt.Printf("  %s pickup <Required Venafi Cloud> OR <Required Trust Protection Platform><Options>\n", os.Args[0])
	fmt.Printf("  %s pickup -k <api key> -pickup-id <request id> OR -pickup-id-file <file with Pickup ID value>\n", os.Args[0])
	fmt.Printf("  %s pickup -tpp-url <https://tpp.example.com> -tpp-user <username> -tpp-password <password> -pickup-id <request id>\n", os.Args[0])

	fmt.Printf("\nRequired for Trust Protection Platform:\n")
	fmt.Println("  -pickup-id")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the certificate ID of the certificate for retrieve."))
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Example: -pickup-id 3260ece0-0da4-11e7-9be2-891dab33d0eb"))
	fmt.Println("  -pickup-id-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify file name from where Pickup ID will be read. Either one of -pickup-id and -pickup-id-file options is required."))

	fmt.Printf("\nRequired Venafi Cloud Options:\n")
	fmt.Println("  -k")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Your API Key"))

	fmt.Printf("\nRequired Trust Protection Platform Options:\n")
	fmt.Println("  -tpp-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the password required to authenticate with Trust Protection Platform."))
	fmt.Println("  -tpp-url")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the URL of the Trust Protection Platform Server. Example: -tpp-url https://tpp.example.com"))
	fmt.Println("  -tpp-user")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the username required to authenticate with Trust Protection Platform."))

	fmt.Printf("\nOptions:\n")

	fmt.Println("  -cert-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting certificate file should be written. Example: /tmp/newcert.pem"))

	fmt.Println("  -chain")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to include the certificate chain in the output, and to specify where to place it in the file. By default, it is placed last. Options include: ignore | root-first | root-last"))

	fmt.Println("  -chain-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting chain file should be written, if no chain file is specified the chain will be stored in the same file as the certificate. Example: /tmp/chain.pem"))

	fmt.Println("  -config")
	fmt.Printf("\t%s\n", ("Use to specify INI configuration file containing connection details\n" +
		"\t\tFor TPP: tpp_url, tpp_user, tpp_password, tpp_zone\n" +
		"\t\tFor Cloud: cloud_url, cloud_apikey, cloud_zone\n" +
		"\t\tTPP & Cloud: trust_bundle, test_mode"))

	fmt.Println("  -file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting file should be written. If this option is used both the certificate and the chain will be written to the same file. Example: /tmp/newcert.pem"))

	fmt.Println("  -format")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the output format. PEM is the default format. Options include: pem | json | pkcs12. If PKCS#12 format is specified, then all objects should be written using -file option."))

	fmt.Println("  -key-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting private key file should be written. Example: /tmp/newkey.pem"))

	fmt.Println("  -key-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a password for encrypting the private key. For a non-encrypted private key, specify -no-prompt without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file. Example: -key-password file:/Temp/mypasswrds.txt"))

	fmt.Println("  -no-prompt")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to exclude the authentication prompt. If you enable the prompt and you enter incorrect information, an error is displayed. This is useful with scripting."))

	fmt.Println("  -profile")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify effective section in ini-configuration file specified by -config option"))

	fmt.Println("  -test-mode")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to test enrollment without a connection to a real endpoint. Options include: true | false (default false uses a real connection for enrollment)."))
	fmt.Println("  -test-mode-delay")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the maximum, random seconds for a test-mode connection delay (default 15)."))

	fmt.Println("  -timeout")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Time to wait for certificate to be processed at the service side (default is 0 for `pickup` meaning just one retrieve attempt)."))

	fmt.Println("  -trust-bundle")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with the remote server."))

	fmt.Println("  -verbose")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to increase the level of logging detail, which is helpful when troubleshooting issues."))

	fmt.Println("  -h")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to show the help text."))
	fmt.Println()
}

func validatePickupFlags() error {

	if pickParams.config != "" {
		if pickParams.apiKey != "" ||
			pickParams.cloudURL != "" ||
			pickParams.tppURL != "" ||
			pickParams.tppUser != "" ||
			pickParams.tppPassword != "" ||
			pickParams.testMode == true {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if pickParams.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}
		if !pickParams.testMode {
			if pickParams.tppURL == "" {
				if pickParams.apiKey == "" {
					return fmt.Errorf("An APIKey is required to pickup a certificate")
				}
			} else {
				if pickParams.tppUser == "" {
					return fmt.Errorf("A username is required for communicating with TPP")
				}
				if pickParams.noPrompt && pickParams.tppPassword == "" {
					return fmt.Errorf("A password is required for communicating with TPP")
				}
			}
		}
	}

	if pickParams.tppURL == "" && pickParams.apiKey == "" && !pickParams.testMode && pickParams.config == "" {
		return fmt.Errorf("Missing required data for certificate pickup. Please check the help to see available command arguments")
	}
	if pickParams.pickupID == "" && pickParams.pickupIdFile == "" {
		return fmt.Errorf("A Pickup ID is required to pickup a certificate provided by -pickup-id OR -pickup-id-file options")
	}
	if pickParams.pickupID != "" && pickParams.pickupIdFile != "" {
		return fmt.Errorf("Both -pickup-id and -pickup-id-file options cannot be specified at the same time")
	}
	if (pickParams.file != "" && pickParams.certFile != "") || (pickParams.file != "" && pickParams.chainFile != "") {
		return fmt.Errorf("the '-file' and '-cert-file' / '-chain-file' cannot be used together. Either use '-file' or '-cert-file' and '-chain-file'")
	}
	if pickParams.format == "pkcs12" {
		if pickParams.file == "" {
			return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
		}
		if pickParams.certFile != "" || pickParams.chainFile != "" || pickParams.keyFile != "" {
			return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
		}
	}
	return nil
}
