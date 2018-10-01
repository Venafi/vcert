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
	"strings"
)

func setupRenewCommandFlags() {
	renewFlags.StringVar(&renewParams.cloudURL, "venafi-saas-url", "", "")
	renewFlags.StringVar(&renewParams.apiKey, "k", "", "")
	renewFlags.StringVar(&renewParams.tppURL, "tpp-url", "", "")
	renewFlags.StringVar(&renewParams.tppUser, "tpp-user", "", "")
	renewFlags.StringVar(&renewParams.tppPassword, "tpp-password", "", "")
	renewFlags.StringVar(&renewParams.trustBundle, "trust-bundle", "", "")
	renewFlags.StringVar(&renewParams.zone, "z", "", "")
	renewFlags.Var(&renewParams.keyCurve, "key-curve", "")
	renewFlags.Var(&renewParams.keyType, "key-type", "")
	renewFlags.IntVar(&renewParams.keySize, "key-size", 0, "")

	renewFlags.StringVar(&renewParams.commonName, "cn", "", "")
	renewFlags.StringVar(&renewParams.org, "o", "", "")
	renewFlags.StringVar(&renewParams.state, "st", "", "")
	renewFlags.StringVar(&renewParams.country, "c", "", "")
	renewFlags.StringVar(&renewParams.locality, "l", "", "")
	renewFlags.Var(&renewParams.orgUnits, "ou", "")
	renewFlags.Var(&renewParams.dnsSans, "san-dns", "")
	renewFlags.Var(&renewParams.ipSans, "san-ip", "")
	renewFlags.Var(&renewParams.emailSans, "san-email", "")
	renewFlags.StringVar(&renewParams.format, "format", "pem", "")
	renewFlags.StringVar(&renewParams.file, "file", "", "")
	renewFlags.StringVar(&renewParams.keyFile, "key-file", "", "")
	renewFlags.StringVar(&renewParams.certFile, "cert-file", "", "")
	renewFlags.StringVar(&renewParams.chainFile, "chain-file", "", "")
	renewFlags.StringVar(&renewParams.chainOption, "chain", "root-last", "")
	renewFlags.BoolVar(&renewParams.verbose, "verbose", false, "")
	renewFlags.BoolVar(&renewParams.noPrompt, "no-prompt", false, "")
	renewFlags.BoolVar(&renewParams.noPickup, "no-pickup", false, "")
	renewFlags.BoolVar(&renewParams.testMode, "test-mode", false, "")
	renewFlags.IntVar(&renewParams.testModeDelay, "test-mode-delay", 15, "")
	renewFlags.StringVar(&renewParams.csrOption, "csr", "", "")
	renewFlags.StringVar(&renewParams.keyPassword, "key-password", "", "")
	renewFlags.StringVar(&renewParams.pickupIdFile, "pickup-id-file", "", "")
	renewFlags.IntVar(&renewParams.timeout, "timeout", 180, "")
	renewFlags.BoolVar(&renewParams.insecure, "insecure", false, "")
	renewFlags.StringVar(&renewParams.distinguishedName, "id", "", "")
	renewFlags.StringVar(&renewParams.thumbprint, "thumbprint", "", "")
	renewFlags.StringVar(&renewParams.config, "config", "", "")
	renewFlags.StringVar(&renewParams.profile, "profile", "", "")

	renewFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showRenewUsage()
	}
}

func showRenewUsage() {
	fmt.Printf("Renew Usage:\n")
	fmt.Printf("  %s renew <Required><Required Venafi Cloud> OR < Required Trust Protection Platform><Options>\n", os.Args[0])
	fmt.Printf("  %s renew -k <api key> -id <certificate DN>\n", os.Args[0])
	fmt.Printf("  %s renew -k <api key> -thumbprint <certificate SHA1 fingerprint>\n", os.Args[0])

	fmt.Printf("\nRequired: for both Venafi Cloud and Trust Protection Platform\n")
	fmt.Println("  -id")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the ID of the certificate to renew. Required unless -thumbprint is specified."))
	fmt.Println("  -thumbprint")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the SHA1 thumbprint of the certificate to renew.  Value may be specified as a string or read from the certificate file using the file: prefix."))

	fmt.Printf("\nRequired for Venafi Cloud:\n")
	fmt.Println("  -k")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Your API Key"))

	fmt.Printf("\nRequired for Trust Protection Platform:\n")
	fmt.Println("  -tpp-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the password required to authenticate with Trust Protection Platform."))
	fmt.Println("  -tpp-url")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the URL of the Trust Protection Platform Server. Example: -tpp-url https://tpp.example.com"))
	fmt.Println("  -tpp-user")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the username required to authenticate with Trust Protection Platform."))

	fmt.Printf("\nOptions:\n")
	fmt.Println("  -chain")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to include the certificate chain in the output, and to specify where to place it in the file. By default, it is placed last. Options include: ignore | root-first | root-last"))
	fmt.Println("  -file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting file should be written. If this option is used the key, certificate, and chain will be written to the same file. Example: /tmp/newcert.pem"))

	fmt.Println("  -config")
	fmt.Printf("\t%s\n", ("Use to specify INI configuration file containing connection details\n" +
		"\t\tFor TPP: tpp_url, tpp_user, tpp_password, tpp_zone\n" +
		"\t\tFor Cloud: cloud_url, cloud_apikey, cloud_zone\n" +
		"\t\tTPP & Cloud: trust_bundle, test_mode"))

	fmt.Println("  -csr")
	fmt.Printf("\t%s\n", ("Use to specify the CSR and private key location. Options include: local | service | file.\n" +
		"\t\tlocal:   New private key and CSR will be generated locally (default)\n" +
		"\t\tservice: The private key and CSR will be generated at service side. If it is allowed by policy, the private key will be reused.\n" +
		"\t\tfile:    CSR used for renewal will be read from a file. Example: -csr file:/tmp/csr.pem."))

	fmt.Println("  -cert-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting certificate file should be written. Example: /tmp/newcert.pem"))
	fmt.Println("  -chain-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a path and file name where the resulting chain file should be written, if no chain file is specified the chain will be stored in the same file as the certificate. Example: /tmp/chain.pem"))
	fmt.Println("  -format")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the output format. PEM is the default format. Options include: pem | json | pkcs12. If PKCS#12 format is specified, then all objects should be written using -file option."))
	fmt.Println("  -key-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting private key file should be written. Example: /tmp/newkey.pem"))
	fmt.Println("  -key-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a password for encrypting the private key. "+
		"For a non-encrypted private key, omit this option and instead specify -no-prompt. "+
		"Example: -key-password file:/Temp/mypasswrds.txt"))
	fmt.Println("  -key-size")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Specify a key size (default 2048)."))
	fmt.Println("  -no-prompt")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Bypasses the authentication prompt. Useful for scripting."))
	fmt.Println("  -no-pickup")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to not wait for the certificate to be issued."))
	fmt.Println("  -pickup-id-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name where Pickup ID will be stored."))
	fmt.Println("  -profile")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify effective section in ini-configuration file specified by -config option"))
	fmt.Println("  -san-dns")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a DNS Subject Alternative Name. "+
		"This option can be repeated to specify more than one value, like this: -san-dns test.abc.xyz -san-dns test1.abc.xyz etc."))
	fmt.Println("  -san-email")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify an Email Subject Alternative Name. "+
		"This option can be repeated to specify more than one value, like this: -san-email abc@abc.xyz -san-email def@abc.xyz etc."))
	fmt.Println("  -san-ip")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify an IP Address Subject Alternative Name. "+
		"This option can be repeated to specify more than one value, like this: -san-ip 1.1.1.1 -san-ip 2.2.2.2."))
	fmt.Println("  -trust-bundle")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a PEM file name to be used "+
		"as trust anchors when communicating with the remote server."))
	fmt.Println("  -test-mode")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to test enrollment without a connection to a real endpoint. Options include: true | false (default false uses a real connection for enrollment)."))
	fmt.Println("  -test-mode-delay")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the maximum, random seconds for a test-mode connection delay (default 15)."))
	fmt.Println("  -verbose")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to increase the level of logging detail, which is helpful when troubleshooting issues."))
	fmt.Println("  -timeout")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Time to wait for certificate to be processed at the service side. In seconds (default 180)."))
	fmt.Println("  -h")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to show the help text."))
	fmt.Println()

	fmt.Printf("\nOptions for Trust Protection Platform:\n")
	fmt.Println("  -key-type")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a key type. Options include: rsa (default) | ecdsa."))
	fmt.Println("  -key-curve value")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the ECDSA key curve. Options include: p521 | p384 | p256 (default p521)."))
}

func validateRenewFlags() error {

	if renewParams.config != "" {
		if renewParams.apiKey != "" ||
			renewParams.cloudURL != "" ||
			renewParams.tppURL != "" ||
			renewParams.tppUser != "" ||
			renewParams.tppPassword != "" ||
			renewParams.testMode == true {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if renewParams.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}
		if !renewParams.testMode {
			if renewParams.tppURL == "" {
				// should be SaaS service
				if renewParams.apiKey == "" {
					return fmt.Errorf("An APIKey is required for enrollment")
				}
			} else {
				// should be TPP service
				if renewParams.tppUser == "" {
					return fmt.Errorf("A username is required for communicating with Trust Protection Platform")
				}
				if renewParams.noPrompt && renewParams.tppPassword == "" {
					return fmt.Errorf("A password is required for communicating with Trust Protection Platform")
				}
			}
		}
	}

	if renewParams.tppURL == "" && renewParams.apiKey == "" && !renewParams.testMode && renewParams.config == "" {
		return fmt.Errorf("Missing required data for certificate renewal. Please check the help to see available command arguments")
	}

	if renewParams.distinguishedName == "" && renewParams.thumbprint == "" {
		return fmt.Errorf("-id or -thumbprint required to identify the certificate to renew")
	}

	if renewParams.distinguishedName != "" && renewParams.thumbprint != "" {
		return fmt.Errorf("-id and -thumbprint cannot be used both at the same time")
	}

	if (renewParams.file != "") && (renewParams.certFile != "" || renewParams.chainFile != "" || renewParams.keyFile != "") {
		return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
	}
	if renewParams.chainOption == "ignore" && renewParams.chainFile != "" {
		return fmt.Errorf("The `-chain ignore` option cannot be used with -chain-file option")
	}

	if renewParams.csrOption == "service" {
		if !(renewParams.noPickup) && renewParams.noPrompt && len(renewParams.keyPassword) == 0 && renewParams.tppURL != "" {
			return fmt.Errorf("-key-password cannot be empty in -csr service mode for TPP unless -no-pickup specified")
		}
		if renewParams.commonName != "" ||
			renewParams.country != "" ||
			renewParams.org != "" ||
			renewParams.state != "" ||
			renewParams.keySize != 0 ||
			len(renewParams.orgUnits) > 0 ||
			len(renewParams.dnsSans) > 0 ||
			len(renewParams.emailSans) > 0 ||
			len(renewParams.ipSans) > 0 {

			return fmt.Errorf("Renewal with -csr=service does not allow options: " +
				"-cn, -c, -o, -ou, -l, -st, -san-*, -key-type, -key-size")
		}
	}
	if 0 == strings.Index(renewParams.csrOption, "file:") {
		if renewParams.commonName != "" ||
			renewParams.country != "" ||
			renewParams.org != "" ||
			renewParams.state != "" ||
			renewParams.keySize != 0 ||
			len(renewParams.orgUnits) > 0 ||
			len(renewParams.dnsSans) > 0 ||
			len(renewParams.emailSans) > 0 ||
			len(renewParams.ipSans) > 0 {

			return fmt.Errorf("Renewal with -csr file:CSR.pem does not allow options: " +
				"-cn, -c, -o, -ou, -l, -st, -san-*, -key-type, -key-size")
		}
	}
	if renewParams.csrOption == "" || renewParams.csrOption == "local" {
		if renewParams.commonName != "" ||
			renewParams.country != "" ||
			renewParams.org != "" ||
			renewParams.state != "" ||
			renewParams.locality != "" ||
			len(renewParams.orgUnits) > 0 {

			return fmt.Errorf("Renewal does not allow options: -cn, -c, -o, -ou, -l, -st")
		}
	}

	if renewParams.format == "pkcs12" {
		if renewParams.file == "" {
			return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
		}
		if renewParams.certFile != "" || renewParams.chainFile != "" || renewParams.keyFile != "" {
			return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
		}
		if strings.Index(renewParams.csrOption, "file:") == 0 {
			return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "file"`)
		}
		if (renewParams.csrOption == "" || renewParams.csrOption == "local") && renewParams.noPickup {
			return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "local" and -no-pickup is specified`)
		}
	}
	return nil
}
