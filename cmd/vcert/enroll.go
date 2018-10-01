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

func setupEnrollCommandFlags() {
	enrollFlags.StringVar(&enrollParams.cloudURL, "venafi-saas-url", "", "")
	enrollFlags.StringVar(&enrollParams.apiKey, "k", "", "")
	enrollFlags.StringVar(&enrollParams.tppURL, "tpp-url", "", "")
	enrollFlags.StringVar(&enrollParams.tppUser, "tpp-user", "", "")
	enrollFlags.StringVar(&enrollParams.tppPassword, "tpp-password", "", "")
	enrollFlags.StringVar(&enrollParams.trustBundle, "trust-bundle", "", "")
	enrollFlags.StringVar(&enrollParams.zone, "z", "", "")
	enrollFlags.Var(&enrollParams.keyCurve, "key-curve", "")
	enrollFlags.Var(&enrollParams.keyType, "key-type", "")
	enrollFlags.IntVar(&enrollParams.keySize, "key-size", 2048, "")
	enrollFlags.StringVar(&enrollParams.friendlyName, "nickname", "", "")
	enrollFlags.StringVar(&enrollParams.commonName, "cn", "", "")
	enrollFlags.StringVar(&enrollParams.org, "o", "", "")
	enrollFlags.StringVar(&enrollParams.state, "st", "", "")
	enrollFlags.StringVar(&enrollParams.country, "c", "", "")
	enrollFlags.StringVar(&enrollParams.locality, "l", "", "")
	enrollFlags.Var(&enrollParams.orgUnits, "ou", "")
	enrollFlags.Var(&enrollParams.dnsSans, "san-dns", "")
	enrollFlags.Var(&enrollParams.ipSans, "san-ip", "")
	enrollFlags.Var(&enrollParams.emailSans, "san-email", "")
	enrollFlags.StringVar(&enrollParams.format, "format", "pem", "")
	enrollFlags.StringVar(&enrollParams.file, "file", "", "")
	enrollFlags.StringVar(&enrollParams.keyFile, "key-file", "", "")
	enrollFlags.StringVar(&enrollParams.certFile, "cert-file", "", "")
	enrollFlags.StringVar(&enrollParams.chainFile, "chain-file", "", "")
	enrollFlags.StringVar(&enrollParams.chainOption, "chain", "root-last", "")
	enrollFlags.BoolVar(&enrollParams.verbose, "verbose", false, "")
	enrollFlags.BoolVar(&enrollParams.noPrompt, "no-prompt", false, "")
	enrollFlags.BoolVar(&enrollParams.noPickup, "no-pickup", false, "")
	enrollFlags.BoolVar(&enrollParams.testMode, "test-mode", false, "")
	enrollFlags.IntVar(&enrollParams.testModeDelay, "test-mode-delay", 15, "")
	enrollFlags.StringVar(&enrollParams.csrOption, "csr", "", "")
	enrollFlags.StringVar(&enrollParams.keyPassword, "key-password", "", "")
	enrollFlags.StringVar(&enrollParams.pickupIdFile, "pickup-id-file", "", "")
	enrollFlags.IntVar(&enrollParams.timeout, "timeout", 180, "")
	enrollFlags.BoolVar(&enrollParams.insecure, "insecure", false, "")
	enrollFlags.StringVar(&enrollParams.config, "config", "", "")
	enrollFlags.StringVar(&enrollParams.profile, "profile", "", "")
	enrollFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showEnrollmentUsage()
	}
}

func showEnrollmentUsage() {
	fmt.Printf("Enrollment Usage:\n")
	fmt.Printf("  %s enroll <Required><Required Venafi Cloud> OR < Required Trust Protection Platform><Options>\n", os.Args[0])
	fmt.Printf("  %s enroll -k <api key> -cn <common name> -z <zone>\n", os.Args[0])
	fmt.Printf("  %s enroll -k <api key> -cn <common name> -z <zone> -key-type rsa -key-size 4096 -san-dns <alt common name> -san-dns <alt common name2>\n", os.Args[0])
	fmt.Printf("  %s enroll -tpp-url <https://tpp.example.com> -tpp-user <username> -tpp-password <password> -cn <common name> -z <zone>\n", os.Args[0])
	fmt.Printf("  %s enroll -tpp-url <https://tpp.example.com> -tpp-user <username> -tpp-password <password> -cn <common name> -z <zone> -key-size 4096 -san-dns <alt common name> -san-dns <alt common name2>\n", os.Args[0])
	fmt.Printf("  %s enroll -tpp-url <https://tpp.example.com> -tpp-user <username> -tpp-password <password> -cn <common name> -z <zone> -key-type ecdsa -key-curve p384 -san-dns <alt common name> -san-dns <alt common name2>\n", os.Args[0])

	fmt.Printf("\nRequired: for both Venafi Cloud and Trust Protection Platform\n")
	fmt.Println("  -cn")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the common name (CN)."))
	fmt.Println("  -san-dns")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a DNS Subject Alternative Name. To specify more than one, use spaces, like this:  -san-dns test.abc.xyz -san-dns test1.abc.xyz etc."))
	fmt.Println("  -z")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Specify the zone used to determine enrollment configuration. In Trust Protection Platform this is equivelant to the policy path where the certificate object will be stored. "+UtilityShortName+" prepends \\VED\\Policy\\, so you only need to specify policy folders within the root Policy folder. Example: -z Corp\\Engineering"))

	fmt.Printf("\nRequired for Venafi Cloud:\n")
	fmt.Println("  -k")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Your API Key"))

	fmt.Printf("\nRequired for Trust Protection Platform:\n")
	fmt.Println("  -nickname")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a name for the new certificate object that will be created and placed in a policy (which you can specify using the -z option)."))
	fmt.Println("  -tpp-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the password required to authenticate with Trust Protection Platform."))
	fmt.Println("  -tpp-url")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the URL of the Trust Protection Platform Server. Example: -tpp-url https://tpp.example.com"))
	fmt.Println("  -tpp-user")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the username required to authenticate with Trust Protection Platform."))

	fmt.Printf("\nOptions:\n")
	fmt.Println("  -chain")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to include the certificate chain in the output, and to specify where to place it in the file. By default, it is placed last. Options include: ignore | root-first | root-last"))
	fmt.Println("  -cn")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the common name (CN). This is required for Enrollment."))

	fmt.Println("  -config")
	fmt.Printf("\t%s\n", ("Use to specify INI configuration file containing connection details\n" +
		"\t\tFor TPP: tpp_url, tpp_user, tpp_password, tpp_zone\n" +
		"\t\tFor Cloud: cloud_url, cloud_apikey, cloud_zone\n" +
		"\t\tTPP & Cloud: trust_bundle, test_mode"))

	fmt.Println("  -file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting file should be written. If this option is used the key, certificate, and chain will be written to the same file. Example: /tmp/newcert.pem"))

	fmt.Println("  -csr")
	fmt.Printf("\t%s\n", ("Use to specify the CSR and private key location. Options include: local | service | file.\n" +
		"\t\tlocal:   The private key and CSR will be generated locally (default)\n" +
		"\t\tservice: The private key and CSR will be generated at service side\n" +
		"\t\tfile:    The CSR will be read from a file by name. Example: file:/tmp/csr.pem"))

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

func validateEnrollmentFlags() error {

	if enrollParams.config != "" {
		if enrollParams.apiKey != "" ||
			enrollParams.cloudURL != "" ||
			enrollParams.tppURL != "" ||
			enrollParams.tppUser != "" ||
			enrollParams.tppPassword != "" ||
			enrollParams.testMode == true {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if enrollParams.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}
	}

	if enrollParams.tppURL == "" && enrollParams.apiKey == "" && !enrollParams.testMode && enrollParams.config == "" {
		return fmt.Errorf("Missing required data for enrollment. Please check the help to see available command arguments")
	}

	if strings.Index(enrollParams.csrOption, "file:") == 0 {
		if enrollParams.commonName != "" {
			return fmt.Errorf("The '-cn' cannot be used in -csr file: provided mode")
		}
	} else {
		if enrollParams.commonName == "" {
			return fmt.Errorf("A Common Name is required for enrollment")
		}
	}

	if (enrollParams.file != "") && (enrollParams.certFile != "" || enrollParams.chainFile != "" || enrollParams.keyFile != "") {
		return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
	}
	if enrollParams.chainOption == "ignore" && enrollParams.chainFile != "" {
		return fmt.Errorf("The `-chain ignore` option cannot be used with -chain-file option")
	}
	if !enrollParams.testMode && enrollParams.config == "" {
		if enrollParams.tppURL == "" {
			// should be SaaS service
			if enrollParams.apiKey == "" {
				return fmt.Errorf("An APIKey is required for enrollment")
			}
			if enrollParams.zone == "" {
				return fmt.Errorf("A zone is required for requesting a certificate from SaaS")
			}
		} else {
			// should be TPP service
			if enrollParams.tppUser == "" {
				return fmt.Errorf("A username is required for communicating with Trust Protection Platform")
			}
			if enrollParams.noPrompt && enrollParams.tppPassword == "" {
				return fmt.Errorf("A password is required for communicating with Trust Protection Platform")
			}
			if enrollParams.zone == "" {
				return fmt.Errorf("A zone is required for requesting a certificate from Trust Protection Platform")
			}
		}
	}

	if enrollParams.csrOption == "service" && (!enrollParams.noPickup) { // key password is required here
		if enrollParams.noPrompt && len(enrollParams.keyPassword) == 0 {
			return fmt.Errorf("-key-password cannot be empty in -csr service mode unless -no-pickup specified")
		}
	}

	if enrollParams.format == "pkcs12" {
		if enrollParams.file == "" {
			return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
		}
		if enrollParams.certFile != "" || enrollParams.chainFile != "" || enrollParams.keyFile != "" {
			return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
		}
		if strings.Index(enrollParams.csrOption, "file:") == 0 {
			return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "file"`)
		}
		if (enrollParams.csrOption == "" || enrollParams.csrOption == "local") && enrollParams.noPickup {
			return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "local" and -no-pickup is specified`)
		}
	}

	return nil
}
