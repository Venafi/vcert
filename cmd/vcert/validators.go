/*
 * Copyright 2020-2021 Venafi, Inc.
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
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/Venafi/vcert/v4/pkg/certificate"
)

// RevocationReasonOptions is an array of strings containing reasons for certificate revocation
var RevocationReasonOptions = []string{
	"none",
	"key-compromise",
	"ca-compromise",
	"affiliation-changed",
	"superseded",
	"cessation-of-operation",
}

//taken from keystore.minPasswordLen constant
const JKSMinPasswordLen = 6

func readData(commandName string) error {
	if strings.HasPrefix(flags.distinguishedName, "file:") {
		fileName := flags.distinguishedName[5:]
		bytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Failed to read Certificate DN: %s", err)
		}
		flags.distinguishedName = strings.TrimSpace(string(bytes))
	}
	if strings.HasPrefix(flags.keyPassword, "file:") {
		fileName := flags.keyPassword[5:]
		bytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Failed to read password from file: %s", err)
		}
		flags.keyPassword = strings.TrimSpace(string(bytes))
	}
	var err error
	if strings.HasPrefix(flags.thumbprint, "file:") {
		certFileName := flags.thumbprint[5:]
		flags.thumbprint, err = readThumbprintFromFile(certFileName)
		if err != nil {
			return fmt.Errorf("Failed to read certificate fingerprint: %s", err)
		}
	}

	if err = readPasswordsFromInputFlags(commandName, &flags); err != nil {
		return fmt.Errorf("Failed to read password from input: %s", err)
	}
	return nil
}

func validateCommonFlags(commandName string) error {
	if flags.format != "" && flags.format != "pem" && flags.format != "json" && flags.format != "pkcs12" && flags.format != JKSFormat {
		return fmt.Errorf("Unexpected output format: %s", flags.format)
	}
	if flags.file != "" && (flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "") {
		return fmt.Errorf("The '-file' option cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
	}

	csrOptionRegex := regexp.MustCompile(`(^file:).*$|^local$|^service$|^$`)
	if !csrOptionRegex.MatchString(flags.csrOption) {
		return fmt.Errorf("unexpected --csr option provided: %s; specify one of the following options: %s, %s, or %s", flags.csrOption, "'file:<filename>'", "'local'", "'service'")
	}

	csrOptFlagResults := csrOptionRegex.FindStringSubmatch(flags.csrOption)

	if csrOptFlagResults[1] != "" && (flags.keyTypeString != "" || flags.keyCurveString != "" || flags.keySize > 0) {
		return fmt.Errorf("the '--keytype','--keycurve' and '--key-size' options cannot be used when '--csr file:' option is provided")
	}

	switch flags.keyTypeString {
	case "rsa":
		kt := certificate.KeyTypeRSA
		flags.keyType = &kt
	case "ecdsa":
		kt := certificate.KeyTypeECDSA
		flags.keyType = &kt
	case "":
	default:
		return fmt.Errorf("unknown key type: %s", flags.keyTypeString)
	}

	switch strings.ToLower(flags.keyCurveString) {
	case "p256":
		flags.keyCurve = certificate.EllipticCurveP256
	case "p384":
		flags.keyCurve = certificate.EllipticCurveP384
	case "p521":
		flags.keyCurve = certificate.EllipticCurveP521
	case "":
	default:
		return fmt.Errorf("unknown EC key curve: %s", flags.keyTypeString)

	}
	return nil
}

func validateConnectionFlags(commandName string) error {
	if flags.config != "" {
		if flags.apiKey != "" ||
			flags.tppUser != "" ||
			flags.tppPassword != "" ||
			flags.tppToken != "" ||
			flags.url != "" ||
			flags.testMode {
			return fmt.Errorf("connection details cannot be specified with flags when -config is used")
		}
	} else {
		if flags.profile != "" {
			return fmt.Errorf("-profile option cannot be used without -config option")
		}

		tppToken := flags.tppToken
		if tppToken == "" {
			tppToken = getPropertyFromEnvironment(vCertToken)
		}

		if flags.testMode {
			return nil
		}
		if flags.tppUser == "" && tppToken == "" {
			// should be SaaS endpoint
			if commandName != "sshgetconfig" && flags.apiKey == "" && getPropertyFromEnvironment(vCertApiKey) == "" {
				return fmt.Errorf("An API key is required for communicating with Venafi as a Service")
			}
		} else {
			// should be TPP service
			if flags.url == "" && getPropertyFromEnvironment(vCertURL) == "" {
				return fmt.Errorf("missing -u (URL) parameter")
			}
			if flags.noPrompt && flags.tppPassword == "" && tppToken == "" {
				return fmt.Errorf("An access token or password is required for communicating with Trust Protection Platform")
			}

			// mutual TLS with TPP service
			if flags.clientP12 == "" && flags.clientP12PW != "" {
				return fmt.Errorf("-client-pkcs12-pw can only be specified in combination with -client-pkcs12")
			}
		}
	}
	return nil
}

func validatePKCS12Flags(commandName string) error {
	if flags.format == "pkcs12" {
		if commandName == commandEnrollName {
			if flags.file == "" && flags.csrOption != "service" {
				return fmt.Errorf("PKCS#12 format requires certificate, private key, and chain to be written to a single file; specify using --file")
			}
		} else {
			if flags.file == "" { // todo: for enroll it also checks  flags.csrOption != "service"
				return fmt.Errorf("PKCS#12 format requires certificate, private key, and chain to be written to a single file; specify using --file")
			}
		}
		if flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "" {
			return fmt.Errorf(`The --file parameter may not be combined with the --cert-file, --key-file, or --chain-file parameters when --format is "pkcs12"`)
		}
		if strings.HasPrefix(flags.csrOption, "file:") {
			return fmt.Errorf(`The --csr "file" option may not be used with the enroll or renew actions when --format is "pkcs12"`)
		}
		if (flags.csrOption == "" || flags.csrOption == "local") && flags.noPickup {
			return fmt.Errorf(`The --csr "local" option may not be used with the enroll or renew actions when --format is "pkcs12" and --no-pickup is specified`)
		}
	}
	return nil
}

func validateJKSFlags(commandName string) error {
	if flags.format == JKSFormat {

		if commandName == commandEnrollName {
			if flags.file == "" && flags.csrOption != "service" {
				return fmt.Errorf("JKS format requires certificate, private key, and chain to be written to a single file; specify using --file")
			}
		} else {
			if flags.file == "" { // todo: for enroll it also checks  flags.csrOption != "service"
				return fmt.Errorf("JKS format requires certificate, private key, and chain to be written to a single file; specify using --file")
			}
		}
		if flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "" {
			return fmt.Errorf(`The --file parameter may not be combined with the --cert-file, --key-file, or --chain-file parameters when --format is "jks"`)
		}
		if strings.HasPrefix(flags.csrOption, "file:") {
			return fmt.Errorf(`The --csr "file" option may not be used with the enroll or renew actions when --format is "jks"`)
		}
		if (flags.csrOption == "" || flags.csrOption == "local") && flags.noPickup {
			return fmt.Errorf(`The --csr "local" option may not be used with the enroll or renew actions when --format is "jks" and --no-pickup is specified`)
		}

		if flags.keyPassword == "" {
			return fmt.Errorf("JKS format requires passwords that are at least %d characters long", JKSMinPasswordLen)
		} else {
			if (flags.jksPassword != "" && len(flags.jksPassword) < JKSMinPasswordLen) || (flags.keyPassword != "" && len(flags.keyPassword) < JKSMinPasswordLen) {
				return fmt.Errorf("JKS format requires passwords that are at least %d characters long", JKSMinPasswordLen)
			}
		}

		if flags.jksAlias == "" {
			return fmt.Errorf("The --jks-alias parameter is required with --format jks")
		}
	} else {

		if flags.jksPassword != "" {
			return fmt.Errorf("The --jks-password parameter may only be used with --format jks")
		}

		if flags.jksAlias != "" {
			return fmt.Errorf("The --jks-alias parameter may only be used with --format jks")
		}
	}

	return nil
}

func validateEnrollFlags(commandName string) error {
	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}
	err = validateCommonFlags(commandName)
	if err != nil {
		return err
	}

	err = readData(commandName)
	if err != nil {
		return err
	}
	if strings.Index(flags.csrOption, "file:") == 0 {
		if flags.commonName != "" {
			return fmt.Errorf("The '-cn' option cannot be used in -csr file: provided mode")
		}
	} else {
		if flags.commonName == "" {
			return fmt.Errorf("A Common Name is required for enrollment")
		}
	}

	if flags.chainOption == "ignore" && flags.chainFile != "" {
		return fmt.Errorf("The `-chain ignore` option cannot be used with -chain-file option")
	}

	apiKey := flags.apiKey
	if apiKey == "" {
		apiKey = getPropertyFromEnvironment(vCertApiKey)
	}

	if !flags.testMode && flags.config == "" {

		tppToken := flags.tppToken
		if tppToken == "" {
			tppToken = getPropertyFromEnvironment(vCertToken)
		}

		zone := flags.zone
		if zone == "" {
			zone = getPropertyFromEnvironment(vCertZone)
		}

		if flags.tppUser == "" && tppToken == "" {
			// should be SaaS endpoint
			if apiKey == "" {
				return fmt.Errorf("An API key is required for enrollment with Venafi as a Service")
			}
			if zone == "" {
				return fmt.Errorf("A zone is required for requesting a certificate from Venafi as a Service")
			}
		} else {
			// should be TPP service
			if flags.tppUser == "" && tppToken == "" {
				return fmt.Errorf("An access token or username is required for communicating with Trust Protection Platform")
			}
			if flags.noPrompt && flags.tppPassword == "" && tppToken == "" {
				return fmt.Errorf("An access token or password is required for communicating with Trust Protection Platform")
			}

			if zone == "" {
				return fmt.Errorf("A zone is required for requesting a certificate from Trust Protection Platform")
			}

			// mutual TLS with TPP service
			if flags.clientP12 == "" && flags.clientP12PW != "" {
				return fmt.Errorf("-client-pkcs12-pw can only be specified in combination with -client-pkcs12")
			}
		}

		if flags.validDays != "" {

			valid := validateValidDaysFlag(commandName)

			if !valid {
				return fmt.Errorf("--valid-days is set but, it have an invalid format/data")
			}

		}

	}

	if flags.csrOption == "file" && flags.keyFile != "" { // Do not specify -key-file with -csr file as VCert cannot access the private key
		return fmt.Errorf("-key-file cannot be used with -csr file as VCert cannot access the private key")
	}
	if flags.csrOption == "service" && (!flags.noPickup) { // Key password is required here
		if flags.noPrompt && len(flags.keyPassword) == 0 {
			return fmt.Errorf("-key-password cannot be empty in -csr service mode unless -no-pickup specified")
		}
	}
	err = validatePKCS12Flags(commandName)
	if err != nil {
		return err
	}

	err = validateJKSFlags(commandName)
	if err != nil {
		return err
	}

	if flags.tppUser != "" || flags.tppPassword != "" {
		logf("Warning: User\\Password authentication is deprecated, please use access token instead.")
	}

	if flags.tlsAddress != "" && flags.instance == "" {
		return fmt.Errorf("--tls-address cannot be used without --instance")
	}

	if (flags.tlsAddress != "" || flags.instance != "") && apiKey != "" {
		return fmt.Errorf("--instance and --tls-address are not applicable to Venafi as a Service")
	}

	return nil
}

func validateValidDaysFlag(cn string) bool {
	if cn != "enroll" {
		return false
	}

	if flags.validDays != "" {

		validDays := flags.validDays

		var regex = regexp.MustCompile("[1-9]+[0-9]*(#[DdEeMm])?")

		return regex.MatchString(validDays)

	}

	return true
}

func validateCredMgmtFlags1(commandName string) error {
	var err error

	tppTokenS := flags.tppToken
	if tppTokenS == "" {
		tppTokenS = getPropertyFromEnvironment(vCertToken)
	}

	if flags.config != "" {
		if flags.apiKey != "" ||
			flags.tppUser != "" ||
			flags.tppPassword != "" ||
			tppTokenS != "" ||
			flags.url != "" ||
			flags.testMode {
			return fmt.Errorf("connection details cannot be specified with flags or environment variables when --config is used")
		}
	} else {
		if flags.profile != "" {
			return fmt.Errorf("--profile option cannot be used without --config option")
		}
		if flags.testMode {
			return fmt.Errorf("There is no test mode for %s command", commandName)
		}
		if commandName == commandGetCredName {
			if flags.tppUser == "" && tppTokenS == "" && flags.clientP12 == "" {
				return fmt.Errorf("either --username, --p12-file, or -t must be specified")
			}
		} else {
			if tppTokenS == "" {
				return fmt.Errorf("missing -t (access token) parameter")
			}
		}

		if flags.url == "" && getPropertyFromEnvironment(vCertURL) == "" {
			return fmt.Errorf("missing -u (URL) parameter")
		}

		if flags.noPrompt && flags.tppPassword == "" && tppTokenS == "" {
			return fmt.Errorf("An access token or password is required for communicating with Trust Protection Platform")
		}

		// mutual TLS with TPP service
		if flags.clientP12 == "" && flags.clientP12PW != "" {
			return fmt.Errorf("--client-pkcs12-pw can only be specified in combination with --client-pkcs12")
		}
	}

	err = validateCommonFlags(commandName)
	if err != nil {
		return err
	}
	err = readData(commandName)
	if err != nil {
		return err
	}

	return nil
}

func validateGenerateFlags1(commandName string) error {
	err := validateCommonFlags(commandName)
	if err != nil {
		return err
	}
	err = readData(commandName)
	if err != nil {
		return err
	}

	if flags.commonName == "" && len(flags.dnsSans) == 0 {
		return fmt.Errorf("A Common Name (cn) or Subject Alternative Name: DNS (san-dns) value is required")
	}

	return nil
}

func validateRenewFlags1(commandName string) error {

	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}
	err = validateCommonFlags(commandName)
	if err != nil {
		return err
	}
	err = readData(commandName)
	if err != nil {
		return err
	}

	if flags.distinguishedName == "" && flags.thumbprint == "" {
		return fmt.Errorf("-id or -thumbprint required to identify the certificate to renew")
	}
	if flags.distinguishedName != "" && flags.thumbprint != "" {
		return fmt.Errorf("-id and -thumbprint cannot be used at the same time")
	}
	if flags.chainOption == "ignore" && flags.chainFile != "" {
		return fmt.Errorf("The `-chain ignore` option cannot be used with -chain-file option")
	}

	if flags.csrOption == "service" {
		if !(flags.noPickup) && flags.noPrompt && len(flags.keyPassword) == 0 && (flags.tppUser != "" || flags.tppToken != "") {
			return fmt.Errorf("-key-password cannot be empty in -csr service mode for TPP unless -no-pickup specified")
		}
		if flags.commonName != "" ||
			flags.country != "" ||
			flags.org != "" ||
			flags.state != "" ||
			flags.keySize != 0 ||
			len(flags.orgUnits) > 0 ||
			len(flags.dnsSans) > 0 ||
			len(flags.emailSans) > 0 ||
			len(flags.ipSans) > 0 {

			return fmt.Errorf("Renewal with -csr=service does not allow options: " +
				"-cn, -c, -o, -ou, -l, -st, -san-*, -key-type, -key-size")
		}
	}
	if strings.HasPrefix(flags.csrOption, "file:") {
		if flags.commonName != "" ||
			flags.country != "" ||
			flags.org != "" ||
			flags.state != "" ||
			flags.keySize != 0 ||
			len(flags.orgUnits) > 0 ||
			len(flags.dnsSans) > 0 ||
			len(flags.emailSans) > 0 ||
			len(flags.ipSans) > 0 {

			return fmt.Errorf("Renewal with -csr file:CSR.pem does not allow options: " +
				"-cn, -c, -o, -ou, -l, -st, -san-*, -key-type, -key-size")
		}
	}
	if flags.csrOption == "" || flags.csrOption == "local" {
		if flags.commonName != "" ||
			flags.country != "" ||
			flags.org != "" ||
			flags.state != "" ||
			flags.locality != "" ||
			len(flags.orgUnits) > 0 {

			return fmt.Errorf("Renewal does not allow options: -cn, -c, -o, -ou, -l, -st")
		}
	}

	err = validatePKCS12Flags(commandName)
	if err != nil {
		return err
	}

	err = validateJKSFlags(commandName)
	if err != nil {
		return err
	}

	return nil
}

func validatePickupFlags1(commandName string) error {

	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}
	err = validateCommonFlags(commandName)
	if err != nil {
		return err
	}

	cloudSerViceGenerated := IsCSRServiceVaaSGenerated(commandName)
	if cloudSerViceGenerated && flags.noPrompt && (flags.keyPassword == "") {
		return fmt.Errorf("key-password is required")
	}

	err = readData(commandName)
	if err != nil {
		return err
	}

	if flags.pickupID == "" && flags.pickupIDFile == "" {
		return fmt.Errorf("A Pickup ID is required to pickup a certificate provided by -pickup-id OR -pickup-id-file options")
	}
	if flags.pickupID != "" && flags.pickupIDFile != "" {
		return fmt.Errorf("Both -pickup-id and -pickup-id-file options cannot be specified at the same time")
	}

	err = validatePKCS12Flags(commandName)
	if err != nil {
		return err
	}

	err = validateJKSFlags(commandName)
	if err != nil {
		return err
	}

	return nil
}

func validateRevokeFlags1(commandName string) error {

	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}
	err = validateCommonFlags(commandName)
	if err != nil {
		return err
	}
	err = readData(commandName)
	if err != nil {
		return err
	}
	if flags.distinguishedName == "" && flags.thumbprint == "" {
		return fmt.Errorf("Certificate DN or Thumbprint is required to revoke the certificate")
	}

	if flags.distinguishedName != "" && flags.thumbprint != "" {
		return fmt.Errorf("Either -id or -thumbprint can be used")
	}

	if flags.revocationReason != "" {
		isValidReason := func(reason string) bool {
			for _, v := range RevocationReasonOptions {
				if v == reason {
					return true
				}
			}
			return false
		}(flags.revocationReason)

		if !isValidReason {
			return fmt.Errorf("%s is not valid revocation reason. it should be one of %v", flags.revocationReason, RevocationReasonOptions)
		}
	}

	return nil
}

func validateOverWritingEnviromentVariables() {

	colorYellow := "\033[33m"
	colorReset := "\033[0m"

	if getPropertyFromEnvironment(vCertURL) != "" {
		if flags.url != "" {
			logger.Println(colorYellow, "Warning Command line parameter -u has overridden environment variable VCERT_URL", colorReset)
		}

	}

	if getPropertyFromEnvironment(vCertZone) != "" {
		if flags.zone != "" {
			logger.Println(colorYellow, "Warning: Command line parameter -z has overridden environment variable VCERT_ZONE", colorReset)
		}

	}

	if getPropertyFromEnvironment(vCertToken) != "" {
		if flags.tppToken != "" {
			logger.Println(colorYellow, "Warning: Command line parameter -t has overridden environment variable VCERT_TOKEN", colorReset)
		}
	}

	if getPropertyFromEnvironment(vCertApiKey) != "" {
		if flags.apiKey != "" {
			logger.Println(colorYellow, "Warning: Command line parameter -k has overridden environment variable VCERT_APIKEY", colorReset)
		}

	}

	if getPropertyFromEnvironment(vCertTrustBundle) != "" {
		if flags.trustBundle != "" {
			logger.Println(colorYellow, "Warning: Command line parameter --trust-bundle has overridden environment variable VCERT_TRUST_BUNDLE", colorReset)
		}

	}

}

func validateGetPolicyFlags(commandName string) error {
	isPolicyConfigStarter := flags.policyConfigStarter
	if isPolicyConfigStarter {
		if flags.tppUser != "" || flags.tppPassword != "" || flags.tppToken != "" || flags.apiKey != "" {
			return fmt.Errorf("starter flag and credentials are set, please remove credentials to be able to use starter flag")
		}

	} else {
		if flags.tppUser != "" && flags.tppPassword != "" && flags.tppToken != "" && flags.apiKey != "" {
			return fmt.Errorf("credentials are required")
		}

		if flags.policyName == "" {
			return fmt.Errorf("zone is required")
		}
	}
	return nil
}

func validateSetPolicyFlags(commandName string) error {

	isVerifyPolicy := flags.verifyPolicyConfig

	if isVerifyPolicy {

		if flags.tppUser != "" || flags.tppPassword != "" || flags.tppToken != "" || flags.apiKey != "" {
			return fmt.Errorf("starter flag and credentials are set, please remove credentials to be able to use starter flag")
		}

	} else {

		if flags.tppUser != "" && flags.tppPassword != "" && flags.tppToken != "" && flags.apiKey != "" {
			return fmt.Errorf("credentials are required")
		}

		if flags.policyName == "" {
			return fmt.Errorf("zone is required")
		}

		if flags.policySpecLocation == "" {
			return fmt.Errorf("a policy specification file is required")
		}

	}

	return nil
}

func validateSshEnrollFlags(commandName string) error {
	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}

	if flags.sshCertTemplate == "" {
		return fmt.Errorf("certificate issuing template value is required (--template)")
	}

	if flags.sshCertPubKey == "" {
		return fmt.Errorf("public-key value is required")
	} else {
		pubKeyType := flags.sshCertPubKey

		if pubKeyType != SshCertPubKeyServ && pubKeyType != SshCertPubKeyLocal && !strings.HasPrefix(pubKeyType, SshCertPubKeyFilePreff) {
			return fmt.Errorf("public-key value: %s is not expected, please provide: service, local or file:path value", pubKeyType)
		}
	}

	err = readData(commandName)
	if err != nil {
		return err
	}

	return nil
}

func validateGetSshConfigFlags(commandName string) error {

	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}

	if flags.sshCertTemplate == "" && flags.sshCertGuid == "" {
		return fmt.Errorf("SSH certificate issuance template name (--template) or template guid (--guid) value is required")
	}

	return nil
}

func validateSshRetrieveFlags(commandName string) error {

	err := validateConnectionFlags(commandName)
	if err != nil {
		return err
	}

	if flags.sshCertPickupId == "" && flags.sshCertGuid == "" {
		return fmt.Errorf("please provide a pick up id or guid value")
	}

	err = readData(commandName)
	if err != nil {
		return err
	}
	return nil
}

func validateExistingFile(f string) error {
	fileNames, err := getExistingSshFiles(f)

	if err != nil {
		return err
	}

	if len(fileNames) > 0 {
	START:
		fmt.Print("The following files already exists: ", fileNames, " would you like to override them? y/n: ")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		text = strings.ToLower(text)
		if !strings.HasPrefix(text, "y") {
			if strings.HasPrefix(text, "n") {
				return fmt.Errorf("user aborted operation")
			} else {
				goto START
			}
		}
	}
	return nil
}
