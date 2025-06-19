/*
 * Copyright 2020-2023 Venafi, Inc.
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
	"os"
	"regexp"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi"
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

// JKSMinPasswordLen taken from keystore.minPasswordLen constant
const JKSMinPasswordLen = 6

func validateCommonFlags(commandName string) error {

	if flags.format != "" && flags.format != "pem" && flags.format != "json" && flags.format != P12Format && flags.format != LegacyP12Format && flags.format != JKSFormat && flags.format != util.LegacyPem {
		return fmt.Errorf("Unexpected output format: %s", flags.format)
	}
	if flags.file != "" && (flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "") {
		return fmt.Errorf("The '-file' option cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
	}

	var csrOptionRegex *regexp.Regexp
	if flags.platform == venafi.Firefly {
		csrOptionRegex = regexp.MustCompile(`(^file:).*$|^service$|^$`)
		if !csrOptionRegex.MatchString(flags.csrOption) {
			return fmt.Errorf("unexpected --csr option provided: %s; specify one of the following options: %s, or %s", flags.csrOption, "'file:<filename>'", "'service'")
		}
	} else {
		csrOptionRegex = regexp.MustCompile(`(^file:).*$|^local$|^service$|^$`)
		if !csrOptionRegex.MatchString(flags.csrOption) {
			return fmt.Errorf("unexpected --csr option provided: %s; specify one of the following options: %s, %s, or %s", flags.csrOption, "'file:<filename>'", "'local'", "'service'")
		}
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
			flags.userName != "" ||
			flags.password != "" ||
			flags.token != "" ||
			flags.url != "" ||
			flags.tokenURL != "" ||
			flags.externalJWT != "" ||
			flags.testMode {
			return fmt.Errorf("connection details cannot be specified with flags when --config is used")
		}
		return nil
	}

	if flags.profile != "" {
		return fmt.Errorf("--profile option cannot be used without --config option")
	}

	// Nothing to do in test mode
	if flags.testMode {
		if commandName == commandGetCredName {
			// unless it is get credentials which cannot be emulated
			return fmt.Errorf("there is no test mode for %s command", commandName)
		}
		return nil
	}

	switch flags.platform {
	case venafi.TPP:
		return validateConnectionFlagsTPP(commandName)
	case venafi.TLSPCloud:
		return validateConnectionFlagsCloud(commandName)
	case venafi.Firefly:
		return validateConnectionFlagsFirefly(commandName)
	}

	tppToken := flags.token
	if tppToken == "" {
		tppToken = getPropertyFromEnvironment(vCertToken)
	}

	//Guessing the platform by checking flags
	//	- Firefly not present here as it is required to pass the platform flag
	//	- Token empty is considered to mean Cloud connector to keep previous behavior where token was exclusive to TPP
	//	- To use token with VaaS, the platform flag is required.
	//	- If the platform flag is set we would not be guessing here
	if flags.userName == "" && tppToken == "" && flags.clientP12 == "" {
		// should be SaaS endpoint
		return validateConnectionFlagsCloud(commandName)
	} else {
		// should be TPP service
		return validateConnectionFlagsTPP(commandName)
	}
}

func validateProvisionConnectionFlags(commandName string) error {
	err := commonConnectionFlagsValidations(commandName)
	if err != nil {
		return err
	}

	switch flags.platform {
	case venafi.TPP:
		return fmt.Errorf("command %s not supported for %s", commandName, venafi.TPP.String())
	case venafi.TLSPCloud:
		return validateConnectionFlagsCloud(commandName)
	case venafi.Firefly:
		return fmt.Errorf("command %s not supported for %s", commandName, venafi.TPP.String())
	}

	tppToken := flags.token
	if tppToken == "" {
		tppToken = getPropertyFromEnvironment(vCertToken)
	}

	//Guessing the platform by checking flags
	//	- Firefly not present here as it is required to pass the platform flag
	//	- Token empty is considered to mean Cloud connector to keep previous behavior where token was exclusive to TPP
	//	- To use token with VaaS, the platform flag is required.
	//	- If the platform flag is set we would not be guessing here
	if flags.userName == "" && tppToken == "" && flags.clientP12 == "" {
		// should be SaaS endpoint
		return validateConnectionFlagsCloud(commandName)
	} else {
		// should be TPP service
		return fmt.Errorf("command %s not supported for %s", commandName, venafi.TPP.String())
	}
}

func commonConnectionFlagsValidations(commandName string) error {
	if flags.config != "" {
		if flags.apiKey != "" ||
			flags.userName != "" ||
			flags.password != "" ||
			flags.token != "" ||
			flags.url != "" ||
			flags.tokenURL != "" ||
			flags.externalJWT != "" ||
			flags.testMode {
			return fmt.Errorf("connection details cannot be specified with flags when --config is used")
		}
		return nil
	}

	if flags.profile != "" {
		return fmt.Errorf("--profile option cannot be used without --config option")
	}

	// Nothing to do in test mode
	if flags.testMode {
		if commandName == commandGetCredName {
			// unless it is get credentials which cannot be emulated
			return fmt.Errorf("there is no test mode for %s command", commandName)
		}
		return nil
	}
	return nil
}

func validatePKCS12Flags(commandName string) error {
	if flags.format == P12Format || flags.format == LegacyP12Format {
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
			return fmt.Errorf(`The --file parameter may not be combined with the --cert-file, --key-file, or --chain-file parameters when --format is %q`, flags.format)
		}
		if strings.HasPrefix(flags.csrOption, "file:") {
			return fmt.Errorf(`The --csr "file" option may not be used with the enroll or renew actions when --format is %q`, flags.format)
		}
		if (flags.csrOption == "" || flags.csrOption == "local") && flags.noPickup {
			return fmt.Errorf(`The --csr "local" option may not be used with the enroll or renew actions when --format is %q and --no-pickup is specified`, flags.format)
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
			return fmt.Errorf("the '--cn' option cannot be used in --csr file: provided mode")
		}
	} else {
		if flags.commonName == "" {
			return fmt.Errorf("a Common Name is required for enrollment")
		}
	}

	if flags.chainOption == "ignore" && flags.chainFile != "" {
		return fmt.Errorf("the `--chain ignore` option cannot be used with --chain-file option")
	}

	if !flags.testMode && flags.config == "" {
		zone := flags.zone
		if zone == "" {
			zone = getPropertyFromEnvironment(vCertZone)
		}
		if zone == "" {
			return fmt.Errorf("a zone is required for requesting a certificate. You can set the zone using the -z flag")
		}

		if flags.validDays != "" {
			valid := validateValidDaysFlag(commandName)
			if !valid {
				return fmt.Errorf("--valid-days is set but, it have an invalid format/data")
			}
		}
	}

	if flags.csrOption == "file" && flags.keyFile != "" { // Do not specify -key-file with -csr file as VCert cannot access the private key
		return fmt.Errorf("--key-file cannot be used with -csr file as VCert cannot access the private key")
	}

	err = validatePKCS12Flags(commandName)
	if err != nil {
		return err
	}

	err = validateJKSFlags(commandName)
	if err != nil {
		return err
	}

	if flags.tlsAddress != "" && flags.instance == "" {
		return fmt.Errorf("--tls-address cannot be used without --instance")
	}

	apiKey := flags.apiKey
	if apiKey == "" {
		apiKey = getPropertyFromEnvironment(vCertApiKey)
	}

	addrInstPresent := flags.tlsAddress != "" || flags.instance != ""
	isCloud := apiKey != "" || flags.platform == venafi.TLSPCloud
	if addrInstPresent && isCloud {
		return fmt.Errorf("--instance and --tls-address are not applicable to Venafi as a Service platform")
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

	// X.509 certificates must have either a Subject DN...
	if flags.commonName != "" || len(flags.orgUnits) > 0 || flags.org != "" ||
		flags.locality != "" || flags.state != "" || flags.country != "" {
		return nil
	}
	// ...or at least one Subject Alternative Name
	if len(flags.dnsSans) > 0 || len(flags.ipSans) > 0 || len(flags.emailSans) > 0 ||
		len(flags.uriSans) > 0 || len(flags.upnSans) > 0 {
		return nil
	}
	// the enrolling CA may have more strict requirements when the CSR is submitted
	return fmt.Errorf("At least one Subject DN component or Subject Alternative Name value is required")
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
		if !(flags.noPickup) && flags.noPrompt && len(flags.keyPassword) == 0 && (flags.userName != "" || flags.token != "") {
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

func validateRetireFlags(commandName string) error {

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

	return nil
}

func validateGetPolicyFlags(commandName string) error {
	isPolicyConfigStarter := flags.policyConfigStarter
	if isPolicyConfigStarter {
		if flags.userName != "" || flags.password != "" || flags.token != "" || flags.apiKey != "" {
			return fmt.Errorf("starter flag and credentials are set, please remove credentials to be able to use starter flag")
		}

	} else {
		if flags.userName != "" && flags.password != "" && flags.token != "" && flags.apiKey != "" {
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

		if flags.userName != "" || flags.password != "" || flags.token != "" || flags.apiKey != "" {
			return fmt.Errorf("starter flag and credentials are set, please remove credentials to be able to use starter flag")
		}

	} else {

		if flags.userName != "" && flags.password != "" && flags.token != "" && flags.apiKey != "" {
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

func validateProvisionFlags(commandName string) error {
	err := validateProvisionConnectionFlags(commandName)
	if err != nil {
		return err
	}

	if flags.gcmCertScope != "" && domain.GetScopeFromString(flags.gcmCertScope) == domain.GCMCertificateScopeInvalid {
		return fmt.Errorf("unexpected Google Cloud Certificate Scope provided in --%s: %s", flagGCMCertScope.Name, flags.gcmCertScope)
	}

	if flags.provisionFormat != "" && flags.provisionFormat != "json" {
		return fmt.Errorf("unexpected output format: %s", flags.format)
	}

	if flags.certificateID == "" && flags.provisionPickupID == "" && flags.pickupIDFile == "" && flags.certificateIDFile == "" {
		return fmt.Errorf("please, provide any of --certificate-id or --certificate-id-file or --pickup-id or --pickup-id-file")
	}

	if flags.pickupIDFile != "" {
		if flags.provisionPickupID != "" {
			return fmt.Errorf("both --pickup-id and --pickup-id-file options cannot be specified at the same time")
		}
		if flags.certificateID != "" {
			return fmt.Errorf("both --certificate-id and --pickup-id-file options cannot be specified at the same time")
		}
	}

	if flags.certificateIDFile != "" {
		if flags.provisionPickupID != "" {
			return fmt.Errorf("both --certificate-id and --pickup-id-file options cannot be specified at the same time")
		}
		if flags.certificateID != "" {
			return fmt.Errorf("both --certificate-id and --certificate-id-file options cannot be specified at the same time")
		}
	}

	if flags.keystoreID == "" {
		if flags.keystoreName == "" || flags.providerName == "" {
			return fmt.Errorf("any of keystore ID or both Provider Name and Keystore Name must be provided for provisioning")
		}
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
