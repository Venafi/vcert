package main

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"io/ioutil"
	"regexp"
	"strings"
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

func readData(commandName string) error {
	if strings.HasPrefix(flags.distinguishedName, "file:") {
		fileName := flags.distinguishedName[5:]
		bytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Failed to read Certificate DN: %s", err)
		}
		flags.distinguishedName = strings.TrimSpace(string(bytes))
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
	if flags.format != "" && flags.format != "pem" && flags.format != "json" && flags.format != "pkcs12" {
		return fmt.Errorf("Unexpected output format: %s", flags.format)
	}
	if flags.file != "" && (flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "") {
		return fmt.Errorf("The '-file' option cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
	}

	csrOptionRegex := regexp.MustCompile(`^file:.*$|^local$|^service$|^$`)
	if !csrOptionRegex.MatchString(flags.csrOption) {
		return fmt.Errorf("unexpected -csr option: %s", flags.csrOption)
	}

	switch flags.keyTypeString {
	case "rsa":
		flags.keyType = certificate.KeyTypeRSA
	case "ecdsa":
		flags.keyType = certificate.KeyTypeECDSA
	case "":
	default:
		return fmt.Errorf("unknown key type: %s", flags.keyTypeString)
	}

	switch flags.keyCurveString {
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
		if flags.testMode {
			return nil
		}
		if flags.tppUser == "" && flags.tppToken == "" {
			// should be SaaS endpoint
			if flags.apiKey == "" {
				return fmt.Errorf("An API key is required for communicating with Venafi Cloud")
			}
		} else {
			// should be TPP service
			if flags.url == "" {
				return fmt.Errorf("missing -u (URL) parameter")
			}
			if flags.noPrompt && flags.tppPassword == "" && flags.tppToken == "" {
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
				return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
			}
			if flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "" {
				return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
			}
			if strings.Index(flags.csrOption, "file:") == 0 {
				return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "file"`)
			}
			if (flags.csrOption == "" || flags.csrOption == "local") && flags.noPickup {
				return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "local" and -no-pickup is specified`)
			}
		} else {
			if flags.file == "" { // todo: for enroll it also checks  flags.csrOption != "service"
				return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
			}
		}
		if flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "" {
			return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
		}
		if strings.HasPrefix(flags.csrOption, "file:") {
			return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "file"`)
		}
		if (flags.csrOption == "" || flags.csrOption == "local") && flags.noPickup {
			return fmt.Errorf(`PKCS#12 format is not allowed for the enroll or renew actions when -csr is "local" and -no-pickup is specified`)
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

	if !flags.testMode && flags.config == "" {
		if flags.tppUser == "" && flags.tppToken == "" {
			// should be SaaS endpoint
			if flags.apiKey == "" {
				return fmt.Errorf("An API key is required for enrollment with Venafi Cloud")
			}
			if flags.zone == "" {
				return fmt.Errorf("A zone is required for requesting a certificate from Venafi Cloud")
			}
		} else {
			// should be TPP service
			if flags.tppUser == "" && flags.tppToken == "" {
				return fmt.Errorf("An access token or username is required for communicating with Trust Protection Platform")
			}
			if flags.noPrompt && flags.tppPassword == "" && flags.tppToken == "" {
				return fmt.Errorf("An access token or password is required for communicating with Trust Protection Platform")
			}
			if flags.zone == "" {
				return fmt.Errorf("A zone is required for requesting a certificate from Trust Protection Platform")
			}

			// mutual TLS with TPP service
			if flags.clientP12 == "" && flags.clientP12PW != "" {
				return fmt.Errorf("-client-pkcs12-pw can only be specified in combination with -client-pkcs12")
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

	if flags.tppUser != "" || flags.tppPassword != "" {
		logf("Warning: User\\Password authentication is deprecated, please use access token instead.")
	}

	return nil
}

func validateGetcredFlags1(commandName string) error {
	var err error

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
		if flags.testMode {
			return fmt.Errorf("There is no test mode for getcred command")
		}
		if flags.tppUser == "" && flags.tppToken == "" && flags.clientP12 == "" {
			return fmt.Errorf("either -username, -p12-file, or -t must be specified")
		}

		if flags.url == "" {
			return fmt.Errorf("missing -u (URL) parameter")
		}

		if flags.noPrompt && flags.tppPassword == "" && flags.tppToken == "" {
			return fmt.Errorf("An access token or password is required for communicating with Trust Protection Platform")
		}

		// mutual TLS with TPP service
		if flags.clientP12 == "" && flags.clientP12PW != "" {
			return fmt.Errorf("-client-pkcs12-pw can only be specified in combination with -client-pkcs12")
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
	if flags.tppToken == "" && flags.tppUser == "" && flags.clientP12 == "" {
		return fmt.Errorf("either -username, -p12-file, or -t must be specified")
	}

	err = validatePKCS12Flags(commandName)
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
