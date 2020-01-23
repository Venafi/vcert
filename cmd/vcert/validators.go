package main

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"io/ioutil"
	"strings"
)

func readFiles() {
	if strings.HasPrefix(flags.distinguishedName, "file:") {
		fileName := flags.distinguishedName[5:]
		bytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			logger.Panicf("Failed to read Certificate DN: %s", err)
		}
		flags.distinguishedName = strings.TrimSpace(string(bytes))
	}
	var err error
	if strings.HasPrefix(flags.thumbprint, "file:") {
		certFileName := flags.thumbprint[5:]
		flags.thumbprint, err = readThumbprintFromFile(certFileName)
		if err != nil {
			logger.Panicf("Failed to read certificate fingerprint: %s", err)
		}
	}
}

func validateCommonFlags() error {
	if flags.format != "" && flags.format != "pem" && flags.format != "json" && flags.format != "pkcs12" {
		return fmt.Errorf("Unexpected output format: %s", flags.format)
	}
	if flags.file != "" && (flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "") {
		return fmt.Errorf("The '-file' option cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
	}
	return nil
}

func validateConnectionFlags() error {
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

func validateEnrollFlags() error {
	err := validateConnectionFlags()
	if err != nil {
		return err
	}
	err = validateCommonFlags()
	if err != nil {
		return err
	}
	readFiles()
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
	// todo: validate not "" zone for tpp

	if flags.csrOption == "file" && flags.keyFile != "" { // Do not specify -key-file with -csr file as VCert cannot access the private key
		return fmt.Errorf("-key-file cannot be used with -csr file as VCert cannot access the private key")
	}
	if flags.csrOption == "service" && (!flags.noPickup) { // Key password is required here
		if flags.noPrompt && len(flags.keyPassword) == 0 {
			return fmt.Errorf("-key-password cannot be empty in -csr service mode unless -no-pickup specified")
		}
	}
	err = validatePKCS12Flags()
	if err != nil {
		return err
	}

	if flags.tppUser != "" || flags.tppPassword != "" {
		logf("Warning: User\\Password authentication is deprecated, please use access token instead.")
	}

	return nil
}

func validateGetcredFlags1() error {
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

	err = validateCommonFlags()
	if err != nil {
		return err
	}
	readFiles()
	if flags.tppToken == "" && flags.tppUser == "" && flags.clientP12 == "" {
		return fmt.Errorf("either -username, -p12-file, or -t must be specified")
	}
	return nil
}

func validateGenerateFlags1() error {
	err := validateCommonFlags()
	if err != nil {
		return err
	}
	readFiles()
	if flags.keyType == certificate.KeyTypeRSA && flags.keySize < 1024 {
		return fmt.Errorf("Key Size must be 1024 or greater")
	}

	if flags.commonName == "" && len(flags.dnsSans) == 0 {
		return fmt.Errorf("A Common Name (cn) or Subject Alternative Name: DNS (san-dns) value is required")
	}

	return nil
}

func validateRenewFlags1() error {
	err := validateConnectionFlags()
	if err != nil {
		return err
	}
	err = validateCommonFlags()
	if err != nil {
		return err
	}
	readFiles()

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

	err = validatePKCS12Flags()
	if err != nil {
		return err
	}

	return nil
}

func validatePKCS12Flags() error {
	if flags.format == "pkcs12" {
		if flags.file == "" { // todo: for enroll it also checks  flags.csrOption != "service"
			return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
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

func validatePickupFlags1() error {
	err := validateConnectionFlags()
	if err != nil {
		return err
	}
	err = validateCommonFlags()
	if err != nil {
		return err
	}
	readFiles()

	if flags.pickupID == "" && flags.pickupIDFile == "" {
		return fmt.Errorf("A Pickup ID is required to pickup a certificate provided by -pickup-id OR -pickup-id-file options")
	}
	if flags.pickupID != "" && flags.pickupIDFile != "" {
		return fmt.Errorf("Both -pickup-id and -pickup-id-file options cannot be specified at the same time")
	}

	if flags.format == "pkcs12" {
		if flags.file == "" {
			return fmt.Errorf("PKCS#12 format can only be used if all objects are written to one file (see -file option)")
		}
		if flags.certFile != "" || flags.chainFile != "" || flags.keyFile != "" {
			return fmt.Errorf("The '-file' cannot be used used with any other -*-file flags. Either all data goes into one file or individual files must be specified using the appropriate flags")
		}
	}

	return nil
}

func validateRevokeFlags1() error {
	err := validateConnectionFlags()
	if err != nil {
		return err
	}
	err = validateCommonFlags()
	if err != nil {
		return err
	}
	readFiles()
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
