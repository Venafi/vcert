/*
 * Copyright 2018-2023 Venafi, Inc.
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
	// nolint:gosec // TODO: figure out a way to obtain cert thumbprint/fingerprint to remove the use of weak cryptographic primitive (G401)
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const (
	JKSFormat              = "jks"
	P12Format              = "pkcs12"
	LegacyP12Format        = "legacy-pkcs12"
	Sha256                 = "SHA256"
	SshCertPubKeyServ      = "service"
	SshCertPubKeyFilePreff = "file:"
	SshCertPubKeyLocal     = "local"
	sshCertFileExt         = "-cert.pub"
	sshPubKeyFileExt       = ".pub"
	ENV_DUMMY_PASS         = "DUMMY_PASS"
)

func parseCustomField(s string) (key, value string, err error) {
	sl := strings.Split(s, "=")
	if len(sl) < 2 {
		err = fmt.Errorf("custom field should have format key=value")
		return
	}
	key = strings.TrimSpace(sl[0])
	value = strings.TrimSpace(strings.Join(sl[1:], "="))
	return
}

// fillCertificateRequest populates the certificate request payload with values from command flags
func fillCertificateRequest(req *certificate.Request, cf *commandFlags) *certificate.Request {
	if cf.caDN != "" {
		req.CADN = cf.caDN
	}
	if cf.friendlyName != "" {
		req.FriendlyName = cf.friendlyName
	}
	if cf.commonName != "" {
		req.Subject.CommonName = cf.commonName
	}
	if cf.country != "" {
		req.Subject.Country = []string{cf.country}
	}
	if cf.state != "" {
		req.Subject.Province = []string{cf.state}
	}
	if cf.locality != "" {
		req.Subject.Locality = []string{cf.locality}
	}
	if cf.org != "" {
		req.Subject.Organization = []string{cf.org}
	}
	if len(cf.orgUnits) > 0 {
		req.Subject.OrganizationalUnit = cf.orgUnits
	}
	if len(cf.dnsSans) > 0 {
		req.DNSNames = cf.dnsSans
	}
	if len(cf.ipSans) > 0 {
		req.IPAddresses = cf.ipSans
	}
	if len(cf.emailSans) > 0 {
		req.EmailAddresses = cf.emailSans
	}
	if len(cf.uriSans) > 0 {
		req.URIs = cf.uriSans
	}
	if len(cf.upnSans) > 0 {
		req.UPNs = cf.upnSans
	}
	req.OmitSANs = cf.omitSans
	for _, f := range cf.customFields {
		k, v, err := parseCustomField(f)
		if err != nil {
			logger.Panic(err)
		}
		req.CustomFields = append(req.CustomFields, certificate.CustomField{Name: k, Value: v})
	}

	if len(cf.instance) > 0 {
		req.Location = &certificate.Location{}
		instance := strings.Split(cf.instance, ":")
		req.Location.Instance = instance[0]
		if len(instance) > 1 {
			req.Location.Workload = instance[1]
		}

		req.Location.TLSAddress = cf.tlsAddress
		req.Location.Replace = cf.replaceInstance
	}

	origin := OriginName
	if len(cf.appInfo) > 0 {
		origin = cf.appInfo
	}
	req.CustomFields = append(req.CustomFields, certificate.CustomField{Name: "Origin", Value: origin, Type: certificate.CustomFieldOrigin})

	switch true {
	case 0 == strings.Index(cf.csrOption, "file:"):
		var err error
		csrFileName := cf.csrOption[5:]
		csr, err := readCSRfromFile(csrFileName)
		if err != nil {
			logger.Panicf("Failed to read CSR from file %s: %s", csrFileName, err)
		}
		err = req.SetCSR(csr)
		if err != nil {
			logger.Panicf("Failed to set CSR %s", err)
		}
		req.CsrOrigin = certificate.UserProvidedCSR

	case "service" == cf.csrOption:
		if cf.keyType != nil {
			req.KeyType = *cf.keyType
		}
		if cf.keySize > 0 {
			req.KeyLength = cf.keySize
		} else if req.KeyLength == 0 {
			req.KeyLength = 2048
		}
		if cf.keyCurve != certificate.EllipticCurveNotSet {
			req.KeyCurve = cf.keyCurve
		}
		req.CsrOrigin = certificate.ServiceGeneratedCSR

	default: // "local" == cf.csrOption:
		if cf.keyType != nil {
			req.KeyType = *cf.keyType
		}
		if cf.keySize > 0 {
			req.KeyLength = cf.keySize
		} else if req.KeyLength == 0 {
			req.KeyLength = 2048
		}
		if cf.keyCurve != certificate.EllipticCurveNotSet {
			req.KeyCurve = cf.keyCurve
		}
		req.CsrOrigin = certificate.LocalGeneratedCSR
		if len(cf.extKeyUsage) > 0 {
			req.ExtKeyUsages = cf.extKeyUsage
		}
	}

	if cf.validDays != "" {
		data := strings.Split(cf.validDays, "#")
		days, _ := strconv.ParseInt(data[0], 10, 64)
		duration := time.Duration(days) * time.Hour * 24

		req.ValidityDuration = &duration

		if len(data) > 1 { // means that issuer hint is set
			var issuerHint util.IssuerHint

			switch strings.ToLower(data[1]) {
			case "m":
				issuerHint = util.IssuerHintMicrosoft
			case "d":
				issuerHint = util.IssuerHintDigicert
			case "e":
				issuerHint = util.IssuerHintEntrust
			}

			req.IssuerHint = issuerHint
		}
	}

	if cf.validPeriod != "" {
		req.ValidityPeriod = cf.validPeriod
	}

	return req
}

func generateRenewalRequest(cf *commandFlags, certReq *certificate.Request) *certificate.RenewalRequest {
	req := &certificate.RenewalRequest{}

	req.Thumbprint = cf.thumbprint
	req.CertificateDN = cf.distinguishedName
	req.CertificateRequest = certReq

	return req
}

func readThumbprintFromFile(fname string) (string, error) {
	var err error
	bytes, err := os.ReadFile(fname)
	if err != nil {
		return "", err
	}

	// check if there's a thumbprint in the file
	s := strings.TrimSpace(string(bytes))
	s = strings.Replace(s, ":", "", -1)
	s = strings.ToUpper(s)
	matched, _ := regexp.MatchString("^[A-F0-9]{40}$", s)
	if matched {
		return s, nil
	}

	// check if there's a PEM certificate in the file
	var block *pem.Block
	var rest []byte
	for {
		block, rest = pem.Decode(bytes)
		if block != nil && block.Type == "CERTIFICATE" {
			break
		}
		if block == nil || len(rest) == 0 {
			break
		}
		bytes = rest
	}

	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to read certificate from file: %s: %s", fname, err)
		}
		// nolint:gosec // TODO: figure out a way to obtain cert fingerprint to remove the use of weak cryptographic primitive (G401)
		fp := sha1.Sum(cert.Raw)
		return strings.ToUpper(hex.EncodeToString(fp[:])), nil
	}

	return "", fmt.Errorf("failed to parse file %s", fname)
}

func readCSRfromFile(fileName string) ([]byte, error) {
	bytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	for {
		block, rest := pem.Decode(bytes)
		if block != nil && strings.HasSuffix(block.Type, "CERTIFICATE REQUEST") {
			return pem.EncodeToMemory(block), nil
		}
		if block == nil || len(rest) == 0 {
			return nil, fmt.Errorf("failed to find CSR in file: %s", fileName)
		}
		bytes = rest
	}
}

func retrieveCertificate(connector endpoint.Connector, req *certificate.Request, timeout time.Duration) (certificates *certificate.PEMCollection, err error) {
	startTime := time.Now()
	for {
		certificates, err = connector.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok && timeout > 0 {
				if time.Now().After(startTime.Add(timeout)) {
					return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
				}
				if timeout > 0 {
					logger.Printf("Issuance of certificate is pending...")
					time.Sleep(time.Duration(5) * time.Second)
				}
			} else {
				return nil, err
			}
		} else if certificates == nil {
			return nil, fmt.Errorf("fail: certificate is not returned by remote, while error is nil")
		} else {
			return certificates, nil
		}
	}
}

// TODO: This one utilizes req.Timeout feature that is added to connector.RetrieveCertificate(), but
// it cannot do logging in CLI context right now -- logger.Printf("Issuance of certificate is pending ...")
func retrieveCertificateNew(connector endpoint.Connector, req *certificate.Request, timeout time.Duration) (certificates *certificate.PEMCollection, err error) {
	req.Timeout = timeout
	certificates, err = connector.RetrieveCertificate(req)
	if err != nil {
		return nil, err
	}
	if certificates == nil {
		return nil, fmt.Errorf("fail: certificate is not returned by remote, while error is nil")
	}
	return certificates, nil
}

func getFileWriter(fileName string) io.Writer {
	var writer io.Writer
	if fileName != "" {
		f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		writer = f
		if err != nil {
			logger.Panicf("%s", err)
		}
	} else {
		writer = os.Stdout
	}

	return writer
}

func doValuesMatch(value1 []byte, value2 []byte) bool {
	if len(value1) != len(value2) {
		return false
	}
	for idx := range value1 {
		if value1[idx] != value2[idx] {
			return false
		}
	}
	return true
}

func isValidRFC822Name(name string) bool {
	reg := regexp.MustCompile(rfc822NameRegex)
	return reg.FindStringIndex(name) != nil
}

func getPropertyFromEnvironment(s string) string {
	viper.AutomaticEnv()

	urlS := viper.Get(s)

	if urlS == nil {

		return ""

	} else {

		return fmt.Sprintf("%v", urlS)

	}

}

func writeToFile(content []byte, fileName string, perm os.FileMode) error {

	err := os.WriteFile(fileName, content, perm)

	if err != nil {
		return err
	}

	return nil
}

func writeSshFiles(privateKeyFileName string, privKey, pubKey, cert []byte) error {

	fileName, err := normalizeSshCertFileName(privateKeyFileName)

	if err != nil {
		return err
	}

	if !isPubKeyInFile() && len(privKey) > 0 {
		err = writeToFile(privKey, fileName, 0600)
		if err != nil {
			return err
		}
		log.Println("Private key has been written to: " + fileName)
	}

	//only write public key into a file if is not provided.
	if !isPubKeyInFile() {
		pubFileName := fileName + sshPubKeyFileExt
		err = writeToFile(pubKey, pubFileName, 0644)
		if err != nil {
			return err
		}
		log.Println("Public key has been written to:  " + pubFileName)

	}

	certFileName := fileName + sshCertFileExt
	err = writeToFile(cert, certFileName, 0644)
	if err != nil {
		return err
	}
	log.Println("Certificate has been written to: " + certFileName)

	return nil

}

func printExtensions(e map[string]interface{}) {
	logf("\tExtensions: ")
	if len(e) > 0 {
		for k, v := range e {
			if v != "" {
				kv := fmt.Sprintf("%s:%v", k, v)

				logf("\t\t%s", kv)
			} else {
				logf("\t\t%s", k)
			}
		}
	} else {
		logf("\t\tNone")
	}
}

func printPrincipals(p []string) {
	logf("\tPrincipals: ")
	if len(p) > 0 {
		for _, v := range p {
			logf("\t\t%s", v)
		}
	} else {
		logf("\t\tNone")
	}

}

func printCriticalOptions(fc string, sa []string) {
	logf("\tCritical Options: ")
	if fc == "" && len(sa) == 0 {
		logf("\t\tNone")
	} else {
		if fc != "" {
			logf("\t\tForce command: %s", fc)
		}
		if len(sa) > 0 {
			sourceAddsStr := ""
			size := len(sa)
			for i, val := range sa {
				sourceAddsStr = sourceAddsStr + val
				if i < size-1 {
					sourceAddsStr = sourceAddsStr + ","
				}
			}
			logf("\t\tSource addresses: %s", sourceAddsStr)
		}
	}
}

func printSshMetadata(data *certificate.SshCertificateObject) {
	logf("SSH certificate:")

	logf("\tCertificate Type: %s", data.CertificateDetails.CertificateType)
	pubKey := fmt.Sprintf("%s:%s", Sha256, data.CertificateDetails.PublicKeyFingerprintSHA256)
	logf("\tPublic key: %s", pubKey)
	signingCa := fmt.Sprintf("%s:%s", Sha256, data.CertificateDetails.CAFingerprintSHA256)
	logf("\tSigning CA: %s", signingCa)
	logf("\tCertificate Identifier: %s", data.CertificateDetails.KeyID)
	logf("\tSerial: %s", data.CertificateDetails.SerialNumber)
	logf("\tValid From: %s", util.ConvertSecondsToTime(data.CertificateDetails.ValidFrom).String())
	logf("\tValid To: %s", util.ConvertSecondsToTime(data.CertificateDetails.ValidTo).String())
	printPrincipals(data.CertificateDetails.Principals)
	printCriticalOptions(data.CertificateDetails.ForceCommand, data.CertificateDetails.SourceAddresses)
	printExtensions(data.CertificateDetails.Extensions)
}

func isPubKeyInFile() bool {

	value := flags.sshCertPubKey

	if value != "" {

		if strings.HasPrefix(value, SshCertPubKeyFilePreff) {
			return true
		}

	}
	return false
}

func isServiceGenerated() bool {
	value := flags.sshCertPubKey
	return value == SshCertPubKeyServ
}

func getSshPubKeyFromFile() (content string, err error) {
	value := flags.sshCertPubKey

	if value != "" {
		data := strings.Split(value, ":")
		if len(data) == 2 {
			fileName := data[1]

			var fileContent []byte

			fileContent, err = os.ReadFile(fileName)
			if err != nil {
				return
			}

			content = string(fileContent)

		} else {
			err = fmt.Errorf("wrong specification on sshCertPubKey flag value, please provide a file name in the format: file:file-name")
			return
		}
	}
	return
}

func getExistingSshFiles(id string) ([]string, error) {
	fileName, err := normalizeSshCertFileName(id)
	if err != nil {
		return nil, err
	}
	existingFiles := make([]string, 0)

	certFile, err := os.ReadFile(fileName + sshCertFileExt)
	if err == nil && certFile != nil { //means file exists.
		existingFiles = append(existingFiles, fileName+sshCertFileExt)
	}

	pubKeyFile, err := os.ReadFile(fileName + sshPubKeyFileExt)
	if err == nil && pubKeyFile != nil { //means file exists.
		existingFiles = append(existingFiles, fileName+sshPubKeyFileExt)
	}
	privKeyFile, err := os.ReadFile(fileName)
	if err == nil && privKeyFile != nil { //means file exists.
		existingFiles = append(existingFiles, fileName)
	}

	return existingFiles, nil
}

func normalizeSshCertFileName(s string) (string, error) {
	regex, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		return "", err
	}
	fileName := regex.ReplaceAllString(s, "_")
	return fileName, err
}

func AddLineEnding(s string) string {
	if !flags.sshCertWindows {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	return s
}

func IsCSRServiceVaaSGenerated(commandName string) bool {
	cloudSerViceGenerated := false
	if commandName == commandPickupName {
		context := &cli.Context{
			Command: &cli.Command{
				Name: commandPickupName,
			},
		}
		cfg, err := buildConfig(context, &flags)
		if err == nil {
			connector, err := vcert.NewClient(&cfg)
			if err == nil && endpoint.ConnectorTypeCloud == connector.GetType() {
				var req = &certificate.Request{
					PickupID: flags.pickupID,
				}
				cloudSerViceGenerated, _ = connector.IsCSRServiceGenerated(req)
			}
		}
	}
	return cloudSerViceGenerated
}

func isTppConnector(commandName string) bool {

	if commandName == commandPickupName {
		context := &cli.Context{
			Command: &cli.Command{
				Name: commandPickupName,
			},
		}

		cfg, err := buildConfig(context, &flags)

		if err == nil {
			connector, err := vcert.NewClient(&cfg)
			if err == nil && endpoint.ConnectorTypeTPP == connector.GetType() {
				return true
			}
		}
	}
	return false
}

func randRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		/* #nosec */
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// fillProvisioningRequest populates the provisioning request payload with values from command flags
func fillProvisioningRequest(req *domain.ProvisioningRequest, keystore domain.CloudKeystore, cf *commandFlags) (*domain.ProvisioningRequest, *domain.ProvisioningOptions) {
	req.CertificateID = cleanEmptyStringPointer(cf.certificateID)
	req.Keystore = &keystore
	req.PickupID = &(cf.provisionPickupID)

	var options *domain.ProvisioningOptions

	if cf.keystoreCertName != "" || cf.keystoreARN != "" || cf.gcmCertScope != "" {
		options = &domain.ProvisioningOptions{}
		options.CloudCertificateName = cf.keystoreCertName
		options.ARN = cf.keystoreARN
		options.GCMCertificateScope = domain.GetScopeFromString(cf.gcmCertScope)
	}

	return req, options

}

func buildGetCloudKeystoreRequest(flags *commandFlags) domain.GetCloudKeystoreRequest {

	getKeystoreReq := domain.GetCloudKeystoreRequest{
		CloudProviderID:   nil,
		CloudProviderName: cleanEmptyStringPointer(flags.providerName),
		CloudKeystoreID:   cleanEmptyStringPointer(flags.keystoreID),
		CloudKeystoreName: cleanEmptyStringPointer(flags.keystoreName),
	}

	return getKeystoreReq
}

func cleanEmptyStringPointer(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
