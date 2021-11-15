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
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
)

const (
	vCertURL  = "VCERT_URL"
	vCertZone = "VCERT_ZONE"
	/* #nosec */
	vCertToken = "VCERT_TOKEN"
	/* #nosec */
	vCertApiKey      = "VCERT_APIKEY"
	vCertTrustBundle = "VCERT_TRUST_BUNDLE"

	JKSFormat              = "jks"
	Sha256                 = "SHA256"
	SshCertPubKeyServ      = "service"
	SshCertPubKeyFilePreff = "file:"
	SshCertPubKeyLocal     = "local"
	sshCertFileExt         = "-cert.pub"
	sshPubKeyFileExt       = ".pub"
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
	}

	if cf.validDays != "" {
		validDays := cf.validDays

		data := strings.Split(validDays, "#")
		days, _ := strconv.ParseInt(data[0], 10, 64)
		hours := days * 24

		req.ValidityHours = int(hours)

		issuerHint := ""
		if len(data) > 1 { //means that issuer hint is set

			option := strings.ToLower(data[1])

			switch option {

			case "m":
				issuerHint = util.IssuerHintMicrosoft
			case "d":
				issuerHint = util.IssuerHintDigicert
			case "e":
				issuerHint = util.IssuerHintEntrust

			}
		}

		req.IssuerHint = issuerHint
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
	bytes, err := ioutil.ReadFile(fname)
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
		fp := sha1.Sum(cert.Raw)
		return strings.ToUpper(hex.EncodeToString(fp[:])), nil
	}

	return "", fmt.Errorf("failed to parse file %s", fname)
}

func readCSRfromFile(fileName string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(fileName)
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

/* TODO: This one utilizes req.Timeout feature that is added to connector.RetrieveCertificate(), but
it cannot do logging in CLI context right now -- logger.Printf("Issuance of certificate is pending ...") */
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

func sliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
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

func getFileAndBytes(p string) (*os.File, []byte, error) {
	file, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	return file, bytes, nil
}

func getEmptyPolicySpec() *policy.PolicySpecification {

	emptyString := ""
	intVal := 0
	falseBool := false

	specification := policy.PolicySpecification{
		Policy: &policy.Policy{
			CertificateAuthority: &emptyString,
			Domains:              []string{""},
			WildcardAllowed:      &falseBool,
			AutoInstalled:        &falseBool,
			MaxValidDays:         &intVal,
			Subject: &policy.Subject{
				Orgs:       []string{""},
				OrgUnits:   []string{""},
				Localities: []string{""},
				States:     []string{""},
				Countries:  []string{""},
			},
			KeyPair: &policy.KeyPair{
				KeyTypes:         []string{""},
				RsaKeySizes:      []int{0},
				ServiceGenerated: &falseBool,
				ReuseAllowed:     &falseBool,
				EllipticCurves:   []string{""},
			},
			SubjectAltNames: &policy.SubjectAltNames{
				DnsAllowed:   &falseBool,
				IpAllowed:    &falseBool,
				EmailAllowed: &falseBool,
				UriAllowed:   &falseBool,
				UpnAllowed:   &falseBool,
			},
		},
		Default: &policy.Default{
			Domain: &emptyString,
			Subject: &policy.DefaultSubject{
				Org:      &emptyString,
				OrgUnits: []string{""},
				Locality: &emptyString,
				State:    &emptyString,
				Country:  &emptyString,
			},
			KeyPair: &policy.DefaultKeyPair{
				KeyType:          &emptyString,
				RsaKeySize:       &intVal,
				EllipticCurve:    &emptyString,
				ServiceGenerated: &falseBool,
			},
		},
	}
	return &specification
}

func verifyPolicySpec(bytes []byte, fileExt string) error {

	var err error
	var policySpecification policy.PolicySpecification

	if fileExt == policy.JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else if fileExt == policy.YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("the specified file is not supported")
	}

	return nil
}

func writeToFile(content []byte, fileName string, perm os.FileMode) error {

	err := ioutil.WriteFile(fileName, content, perm)

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
		logf("\t\t", "None")
	}
}

func printPrincipals(p []string) {
	logf("\tPrincipals: ")
	if len(p) > 0 {
		for _, v := range p {
			logf("\t\t%s", v)
		}
	} else {
		logf("\t\t", "None")
	}

}

func printCriticalOptions(fc string, sa []string) {
	logf("\tCritical Options: ")
	if fc == "" && len(sa) == 0 {
		logf("\t\t", "None")
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

			fileContent, err = ioutil.ReadFile(fileName)
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

	certFile, err := ioutil.ReadFile(fileName + sshCertFileExt)
	if err == nil && certFile != nil { //means file exists.
		existingFiles = append(existingFiles, fileName+sshCertFileExt)
	}

	pubKeyFile, err := ioutil.ReadFile(fileName + sshPubKeyFileExt)
	if err == nil && pubKeyFile != nil { //means file exists.
		existingFiles = append(existingFiles, fileName+sshPubKeyFileExt)
	}
	privKeyFile, err := ioutil.ReadFile(fileName)
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
