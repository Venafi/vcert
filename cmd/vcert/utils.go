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
	"encoding/pem"
	"fmt"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

const (
	vCertURL  = "VCERT_URL"
	vCertZone = "VCERT_ZONE"
	/* #nosec */
	vCertToken = "VCERT_TOKEN"
	/* #nosec */
	vCertApiKey      = "VCERT_APIKEY"
	vCertTrustBundle = "VCERT_TRUST_BUNDLE"
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
