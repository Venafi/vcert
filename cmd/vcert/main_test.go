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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

var testEmail = "test@vcert.test"

func getCertificateRequestForTest() *certificate.Request {
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Engineering", "Automated Tests"}
	req.Subject.Country = []string{"US"}
	req.Subject.Locality = []string{"SLC"}
	req.Subject.Province = []string{"Utah"}

	host, _ := os.Hostname()
	req.DNSNames = []string{host}

	addrs, _ := net.InterfaceAddrs()
	var ips []net.IP
	for _, add := range addrs {
		ip, _, _ := net.ParseCIDR(add.String())
		v4 := ip.To4()
		if v4 != nil && !v4.IsLoopback() {
			ips = append(ips, ip)
		}

	}
	req.IPAddresses = ips
	return &req
}

func generateTestCertificate() (*x509.Certificate, interface{}, error) {
	req := getCertificateRequestForTest()

	priv, err := certificate.GenerateECDSAPrivateKey(certificate.EllipticCurveP384)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := generateSelfSigned(req, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func generateTestCertificateWithChain() ([]*x509.Certificate, *x509.Certificate, interface{}, error) {
	req := getCertificateRequestForTest()

	priv, err := certificate.GenerateECDSAPrivateKey(certificate.EllipticCurveP384)
	if err != nil {
		return nil, nil, nil, err
	}

	caBytes, certBytes, err := generateCASigned(req, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, priv)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	caCerts, err := x509.ParseCertificates(caBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return caCerts, cert, priv, nil
}

func generateSelfSigned(request *certificate.Request, ku x509.KeyUsage, eku []x509.ExtKeyUsage, privateKey crypto.Signer) ([]byte, error) {
	notBefore := time.Now()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	certRequest := x509.Certificate{
		SerialNumber: serial,
	}
	certRequest.Subject = request.Subject
	certRequest.DNSNames = request.DNSNames
	certRequest.EmailAddresses = request.EmailAddresses
	certRequest.IPAddresses = request.IPAddresses
	certRequest.SignatureAlgorithm = request.SignatureAlgorithm
	certRequest.ExtKeyUsage = eku
	certRequest.NotBefore = notBefore.UTC()
	if ku&x509.KeyUsageCertSign != x509.KeyUsageCertSign {
		certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 90)
		certRequest.IsCA = false
	} else {
		certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 180)
		certRequest.IsCA = true
	}
	certRequest.BasicConstraintsValid = true

	pub := publicKey(privateKey)

	cert, err := x509.CreateCertificate(rand.Reader, &certRequest, &certRequest, pub, privateKey)
	if err != nil {
		cert = nil
	}

	return cert, err
}

func generateCASigned(request *certificate.Request, ku x509.KeyUsage, eku []x509.ExtKeyUsage, privateKey interface{}) (caCert []byte, cert []byte, err error) {
	caReq := certificate.Request{}
	caReq.Subject.Organization = []string{"Vfi Dev Test CA"}
	caReq.Subject.OrganizationalUnit = []string{"Engineering", "Automated Tests"}
	caReq.Subject.Country = []string{"US"}
	caReq.Subject.Locality = []string{"SLC"}
	caReq.Subject.Province = []string{"Utah"}

	caPriv, err := certificate.GenerateECDSAPrivateKey(certificate.EllipticCurveP384)
	if err != nil {
		return nil, nil, err
	}

	caCert, err = generateSelfSigned(&caReq, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, caPriv)

	notBefore := time.Now()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	certRequest := x509.Certificate{
		SerialNumber: serial,
	}
	certRequest.Subject = request.Subject
	certRequest.DNSNames = request.DNSNames
	certRequest.EmailAddresses = request.EmailAddresses
	certRequest.IPAddresses = request.IPAddresses
	certRequest.SignatureAlgorithm = request.SignatureAlgorithm
	certRequest.ExtKeyUsage = eku
	certRequest.NotBefore = notBefore.UTC()
	if ku&x509.KeyUsageCertSign != x509.KeyUsageCertSign {
		certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 90)
		certRequest.IsCA = false
	} else {
		certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 180)
		certRequest.IsCA = true
	}
	certRequest.BasicConstraintsValid = true

	signer, err := x509.ParseCertificate(caCert)
	if err != nil {
		cert = nil
	}

	pub := publicKey(privateKey)
	cert, err = x509.CreateCertificate(rand.Reader, &certRequest, signer, pub, caPriv)
	if err != nil {
		cert = nil
	}

	return caCert, cert, err
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

type fakeEndPointConnector struct{}

func (ep *fakeEndPointConnector) Ping() error {
	return nil
}
func (ep *fakeEndPointConnector) SetBaseURL(string) error {
	return nil
}

func (ep *fakeEndPointConnector) Authenticate(auth endpoint.Authentication) error {
	return nil
}
func (ep *fakeEndPointConnector) ReadZoneConfiguration(string) (*endpoint.ZoneConfiguration, error) {
	return nil, nil
}
func (ep *fakeEndPointConnector) GenerateRequest(*endpoint.ZoneConfiguration, *certificate.Request) error {
	return nil
}
func (ep *fakeEndPointConnector) RequestCertificate(*certificate.Request, string) (string, error) {
	return "", nil
}
func (ep *fakeEndPointConnector) RetrieveCertificate(string, certificate.ChainOption) (*certificate.PEMCollection, error) {
	return nil, nil
}

func newFakeConnector() (*fakeEndPointConnector, error) {
	ep := fakeEndPointConnector{}
	return &ep, nil
}

func TestValidateFlagsForEnrollmentMissingData(t *testing.T) {

	flags = commandFlags{}

	flags.apiKey = ""

	err := validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for enrollment")
	}
}

func TestGetcredFlagsNoUrl(t *testing.T) {

	flags = commandFlags{}

	flags.tppToken = "3rlybZwAdV1qo/KpNJ5FWg=="

	err := validateGetcredFlags1(commandGetcredName)
	if err == nil {
		t.Fatalf("-u must be specified")
	}
}

func TestValidateFlagsForTPPMissingData(t *testing.T) {

	flags = commandFlags{}

	flags.url = "https://localhost/vedsdk"
	flags.tppUser = ""

	err := validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  Username and password are required for enrollment")
	}

	flags.url = "https://localhost/vedsdk"
	flags.tppUser = "admin"
	flags.tppPassword = "xxxx"
	flags.noPrompt = true
	flags.zone = "Test Policy"

	flags = commandFlags{}

	err = validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  CN is required for enrollment")
	}

	flags.url = "https://localhost/vedsdk"
	flags.tppUser = "admin"
	flags.noPrompt = true
	flags.commonName = "test"
	flags.zone = "Test"

	err = validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  tpp-password is required for enrollment")
	}

	flags = commandFlags{}

	flags.url = "https://localhost/vedsdk"
	flags.tppUser = "admin"
	flags.tppPassword = "secret"
	flags.commonName = "test"
	flags.noPickup = true
	flags.zone = ""
	flags.csrOption = "service"

	err = validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  Zone is required for enrollment")
	}

	flags.url = "https://localhost/vedsdk"
	flags.tppToken = "udd3OCDO/Vu3An01KSlLzQ=="
	flags.commonName = "test"
	flags.zone = "Test Policy"

	err = validateEnrollFlags(commandEnrollName)
	if err != nil {
		t.Fatalf("%s", err)
	}

}

func TestValidateFlagsForPickupMissingData(t *testing.T) {

	flags = commandFlags{}

	flags.apiKey = ""

	err := validatePickupFlags1(commandPickupName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for Pickup")
	}

	flags.apiKey = "asdf"

	err = validatePickupFlags1(commandPickupName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	flags.apiKey = "asdf"
	flags.pickupID = "asdf"

	err = validatePickupFlags1(commandPickupName)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestValidateFlagsMixedEnrollmentFileOutputs(t *testing.T) {

	flags = commandFlags{}

	flags.apiKey = "1234"
	flags.file = "file123"
	flags.keyFile = "file123"
	err := validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for Pickup")
	}

	flags.apiKey = "1234"
	flags.file = "file123"
	flags.certFile = "file123"
	flags.keyFile = ""
	err = validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	flags.apiKey = "1234"
	flags.file = "file123"
	flags.chainFile = "file123"
	flags.certFile = ""
	flags.keyFile = ""
	err = validateEnrollFlags(commandEnrollName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	flags.apiKey = "1234"
	flags.zone = "zone"
	flags.file = "file123"
	flags.chainFile = ""
	flags.certFile = ""
	flags.keyFile = ""
	flags.noPrompt = true
	flags.commonName = "example.com"
	err = validateEnrollFlags(commandEnrollName)
	if err != nil {
		t.Fatalf("%s", err)
	}

	flags.apiKey = "1234"
	flags.zone = "zone"
	flags.file = ""
	flags.chainFile = ""
	flags.certFile = ""
	flags.keyFile = "asdf"
	flags.keyFile = "asdf"
	err = validateEnrollFlags(commandEnrollName)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestValidateFlagsMixedPickupFileOutputs(t *testing.T) {

	flags = commandFlags{}

	flags.apiKey = "1234"
	flags.file = "file123"
	flags.certFile = "file123"
	err := validatePickupFlags1(commandPickupName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for Pickup")
	}

	flags.apiKey = "1234"
	flags.file = "file123"
	flags.chainFile = "file123"
	flags.certFile = ""
	err = validatePickupFlags1(commandPickupName)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	flags.apiKey = "1234"
	flags.file = "file123"
	flags.chainFile = ""
	flags.certFile = ""
	flags.pickupID = "pickup/id"
	err = validatePickupFlags1(commandPickupName)
	if err != nil {
		t.Fatalf("%s", err)
	}

	flags.apiKey = "1234"
	flags.file = ""
	flags.chainFile = ""
	flags.certFile = "asdf"
	err = validatePickupFlags1(commandPickupName)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestGetcredFlagsTrustBundle(t *testing.T) {

	flags = commandFlags{}

	var err error

	flags.tppToken = "3rlybZwAdV1qo/KpNJ5FWg=="
	flags.url = "https://tpp.example.com"
	flags.trustBundle = "/opt/venafi/bundle.pem"

	err = validateGetcredFlags1(commandGetcredName)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestGetcredFlagsNoTrust(t *testing.T) {

	flags = commandFlags{}

	var err error

	flags.tppToken = "3rlybZwAdV1qo/KpNJ5FWg=="
	flags.url = "https://tpp.example.com"

	err = validateGetcredFlags1(commandGetcredName)
	if err != nil {
		t.Fatalf("%s", err)
	}

}

func TestIPSliceString(t *testing.T) {
	ips := ipSlice{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.2"), net.ParseIP("1.1.1.3")}
	ipString := ips.String()
	if !strings.Contains(ipString, "1.1.1.1") || !strings.Contains(ipString, "1.1.1.2") || !strings.Contains(ipString, "1.1.1.3") {
		t.Fatalf("Unexpected string value was returned.  Expected: %s\n%s\n%s\n Actual: %s", "1.1.1.1", "1.1.1.2", "1.1.1.3", ipString)
	}
}

func TestIPSliceSetByString(t *testing.T) {
	ips := ipSlice{}
	data := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}
	for i, s := range data {
		ips.Set(s)
		if len(ips) != i+1 {
			t.Fatalf("Unexpected count after adding to [].  Expected: %d Actual: %d", i+1, len(ips))
		}
	}
}

func TestURISliceString(t *testing.T) {
	var uris uriSlice
	data := []string{"https://www.abc.xyz", "ldaps://directory.abc.xyz", "spiffe://cluster.abc.xyz"}
	for _, s := range data {
		u, _ := url.Parse(s)
		uris = append(uris, u)
	}
	uriString := uris.String()
	if !strings.Contains(uriString, data[0]) || !strings.Contains(uriString, data[1]) || !strings.Contains(uriString, data[2]) {
		t.Fatalf("Unexpected string value was returned.  Expected: %s\n%s\n%s\n Actual: %s", data[0], data[1], data[2], uriString)
	}
}

func TestURISliceSetByString(t *testing.T) {
	uris := uriSlice{}
	data := []string{"https://www.abc.xyz", "ldaps://directory.abc.xyz", "spiffe://cluster.abc.xyz"}
	for i, s := range data {
		uris.Set(s)
		if len(uris) != i+1 {
			t.Fatalf("Unexpected count after adding to [].  Expected: %d Actual: %d", i+1, len(uris))
		}
	}
}

func TestRFC822NameSliceString(t *testing.T) {
	emails := rfc822NameSlice{"email@email1.com", "email@email2.com", "email@email3.com"}
	emailString := emails.String()
	if !strings.Contains(emailString, "email@email1.com") || !strings.Contains(emailString, "email@email2.com") || !strings.Contains(emailString, "email@email3.com") {
		t.Fatalf("Unexpected string value was returned.  Expected: %s\n%s\n%s\n Actual: %s", "email@email1.com", "email@email2.com", "email@email3.com", emailString)
	}
}

func TestRFC822NameSliceSetByString(t *testing.T) {
	emails := rfc822NameSlice{}
	data := []string{"email@email1.com", "email@email2.com", "email@email3.com", "barney.fife@venafi.com", "gpile@venafi.com", "andy@venafi.com", "some.other@anything.co.uk"}
	for i, s := range data {
		err := emails.Set(s)
		if err != nil {
			t.Fatalf("%s", err)
		}
		if len(emails) != i+1 {
			t.Fatalf("Unexpected count after adding to [].  Expected: %d Actual: %d", i+1, len(emails))
		}
	}
}

func TestIsValidEmailAddress(t *testing.T) {
	good := []string{"gomer.pile@venafi.com", "agriffith@venafi.com", "barney@venafi.com", "some.other@anything.co.uk"}
	bad := []string{"bob@bob", "User@", "user@a", "user@a.b.c.d.e.f.g.h.j.k.l.", "user@.com", "domain.com", "1.2.3.4"}

	for _, e := range good {
		if !isValidRFC822Name(e) {
			t.Fatalf("Email address %s failed validation", e)
		}
	}
	for _, e := range bad {
		if isValidRFC822Name(e) {
			t.Fatalf("Email address %s should have failed validation", e)
		}
	}
}

func TestStringSliceString(t *testing.T) {
	ss := stringSlice{"bob", "larry", "curly", "mo"}
	s := ss.String()
	if !strings.Contains(s, "bob") || !strings.Contains(s, "larry") || !strings.Contains(s, "curly") || !strings.Contains(s, "mo") {
		t.Fatalf("Unexpected string value was returned.  Expected: %s\n%s\n%s\n%s\n Actual: %s", "bob", "larry", "curly", "mo", s)
	}
}

func TestStringSliceSetByString(t *testing.T) {
	ss := stringSlice{}
	data := []string{"bob", "larry", "curly", "mo"}
	for i, s := range data {
		ss.Set(s)
		if len(ss) != i+1 {
			t.Fatalf("Unexpected count after adding to [].  Expected: %d Actual: %d", i+1, len(ss))
		}
	}
}

func TestGenerateCertRequest(t *testing.T) {
	//setup flags
	flags = commandFlags{}

	flags.distinguishedName = "vcert Unit Test"
	flags.commonName = "unit.test.vcert"
	flags.org = "Venafi"
	flags.orgUnits = []string{"vcert Unit Testing"}

	//cf := createFromCommandFlags(commandEnroll)

	req := &certificate.Request{}
	req = fillCertificateRequest(req, &flags)
	if req == nil {
		t.Fatalf("generateCertificateRequest returned a nil request")
	}
	if req.Subject.CommonName != flags.commonName {
		t.Fatalf("generated request did not contain the expected common name, expected: %s -- actual: %s", flags.commonName, req.Subject.CommonName)
	}
}

func TestGetFileWriter(t *testing.T) {
	//set the pem file var so we get a file handle
	temp, err := ioutil.TempFile(os.TempDir(), "vcertTest")
	if err != nil {
		t.Fatalf("Failed to create temp file for testing getFileWriter.  Error: %s", err)
	}
	defer os.Remove(temp.Name())
	fileName := temp.Name()
	temp.Close()
	writer := getFileWriter(fileName)
	f, ok := writer.(*os.File)
	if ok {
		defer f.Close()
	} else {
		t.Fatalf("io.Writer returned from getFileWriter was not expected type of *os.File.  Actual type: %T", writer)
	}
}

func TestReadPasswordFromInputFlags(t *testing.T) {

	flags = commandFlags{}

	f, err := ioutil.TempFile(os.TempDir(), "vcertTest")
	if err != nil {
		t.Fatalf("Failed to create temp file for testing readPasswordsFromInputFlags.  Error: %s", err)
	}
	tempFileName := f.Name()
	defer os.Remove(tempFileName)
	_, err = f.WriteString("password0\npassword1\npassword2\npassword3")
	if err != nil {
		t.Fatalf("Failed to write to temp file for testing readPasswordsFromInputFlags.  Error: %s", err)
	}
	f.Close()

	flags.url = "https://localhost"
	flags.tppPassword = fmt.Sprintf("file:%s", tempFileName)
	flags.keyPassword = fmt.Sprintf("file:%s", tempFileName)

	err = readPasswordsFromInputFlags(commandEnrollName, &flags)
	if err != nil {
		t.Fatalf("Failed to readPasswordsFromInputFlags.  Error: %s", err)
	}
	if flags.tppPassword != "password0" {
		t.Fatalf("tpp-password read from file did not match expected value.  Expected: password0 -- Actual: %s", flags.tppPassword)
	}
	if flags.keyPassword != "password1" {
		t.Fatalf("key-password read from file did not match expected value.  Expected: password1 -- Actual: %s", flags.keyPassword)
	}

	flags.tppPassword = fmt.Sprintf("file:%s", tempFileName)
	f, err = ioutil.TempFile(os.TempDir(), "vcertTest")
	if err != nil {
		t.Fatalf("Failed to create temp file for testing readPasswordsFromInputFlags.  Error: %s", err)
	}
	tempFileName = f.Name()
	defer os.Remove(tempFileName)
	_, err = f.WriteString("key-pass")
	if err != nil {
		t.Fatalf("Failed to write to temp file for testing readPasswordsFromInputFlags.  Error: %s", err)
	}
	f.Close()

	//enrollFlags.Set("key-password", fmt.Sprintf("file:%s", tempFileName))
	//cf = createFromCommandFlags(commandEnroll)
	flags.keyPassword = fmt.Sprintf("file:%s", tempFileName)

	err = readPasswordsFromInputFlags(commandEnrollName, &flags)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromInput.  Error: %s", err)
	}
	if flags.tppPassword != "password0" {
		t.Fatalf("tpp-password read from file did not match expected value.  Expected: password0 -- Actual: %s", flags.tppPassword)
	}
	if flags.keyPassword != "key-pass" {
		t.Fatalf("key-password read from file did not match expected value.  Expected: key-pass -- Actual: %s", flags.keyPassword)
	}
}

func TestReadPasswordFromInput(t *testing.T) {

	f, err := ioutil.TempFile(os.TempDir(), "vcertTest")
	if err != nil {
		t.Fatalf("Failed to create temp file for testing readPasswordFromInput.  Error: %s", err)
	}
	tempFileName := f.Name()
	defer os.Remove(tempFileName)
	_, err = f.WriteString("password0\npassword1\npassword2\npassword3")
	if err != nil {
		t.Fatalf("Failed to write to temp file for testing readPasswordFromInput.  Error: %s", err)
	}
	f.Close()
	pass, err := readPasswordsFromInputFlag(fmt.Sprintf("file:%s", tempFileName), 0)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromInput.  Error: %s", err)
	}
	if pass != "password0" {
		t.Fatalf("Password read from file did not match expected value.  Expected: password0 -- Actual: %s", pass)
	}

	pass, err = readPasswordsFromInputFlag("pass:password", -1)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromInput.  Error: %s", err)
	}
	if pass != "password" {
		t.Fatalf("Password read from file did not match expected value.  Expected: password -- Actual: %s", pass)
	}

	pass, err = readPasswordsFromInputFlag("password", -1)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromInput.  Error: %s", err)
	}
	if pass != "password" {
		t.Fatalf("Password read from file did not match expected value.  Expected: password -- Actual: %s", pass)
	}
}

func TestReadPasswordFromFile(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "vcertTest")
	if err != nil {
		t.Fatalf("Failed to create temp file for testing readPasswordFromFile.  Error: %s", err)
	}
	tempFileName := f.Name()
	defer os.Remove(tempFileName)
	_, err = f.WriteString("password0\npassword1\npassword2\npassword3")
	if err != nil {
		t.Fatalf("Failed to write to temp file for testing readPasswordFromFile.  Error: %s", err)
	}
	f.Close()
	pass, err := readPasswordFromFile(tempFileName, 0)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromFile.  Error: %s", err)
	}
	if pass != "password0" {
		t.Fatalf("Password read from file did not match expected value.  Expected: password0 -- Actual: %s", pass)
	}

	pass, err = readPasswordFromFile(tempFileName, 3)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromFile.  Error: %s", err)
	}
	if pass != "password3" {
		t.Fatalf("Password read from file did not match expected value.  Expected: password3 -- Actual: %s", pass)
	}

	pass, err = readPasswordFromFile(tempFileName, 10)
	if err == nil {
		t.Fatalf("Expected error for reading password from line in file where file did not contain that many lines")
	}
	if pass != "" {
		t.Fatalf("Password read from file did not match expected value.  Expected:  -- Actual: %s", pass)
	}
}

func TestDoValuesMatch(t *testing.T) {
	value1 := []byte("string")
	value2 := []byte("string")

	if !doValuesMatch(value1, value2) {
		t.Fatalf("Values %s - %s should have matched", value1, value2)
	}

	value1 = []byte("string1")
	value2 = []byte("string2")

	if doValuesMatch(value1, value2) {
		t.Fatalf("Values %s - %s should not have matched", value1, value2)
	}
}

func TestWrapArgumentDescription(t *testing.T) {
	desc := "This is an agrument which goes over the current limit of 80 characters causing this line to have 1 line break"

	edited := wrapArgumentDescriptionText(desc)

	if len(edited) <= len(desc) {
		t.Fatalf("Description was not wrapped as expected. Original: %s -- Wrapped: %s", desc, edited)
	}

	desc = "This is shorter than 80 characters"

	edited = wrapArgumentDescriptionText(desc)

	if len(edited) > len(desc) {
		t.Fatalf("Description was wrapped when not expected. Original: %s -- Wrapped: %s", desc, edited)
	}
}

func TestConfigEnvironmentVariablesForTpp(t *testing.T) {

	//create the environment variables.
	setEnvironmentVariablesForTpp()

	//create a context, thiw will be used on the build config function.
	context := getCliContext()

	cfg, err := buildConfig(context, &flags)

	//execute the validations.
	if err != nil {
		t.Fatalf("Failed to build vcert config: %s", err)
	}

	if cfg.Zone == "" {
		t.Fatalf("Zone is empty")
	}

	if cfg.BaseUrl == "" {
		t.Fatalf("Base URL is empty")
	}

	if cfg.Credentials.AccessToken == "" {
		t.Fatalf("Access token is empty")
	}

	unsetEnvironmentVariables()
}

func TestConfigEnvironmentVariablesForCloud(t *testing.T) {

	//create the environment variables.
	setEnvironmentVariablesForCloud()

	//create a context, thiw will be used on the build config function.
	context := getCliContext()

	cfg, err := buildConfig(context, &flags)

	//execute the validations.
	if err != nil {
		t.Fatalf("Failed to build vcert config: %s", err)
	}

	//for cloud we only require a zone and an api, to be able
	//to do most of the operations.
	if cfg.Zone == "" {
		t.Fatalf("Zone is empty")
	}

	if cfg.Credentials.APIKey == "" {
		t.Fatalf("API key is empty")
	}

	unsetEnvironmentVariables()
}

func TestEnvironmentVariableTrustBundleFileName(t *testing.T) {
	setEnvironmentVariableForTrustBundle()

	trustBundleFile := getPropertyFromEnvironment(vCertTrustBundle)

	if trustBundleFile == "" {
		t.Fatalf("Trust bundle is empty")
	}

	unsetEnvironmentVariables()
}

func TestValidatePrecedenceForFlagsTpp(t *testing.T) {

	flags.tppToken = tppTokenTestFlagValue
	flags.zone = tppZoneTestFlagValue
	flags.url = tppURlTestFlagValue

	setEnvironmentVariablesForTpp()

	context := getCliContext()
	cfg, err := buildConfig(context, &flags)

	//execute the validations.
	if err != nil {
		t.Fatalf("Failed to build vcert config: %s", err)
	}

	if cfg.Zone != tppZoneTestFlagValue {
		t.Fatalf("Zone flag was overwritten")
	}

	if cfg.BaseUrl != tppURlTestFlagValue {
		t.Fatalf("Base URL flag was overwritten")
	}

	if cfg.Credentials.AccessToken != tppTokenTestFlagValue {
		t.Fatalf("Access token flag was overwritten")
	}

	unsetEnvironmentVariables()
	unsetFlags()
}

func TestValidatePrecedenceForFlagsCloud(t *testing.T) {

	flags.apiKey = cloudApiKeyTestValue
	flags.zone = cloudZoneTestValue

	//create the environment variables.
	setEnvironmentVariablesForCloud()

	//create a context, thiw will be used on the build config function.
	context := getCliContext()

	cfg, err := buildConfig(context, &flags)

	//execute the validations.
	if err != nil {
		t.Fatalf("Failed to build vcert config: %s", err)
	}

	if cfg.Zone != cloudZoneTestValue {
		t.Fatalf("Zone is empty")
	}

	if cfg.Credentials.APIKey != cloudApiKeyTestValue {
		t.Fatalf("API key is empty")
	}
	unsetEnvironmentVariables()
	unsetFlags()
}
