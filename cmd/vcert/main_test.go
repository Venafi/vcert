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
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"math/big"
	"net"
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

func generateSelfSigned(request *certificate.Request, ku x509.KeyUsage, eku []x509.ExtKeyUsage, privateKey interface{}) ([]byte, error) {
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
	certRequest.PublicKeyAlgorithm = request.PublicKeyAlgorithm
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
	certRequest.PublicKeyAlgorithm = request.PublicKeyAlgorithm
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
func (ep *fakeEndPointConnector) Register(string) error {
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

func TestValidateFlagsForRegistration(t *testing.T) {
	registerFlags.Set("email", testEmail)

	err := validateFlags(commandRegister)
	if err != nil {
		t.Fatalf("Error was expected to be nil.  Error: %s", err)
	}

	if regParams.email != testEmail {
		t.Fatalf("Email was not parsed according to set flag.  Expected: %s Actual: %s", testEmail, regParams.email)
	}
}

func TestValidateFlagsForTPPMissingData(t *testing.T) {
	enrollFlags.Set("tpp-url", "https://localhost/vedsdk")
	enrollFlags.Set("tpp-user", "")

	err := validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  Username and password are required for enrollment")
	}

	enrollFlags.Set("tpp-url", "https://localhost/vedsdk")
	enrollFlags.Set("tpp-user", "admin")
	enrollFlags.Set("z", "Test Policy")

	err = validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  CN is required for enrollment")
	}

	enrollFlags.Set("tpp-url", "https://localhost/vedsdk")
	enrollFlags.Set("tpp-user", "admin")
	enrollFlags.Set("no-prompt", "true")
	enrollFlags.Set("cn", "test")
	enrollFlags.Set("z", "Test")

	err = validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  tpp-password is required for enrollment")
	}

	enrollFlags.Set("tpp-url", "https://localhost/vedsdk")
	enrollFlags.Set("tpp-user", "admin")
	enrollFlags.Set("tpp-password", "secret")
	enrollFlags.Set("cn", "test")
	enrollFlags.Set("z", "")

	err = validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  Zone is required for enrollment")
	}
}

func TestValidateFlagsForEnrollmentMissingData(t *testing.T) {
	enrollFlags.Set("k", "")

	err := validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for enrollment")
	}
}

func TestValidateFlagsForPickupMissingData(t *testing.T) {
	pickupFlags.Set("k", "")

	err := validateFlags(commandPickup)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for Pickup")
	}

	pickupFlags.Set("k", "asdf")

	err = validateFlags(commandPickup)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	pickupFlags.Set("k", "asdf")
	pickupFlags.Set("pickup-id", "asdf")

	err = validateFlags(commandPickup)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestValidateFlagsMixedEnrollmentFileOutputs(t *testing.T) {
	enrollFlags.Set("k", "1234")
	enrollFlags.Set("file", "file123")
	enrollFlags.Set("key-file", "file123")
	err := validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for Pickup")
	}

	enrollFlags.Set("k", "1234")
	enrollFlags.Set("file", "file123")
	enrollFlags.Set("cert-file", "file123")
	enrollFlags.Set("key-file", "")
	err = validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	enrollFlags.Set("k", "1234")
	enrollFlags.Set("file", "file123")
	enrollFlags.Set("chain-file", "file123")
	enrollFlags.Set("cert-file", "")
	enrollFlags.Set("key-file", "")
	err = validateFlags(commandEnroll)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	enrollFlags.Set("k", "1234")
	enrollFlags.Set("z", "zone")
	enrollFlags.Set("file", "file123")
	enrollFlags.Set("chain-file", "")
	enrollFlags.Set("cert-file", "")
	enrollFlags.Set("key-file", "")
	err = validateFlags(commandEnroll)
	if err != nil {
		t.Fatalf("%s", err)
	}

	enrollFlags.Set("k", "1234")
	enrollFlags.Set("z", "zone")
	enrollFlags.Set("file", "")
	enrollFlags.Set("chain-file", "")
	enrollFlags.Set("cert-file", "")
	enrollFlags.Set("key-file", "asdf")
	err = validateFlags(commandEnroll)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestValidateFlagsMixedPickupFileOutputs(t *testing.T) {
	pickupFlags.Set("k", "1234")
	pickupFlags.Set("file", "file123")
	pickupFlags.Set("cert-file", "file123")
	err := validateFlags(commandPickup)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  APIKey is required for Pickup")
	}

	pickupFlags.Set("k", "1234")
	pickupFlags.Set("file", "file123")
	pickupFlags.Set("chain-file", "file123")
	pickupFlags.Set("cert-file", "")
	err = validateFlags(commandPickup)
	if err == nil {
		t.Fatalf("Error was not expected to be nil.  pickup-id is required for Pickup")
	}

	pickupFlags.Set("k", "1234")
	pickupFlags.Set("file", "file123")
	pickupFlags.Set("chain-file", "")
	pickupFlags.Set("cert-file", "")
	err = validateFlags(commandPickup)
	if err != nil {
		t.Fatalf("%s", err)
	}

	pickupFlags.Set("k", "1234")
	pickupFlags.Set("file", "")
	pickupFlags.Set("chain-file", "")
	pickupFlags.Set("cert-file", "asdf")
	err = validateFlags(commandPickup)
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

func TestEmailSliceString(t *testing.T) {
	emails := emailSlice{"email@email1.com", "email@email2.com", "email@email3.com"}
	emailString := emails.String()
	if !strings.Contains(emailString, "email@email1.com") || !strings.Contains(emailString, "email@email2.com") || !strings.Contains(emailString, "email@email3.com") {
		t.Fatalf("Unexpected string value was returned.  Expected: %s\n%s\n%s\n Actual: %s", "email@email1.com", "email@email2.com", "email@email3.com", emailString)
	}
}

func TestEmailSliceSetByString(t *testing.T) {
	emails := emailSlice{}
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
		if !isValidEmailAddress(e) {
			t.Fatalf("Email address %s failed validation", e)
		}
	}
	for _, e := range bad {
		if isValidEmailAddress(e) {
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

func TestGetEmailForRegistration(t *testing.T) {
	email, err := getEmailForRegistration(bufio.NewWriter(ioutil.Discard), bufio.NewReader(strings.NewReader(testEmail)))
	if err != nil {
		t.Fatalf("Error was expected to be nil.  Error: %s", err)
	}
	if email != testEmail {
		t.Fatalf("Unexpected email returned. Expected: %s Actual %s", testEmail, email)
	}
}

func TestGenerateCertRequest(t *testing.T) {
	//setup flags
	enrollFlags.Set("nickname", "vcert Unit Test")
	enrollFlags.Set("cn", "unit.test.vcert")
	enrollFlags.Set("o", "Venafi")
	enrollFlags.Set("ou", "vcert Unit Testing")
	cf := createFromCommandFlags(commandEnroll)

	req := &certificate.Request{}
	req = fillCertificateRequest(req, cf)
	if req == nil {
		t.Fatalf("generateCertificateRequest returned a nil request")
	}
	if req.Subject.CommonName != cf.commonName {
		t.Fatalf("generated request did not contain the expected common name, expected: %s -- actual: %s", cf.commonName, req.Subject.CommonName)
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
	enrollFlags.Set("tpp-url", "https://localhost")
	enrollFlags.Set("tpp-password", fmt.Sprintf("file:%s", tempFileName))
	enrollFlags.Set("key-password", fmt.Sprintf("file:%s", tempFileName))
	cf := createFromCommandFlags(commandEnroll)

	err = readPasswordsFromInputFlags(commandEnroll, cf)
	if err != nil {
		t.Fatalf("Failed to readPasswordsFromInputFlags.  Error: %s", err)
	}
	if cf.tppPassword != "password0" {
		t.Fatalf("tpp-password read from file did not match expected value.  Expected: password0 -- Actual: %s", cf.tppPassword)
	}
	if cf.keyPassword != "password1" {
		t.Fatalf("key-password read from file did not match expected value.  Expected: password1 -- Actual: %s", cf.keyPassword)
	}

	enrollFlags.Set("tpp-password", fmt.Sprintf("file:%s", tempFileName))
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
	enrollFlags.Set("key-password", fmt.Sprintf("file:%s", tempFileName))
	cf = createFromCommandFlags(commandEnroll)

	err = readPasswordsFromInputFlags(commandEnroll, cf)
	if err != nil {
		t.Fatalf("Failed to readPasswordFromInput.  Error: %s", err)
	}
	if cf.tppPassword != "password0" {
		t.Fatalf("tpp-password read from file did not match expected value.  Expected: password0 -- Actual: %s", cf.tppPassword)
	}
	if cf.keyPassword != "key-pass" {
		t.Fatalf("key-password read from file did not match expected value.  Expected: key-pass -- Actual: %s", cf.keyPassword)
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
