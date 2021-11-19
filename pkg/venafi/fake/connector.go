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

package fake

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

type Connector struct {
	verbose bool
}

func (c *Connector) IsCSRServiceGenerated(req *certificate.Request) (bool, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSshConfig(ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RequestSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {

	caName := "\\VED\\Policy\\Certificate Authorities\\TEST CA\\QA Test CA - Server 90 Days"
	validityHours := 120
	wildcardAllowed := true
	serviceGenerated := true
	reuseAllowed := false
	subjectAltNamesAllowed := true

	domain := "venafi.com"
	org := "Venafi"
	locality := "Salt Lake City"
	state := "Utah"
	country := "US"

	specification := policy.PolicySpecification{
		Owners:    []string{"amoo"},
		Users:     []string{"rvela", "malborno"},
		Approvers: []string{"rrodrig", "lpresuel"},
		Policy: &policy.Policy{
			CertificateAuthority: &caName,
			Domains:              []string{"venafi.com"},
			WildcardAllowed:      &wildcardAllowed,
			MaxValidDays:         &validityHours,
			Subject: &policy.Subject{
				Orgs:       []string{"Venafi"},
				OrgUnits:   []string{"DevOps"},
				Localities: []string{"Salt Lake City"},
				States:     []string{"Utah"},
				Countries:  []string{"US"},
			},
			KeyPair: &policy.KeyPair{
				KeyTypes:         []string{"RSA"},
				RsaKeySizes:      []int{3072},
				ServiceGenerated: &serviceGenerated,
				ReuseAllowed:     &reuseAllowed,
				EllipticCurves:   []string{"P384"},
			},
			SubjectAltNames: &policy.SubjectAltNames{
				DnsAllowed:   &subjectAltNamesAllowed,
				IpAllowed:    &subjectAltNamesAllowed,
				EmailAllowed: &subjectAltNamesAllowed,
				UriAllowed:   &subjectAltNamesAllowed,
				UpnAllowed:   &subjectAltNamesAllowed,
			},
		},
		Default: &policy.Default{
			Domain: &domain,
			Subject: &policy.DefaultSubject{
				Org:      &org,
				OrgUnits: []string{"DevOps"},
				Locality: &locality,
				State:    &state,
				Country:  &country,
			},
			KeyPair: &policy.DefaultKeyPair{
				KeyType:          nil,
				RsaKeySize:       nil,
				EllipticCurve:    nil,
				ServiceGenerated: nil,
			},
		},
	}
	return &specification, nil
}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {
	return "OK", nil
}

func NewConnector(verbose bool, trust *x509.CertPool) *Connector {
	c := Connector{verbose: verbose}
	return &c
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeFake
}

func (c *Connector) SetZone(z string) {
}

func (c *Connector) Ping() (err error) {
	return
}

func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	return
}

type fakeRequestID struct {
	Req *certificate.Request
	CSR string
}

func validateRequest(req *certificate.Request) error {
	if strings.HasSuffix(req.Subject.CommonName, "venafi.com") {
		return fmt.Errorf("%s certificate cannot be requested", req.Subject.CommonName)
	}
	return nil
}

func (c *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {
	err = validateRequest(req)
	if err != nil {
		return "", fmt.Errorf("certificate request validation fail: %s", err)
	}

	var fakeRequest = fakeRequestID{}

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR, certificate.UserProvidedCSR:
		// should return CSR as requestID payload
		fakeRequest.CSR = base64.StdEncoding.EncodeToString(req.GetCSR())

	case certificate.ServiceGeneratedCSR:
		// should return certificate.Request as requestID payload
		fakeRequest.Req = req

	default:
		return "", fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	js, err := json.Marshal(fakeRequest)
	if err != nil {
		return "", fmt.Errorf("failed to json.Marshal(certificate.Request: %v)", req)
	}
	pickupID := base64.StdEncoding.EncodeToString(js)
	req.PickupID = pickupID
	return pickupID, nil
}

func issueCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	if "disabled" == "CSR pre-precessing for HTTPS" {
		csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)

		nameSet := map[string]bool{}
		for _, name := range csr.DNSNames {
			nameSet[name] = true
		}
		uniqNames := []string{}
		for name := range nameSet {
			uniqNames = append(uniqNames, name)
		}
		csr.DNSNames = uniqNames
	}

	certRequest := x509.Certificate{
		SerialNumber: serial,
	}
	certRequest.Subject = csr.Subject
	certRequest.ExtraExtensions = csr.Extensions // this will include any SANs including UPN
	certRequest.SignatureAlgorithm = x509.SHA256WithRSA
	certRequest.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	certRequest.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	certRequest.NotBefore = time.Now().Add(-24 * time.Hour)
	certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 90)
	certRequest.IsCA = false
	certRequest.BasicConstraintsValid = true
	// ku := x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &certRequest, caCrt, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	res := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return res, nil
}

func (c *Connector) RetrieveCertificate(req *certificate.Request) (pcc *certificate.PEMCollection, err error) {

	bytes, err := base64.StdEncoding.DecodeString(req.PickupID)
	if err != nil {
		return nil, fmt.Errorf("Test-mode: could not parse requestID as base64 encoded fakeRequestID structure")
	}

	var fakeRequest = &fakeRequestID{}
	err = json.Unmarshal(bytes, fakeRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to json.Unmarshal(fakeRequestId): %s\n", err)
	}

	var csrPEMbytes []byte
	var pk crypto.Signer

	if fakeRequest.CSR != "" {
		csrPEMbytes, err = base64.StdEncoding.DecodeString(fakeRequest.CSR)
		if err != nil {
			return nil, err
		}

	} else {
		req := fakeRequest.Req

		err = req.GeneratePrivateKey()
		if err != nil {
			return
		}

		req.DNSNames = append(req.DNSNames, "fake-service-generated."+req.Subject.CommonName)

		err = req.GenerateCSR()
		if err != nil {
			return
		}
		csrPEMbytes = req.GetCSR()
		pk = req.PrivateKey
	}

	var (
		csrBlock *pem.Block
		csr      *x509.CertificateRequest
	)
	csrBlock, _ = pem.Decode([]byte(csrPEMbytes))
	if csrBlock == nil || !strings.HasSuffix(csrBlock.Type, "CERTIFICATE REQUEST") {
		return nil, fmt.Errorf("Test-mode: could not parse requestID as base64 encoded certificate request block")
	}

	csr, err = x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	cert_pem, err := issueCertificate(csr)
	if err != nil {
		return nil, err
	}

	var certBytes []byte
	switch req.ChainOption {
	case certificate.ChainOptionRootFirst:
		certBytes = append([]byte(CaCertPEM+"\n"), cert_pem...)
	default:
		certBytes = append(cert_pem, []byte(CaCertPEM)...)
	}
	pcc, err = certificate.PEMCollectionFromBytes(certBytes, req.ChainOption)
	if err != nil {
		return nil, err
	}
	// no key password -- no key
	if pk != nil && req.KeyPassword != "" {
		err = pcc.AddPrivateKey(pk, []byte(req.KeyPassword))
		if err != nil {
			return
		}
	}
	err = req.CheckCertificate(pcc.Certificate)
	return
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	return fmt.Errorf("revocation is not supported in -test-mode")
}

func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	config = endpoint.NewZoneConfiguration()
	policy, err := c.ReadPolicyConfiguration()
	config.Policy = *policy
	return
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(revReq *certificate.RenewalRequest) (requestID string, err error) {
	return "", fmt.Errorf("renew is not supported in -test-mode")
}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	return nil, fmt.Errorf("import is not supported in -test-mode")
}

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	policy = &endpoint.Policy{
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		[]endpoint.AllowedKeyConfiguration{
			{certificate.KeyTypeRSA, certificate.AllSupportedKeySizes(), nil},
			{certificate.KeyTypeECDSA, nil, certificate.AllSupportedCurves()},
		},
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		[]string{".*"},
		true,
		true,
	}
	return
}

func (c *Connector) SetHTTPClient(client *http.Client) {
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
	return nil, nil
}
