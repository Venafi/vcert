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

package endpoint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/policy"
)

const SDKName = "Venafi VCert-Go"

var LocalIP string

// ConnectorType represents the available connectors
type ConnectorType int

const (
	ConnectorTypeUndefined ConnectorType = iota
	// ConnectorTypeFake is a fake connector for tests
	ConnectorTypeFake
	// ConnectorTypeCloud represents the Cloud connector type
	ConnectorTypeCloud
	// ConnectorTypeTPP represents the TPP connector type
	ConnectorTypeTPP
	// ConnectorTypeFirefly represents the Firefly connector type
	ConnectorTypeFirefly
)

func init() {
	log.SetPrefix("vCert: ")
	LocalIP = getPrimaryNetAddr()
}

func (t ConnectorType) String() string {
	switch t {
	case ConnectorTypeUndefined:
		return "Undefined Endpoint"
	case ConnectorTypeFake:
		return "Fake Endpoint"
	case ConnectorTypeCloud:
		return "Venafi as a Service"
	case ConnectorTypeTPP:
		return "Trust Protection Platform"
	case ConnectorTypeFirefly:
		return "Firefly"
	default:
		return fmt.Sprintf("unexpected connector type: %d", t)
	}
}

// Connector provides a common interface for external communications with TPP or Venafi Cloud
type Connector interface {
	// GetType returns a connector type (cloud/TPP/fake). Can be useful because some features are not supported by a Cloud connection.
	GetType() ConnectorType
	// SetZone sets a zone (by name) for requests with this connector.
	SetZone(z string)
	// SetHTTPClient allows to set custom http.Client to this Connector.
	SetHTTPClient(client *http.Client)
	Ping() (err error)
	// SetAuthentication can be used to set the authentication details for the connector, it does not perform the validation
	// done by Authenticate. It is useful when you want to set the authentication details without validating them.
	SetAuthentication(auth *Authentication) (err error)
	// Authenticate calls SetAuthentication and then validates the authentication details by making a request to the server.
	// Authenticate is usually called by NewClient and it is not required that you manually call it.
	Authenticate(auth *Authentication) (err error)

	// ReadPolicyConfiguration returns information about zone policies. It can be used for checking request compatibility with policies.
	ReadPolicyConfiguration() (policy *Policy, err error)
	// ReadZoneConfiguration returns the zone configuration. A zone configuration includes zone policy and additional zone information.
	ReadZoneConfiguration() (config *ZoneConfiguration, err error)
	// GetZonesByParent returns a list of valid zones specified by parent
	GetZonesByParent(parent string) ([]string, error)
	// GenerateRequest update certificate.Request with data from zone configuration.
	GenerateRequest(config *ZoneConfiguration, req *certificate.Request) (err error)

	// ResetCertificate resets the state of a certificate.
	// This function is idempotent, i.e., it won't fail if there is nothing to be reset.
	ResetCertificate(req *certificate.Request, restart bool) (err error)
	// RequestCertificate makes a request to the server with data for enrolling the certificate.
	RequestCertificate(req *certificate.Request) (requestID string, err error)
	// RetrieveCertificate immediately returns an enrolled certificate. Otherwise, RetrieveCertificate waits and retries during req.Timeout.
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	ProvisionCertificate(req *domain.ProvisioningRequest, options *domain.ProvisioningOptions) (*domain.ProvisioningMetadata, error)
	IsCSRServiceGenerated(req *certificate.Request) (bool, error)
	RevokeCertificate(req *certificate.RevocationRequest) error
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
	RetireCertificate(req *certificate.RetireRequest) error
	// ImportCertificate adds an existing certificate to Venafi Platform even if the certificate was not issued by Venafi Cloud or Venafi Platform. For information purposes.
	ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error)
	// ListCertificates returns a list of certificates from inventory that matches the filter
	ListCertificates(filter Filter) ([]certificate.CertificateInfo, error)
	SearchCertificates(req *certificate.SearchRequest) (*certificate.CertSearchResponse, error)
	// SearchCertificate returns a valid certificate
	//
	// If it returns no error, the certificate returned should be the latest [1]
	// exact matching zone [2], CN and sans.DNS [3] provided, with a minimum
	// validity of `certMinTimeLeft`
	//
	// [1] the one with the longest validity; field named ValidTo for TPP and
	// validityEnd for VaaS
	// [2] application name for VaaS
	// [3] an array of strings representing the DNS names
	SearchCertificate(zone string, cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) (*certificate.CertificateInfo, error)
	RetrieveCertificateMetaData(dn string) (*certificate.CertificateMetaData, error)

	SetPolicy(name string, ps *policy.PolicySpecification) (string, error)
	GetPolicy(name string) (*policy.PolicySpecification, error)

	RequestSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error)
	RetrieveSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error)
	RetrieveSshConfig(ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error)
	RetrieveAvailableSSHTemplates() ([]certificate.SshAvaliableTemplate, error)

	// SynchronousRequestCertificate makes a request to the server with data for enrolling the certificate and returns the enrolled certificate.
	SynchronousRequestCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	// SupportSynchronousRequestCertificate returns if the connector support synchronous calls to request a certificate.
	SupportSynchronousRequestCertificate() bool

	RetrieveSystemVersion() (string, error)
	WriteLog(req *LogRequest) error
	// SetUserAgent sets the value of the UserAgent header in HTTP requests to
	// Venafi API endpoints by this connector.
	// The default is `vcert/v5`.
	// Further reading: https://www.rfc-editor.org/rfc/rfc9110#field.user-agent
	SetUserAgent(userAgent string)
}

type Filter struct {
	Limit       *int
	WithExpired bool
}

// todo: replace with verror
// ErrRetrieveCertificateTimeout provides a common error structure for a timeout while retrieving a certificate
type ErrRetrieveCertificateTimeout struct {
	CertificateID string
}

func (err ErrRetrieveCertificateTimeout) Error() string {
	return fmt.Sprintf("Operation timed out. You may try retrieving the certificate later using Pickup ID: %s", err.CertificateID)
}

// todo: replace with verror
// ErrCertificatePending provides a common error structure for a timeout while retrieving a certificate
type ErrCertificatePending struct {
	CertificateID string
	Status        string
}

func (err ErrCertificatePending) Error() string {
	if err.Status == "" {
		return fmt.Sprintf("Issuance is pending. You may try retrieving the certificate later using Pickup ID: %s", err.CertificateID)
	}
	return fmt.Sprintf("Issuance is pending. You may try retrieving the certificate later using Pickup ID: %s\n\tStatus: %s", err.CertificateID, err.Status)
}

type ErrCertificateRejected struct {
	CertificateID string
	Status        string
}

func (err ErrCertificateRejected) Error() string {
	if err.Status == "" {
		return fmt.Sprintf("Certificate request was rejected. You may need to verify the certificate id: %s", err.CertificateID)
	}
	return fmt.Sprintf("Status: %s", err.Status)
}

// Policy is struct that contains restrictions for certificates. Most of the fields contains list of regular expression.
// For satisfying policies, all values in the certificate field must match AT LEAST ONE regular expression in corresponding policy field.
type Policy struct {
	SubjectCNRegexes []string
	SubjectORegexes  []string
	SubjectOURegexes []string
	SubjectSTRegexes []string
	SubjectLRegexes  []string
	SubjectCRegexes  []string
	// AllowedKeyConfigurations lists all allowed key configurations. Certificate key configuration have to be listed in this list.
	// For example: If key has type RSA and length 2048 bit for satisfying the policy, that list must contain AT LEAST ONE configuration with type RSA and value 2048 in KeySizes list of this configuration.
	AllowedKeyConfigurations []AllowedKeyConfiguration
	// DnsSanRegExs is a list of regular expressions that show allowable DNS names in SANs.
	DnsSanRegExs []string
	// IpSanRegExs is a list of regular expressions that show allowable DNS names in SANs.
	IpSanRegExs    []string
	EmailSanRegExs []string
	UriSanRegExs   []string
	UpnSanRegExs   []string
	AllowWildcards bool
	AllowKeyReuse  bool
}

// ZoneConfiguration provides a common structure for certificate request data provided by the remote endpoint
type ZoneConfiguration struct {
	Organization       string
	OrganizationalUnit []string
	Country            string
	Province           string
	Locality           string
	Policy
	HashAlgorithm         x509.SignatureAlgorithm
	CustomAttributeValues map[string]string
	KeyConfiguration      *AllowedKeyConfiguration
}

type LogRequest struct {
	LogID     string `json:"ID,omitempty"`
	Component string `json:",omitempty"`
	Text1     string `json:",omitempty"`
	Text2     string `json:",omitempty"`
	Value1    string `json:",omitempty"`
	Value2    string `json:",omitempty"`
	SourceIp  string `json:",omitempty"`
	Severity  string `json:",omitempty"`
}

// AllowedKeyConfiguration contains an allowed key type with its sizes or curves
type AllowedKeyConfiguration struct {
	KeyType   certificate.KeyType
	KeySizes  []int
	KeyCurves []certificate.EllipticCurve
}

// NewZoneConfiguration creates a new zone configuration which creates the map used in the configuration
func NewZoneConfiguration() *ZoneConfiguration {
	zc := ZoneConfiguration{}
	zc.CustomAttributeValues = make(map[string]string)

	return &zc
}

// ValidateCertificateRequest validates the request against the Policy
func (p *Policy) ValidateCertificateRequest(request *certificate.Request) error {

	const (
		emailError            = "email addresses %v do not match regular expressions: %v"
		ipError               = "IP addresses %v do not match regular expressions: %v"
		uriError              = "URIs %v do not match regular expressions: %v"
		organizationError     = "organization %v doesn't match regular expressions: %v"
		organizationUnitError = "organization unit %v doesn't match regular expressions: %v"
		countryError          = "country %v doesn't match regular expressions: %v"
		locationError         = "location %v doesn't match regular expressions: %v"
		provinceError         = "state (province) %v doesn't match regular expressions: %v"
		keyError              = "the requested Key Type and Size do not match any of the allowed Key Types and Sizes"
	)
	err := p.SimpleValidateCertificateRequest(*request)
	if err != nil {
		return err
	}
	csr := request.GetCSR()
	if len(csr) > 0 {
		pemBlock, _ := pem.Decode(csr)
		parsedCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			return err
		}
		if !isComponentValid(parsedCSR.EmailAddresses, p.EmailSanRegExs, true) {
			return fmt.Errorf(emailError, p.EmailSanRegExs, p.EmailSanRegExs)
		}
		ips := make([]string, len(parsedCSR.IPAddresses))
		for i, ip := range parsedCSR.IPAddresses {
			ips[i] = ip.String()
		}
		if !isComponentValid(ips, p.IpSanRegExs, true) {
			return fmt.Errorf(ipError, p.IpSanRegExs, p.IpSanRegExs)
		}
		uris := make([]string, len(parsedCSR.URIs))
		for i, uri := range parsedCSR.URIs {
			uris[i] = uri.String()
		}
		if !isComponentValid(uris, p.UriSanRegExs, true) {
			return fmt.Errorf(uriError, uris, p.UriSanRegExs)
		}
		if !isComponentValid(parsedCSR.Subject.Organization, p.SubjectORegexes, false) {
			return fmt.Errorf(organizationError, p.SubjectORegexes, p.SubjectORegexes)
		}

		if !isComponentValid(parsedCSR.Subject.OrganizationalUnit, p.SubjectOURegexes, false) {
			return fmt.Errorf(organizationUnitError, parsedCSR.Subject.OrganizationalUnit, p.SubjectOURegexes)
		}

		if !isComponentValid(parsedCSR.Subject.Country, p.SubjectCRegexes, false) {
			return fmt.Errorf(countryError, parsedCSR.Subject.Country, p.SubjectCRegexes)
		}

		if !isComponentValid(parsedCSR.Subject.Locality, p.SubjectLRegexes, false) {
			return fmt.Errorf(locationError, parsedCSR.Subject.Locality, p.SubjectLRegexes)
		}

		if !isComponentValid(parsedCSR.Subject.Province, p.SubjectSTRegexes, false) {
			return fmt.Errorf(provinceError, parsedCSR.Subject.Province, p.SubjectSTRegexes)
		}
		if len(p.AllowedKeyConfigurations) > 0 {
			var keyValid bool
			if parsedCSR.PublicKeyAlgorithm == x509.RSA {
				pubkey, ok := parsedCSR.PublicKey.(*rsa.PublicKey)
				if ok {
					keyValid = checkKey(certificate.KeyTypeRSA, pubkey.Size()*8, "", p.AllowedKeyConfigurations)
				} else {
					return fmt.Errorf("invalid key in csr")
				}
			} else if parsedCSR.PublicKeyAlgorithm == x509.ECDSA {
				pubkey, ok := parsedCSR.PublicKey.(*ecdsa.PublicKey)
				if ok {
					keyValid = checkKey(certificate.KeyTypeECDSA, 0, pubkey.Curve.Params().Name, p.AllowedKeyConfigurations)
				} else {
					return fmt.Errorf("invalid key in csr")
				}
			} else if parsedCSR.PublicKeyAlgorithm == x509.Ed25519 {
				_, ok := parsedCSR.PublicKey.(*ed25519.PublicKey)
				if ok {
					keyValid = checkKey(certificate.KeyTypeECDSA, 0, "ed25519", p.AllowedKeyConfigurations)
				} else {
					return fmt.Errorf("invalid key in csr")
				}
			}
			if !keyValid {
				return errors.New(keyError)
			}
		}

	} else {
		//todo: add ip, email, uri cheking
		if !isComponentValid(request.Subject.Organization, p.SubjectORegexes, false) {
			return fmt.Errorf(organizationError, request.Subject.Organization, p.SubjectORegexes)
		}
		if !isComponentValid(request.Subject.OrganizationalUnit, p.SubjectOURegexes, false) {
			return fmt.Errorf(organizationUnitError, request.Subject.OrganizationalUnit, p.SubjectOURegexes)
		}
		if !isComponentValid(request.Subject.Province, p.SubjectSTRegexes, false) {
			return fmt.Errorf(provinceError, request.Subject.Province, p.SubjectSTRegexes)
		}
		if !isComponentValid(request.Subject.Locality, p.SubjectLRegexes, false) {
			return fmt.Errorf(locationError, request.Subject.Locality, p.SubjectLRegexes)
		}
		if !isComponentValid(request.Subject.Country, p.SubjectCRegexes, false) {
			return fmt.Errorf(countryError, request.Subject.Country, p.SubjectCRegexes)
		}

		if len(p.AllowedKeyConfigurations) > 0 {
			if !checkKey(request.KeyType, request.KeyLength, request.KeyCurve.String(), p.AllowedKeyConfigurations) {
				return errors.New(keyError)
			}
		}
	}

	return nil
}

// SimpleValidateCertificateRequest functions just check Common Name and SANs mathching with policies
func (p *Policy) SimpleValidateCertificateRequest(request certificate.Request) error {
	csr := request.GetCSR()
	const (
		cnError   = "common name %s is not allowed in this policy: %v"
		SANsError = "DNS SANs %v do not match regular expressions: %v"
	)
	if len(csr) > 0 {
		pemBlock, _ := pem.Decode(csr)
		parsedCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			return err
		}
		if !checkStringByRegexp(parsedCSR.Subject.CommonName, p.SubjectCNRegexes) {
			return fmt.Errorf(cnError, parsedCSR.Subject.CommonName, p.SubjectCNRegexes)
		}
		if !isComponentValid(parsedCSR.DNSNames, p.DnsSanRegExs, true) {
			return fmt.Errorf(SANsError, parsedCSR.DNSNames, p.DnsSanRegExs)
		}
	} else {
		if !checkStringByRegexp(request.Subject.CommonName, p.SubjectCNRegexes) {
			return fmt.Errorf(cnError, request.Subject.CommonName, p.SubjectCNRegexes)
		}
		if !isComponentValid(request.DNSNames, p.DnsSanRegExs, true) {
			return fmt.Errorf(SANsError, request.DNSNames, p.DnsSanRegExs)
		}
	}
	return nil
}

func checkKey(kt certificate.KeyType, bitsize int, curveStr string, allowed []AllowedKeyConfiguration) (valid bool) {
	for _, allowedKey := range allowed {
		if allowedKey.KeyType == kt {
			switch allowedKey.KeyType {
			case certificate.KeyTypeRSA:
				return intInSlice(bitsize, allowedKey.KeySizes)
			case certificate.KeyTypeECDSA:
				var curve certificate.EllipticCurve
				if err := curve.Set(curveStr); err != nil {
					return false
				}
				return curveInSlice(curve, allowedKey.KeyCurves)
			case certificate.KeyTypeED25519:
				// ED25519 Key is fixed by its own on size.
				// Currently, as VaaS sees ED25519 as another curve, we do two things:
				// 1. If from flow of:
				// -> cfg = ReadZoneConfiguration()
				// -> cfg.ValidateCertificateRequest(enrollRequest)
				// -> cfg.UpdateCertificateRequest(enrollReq)
				// we allow the user on setting the EllipticCurve or to leave it empty
				auxCurve := certificate.EllipticCurveED25519
				if curveStr == "" || curveStr == auxCurve.String() {
					return true
				}
			default:
				return
			}
		} else if kt == certificate.KeyTypeED25519 && allowedKey.KeyType == certificate.KeyTypeECDSA {
			// 2. else we validate as policy returns to us ED25199 as an elliptic curve from ECDSA from VaaS
			// flow - You already have a configuration, you read from it and you validate the policy against it:
			// -> policy = cfg.ReadPolicyConfiguration()
			// -> err = policy.ValidateCertificateRequest(enrollRequest)
			var curve certificate.EllipticCurve
			if err := curve.Set("ed25519"); err != nil {
				return false
			}
			return curveInSlice(curve, allowedKey.KeyCurves)
		}
	}
	return
}

func intInSlice(i int, s []int) bool {
	for _, j := range s {
		if i == j {
			return true
		}
	}
	return false
}

func curveInSlice(i certificate.EllipticCurve, s []certificate.EllipticCurve) bool {
	for _, j := range s {
		if i == j {
			return true
		}
	}
	return false
}

func checkStringByRegexp(s string, regexs []string) bool {
	for _, r := range regexs {
		matched, err := regexp.MatchString(r, s)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func isComponentValid(ss []string, regexs []string, optional bool) bool {
	if optional && len(ss) == 0 {
		return true
	}
	if len(ss) == 0 {
		ss = []string{""}
	}
	for _, s := range ss {
		if !checkStringByRegexp(s, regexs) {
			return false
		}
	}
	return true
}

// UpdateCertificateRequest updates a certificate request based on the zone configuration retrieved from the remote endpoint
func (z *ZoneConfiguration) UpdateCertificateRequest(request *certificate.Request) {
	if len(request.Subject.Organization) == 0 && z.Organization != "" {
		request.Subject.Organization = []string{z.Organization}
	}

	if len(request.Subject.OrganizationalUnit) == 0 && z.OrganizationalUnit != nil {
		request.Subject.OrganizationalUnit = z.OrganizationalUnit
	}

	if len(request.Subject.Country) == 0 && z.Country != "" {
		request.Subject.Country = []string{z.Country}
	}

	if len(request.Subject.Province) == 0 && z.Province != "" {
		request.Subject.Province = []string{z.Province}
	}

	if len(request.Subject.Locality) == 0 && z.Locality != "" {
		request.Subject.Locality = []string{z.Locality}
	}

	if z.HashAlgorithm != x509.UnknownSignatureAlgorithm {
		request.SignatureAlgorithm = z.HashAlgorithm
	} else {
		request.SignatureAlgorithm = x509.SHA256WithRSA
	}

	if z.KeyConfiguration != nil {
		if request.KeyType.String() == "" {
			request.KeyType = z.KeyConfiguration.KeyType
		}
		if request.KeyType == certificate.KeyTypeRSA {
			if len(z.KeyConfiguration.KeySizes) != 0 && request.KeyLength == 0 {
				request.KeyLength = z.KeyConfiguration.KeySizes[0]
			}
		}
		if request.KeyType == certificate.KeyTypeECDSA {
			if len(z.KeyConfiguration.KeyCurves) != 0 && request.KeyCurve == certificate.EllipticCurveNotSet {
				request.KeyCurve = z.KeyConfiguration.KeyCurves[0]
			}
		}
	} else {
		// Zone config has no key length parameters, so we just pass user's -key-size or fall to default 2048
		if request.KeyType == certificate.KeyTypeRSA && request.KeyLength == 0 {
			request.KeyLength = 2048
		}
	}
}

func getPrimaryNetAddr() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
