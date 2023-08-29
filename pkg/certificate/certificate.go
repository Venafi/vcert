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

package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/youmark/pkcs8"

	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

const (
	DefaultRSAlength int = 2048
)

func AllSupportedKeySizes() []int {
	return []int{1024, DefaultRSAlength, 4096, 8192}
}

//SSH Certificate structures

// SshCertRequest This request is a standard one, it will hold data for tpp request
// and in the future it will hold VaS data.
type SshCertRequest struct {
	Template             string
	PolicyDN             string
	ObjectName           string
	DestinationAddresses []string
	KeyId                string
	Principals           []string
	ValidityPeriod       string
	PublicKeyData        string
	Extensions           []string
	ForceCommand         string
	SourceAddresses      []string

	PickupID                  string
	Guid                      string
	IncludePrivateKeyData     bool
	PrivateKeyPassphrase      string
	PrivateKeyFormat          string
	IncludeCertificateDetails bool

	Timeout time.Duration
}

type TPPSshCertRequest struct {
	CADN                      string                 `json:"CADN,omitempty"`
	PolicyDN                  string                 `json:"PolicyDN,omitempty"`
	ObjectName                string                 `json:"ObjectName,omitempty"`
	DestinationAddresses      []string               `json:"DestinationAddresses,omitempty"`
	KeyId                     string                 `json:"KeyId,omitempty"`
	Principals                []string               `json:"Principals,omitempty"`
	ValidityPeriod            string                 `json:"ValidityPeriod,omitempty"`
	PublicKeyData             string                 `json:"PublicKeyData,omitempty"`
	Extensions                map[string]interface{} `json:"Extensions,omitempty"`
	ForceCommand              string                 `json:"ForceCommand,omitempty"`
	SourceAddresses           []string               `json:"SourceAddresses,omitempty"`
	IncludePrivateKeyData     bool                   `json:"IncludePrivateKeyData,omitempty"`
	PrivateKeyPassphrase      string                 `json:"PrivateKeyPassphrase,omitempty"`
	IncludeCertificateDetails bool                   `json:"IncludeCertificateDetails,omitempty"`
	ProcessingTimeout         string                 `json:"ProcessingTimeout,omitempty"`
}

type TppSshCertResponseInfo struct {
	ErrorCode    int
	ErrorMessage string
	Success      bool
}

type TppSshCertRetrieveRequest struct {
	Guid                      string
	DN                        string
	IncludePrivateKeyData     bool
	PrivateKeyPassphrase      string
	PrivateKeyFormat          string
	IncludeCertificateDetails bool
}

type TppSshCertOperationResponse struct {
	ProcessingDetails  ProcessingDetails
	Guid               string
	DN                 string
	CertificateData    string
	PrivateKeyData     string
	PublicKeyData      string
	CAGuid             string
	CADN               string
	CertificateDetails SshCertificateDetails
	Response           TppSshCertResponseInfo
}

type SshCertificateObject struct {
	Guid               string
	DN                 string
	CAGuid             string
	CADN               string
	CertificateData    string
	PrivateKeyData     string
	PublicKeyData      string
	CertificateDetails SshCertificateDetails
	ProcessingDetails  ProcessingDetails
}

type SshCertificateDetails struct {
	KeyType                      string                 `json:"KeyType,omitempty"`
	CertificateType              string                 `json:"CertificateType,omitempty"`
	CertificateFingerprintSHA256 string                 `json:"CertificateFingerprintSHA256,omitempty"`
	CAFingerprintSHA256          string                 `json:"CAFingerprintSHA256,omitempty"`
	KeyID                        string                 `json:"KeyID,omitempty"`
	SerialNumber                 string                 `json:"SerialNumber,omitempty"`
	Principals                   []string               `json:"Principals,omitempty"`
	ValidFrom                    int64                  `json:"ValidFrom,omitempty"`
	ValidTo                      int64                  `json:"ValidTo,omitempty"`
	ForceCommand                 string                 `json:"ForceCommand,omitempty"`
	SourceAddresses              []string               `json:"SourceAddresses,omitempty"`
	PublicKeyFingerprintSHA256   string                 `json:"PublicKeyFingerprintSHA256,omitempty"`
	Extensions                   map[string]interface{} `json:"Extensions,omitempty"`
}

type ProcessingDetails struct {
	Status            string `json:"Status,omitempty"`
	StatusDescription string `json:"StatusDescription,omitempty"`
}

type RevocationRequest struct {
	CertificateDN string
	Thumbprint    string
	Reason        string
	Comments      string
	Disable       bool
}

type RetireRequest struct {
	CertificateDN string
	Thumbprint    string
	Description   string
}

type RenewalRequest struct {
	CertificateDN      string // these fields are for certificate lookup on remote
	Thumbprint         string
	CertificateRequest *Request // here CSR should be filled
}

type ImportRequest struct {
	PolicyDN        string
	ObjectName      string
	CertificateData string
	PrivateKeyData  string
	Password        string
	Reconcile       bool
	CustomFields    []CustomField
}

type ImportResponse struct {
	CertificateDN      string `json:",omitempty"`
	CertId             string `json:",omitempty"`
	CertificateVaultId int    `json:",omitempty"`
	Guid               string `json:",omitempty"`
	PrivateKeyVaultId  int    `json:",omitempty"`
}

type Sans struct {
	DNS   []string
	Email []string `json:",omitempty"`
	IP    []string `json:",omitempty"`
	URI   []string `json:",omitempty"`
	UPN   []string `json:",omitempty"`
}

type CertificateInfo struct {
	ID         string `json:",omitempty"`
	CN         string
	SANS       Sans
	Serial     string
	Thumbprint string
	ValidFrom  time.Time
	ValidTo    time.Time
}

type SearchRequest []string

type CertSearchResponse struct {
	Certificates []CertSeachInfo `json:"Certificates"`
	Count        int             `json:"TotalCount"`
}

type CertificateMetaData struct {
	Approver               []string `json:"Approver"`
	CreatedOn              string   `json:"CreatedOn"`
	CertificateAuthorityDN string   `json:"CertificateAuthorityDN"`
	Contact                []string `json:"Contact"`
	CreatedBy              []string `json:"CreatedBy"`
	CertificateDetails     struct {
		AIACAIssuerURL        []string  `json:"AIACAIssuerURL"`
		AIAKeyIdentifier      string    `json:"AIAKeyIdentifier"`
		C                     string    `json:"C"`
		CDPURI                string    `json:"CDPURI"`
		CN                    string    `json:"CN"`
		EnhancedKeyUsage      string    `json:"EnhancedKeyUsage"`
		Issuer                string    `json:"Issuer"`
		KeyAlgorithm          string    `json:"KeyAlgorithm"`
		KeySize               int       `json:"KeySize"`
		KeyUsage              string    `json:"KeyUsage"`
		L                     string    `json:"L"`
		O                     string    `json:"O"`
		OU                    []string  `json:"OU"`
		PublicKeyHash         string    `json:"PublicKeyHash"`
		S                     string    `json:"S"`
		SKIKeyIdentifier      string    `json:"SKIKeyIdentifier"`
		Serial                string    `json:"Serial"`
		SignatureAlgorithm    string    `json:"SignatureAlgorithm"`
		SignatureAlgorithmOID string    `json:"SignatureAlgorithmOID"`
		StoreAdded            time.Time `json:"StoreAdded"`
		Subject               string    `json:"Subject"`
		TemplateMajorVersion  string    `json:"TemplateMajorVersion"`
		TemplateMinorVersion  string    `json:"TemplateMinorVersion"`
		TemplateName          string    `json:"TemplateName"`
		TemplateOID           string    `json:"TemplateOID"`
		Thumbprint            string    `json:"Thumbprint"`
		ValidFrom             time.Time `json:"ValidFrom"`
		ValidTo               time.Time `json:"ValidTo"`
	} `json:"CertificateDetails"`

	RenewalDetails struct {
		City               string   `json:"City"`
		Country            string   `json:"Country"`
		KeySize            int      `json:"KeySize"`
		Organization       string   `json:"Organization"`
		OrganizationalUnit []string `json:"OrganizationalUnit"`
		State              string   `json:"State"`
		Subject            string   `json:"Subject"`
	} `json:"RenewalDetails"`

	ValidationDetails struct {
		LastValidationStateUpdate time.Time `json:"LastValidationStateUpdate"`
		NetworkValidationDisabled bool      `json:"NetworkValidationDisabled"`
		ValidationDisabled        bool      `json:"ValidationDisabled"`
	} `json:"ValidationDetails"`

	CustomFields []CustomFieldDetails `json:"CustomFields"`

	DN             string `json:"DN"`
	Guid           string `json:"Guid"`
	ManagementType string `json:"ManagementType"`
	Name           string `json:"Name"`
	Origin         string `json:"Origin"`
	ParentDn       string `json:"ParentDn"`
	SchemaClass    string `json:"SchemaClass"`
}
type CustomFieldDetails struct {
	Name  string   `json:"Name"`
	Type  string   `json:"Type"`
	Value []string `json:"Value"`
}

type CertSeachInfo struct {
	CertificateRequestId   string `json:"DN"`
	CertificateRequestGuid string `json:"Guid"`
}

// Deprecated: GenerateRequest is deprecated
// Please use method Request.GenerateCSR()
// GenerateRequest generates a certificate request
// TODO: Remove usage from all libraries, deprecated
func GenerateRequest(request *Request, privateKey crypto.Signer) error {
	pk := request.PrivateKey
	request.PrivateKey = privateKey
	err := request.GenerateCSR()
	request.PrivateKey = pk
	return err
}

func publicKey(priv crypto.Signer) crypto.PublicKey {
	if priv != nil {
		return priv.Public()
	}
	return nil
}

func PublicKey(priv crypto.Signer) crypto.PublicKey {
	return publicKey(priv)
}

// GetPrivateKeyPEMBock gets the private key as a PEM data block
func GetPrivateKeyPEMBock(key crypto.Signer, format ...string) (*pem.Block, error) {
	currentFormat := ""
	if len(format) > 0 && format[0] != "" {
		currentFormat = format[0]
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if currentFormat == "legacy-pem" {
			return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
		} else {
			dataBytes, err := pkcs8.MarshalPrivateKey(key.(*rsa.PrivateKey), nil, nil)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "PRIVATE KEY", Bytes: dataBytes}, err
		}
	case *ecdsa.PrivateKey:
		if currentFormat == "legacy-pem" {
			b, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
		} else {
			dataBytes, err := pkcs8.MarshalPrivateKey(key.(*ecdsa.PrivateKey), nil, nil)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "PRIVATE KEY", Bytes: dataBytes}, err
		}
	case ed25519.PrivateKey:
		if currentFormat == "legacy-pem" {
			return nil, fmt.Errorf("%w: unable to format Key. Legacy format for ed25519 is not supported", verror.VcertError)
		} else {
			dataBytes, err := pkcs8.MarshalPrivateKey(key.(ed25519.PrivateKey), nil, nil)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "PRIVATE KEY", Bytes: dataBytes}, err
		}
	default:
		return nil, fmt.Errorf("%w: unable to format Key", verror.VcertError)
	}
}

// GetEncryptedPrivateKeyPEMBock gets the private key as an encrypted PEM data block
func GetEncryptedPrivateKeyPEMBock(key crypto.Signer, password []byte, format ...string) (*pem.Block, error) {
	currentFormat := ""
	if len(format) > 0 && format[0] != "" {
		currentFormat = format[0]
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if currentFormat == "legacy-pem" {
			return util.X509EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k), password, util.PEMCipherAES256)
		} else {
			dataBytes, err := pkcs8.MarshalPrivateKey(key.(*rsa.PrivateKey), password, nil)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: dataBytes}, err
		}
	case *ecdsa.PrivateKey:
		if currentFormat == "legacy-pem" {
			b, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, err
			}
			return util.X509EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", b, password, util.PEMCipherAES256)
		} else {
			dataBytes, err := pkcs8.MarshalPrivateKey(key.(*ecdsa.PrivateKey), password, nil)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: dataBytes}, err
		}
	case ed25519.PrivateKey:
		if currentFormat == "legacy-pem" {
			return nil, fmt.Errorf("%w: unable to format Key. Legacy format for ed25519 is not supported", verror.VcertError)
		} else {
			dataBytes, err := pkcs8.MarshalPrivateKey(key.(ed25519.PrivateKey), password, nil)
			if err != nil {
				return nil, err
			}
			return &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: dataBytes}, err
		}
	default:
		return nil, fmt.Errorf("%w: unable to format Key", verror.VcertError)
	}
}

// GetCertificatePEMBlock gets the certificate as a PEM data block
func GetCertificatePEMBlock(cert []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: cert}
}

// GetCertificateRequestPEMBlock gets the certificate request as a PEM data block
func GetCertificateRequestPEMBlock(request []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}
}

// GenerateECDSAPrivateKey generates a new ecdsa private key using the curve specified
func GenerateECDSAPrivateKey(curve EllipticCurve) (crypto.Signer, error) {
	var priv crypto.Signer
	var c elliptic.Curve
	var err error
	if curve == EllipticCurveNotSet {
		curve = EllipticCurveDefault
	}

	switch curve {
	case EllipticCurveP521:
		c = elliptic.P521()
	case EllipticCurveP384:
		c = elliptic.P384()
	case EllipticCurveP256:
		c = elliptic.P256()
	case EllipticCurveED25519:
		return nil, fmt.Errorf("%w: unable to generate ECDSA key. ED25519 curve is not supported, use GenerateED25519PrivateKey instead", verror.VcertError)
	}

	priv, err = ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func GenerateED25519PrivateKey() (crypto.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// GenerateRSAPrivateKey generates a new rsa private key using the size specified
func GenerateRSAPrivateKey(size int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// NewRequest duplicates new Request object based on issued certificate
func NewRequest(cert *x509.Certificate) *Request {
	req := &Request{}

	// First populate with *cert content
	req.Subject = cert.Subject
	req.DNSNames = cert.DNSNames
	req.EmailAddresses = cert.EmailAddresses
	req.IPAddresses = cert.IPAddresses
	req.URIs = cert.URIs
	req.UPNs, _ = getUserPrincipalNameSANs(cert)

	req.SignatureAlgorithm = cert.SignatureAlgorithm
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		req.KeyType = KeyTypeRSA
		req.KeyLength = pub.N.BitLen()
	case *ecdsa.PublicKey:
		req.KeyType = KeyTypeECDSA
		_ = req.KeyCurve.Set(pub.Curve.Params().Name)
	case ed25519.PublicKey:
		req.KeyType = KeyTypeED25519
		_ = req.KeyCurve.Set("ed25519")
	default:
		// vcert only works with RSA, ECDSA & Ed25519 keys
	}
	return req
}

// FindNewestCertificateWithSans finds a certificate from a list of certificates whose Sans.DNS matches and is
// the newest
func FindNewestCertificateWithSans(certificates []*CertificateInfo, sans_ *Sans) (*CertificateInfo, error) {
	sans := Sans{}

	if sans_ != nil {
		sans.DNS = sans_.DNS
	}

	// order provided SANS-DNS
	sort.Strings(sans.DNS)

	// create local variable to hold the newest certificate
	var newestCertificate *CertificateInfo
	for _, certificate := range certificates {
		// order certificate SANS before comparison
		if certificate.SANS.DNS != nil {
			sort.Strings(certificate.SANS.DNS)
		}
		// exact match SANs
		if reflect.DeepEqual(sans.DNS, certificate.SANS.DNS) {
			// update the certificate to the newest match
			if newestCertificate == nil || certificate.ValidTo.Unix() > newestCertificate.ValidTo.Unix() {
				newestCertificate = certificate
			}
		}
	}

	// a valid certificate has been found, return it
	if newestCertificate != nil {
		return newestCertificate, nil
	}

	// fail, since no valid certificate was found at this point
	return nil, verror.NoCertificateFoundError
}
