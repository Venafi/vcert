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

package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"net"
	"net/url"
	"strings"
	"time"
)

// EllipticCurve represents the types of supported elliptic curves
type EllipticCurve int

func (ec *EllipticCurve) String() string {
	switch *ec {
	case EllipticCurveP521:
		return "P521"
	case EllipticCurveP384:
		return "P384"
	case EllipticCurveP256:
		return "P256"
	default:
		return ""
	}
}

// Set EllipticCurve value via a string
func (ec *EllipticCurve) Set(value string) error {
	switch strings.ToLower(value) {
	case "p521", "p-521":
		*ec = EllipticCurveP521
	case "p384", "p-384":
		*ec = EllipticCurveP384
	case "p256", "p-256":
		*ec = EllipticCurveP256
	default:
		*ec = EllipticCurveDefault
	}

	return nil
}

const (
	EllipticCurveNotSet EllipticCurve = iota
	// EllipticCurveP521 represents the P521 curve
	EllipticCurveP521
	// EllipticCurveP256 represents the P256 curve
	EllipticCurveP256
	// EllipticCurveP384 represents the P384 curve
	EllipticCurveP384
	EllipticCurveDefault = EllipticCurveP256

	defaultRSAlength int = 2048
)

func AllSupportedCurves() []EllipticCurve {
	return []EllipticCurve{EllipticCurveP521, EllipticCurveP256, EllipticCurveP384}
}
func AllSupportedKeySizes() []int {
	return []int{1024, 2048, 4096, 8192}
}

// KeyType represents the types of supported keys
type KeyType int

func (kt *KeyType) String() string {
	switch *kt {
	case KeyTypeRSA:
		return "RSA"
	case KeyTypeECDSA:
		return "ECDSA"
	default:
		return ""
	}
}

func (kt *KeyType) X509Type() x509.PublicKeyAlgorithm {
	switch *kt {
	case KeyTypeRSA:
		return x509.RSA
	case KeyTypeECDSA:
		return x509.ECDSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

// Set the key type via a string
func (kt *KeyType) Set(value string) error {
	switch strings.ToLower(value) {
	case "rsa":
		*kt = KeyTypeRSA
		return nil
	case "ecdsa", "ec", "ecc":
		*kt = KeyTypeECDSA
		return nil
	}
	return fmt.Errorf("%w: unknown key type: %s", verror.VcertError, value) //todo: check all calls
}

const (
	// KeyTypeRSA represents a key type of RSA
	KeyTypeRSA KeyType = iota
	// KeyTypeECDSA represents a key type of ECDSA
	KeyTypeECDSA
)

type CSrOriginOption int

const (
	// LocalGeneratedCSR - this vcert library generates CSR internally based on Request data
	LocalGeneratedCSR CSrOriginOption = iota // local generation is default.
	// ServiceGeneratedCSR - server generate CSR internally based on zone configuration and data from Request
	ServiceGeneratedCSR
	// UserProvidedCSR - client provides CSR from external resource and vcert library just check and send this CSR to server
	UserProvidedCSR
)

type CustomFieldType int

const (
	CustomFieldPlain CustomFieldType = 0 + iota
	CustomFieldOrigin
)

// CustomField can be used for adding additional information to certificate. For example: custom fields or Origin.
// By default it's custom field. For adding Origin set Type: CustomFieldOrigin
// For adding custom field with one name and few values give to request:
//  request.CustomFields = []CustomField{
//    {Name: "name1", Value: "value1"}
//    {Name: "name1", Value: "value2"}
//  }
type CustomField struct {
	Type  CustomFieldType
	Name  string
	Value string
}

type Location struct {
	Instance, Workload, TLSAddress string
	Replace                        bool
}

// Request contains data needed to generate a certificate request
// CSR is a PEM-encoded Certificate Signing Request
type Request struct {
	CADN               string
	Subject            pkix.Name
	DNSNames           []string
	OmitSANs           bool
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	UPNs               []string
	Attributes         []pkix.AttributeTypeAndValueSET
	SignatureAlgorithm x509.SignatureAlgorithm
	FriendlyName       string
	KeyType            KeyType
	KeyLength          int
	KeyCurve           EllipticCurve
	csr                []byte // should be a PEM-encoded CSR
	PrivateKey         crypto.Signer
	CsrOrigin          CSrOriginOption
	PickupID           string
	//Cloud Certificate ID
	CertID          string
	ChainOption     ChainOption
	KeyPassword     string
	FetchPrivateKey bool
	/*	Thumbprint is here because *Request is used in RetrieveCertificate().
		Code should be refactored so that RetrieveCertificate() uses some abstract search object, instead of *Request{PickupID} */
	Thumbprint    string
	Timeout       time.Duration
	CustomFields  []CustomField
	Location      *Location
	ValidityHours int
	IssuerHint    string
}

//SSH Certificate structures

//This request is a standard one, it will hold data for tpp request
//and in the future it will hold VaS data.
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
	CADN                 string                 `json:"CADN,omitempty"`
	PolicyDN             string                 `json:"PolicyDN,omitempty"`
	ObjectName           string                 `json:"ObjectName,omitempty"`
	DestinationAddresses []string               `json:"DestinationAddresses,omitempty"`
	KeyId                string                 `json:"KeyId,omitempty"`
	Principals           []string               `json:"Principals,omitempty"`
	ValidityPeriod       string                 `json:"ValidityPeriod,omitempty"`
	PublicKeyData        string                 `json:"PublicKeyData,omitempty"`
	Extensions           map[string]interface{} `json:"Extensions,omitempty"`
	ForceCommand         string                 `json:"ForceCommand,omitempty"`
	SourceAddresses      []string               `json:"SourceAddresses,omitempty"`
}

type TppSshCertRequestResponse struct {
	DN                string
	Guid              string
	ProcessingDetails ProcessingDetails
	Response          TppSshCertResponseInfo `json:"Response,omitempty"`
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

type TppSshCertRetrieveResponse struct {
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

type SshCertRetrieveDetails struct {
	Guid               string
	DN                 string
	CAGuid             string
	CADN               string
	CertificateData    string
	PrivateKeyData     string
	PublicKeyData      string
	CertificateDetails SshCertificateDetails
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

type CertificateInfo struct {
	ID   string
	CN   string
	SANS struct {
		DNS, Email, IP, URI, UPN []string
	}
	Serial     string
	Thumbprint string
	ValidFrom  time.Time
	ValidTo    time.Time
}

// SetCSR sets CSR from PEM or DER format
func (request *Request) SetCSR(csr []byte) error {
	pemBlock, _ := pem.Decode(csr)
	if pemBlock != nil {
		if strings.HasSuffix(pemBlock.Type, "CERTIFICATE REQUEST") {
			request.csr = csr
			return nil
		}
	}

	//Determine CSR type and use appropriate function
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return err
	}
	if parsedCSR != nil {
		request.csr = pem.EncodeToMemory(GetCertificateRequestPEMBlock(csr))
		return nil
	}
	return fmt.Errorf("%w: can't determine CSR type for %s", verror.UserDataError, csr)
}

// GetCSR returns CSR in PEM format
func (request Request) GetCSR() []byte {
	return request.csr
}

// GenerateRequest generates a certificate request
// Please use method Request.GenerateCSR()
// TODO: Remove usage from all libraries, deprecated
func GenerateRequest(request *Request, privateKey crypto.Signer) error {
	pk := request.PrivateKey
	request.PrivateKey = privateKey
	err := request.GenerateCSR()
	request.PrivateKey = pk
	return err
}

// GenerateCSR creates CSR for sending to server based on data from Request fields. It rewrites CSR field if it`s already filled.
func (request *Request) GenerateCSR() error {
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject = request.Subject
	if !request.OmitSANs {
		certificateRequest.DNSNames = request.DNSNames
		certificateRequest.EmailAddresses = request.EmailAddresses
		certificateRequest.IPAddresses = request.IPAddresses
		certificateRequest.URIs = request.URIs

		if len(request.UPNs) > 0 {
			addUserPrincipalNameSANs(&certificateRequest, request.UPNs)
		}
	}
	certificateRequest.Attributes = request.Attributes

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, request.PrivateKey)
	if err != nil {
		csr = nil
	}
	err = request.SetCSR(csr)
	//request.CSR = pem.EncodeToMemory(GetCertificateRequestPEMBlock(csr))
	return err
}

// GeneratePrivateKey creates private key (if it doesn`t already exist) based on request.KeyType, request.KeyLength and request.KeyCurve fileds
func (request *Request) GeneratePrivateKey() error {
	if request.PrivateKey != nil {
		return nil
	}
	var err error
	switch request.KeyType {
	case KeyTypeECDSA:
		request.PrivateKey, err = GenerateECDSAPrivateKey(request.KeyCurve)
	case KeyTypeRSA:
		if request.KeyLength == 0 {
			request.KeyLength = defaultRSAlength
		}
		if request.KeyLength < AllSupportedKeySizes()[0] {
			return fmt.Errorf("key Size must be %d or greater. But it is %d", AllSupportedKeySizes()[0], request.KeyLength)
		}
		request.PrivateKey, err = GenerateRSAPrivateKey(request.KeyLength)
	default:
		return fmt.Errorf("%w: unable to generate certificate request, key type %s is not supported", verror.VcertError, request.KeyType.String())
	}
	return err
}

// CheckCertificate validate that certificate returned by server matches data in request object. It can be used for control server.
func (request *Request) CheckCertificate(certPEM string) error {
	pemBlock, _ := pem.Decode([]byte(certPEM))
	if pemBlock == nil {
		return fmt.Errorf("%w: invalid pem format certificate %s", verror.CertificateCheckError, certPEM)
	}
	if pemBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("%w: invalid pem type %s (expect CERTIFICATE)", verror.CertificateCheckError, pemBlock.Type)
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if request.PrivateKey != nil {
		if request.KeyType.X509Type() != cert.PublicKeyAlgorithm {
			return fmt.Errorf("%w: unmatched key type: %s, %s", verror.CertificateCheckError, request.KeyType.X509Type(), cert.PublicKeyAlgorithm)
		}
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			certPubKey := cert.PublicKey.(*rsa.PublicKey)
			reqPubkey, ok := request.PrivateKey.Public().(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: request KeyType not matched with real PrivateKey type", verror.CertificateCheckError)
			}

			if certPubKey.N.Cmp(reqPubkey.N) != 0 {
				return fmt.Errorf("%w: unmatched key modulus", verror.CertificateCheckError)
			}
		case x509.ECDSA:
			certPubkey := cert.PublicKey.(*ecdsa.PublicKey)
			reqPubkey, ok := request.PrivateKey.Public().(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: request KeyType not matched with real PrivateKey type", verror.CertificateCheckError)
			}
			if certPubkey.X.Cmp(reqPubkey.X) != 0 {
				return fmt.Errorf("%w: unmatched X for elliptic keys", verror.CertificateCheckError)
			}
		default:
			return fmt.Errorf("%w: unknown key algorythm %d", verror.CertificateCheckError, cert.PublicKeyAlgorithm)
		}
	} else if len(request.csr) != 0 {
		pemBlock, _ := pem.Decode(request.csr)
		if pemBlock == nil {
			return fmt.Errorf("%w: bad CSR: %s", verror.CertificateCheckError, string(request.csr))
		}
		csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			return err
		}
		if cert.PublicKeyAlgorithm != csr.PublicKeyAlgorithm {
			return fmt.Errorf("%w: unmatched key type: %s, %s", verror.CertificateCheckError, cert.PublicKeyAlgorithm, csr.PublicKeyAlgorithm)
		}
		switch csr.PublicKeyAlgorithm {
		case x509.RSA:
			certPubKey := cert.PublicKey.(*rsa.PublicKey)
			reqPubKey := csr.PublicKey.(*rsa.PublicKey)
			if certPubKey.N.Cmp(reqPubKey.N) != 0 {
				return fmt.Errorf("%w: unmatched key modulus", verror.CertificateCheckError)
			}
		case x509.ECDSA:
			certPubKey := cert.PublicKey.(*ecdsa.PublicKey)
			reqPubKey := csr.PublicKey.(*ecdsa.PublicKey)
			if certPubKey.X.Cmp(reqPubKey.X) != 0 {
				return fmt.Errorf("%w: unmatched X for elliptic keys", verror.CertificateCheckError)
			}
		}
	}
	return nil
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
func GetPrivateKeyPEMBock(key crypto.Signer) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, fmt.Errorf("%w: unable to format Key", verror.VcertError)
	}
}

// GetEncryptedPrivateKeyPEMBock gets the private key as an encrypted PEM data block
func GetEncryptedPrivateKeyPEMBock(key crypto.Signer, password []byte) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k), password, x509.PEMCipherAES256)
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", b, password, x509.PEMCipherAES256)
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
func GenerateECDSAPrivateKey(curve EllipticCurve) (*ecdsa.PrivateKey, error) {
	var priv *ecdsa.PrivateKey
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
	}

	priv, err = ecdsa.GenerateKey(c, rand.Reader)
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
		req.KeyLength = pub.Curve.Params().BitSize
		// TODO: req.KeyCurve = pub.Curve.Params().Name ...
	default: // case *dsa.PublicKey
		// vcert only works with RSA & ECDSA
	}
	return req
}
