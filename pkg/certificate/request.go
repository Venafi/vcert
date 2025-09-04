package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

// Request contains data needed to generate a certificate request
// CSR is a PEM-encoded Certificate Signing Request
type Request struct {
	CADN           string
	Subject        pkix.Name
	DNSNames       []string
	OmitSANs       bool
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
	UPNs           []string
	// Deprecated: Attributes is deprecated from X509.CertificateRequest. See ExtraExtensions
	// instead. Values override any extensions that would otherwise be produced based on the
	// other fields but are overridden by any extensions specified in Attributes.
	Attributes []pkix.AttributeTypeAndValueSET
	// ExtraExtensions may include SAN values and ExtKeyUsage values. If these are
	// specified as part of ExtraExtensions, they will override the other specified values.
	ExtraExtensions    []pkix.Extension
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
	Thumbprint string
	// Timeout usage:
	// TPP (a.k.a TLSPDC): we use it in order to set WorkToDoTimeout, that overrides TPP default timeout waiting time for the CA to finish
	// if the value is more than the maximum value, TPP will automatically set the maximum value supported (as of the moment of this
	// commit, 120 seconds).
	// Cloud (a.k.a VaaS a.k.a TLSPC) : We use this timeout in our RetrieveCertificate function which handles a retry logic
	// TPP SSH feature: We override the http client default timeout to perform http requests.
	// Firefly: not usage at all
	//
	// Note:
	// In VCert CLI we have hardcoded 180 seconds for retrieve certificate operation. For VaaS it will set retry logic for
	// 180 seconds and TPP will override CA timeout as the hardcoded value
	Timeout          time.Duration
	CustomFields     []CustomField
	Location         *Location
	ValidityDuration *time.Duration
	ValidityPeriod   string //represents the validity of the certificate expressed as an ISO 8601 duration
	IssuerHint       util.IssuerHint

	// Contacts allows you to configure email addresses to send notifications
	// about the certificate. This field is TPP-specific.
	//
	// Note: the user who receives the notification isn't automatically given
	// access to that certificate. Access is configured at the policy folder
	// level; if the user doesn't permissions on that folder, they will not be
	// able to see the certificate's status in TPP or remediate the problem
	// through the TPP UI.
	//
	// When an email is used by multiple TPP identities, the first identity
	// found is picked arbitrarily.
	//
	// The scope `configuration` is required. Since Contacts works by searching
	// the emails in the same LDAP or AD as the user attached to the token, you
	// must check that you are using a user in that same identity provider.
	// Contacts doesn't work with the local TPP identities. Using Contacts
	// requires adding `mail` to the list of fields searched when performing a
	// user search, which can be configured in the Venafi Configuration Console
	// by RDP'ing into the TPP VM. This configuration cannot be performed
	// directly in the TPP UI.
	Contacts []string

	// Allow user to specify whether to include
	ExtKeyUsages ExtKeyUsageSlice

	// Deprecated: use ValidityDuration instead, this field is ignored if ValidityDuration is set
	ValidityHours int

	//To support VCP certificate tags
	Tags []string
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
func (request *Request) GetCSR() []byte {
	return request.csr
}

// GenerateCSR creates CSR for sending to server based on data from Request fields. It rewrites CSR field if it`s already filled.
func (request *Request) GenerateCSR() error {
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject = request.Subject

	if !request.OmitSANs {
		addSubjectAltNames(&certificateRequest, request.DNSNames, request.EmailAddresses, request.IPAddresses, request.URIs, request.UPNs)
	}

	if request.ExtKeyUsages != nil {
		err := addExtKeyUsage(&certificateRequest, request.ExtKeyUsages)
		if err != nil {
			return fmt.Errorf("%w: %s %w", verror.VcertError, "failed to add requested EKUs", err)
		}
	}

	// If ExtraExtensions are included in request, they may override the SANs and ExtKeyUsages
	//  that were included. This is by design, so that developers using the SDK are able to
	//  craft specific and strange CSRs if required by their use-case, and they won't be clobbered
	//  by other settings.
	if request.ExtraExtensions != nil {
		certificateRequest.ExtraExtensions = request.ExtraExtensions
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
	case KeyTypeED25519:
		request.PrivateKey, err = GenerateED25519PrivateKey()
	case KeyTypeRSA:
		if request.KeyLength == 0 {
			request.KeyLength = DefaultRSAlength
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
		case x509.Ed25519:
			certPubkey := cert.PublicKey.(ed25519.PublicKey)
			reqPubkey, ok := request.PrivateKey.Public().(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("%w: request KeyType not matched with real PrivateKey type", verror.CertificateCheckError)
			}
			if !certPubkey.Equal(reqPubkey) {
				return fmt.Errorf("%w: unmatched elliptic ed25519 keys", verror.CertificateCheckError)
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
