package domain

import (
	"github.com/Venafi/vcert/v4/pkg/certificate"
)

// PlaybookRequest Contains data needed to generate a certificate request
// CSR is a PEM-encoded Certificate Signing PlaybookRequest
type PlaybookRequest struct {
	CADN            string                      `yaml:"cadn,omitempty"`
	ChainOption     certificate.ChainOption     `yaml:"chainOption,omitempty"`
	CsrOrigin       certificate.CSrOriginOption `yaml:"csrOrigin,omitempty"`
	CustomFields    []certificate.CustomField   `yaml:"customFields,omitempty"`
	DNSNames        []string                    `yaml:"dnsNames,omitempty"`
	EmailAddresses  []string                    `yaml:"emails,omitempty"`
	FetchPrivateKey bool                        `yaml:"fetchPrivateKey,omitempty"`
	FriendlyName    string                      `yaml:"friendlyName,omitempty"`
	IPAddresses     []string                    `yaml:"ips,omitempty"`
	IssuerHint      string                      `yaml:"issuerHint,omitempty"`
	KeyCurve        certificate.EllipticCurve   `yaml:"keyCurve,omitempty"`
	KeyLength       int                         `yaml:"keyLength,omitempty"`
	KeyPassword     string                      `yaml:"keyPassword,omitempty"`
	KeyType         certificate.KeyType         `yaml:"keyType,omitempty"`
	Location        certificate.Location        `yaml:"location,omitempty"`
	OmitSANs        bool                        `yaml:"omitSans,omitempty"`

	Origin string `yaml:"origin,omitempty"`

	Subject Subject  `yaml:"subject,omitempty"`
	Timeout int      `yaml:"timeout"`
	UPNs    []string `yaml:"upns,omitempty"`
	URIs    []string `yaml:"uris,omitempty"`

	ValidDays string `yaml:"validDays,omitempty"`
	Zone      string `yaml:"zone,omitempty"`
}
