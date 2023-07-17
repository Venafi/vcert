package certrequest

// Request Contains data needed to generate a certificate request
// CSR is a PEM-encoded Certificate Signing Request
type Request struct {
	CADN            string          `yaml:"cadn,omitempty"`
	ChainOption     ChainOption     `yaml:"chainOption,omitempty"`
	CsrOrigin       CsrOriginOption `yaml:"csrOrigin,omitempty"`
	CustomFields    CustomFields    `yaml:"customFields,omitempty"`
	DNSNames        []string        `yaml:"dnsNames,omitempty"`
	EmailAddresses  []string        `yaml:"emails,omitempty"`
	FetchPrivateKey bool            `yaml:"fetchPrivateKey,omitempty"`
	FriendlyName    string          `yaml:"friendlyName,omitempty"`
	IPAddresses     []string        `yaml:"ips,omitempty"`
	IssuerHint      string          `yaml:"issuerHint,omitempty"`
	KeyCurve        EllipticCurve   `yaml:"keyCurve,omitempty"`
	KeyLength       int             `yaml:"keyLength,omitempty"`
	KeyPassword     string          `yaml:"keyPassword,omitempty"`
	KeyType         KeyType         `yaml:"keyType,omitempty"`
	Location        Location        `yaml:"location,omitempty"`
	OmitSANs        bool            `yaml:"omitSans,omitempty"`
	Origin          string          `yaml:"origin,omitempty"`
	Subject         Subject         `yaml:"subject,omitempty"`
	UPNs            []string        `yaml:"upns,omitempty"`
	URIs            []string        `yaml:"uris,omitempty"`
	ValidDays       string          `yaml:"validDays,omitempty"`
	Zone            string          `yaml:"zone,omitempty"`
}
