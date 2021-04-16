package policy

type PolicySpecification struct {
	Owners     []string `json:"owners,omitempty" yaml:"owners,omitempty"`
	Users      []string `json:"users,omitempty" yaml:"users,omitempty"`
	UserAccess string   `json:"userAccess,omitempty" yaml:"userAccess,omitempty"`
	Approvers  []string `json:"approvers,omitempty" yaml:"approvers,omitempty"`
	Policy     *Policy  `json:"policy,omitempty" yaml:"policy,omitempty"`
	Default    *Default `json:"defaults,omitempty" yaml:"defaults,omitempty"`
}

type Policy struct {
	Domains              []string         `json:"domains,omitempty" yaml:"domains,omitempty"`
	WildcardAllowed      *bool            `json:"wildcardAllowed,omitempty" yaml:"wildcardAllowed,omitempty"`
	AutoInstalled        *bool            `json:"autoInstalled,omitempty" yaml:"autoInstalled,omitempty"`
	MaxValidDays         *int             `json:"maxValidDays,omitempty" yaml:"maxValidDays,omitempty"`
	CertificateAuthority *string          `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
	Subject              *Subject         `json:"subject,omitempty" yaml:"subject,omitempty"`
	KeyPair              *KeyPair         `json:"keyPair,omitempty" yaml:"keyPair,omitempty"`
	SubjectAltNames      *SubjectAltNames `json:"subjectAltNames,omitempty" yaml:"subjectAltNames,omitempty"`
}

type Subject struct {
	Orgs       []string `json:"orgs,omitempty" yaml:"orgs,omitempty"`
	OrgUnits   []string `json:"orgUnits,omitempty" yaml:"orgUnits,omitempty"`
	Localities []string `json:"localities,omitempty" yaml:"localities,omitempty"`
	States     []string `json:"states,omitempty" yaml:"states,omitempty"`
	Countries  []string `json:"countries,omitempty" yaml:"countries,omitempty"`
}

type KeyPair struct {
	KeyTypes         []string `json:"keyTypes,omitempty" yaml:"keyTypes,omitempty"`
	RsaKeySizes      []int    `json:"rsaKeySizes,omitempty" yaml:"rsaKeySizes,omitempty"`
	EllipticCurves   []string `json:"ellipticCurves,omitempty" yaml:"ellipticCurves,omitempty"`
	ServiceGenerated *bool    `json:"serviceGenerated,omitempty" yaml:"generationType,omitempty"`
	ReuseAllowed     *bool    `json:"reuseAllowed,omitempty" yaml:"reuseAllowed,omitempty"`
}

type SubjectAltNames struct {
	DnsAllowed   *bool `json:"dnsAllowed,omitempty" yaml:"dnsAllowed,omitempty"`
	IpAllowed    *bool `json:"ipAllowed,omitempty" yaml:"ipAllowed,omitempty"`
	EmailAllowed *bool `json:"emailAllowed,omitempty" yaml:"emailAllowed,omitempty"`
	UriAllowed   *bool `json:"uriAllowed,omitempty" yaml:"uriAllowed,omitempty"`
	UpnAllowed   *bool `json:"upnAllowed,omitempty" yaml:"upnAllowed,omitempty"`
}

type Default struct {
	Domain        *string         `json:"domain,omitempty" yaml:"domain,omitempty"`
	Subject       *DefaultSubject `json:"subject,omitempty" yaml:"subject,omitempty"`
	KeyPair       *DefaultKeyPair `json:"keyPair,omitempty" yaml:"keyPair,omitempty"`
	AutoInstalled *bool           `json:"autoInstalled,omitempty" yaml:"autoInstalled,omitempty"`
}

type DefaultSubject struct {
	Org      *string  `json:"org,omitempty" yaml:"org,omitempty"`
	OrgUnits []string `json:"orgUnits,omitempty" yaml:"orgUnits,omitempty"`
	Locality *string  `json:"locality,omitempty" yaml:"locality,omitempty"`
	State    *string  `json:"state,omitempty" yaml:"state,omitempty"`
	Country  *string  `json:"country,omitempty" yaml:"country,omitempty"`
}

type DefaultKeyPair struct {
	KeyType          *string `json:"keyType,omitempty" yaml:"keyType,omitempty"`
	RsaKeySize       *int    `json:"rsaKeySize,omitempty" yaml:"rsaKeySize,omitempty"`
	EllipticCurve    *string `json:"ellipticCurve,omitempty" yaml:"ellipticCurve,omitempty"`
	ServiceGenerated *bool   `json:"serviceGenerated,omitempty" yaml:"serviceGenerated,omitempty"`
}
