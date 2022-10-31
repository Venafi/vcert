package policy

type PolicyPayloadRequest struct {
	Class    string `json:"Class"`
	ObjectDN string `json:"ObjectDN"`
}

type PolicySetAttributePayloadRequest struct {
	Locked        bool     `json:"Locked"`
	ObjectDN      string   `json:"ObjectDN"`
	Class         string   `json:"Class"`
	AttributeName string   `json:"AttributeName"`
	Values        []string `json:"Values"`
}

type PolicySetAttributeResponse struct {
	Error  string `json:"Error"`
	Result int    `json:"Result"`
}

type PolicyGetAttributePayloadRequest struct {
	ObjectDN      string   `json:"ObjectDN"`
	Class         string   `json:"Class"`
	AttributeName string   `json:"AttributeName"`
	Values        []string `json:"Values"`
}

type PolicyExistPayloadRequest struct {
	ObjectDN string `json:"ObjectDN"`
}

type PolicyIsValidResponse struct {
	Error        string       `json:"Error"`
	Result       int          `json:"Result"`
	PolicyObject PolicyObject `json:"Object"`
}

type PolicyGetAttributeResponse struct {
	Locked bool     `json:"Locked"`
	Result int      `json:"Result"`
	Values []string `json:"Values"`
}

type TppPolicy struct {
	//general values
	Name *string
	//Owners []string "owners": string[],(permissions only)	prefixed name/universal
	Contact []string
	//Permissions string "userAccess": string,	(permissions)	prefixed name/universal
	Approver []string

	//policy's values
	ProhibitWildcard      *int
	DomainSuffixWhitelist []string
	ProhibitedSANType     []string
	CertificateAuthority  *string
	ManagementType        *LockedAttribute

	//subject attributes
	Organization       *LockedAttribute
	OrganizationalUnit *LockedArrayAttribute
	City               *LockedAttribute
	State              *LockedAttribute
	Country            *LockedAttribute

	//keypair attributes
	KeyAlgorithm         *LockedAttribute
	KeyBitStrength       *LockedAttribute
	EllipticCurve        *LockedAttribute
	ManualCsr            *LockedAttribute
	AllowPrivateKeyReuse *int
	WantRenewal          *int
}

type BrowseIdentitiesRequest struct {
	Filter       string
	Limit        int
	IdentityType int
}

type BrowseIdentitiesResponse struct {
	Identities []IdentityEntry
}

type IdentitySelfResponse struct {
	Identities []IdentityEntry
}

type ValidateIdentityRequest struct {
	ID IdentityInformation
}

type ValidateIdentityResponse struct {
	ID IdentityEntry
}

type IdentityInformation struct {
	PrefixedUniversal string
}

type IdentityEntry struct {
	FullName          string
	Name              string
	Prefix            string
	PrefixedName      string
	PrefixedUniversal string
	Type              int
	Universal         string
}

type LockedAttribute struct {
	Value  string
	Locked bool
}
type LockedIntAttribute struct {
	Value  int
	Locked bool
}
type LockedArrayAttribute struct {
	Value  []string `json:"Values"`
	Locked bool
}

type CertificateAuthorityInfo struct {
	CAType            string
	CAAccountKey      string
	VendorProductName string
}

type PolicyObject struct {
	AbsoluteGUID string `json:"AbsoluteGUID"`
	DN           string `json:"DN"`
	GUID         string `json:"GUID"`
	Id           int    `json:"Id"`
	Name         string `json:"Name"`
	Parent       string `json:"Parent"`
	Revision     int    `json:"Revision"`
	TypeName     string `json:"TypeName"`
}

type CheckPolicyResponse struct {
	Error  string          `json:"Error"`
	Policy *PolicyResponse `json:"Policy"`
}

type PolicyResponse struct {
	CertificateAuthority    LockedAttribute `json:"CertificateAuthority"`
	CsrGeneration           LockedAttribute `json:"CsrGeneration"`
	KeyGeneration           LockedAttribute `json:"KeyGeneration"`
	KeyPairResponse         KeyPairResponse `json:"KeyPair"`
	ManagementType          LockedAttribute `json:"ManagementType"`
	PrivateKeyReuseAllowed  bool            `json:"PrivateKeyReuseAllowed"`
	SubjAltNameDnsAllowed   bool            `json:"SubjAltNameDnsAllowed"`
	SubjAltNameEmailAllowed bool            `json:"SubjAltNameEmailAllowed"`
	SubjAltNameIpAllowed    bool            `json:"SubjAltNameIpAllowed"`
	SubjAltNameUpnAllowed   bool            `json:"SubjAltNameUpnAllowed"`
	SubjAltNameUriAllowed   bool            `json:"SubjAltNameUriAllowed"`
	Subject                 SubjectResponse `json:"Subject"`
	UniqueSubjectEnforced   bool            `json:"UniqueSubjectEnforced"`
	WhitelistedDomains      []string        `json:"WhitelistedDomains"`
	WildcardsAllowed        bool            `json:"WildcardsAllowed"`
}

type KeyPairResponse struct {
	KeyAlgorithm LockedAttribute    `json:"KeyAlgorithm"`
	KeySize      LockedIntAttribute `json:"KeySize"`
}

type SubjectResponse struct {
	City               LockedAttribute      `json:"City"`
	Country            LockedAttribute      `json:"Country"`
	Organization       LockedAttribute      `json:"Organization"`
	OrganizationalUnit LockedArrayAttribute `json:"OrganizationalUnit"`
	State              LockedAttribute      `json:"State"`
}

type CheckPolicyRequest struct {
	PolicyDN string `json:"PolicyDN"`
}

type ClearTTPAttributesRequest struct {
	ObjectDN      string `json:"ObjectDN"`
	Class         string `json:"Class"`
	AttributeName string `json:"AttributeName"`
}

type CADetails struct {
	CertificateAuthorityProductOptionId *string
	CertificateAuthorityOrganizationId  *int64
}
