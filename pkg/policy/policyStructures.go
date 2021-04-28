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

type CloudPolicyRequest struct {
	Name                                string               `json:"name"`
	CertificateAuthority                string               `json:"certificateAuthority"`
	CertificateAuthorityProductOptionId string               `json:"certificateAuthorityProductOptionId"`
	Product                             Product              `json:"product"`
	TrackingData                        *TrackingData        `json:"trackingData"`
	SubjectCNRegexes                    []string             `json:"subjectCNRegexes"`
	SubjectORegexes                     []string             `json:"subjectORegexes"`
	SubjectOURegexes                    []string             `json:"subjectOURegexes"`
	SubjectLRegexes                     []string             `json:"subjectLRegexes"`
	SubjectSTRegexes                    []string             `json:"subjectSTRegexes"`
	SubjectCValues                      []string             `json:"subjectCValues"`
	SanRegexes                          []string             `json:"sanRegexes"`
	KeyTypes                            []KeyTypes           `json:"keyTypes"`
	KeyReuse                            *bool                `json:"keyReuse"`
	RecommendedSettings                 *RecommendedSettings `json:"recommendedSettings"`
}

type Product struct {
	CertificateAuthority string  `json:"certificateAuthority"`
	ProductName          string  `json:"productName"`
	ValidityPeriod       string  `json:"validityPeriod"`
	HashAlgorithm        *string `json:"hashAlgorithm,omitempty"`
	AutoRenew            *bool   `json:"autoRenew,omitempty"`
	OrganizationId       *int64  `json:"organizationId,omitempty"`
}

type KeyTypes struct {
	KeyType    string `json:"keyType"`
	KeyLengths []int  `json:"keyLengths"`
}

type TrackingData struct {
	CertificateAuthority string `json:"certificateAuthority"`
	RequesterName        string `json:"requesterName"`
	RequesterEmail       string `json:"requesterEmail"`
	RequesterPhone       string `json:"requesterPhone"`
}

type RecommendedSettings struct {
	SubjectCNRegexes []string `json:"subjectCNRegexes"`
	SubjectOValue    *string  `json:"subjectOValue"`
	SubjectOUValue   *string  `json:"subjectOUValue"`
	SubjectLValue    *string  `json:"subjectLValue"`
	SubjectSTValue   *string  `json:"subjectSTValue"`
	SubjectCValue    *string  `json:"subjectCValue"`
	SanRegexes       []string `json:"sanRegexes"`
	Key              *Key     `json:"key"`
	KeyReuse         *bool    `json:"keyReuse"`
}

type Key struct {
	Type   string `json:"type"`
	Length int    `json:"length"`
}

type ApplicationCreateRequest struct {
	OwnerIdsAndTypes                     []OwnerIdType     `json:"ownerIdsAndTypes"`
	Name                                 string            `json:"name"`
	Description                          string            `json:"description"`
	Fqdns                                []string          `json:"fqdns"`
	InternalFqdns                        []string          `json:"internalFqdns"`
	InternalIpRanges                     []string          `json:"internalIpRanges"`
	ExternalIpRanges                     []string          `json:"externalIpRanges"`
	InternalPorts                        []string          `json:"internalPorts"`
	FullyQualifiedDomainNames            []string          `json:"fullyQualifiedDomainNames"`
	IpRanges                             []string          `json:"ipRanges"`
	Ports                                []string          `json:"ports"`
	CertificateIssuingTemplateAliasIdMap map[string]string `json:"certificateIssuingTemplateAliasIdMap"`
	StartTargetedDiscovery               bool              `json:"startTargetedDiscovery"`
	OrganizationalUnitId                 string            `json:"organizationalUnitId"`
}

type OwnerIdType struct {
	OwnerId   string `json:"ownerId"`
	OwnerType string `json:"ownerType"`
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

type Accounts struct {
	Accounts []AccountDetails
}

type AccountDetails struct {
	Account       Account         `json:"account"`
	ProductOption []ProductOption `json:"productOptions"`
}

type Account struct {
	Id                   string `json:"id"`
	Key                  string `json:"Key"`
	CertificateAuthority string `json:"certificateAuthority"`
}

type ProductOption struct {
	ProductName    string         `json:"productName"`
	Id             string         `json:"id"`
	ProductDetails ProductDetails `json:"productDetails"`
}

type ProductDetails struct {
	ProductTemplate ProductTemplate `json:"productTemplate"`
}

type ProductTemplate struct {
	OrganizationId int64 `json:"organizationId"`
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
