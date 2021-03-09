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

type PolicyExistPaloadRequest struct {
	ObjectDN string `json:"ObjectDN"`
}

type PolicyIsValidResponse struct {
	Error  string `json:"Error"`
	Result int    `json:"Result"`
}

type PolicyGetAttributeResponse struct {
	Locked bool     `json:"Locked"`
	Result int      `json:"Result"`
	Values []string `json:"Values"`
}

type CloudPolicyRequest struct {
	Name                                string              `json:"name"`
	CertificateAuthority                string              `json:"certificateAuthority"`
	CertificateAuthorityProductOptionId string              `json:"certificateAuthorityProductOptionId"`
	Product                             Product             `json:"product"`
	TrackingData                        *string              `json:"trackingData"`
	SubjectCNRegexes                    []string            `json:"subjectCNRegexes"`
	SubjectORegexes                     []string            `json:"subjectORegexes"`
	SubjectOURegexes                    []string            `json:"subjectOURegexes"`
	SubjectLRegexes                     []string            `json:"subjectLRegexes"`
	SubjectSTRegexes                    []string            `json:"subjectSTRegexes"`
	SubjectCValues                      []string            `json:"subjectCValues"`
	SanRegexes                          []string            `json:"sanRegexes"`
	KeyTypes                            []KeyTypes            `json:"keyTypes"`
	KeyReuse                            *bool                `json:"keyReuse"`
	RecommendedSettings                 *RecommendedSettings `json:"recommendedSettings"`
}

type Product struct {
	CertificateAuthority string `json:"certificateAuthority"`
	ProductName          string `json:"productName"`
	ValidityPeriod       string `json:"validityPeriod"`
}

type KeyTypes struct {
	KeyType    string `json:"keyType"`
	KeyLengths []int  `json:"keyLengths"`
}

type RecommendedSettings struct {
	SubjectCNRegexes []string `json:"subjectCNRegexes"`
	SubjectOValue    string   `json:"subjectOValue"`
	SubjectOUValue   string   `json:"subjectOUValue"`
	SubjectLValue    string   `json:"subjectLValue"`
	SubjectSTValue   string   `json:"subjectSTValue"`
	SubjectCValue    string   `json:"subjectCValue"`
	SanRegexes       []string `json:"sanRegexes"`
	key              Key      `json:"key"`
	keyReuse         *bool   `json:"keyReuse"`
}

type Key struct {
	Type   string `json:"type"`
	Length int    `json:"length"`
}

type ApplicationCreateRequest struct{

	OwnerIdsAndTypes []OwnerIdType `json:"ownerIdsAndTypes"`
	Name string `json:"name"`
	Description string `json:"description"`
	Fqdns []string `json:"fqdns"`
	InternalFqdns []string `json:"internalFqdns"`
	InternalIpRanges []string `json:"internalIpRanges"`
	ExternalIpRanges []string `json:"externalIpRanges"`
	InternalPorts []string `json:"internalPorts"`
	FullyQualifiedDomainNames []string `json:"fullyQualifiedDomainNames"`
	IpRanges []string `json:"ipRanges"`
	Ports []string `json:"ports"`
	CertificateIssuingTemplateAliasIdMap map[string]string `json:"certificateIssuingTemplateAliasIdMap"`
	StartTargetedDiscovery bool `json:"startTargetedDiscovery"`
	OrganizationalUnitId string  `json:"organizationalUnitId"`

}

type OwnerIdType struct {

	OwnerId string  `json:"ownerId"`
	OwnerType string  `json:"ownerType"`

}