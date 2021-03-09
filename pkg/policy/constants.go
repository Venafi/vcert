package policy

const (
	JsonExtention        = ".json"
	YamlExtention        = ".yaml"
	RootPath             = "\\VED\\Policy\\"
	PolicyClass          = "Policy"
	PolicyAttributeClass = "X509 Certificate"
	//tpp attributes
	TppContact               = "Contact"
	TppApprover              = "Approver"
	TppCertificateAuthority  = "Certificate Authority"
	TppPRProhibitWildcard    = "Prohibit Wildcard"
	TppDomainSuffixWhitelist = "Domain Suffix Whitelist"
	TppOrganization          = "Organization"
	TppOrganizationalUnit    = "Organizational Unit"
	TppCity                  = "City"
	TppState                 = "State"
	TppCountry               = "Country"
	TppKeyAlgorithm          = "Key Algorithm"
	TppKeyBitStrength        = "Key Bit Strength"
	TppEllipticCurve         = "Elliptic Curve"
	TppManualCsr             = "Manual Csr"
	TppProhibitedSANTypes    = "Prohibited SAN Types"
	TppAllowPrivateKeyReuse  = "Allow Private Key Reuse"
	TppWantRenewal           = "Want Renewal"
	TppDnsAllowed            = "DNS"
	TppIpAllowd              = "IP"
	TppEmailAllowed          = "Email"
	TppUriAllowd             = "URI"
	TppUpnAllowed            = "UPN"
)

