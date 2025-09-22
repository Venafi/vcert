package policy

import "github.com/Venafi/vcert/v5/pkg/util"

const (
	JsonExtension        = ".json"
	YamlExtension        = ".yaml"
	RootPath             = util.PathSeparator + "VED" + util.PathSeparator + "Policy"
	PolicyClass          = "Policy"
	PolicyAttributeClass = "X509 Certificate"

	//CyberArk Certificate Manager, Self-Hosted policy attributes
	TppContact                       = "Contact"
	TppApprover                      = "Approver"
	TppCertificateAuthority          = "Certificate Authority"
	TppProhibitWildcard              = "Prohibit Wildcard"
	TppDomainSuffixWhitelist         = "Domain Suffix Whitelist"
	TppOrganization                  = "Organization"
	TppOrganizationalUnit            = "Organizational Unit"
	TppCity                          = "City"
	TppState                         = "State"
	TppCountry                       = "Country"
	TppPkixParameterSetPolicy        = "PKIX Parameter Set Policy"
	TppPkixParameterSetPolicyDefault = "PKIX Parameter Set Policy Default"
	TppKeyAlgorithm                  = "Key Algorithm"
	TppKeyBitStrength                = "Key Bit Strength"
	TppEllipticCurve                 = "Elliptic Curve"
	ServiceGenerated                 = "Manual Csr"
	TppProhibitedSANTypes            = "Prohibited SAN Types"
	TppAllowPrivateKeyReuse          = "Allow Private Key Reuse"
	TppWantRenewal                   = "Want Renewal"
	TppDnsAllowed                    = "DNS"
	TppIpAllowed                     = "IP"
	TppEmailAllowed                  = "Email"
	TppUriAllowed                    = "URI"
	TppUpnAllowed                    = "UPN"
	AllowAll                         = ".*"
	UserProvided                     = "UserProvided"
	DefaultCA                        = "BUILTIN\\Built-In CA\\Default Product"
	TppManagementType                = "Management Type"
	TppManagementTypeEnrollment      = "Enrollment"
	TppManagementTypeProvisioning    = "Provisioning"
	CloudEntrustCA                   = "ENTRUST"
	CloudDigicertCA                  = "DIGICERT"
	CloudRequesterName               = "Venafi Cloud Service"
	CloudRequesterEmail              = "no-reply@venafi.cloud"
	CloudRequesterPhone              = "801-555-0123"
	ipv4                             = "\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}\\b"
	ipv6                             = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
	v4private                        = "^(172\\.(1[6-9]\\.|2[0-9]\\.|3[0-1]\\.)|192\\.168\\.|10\\.).*"
	v6private                        = "^(::1$)|([fF][cCdD]).*"

	IdentityUser              = 1
	IdentitySecurityGroup     = 2
	IdentityDistributionGroup = 8
	AllIdentities             = IdentityUser + IdentitySecurityGroup + IdentityDistributionGroup
)
