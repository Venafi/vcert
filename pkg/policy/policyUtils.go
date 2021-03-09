package policy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

//there is no way for creating an array as constant, so creating a variable
//this is the nearest to a constant on arrays.
var TppKeyType = []string{"RSA", "ECDSA"}
var TppRsaKeySize = []int{512, 1024, 2048, 3072, 4096}
var CloudRsaKeySize = []int{1024, 2048, 4096}
var TppEllipticCurves = []string{"P256", "P384", "P521"}

func GetFileType(f string) string {
	extension := filepath.Ext(f)

	//As yaml extension could be yaml or yml then convert it to just .yaml
	if extension == ".yml" {
		extension = YamlExtention
	}

	return extension
}

func GetParent(p string) string {
	lastIndex := strings.LastIndex(p, "\\")
	parentPath := p[:lastIndex]
	return parentPath
}

func ValidateTppPolicySpecification(ps *PolicySpecification) error {

	err := validatePolicySubject(ps)
	if err != nil {
		return err
	}

	err = validateKeyPair(ps)
	if err != nil {
		return err
	}

	err = validateDefaultSubject(ps)
	if err != nil {
		return err
	}

	err = validateDefaultKeyPair(ps)
	if err != nil {
		return err
	}

	return nil
}

func validatePolicySubject(ps *PolicySpecification) error {

	subject := ps.Policy.Subject

	if len(subject.Orgs) > 1 {
		return fmt.Errorf("attirbute orgs have more than one value")
	}
	if len(subject.OrgUnits) > 1 {
		return fmt.Errorf("attirbute org units have more than one value")
	}
	if len(subject.Localities) > 1 {
		return fmt.Errorf("attirbute localities have more than one value")
	}
	if len(subject.States) > 1 {
		return fmt.Errorf("attirbute states have more than one value")
	}
	if len(subject.Countries) > 1 {
		return fmt.Errorf("attirbute countries have more than one value")
	}

	return nil
}

func validateKeyPair(ps *PolicySpecification) error {
	keyPair := ps.Policy.KeyPair

	//validate algorithm
	if len(keyPair.KeyTypes) > 1 {
		return fmt.Errorf("attirbute keyTypes have more than one value")
	}
	if !existStringInArray(keyPair.KeyTypes, TppKeyType) {
		return fmt.Errorf("specified keyTypes doesn't match witn the supported ones")
	}

	//validate key bit strength
	if len(keyPair.RsaKeySizes) > 1 {
		return fmt.Errorf("attirbute rsaKeySizes have more than one value")
	}
	if !existIntInArray(keyPair.RsaKeySizes, TppRsaKeySize) {
		return fmt.Errorf("specified rsaKeySizes doesn't match witn the supported ones")
	}

	//validate elliptic curve
	if len(keyPair.EllipticCurves) > 1 {
		return fmt.Errorf("attirbute ellipticCurves have more than one value")
	}
	if !existStringInArray(keyPair.EllipticCurves, TppEllipticCurves) {
		return fmt.Errorf("specified ellipticCurves doesn't match witn the supported ones")
	}

	//validate generationType
	if (keyPair.GenerationType != nil) && (*(keyPair.GenerationType) != "0") && (*(keyPair.GenerationType) != "1") {
		return fmt.Errorf("specified generationType doesn't match witn the supported ones")
	}

	return nil
}

func existStringInArray(userValue []string, supportedvalues []string) bool {
	for _, uv := range userValue {
		for _, sv := range supportedvalues {
			if uv == sv {
				return true
			}
		}
	}
	return false
}

func existIntInArray(userValue []int, supportedvalues []int) bool {
	for _, uv := range userValue {
		for _, sv := range supportedvalues {
			if uv == sv {
				return true
			}
		}
	}
	return false
}

func validateDefaultSubject(ps *PolicySpecification) error {

	defaultSubject := ps.Default.Subject
	policySubject := ps.Policy.Subject

	if policySubject.Orgs != nil && policySubject.Orgs[0] != "" && defaultSubject.Org != nil && *(defaultSubject.Org) != "" {
		if policySubject.Orgs[0] != *(defaultSubject.Org) {
			return fmt.Errorf("policy default org doesn't match with policy's org value")
		}
	}

	if policySubject.OrgUnits != nil && policySubject.OrgUnits[0] != "" && defaultSubject.OrgUnits != nil && defaultSubject.OrgUnits[0] != "" {
		if policySubject.OrgUnits[0] != defaultSubject.OrgUnits[0] {
			return fmt.Errorf("policy default orgUnits doesn't match with policy's orgUnits value")
		}
	}

	if policySubject.Localities != nil && policySubject.Localities[0] != "" && defaultSubject.Locality != nil && *(defaultSubject.Locality) != "" {
		if policySubject.Localities[0] != *(defaultSubject.Locality) {
			return fmt.Errorf("policy default locality doesn't match with policy's locality value")
		}
	}
	if policySubject.States != nil && policySubject.States[0] != "" && defaultSubject.State != nil && *(defaultSubject.State) != "" {
		if policySubject.States[0] != *(defaultSubject.State) {
			return fmt.Errorf("policy default state doesn't match with policy's state value")
		}
	}
	if policySubject.Countries != nil && policySubject.Countries[0] != "" && defaultSubject.Country != nil && *(defaultSubject.Country) != "" {
		if policySubject.Countries[0] != *(defaultSubject.Country) {
			return fmt.Errorf("policy default country doesn't match with policy's country value")
		}
	}

	return nil
}

func validateDefaultKeyPair(ps *PolicySpecification) error {
	defaultKeyPair := ps.Default.KeyPair
	policyKeyPair := ps.Policy.KeyPair

	if policyKeyPair.KeyTypes != nil && policyKeyPair.KeyTypes[0] != "" && defaultKeyPair.KeyType != nil && *(defaultKeyPair.KeyType) != "" {
		if policyKeyPair.KeyTypes[0] != *(defaultKeyPair.KeyType) {
			return fmt.Errorf("policy default keyType doesn't match with policy's keyType value")
		}
	}

	if policyKeyPair.RsaKeySizes != nil && policyKeyPair.RsaKeySizes[0] != 0 && defaultKeyPair.RsaKeySize != nil && *(defaultKeyPair.RsaKeySize) != 0 {
		if policyKeyPair.RsaKeySizes[0] != *(defaultKeyPair.RsaKeySize) {
			return fmt.Errorf("policy default rsaKeySize doesn't match with policy's rsaKeySize value")
		}
	}

	if policyKeyPair.EllipticCurves != nil && policyKeyPair.EllipticCurves[0] != "" && defaultKeyPair.EllipticCurve != nil && *(defaultKeyPair.EllipticCurve) != "" {
		if policyKeyPair.EllipticCurves[0] != *(defaultKeyPair.EllipticCurve) {
			return fmt.Errorf("policy default ellipticCurve doesn't match with policy's ellipticCurve value")
		}
	}

	if policyKeyPair.GenerationType != nil && *(policyKeyPair.GenerationType) != "" && defaultKeyPair.GenerationType != nil && *(defaultKeyPair.GenerationType) != "" {
		if *(policyKeyPair.GenerationType) != *(defaultKeyPair.GenerationType) {
			return fmt.Errorf("policy default generationType doesn't match with policy's generationType value")
		}
	}

	return nil
}

func BuildTppPolicy(ps *PolicySpecification) TppPolicy {
	/*
		"owners": string[],					(permissions only)	prefixed name/universal
		"userAccess": string,					(permissions)	prefixed name/universal
		}
	*/
	var tppPolicy TppPolicy

	tppPolicy.Contact = ps.Users
	tppPolicy.Approver = ps.Approvers

	//policy attributes
	tppPolicy.DomainSuffixWhitelist = ps.Policy.Domains

	if ps.Policy.WildcardAllowed != nil {
		tppPolicy.ProhibitWildcard = ps.Policy.WildcardAllowed
	}

	if ps.Policy.CertificateAuthority != nil {
		tppPolicy.CertificateAuthority = ps.Policy.CertificateAuthority
	}

	//policy subject attributes
	if len(ps.Policy.Subject.Orgs) > 0 {
		tppPolicy.Organization = createLockedAttribute(ps.Policy.Subject.Orgs[0], true)
	} else if *(ps.Default.Subject.Org) != "" {
		tppPolicy.Organization = createLockedAttribute(*(ps.Default.Subject.Org), false)
	}

	if len(ps.Policy.Subject.OrgUnits) > 0 {
		tppPolicy.OrganizationalUnit = createLockedAttribute(ps.Policy.Subject.OrgUnits[0], true)
	} else if len(ps.Default.Subject.OrgUnits) > 0 {
		tppPolicy.OrganizationalUnit = createLockedAttribute(ps.Default.Subject.OrgUnits[0], false)
	}

	if len(ps.Policy.Subject.Localities) > 0 {
		tppPolicy.City = createLockedAttribute(ps.Policy.Subject.Localities[0], true)
	} else if (ps.Default.Subject.Locality != nil) && (*(ps.Default.Subject.Locality) != "") {
		tppPolicy.City = createLockedAttribute(*(ps.Default.Subject.Locality), false)
	}

	if len(ps.Policy.Subject.States) > 0 {
		tppPolicy.State = createLockedAttribute(ps.Policy.Subject.States[0], true)
	} else if (ps.Default.Subject.State != nil) && (*(ps.Default.Subject.State) != "") {
		tppPolicy.State = createLockedAttribute(*(ps.Default.Subject.State), false)
	}

	//"countries": string[]			"Country"	lock single value; error if > 1 two-char string in array
	if len(ps.Policy.Subject.Countries) > 0 {
		tppPolicy.Country = createLockedAttribute(ps.Policy.Subject.Countries[0], true)
	} else if (ps.Default.Subject.Country != nil) && (*(ps.Default.Subject.Country) != "") {
		tppPolicy.Country = createLockedAttribute(*(ps.Default.Subject.Country), false)
	}

	if len(ps.Policy.KeyPair.KeyTypes) > 0 {
		tppPolicy.KeyAlgorithm = createLockedAttribute(ps.Policy.KeyPair.KeyTypes[0], true)
	} else if (ps.Default.KeyPair.KeyType != nil) && (*(ps.Default.KeyPair.KeyType) != "") {
		tppPolicy.KeyAlgorithm = createLockedAttribute(*(ps.Default.KeyPair.KeyType), false)
	}

	if len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
		rsaKey := ps.Policy.KeyPair.RsaKeySizes[0]
		tppPolicy.KeyBitStrength = createLockedAttribute(strconv.Itoa(rsaKey), true)
	} else if (ps.Default.KeyPair.RsaKeySize != nil) && *(ps.Default.KeyPair.RsaKeySize) != 0 {
		tppPolicy.KeyBitStrength = createLockedAttribute(strconv.Itoa(*(ps.Default.KeyPair.RsaKeySize)), true)
	}

	if len(ps.Policy.KeyPair.EllipticCurves) > 0 {
		tppPolicy.EllipticCurve = createLockedAttribute(ps.Policy.KeyPair.EllipticCurves[0], true)
	} else if (ps.Default.KeyPair.EllipticCurve != nil) && (*(ps.Default.KeyPair.EllipticCurve) != "") {
		tppPolicy.EllipticCurve = createLockedAttribute(*(ps.Default.KeyPair.EllipticCurve), false)
	}

	if ps.Policy.KeyPair.GenerationType != nil {
		tppPolicy.ManualCsr = createLockedAttribute(*(ps.Policy.KeyPair.GenerationType), true)
	} else if (ps.Default.KeyPair.GenerationType != nil) && (*(ps.Default.KeyPair.GenerationType) != "") {
		tppPolicy.ManualCsr = createLockedAttribute(*(ps.Default.KeyPair.GenerationType), false)
	}

	if ps.Policy.KeyPair.ReuseAllowed != nil {
		tppPolicy.AllowPrivateKeyReuse = ps.Policy.KeyPair.ReuseAllowed
		tppPolicy.WantRenewal = ps.Policy.KeyPair.ReuseAllowed
	}

	prohibitedSANType := getProhibitedSanTypes(ps.Policy.SubjectAltNames)
	if prohibitedSANType != nil {
		tppPolicy.ProhibitedSANType = prohibitedSANType
	}

	return tppPolicy
}

func createLockedAttribute(value string, locked bool) *LockedAttribute {
	lockecdAtr := LockedAttribute{
		Value:  value,
		Locked: locked,
	}
	return &lockecdAtr
}

func getProhibitedSanTypes(sa SubjectAltNames) []string {

	var prohibitedSanTypes []string

	if (sa.DnsAllowed != nil) && !*(sa.DnsAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "DNS")
	}
	if (sa.IpAllowed != nil) && !*(sa.IpAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "IP")
	}

	if (sa.EmailAllowed != nil) && !*(sa.EmailAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "Email")
	}

	if (sa.UriAllowed != nil) && !*(sa.UriAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "URI")
	}

	if (sa.UpnAllowed != nil) && !*(sa.UpnAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "UPN")
	}

	if len(prohibitedSanTypes) == 0 {
		return nil
	}

	return prohibitedSanTypes
}

func BuildPolicySpecification(tp TppPolicy) (*PolicySpecification, error) {

	var ps PolicySpecification

	ps.Users = tp.Contact
	ps.Approvers = tp.Approver

	var p Policy

	p.Domains = tp.DomainSuffixWhitelist
	p.WildcardAllowed = tp.ProhibitWildcard
	p.CertificateAuthority = tp.CertificateAuthority

	var subject Subject
	var defaultSubject DefaultSubject

	var keyPair KeyPair
	var defaultKeyPair DefaultKeyPair

	//resolve subject's attributes

	//resolve org
	if tp.Organization != nil {
		if tp.Organization.Locked {
			subject.Orgs = []string{tp.Organization.Value}
		} else {
			defaultSubject.Org = &tp.Organization.Value
		}
	}

	//resolve orgUnit
	if tp.OrganizationalUnit != nil {
		if tp.OrganizationalUnit.Locked {
			subject.OrgUnits = []string{tp.OrganizationalUnit.Value}
		} else {
			defaultSubject.OrgUnits = []string{tp.OrganizationalUnit.Value}
		}
	}

	//resolve localities
	if tp.City != nil {
		if tp.City.Locked {
			subject.Localities = []string{tp.City.Value}
		} else {
			defaultSubject.Locality = &tp.City.Value
		}
	}

	//resolve states
	if tp.State != nil {
		if tp.State.Locked {
			subject.States = []string{tp.State.Value}
		} else {
			defaultSubject.State = &tp.State.Value
		}
	}

	//resolve countries
	if tp.Country != nil {
		if tp.Country.Locked {
			subject.Countries = []string{tp.Country.Value}
		} else {
			defaultSubject.Country = &tp.Country.Value
		}
	}

	//resolve key pair's attributes

	//resolve keyTypes
	if tp.KeyAlgorithm != nil {
		if tp.KeyAlgorithm.Locked {
			keyPair.KeyTypes = []string{tp.KeyAlgorithm.Value}
		} else {
			defaultKeyPair.KeyType = &tp.KeyAlgorithm.Value
		}
	}

	//resolve rsaKeySizes
	if tp.KeyBitStrength != nil {
		value := tp.KeyBitStrength.Value
		intVal, err := strconv.Atoi(value)

		if err != nil {
			return nil, err
		}

		if tp.KeyAlgorithm.Locked {
			keyPair.RsaKeySizes = []int{intVal}
		} else {
			defaultKeyPair.RsaKeySize = &intVal
		}
	}

	//resolve ellipticCurves
	if tp.EllipticCurve != nil {
		if tp.EllipticCurve.Locked {
			keyPair.EllipticCurves = []string{tp.EllipticCurve.Value}
		} else {
			defaultKeyPair.EllipticCurve = &tp.EllipticCurve.Value
		}
	}

	//resolve generationType
	if tp.ManualCsr != nil {
		if tp.ManualCsr.Locked {
			keyPair.GenerationType = &tp.ManualCsr.Value
		} else {
			defaultKeyPair.GenerationType = &tp.ManualCsr.Value
		}
	}

	//resolve reuseAllowed, as on tpp this value represents: Allow Private Key Reuse Want Renewal
	//so if one of these two values is set then apply the value to  ReuseAllowed
	if tp.AllowPrivateKeyReuse != nil {
		keyPair.ReuseAllowed = tp.AllowPrivateKeyReuse
	} else if tp.WantRenewal != nil {
		keyPair.ReuseAllowed = tp.AllowPrivateKeyReuse
	}

	//assign policy's subject and key pair values
	p.Subject = subject
	p.KeyPair = keyPair

	subjectAltNames := resolveSubjectAltNames(tp.ProhibitedSANType)

	if subjectAltNames != nil {
		p.SubjectAltNames = *(subjectAltNames)
	}

	//set policy and defaults to policy specification.
	ps.Policy = p

	var def Default
	def.Subject = defaultSubject
	def.KeyPair = defaultKeyPair

	ps.Default = def

	return &ps, nil

}

func resolveSubjectAltNames(prohibitedSanTypes []string) *SubjectAltNames {
	if prohibitedSanTypes == nil {
		return nil
	}
	trueVal := true
	falseVal := false
	var subjectAltName SubjectAltNames

	if !existValueInArray(prohibitedSanTypes, TppDnsAllowed) {
		subjectAltName.DnsAllowed = &trueVal
	} else {
		subjectAltName.DnsAllowed = &falseVal
	}

	if !existValueInArray(prohibitedSanTypes, TppIpAllowd) {
		subjectAltName.IpAllowed = &trueVal
	} else {
		subjectAltName.IpAllowed = &falseVal
	}

	if !existValueInArray(prohibitedSanTypes, TppEmailAllowed) {
		subjectAltName.EmailAllowed = &trueVal
	} else {
		subjectAltName.EmailAllowed = &falseVal
	}

	if !existValueInArray(prohibitedSanTypes, TppUriAllowd) {
		subjectAltName.UriAllowed = &trueVal
	} else {
		subjectAltName.UriAllowed = &falseVal
	}

	if !existValueInArray(prohibitedSanTypes, TppUpnAllowed) {
		subjectAltName.UpnAllowed = &trueVal
	} else {
		subjectAltName.UpnAllowed = &falseVal
	}

	return &subjectAltName
}

func existValueInArray(array []string, value string) bool {
	for _, currentValue := range array {

		if currentValue == value {
			return true
		}

	}

	return false
}

//////////////////////---------------------Venafi Cloud policy management code-------------//////////////////////////////////////

func ValidateCloudPolicySpecification(ps *PolicySpecification) error {

	//validate key type
	if len(ps.Policy.KeyPair.KeyTypes) > 1 {
		return fmt.Errorf("attirbute keyTypes have more than one value")
	}

	if ps.Policy.KeyPair.KeyTypes[0] != "RSA" {
		return fmt.Errorf("specified attirbute keyTypes value is not supported on Venafi cloud")
	}

	//validate key KeyTypes:keyLengths
	if len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
		unSupported := getInvalidCloudRsaKeySizeValue(ps.Policy.KeyPair.RsaKeySizes)
		if unSupported != nil {
			return fmt.Errorf("specified attirbute key lenght value: %s is not supported on Venafi cloud", strconv.Itoa(*(unSupported)))
		}
	}

	//validate subjectCNRegexes & sanRegexes
	subjectAltNames := getSubjectAltNames(ps.Policy.SubjectAltNames)
	if len(subjectAltNames) > 0 {
		for k, v := range subjectAltNames {
			if v {
				return fmt.Errorf("specified subjectAltNames: %s value is true, this value is not allowed ", k)
			}
		}
	}
	//if defaults are define validate that them matches with policy values

	if ps.Default.Subject.Org != nil && len(ps.Policy.Subject.Orgs) > 0 {
		exist := existValueInArray(ps.Policy.Subject.Orgs, *(ps.Default.Subject.Org))
		if !exist {
			return fmt.Errorf("specified default org value: %s  doesn't match with specified policy org", *(ps.Default.Subject.Org))
		}
	}

	if ps.Default.Subject.OrgUnits != nil && len(ps.Policy.Subject.Orgs) > 0 {

	}

	if ps.Default.Subject.Locality != nil && len(ps.Policy.Subject.Localities) > 0 {
		exist := existValueInArray(ps.Policy.Subject.Localities, *(ps.Default.Subject.Locality))
		if !exist {
			return fmt.Errorf("specified default locality value: %s  doesn't match with specified policy locality", *(ps.Default.Subject.Locality))
		}
	}

	if ps.Default.Subject.State != nil && len(ps.Policy.Subject.States) > 0 {
		exist := existValueInArray(ps.Policy.Subject.States, *(ps.Default.Subject.State))
		if !exist {
			return fmt.Errorf("specified default state value: %s  doesn't match with specified policy state", *(ps.Default.Subject.State))
		}
	}

	if ps.Default.Subject.Country != nil && len(ps.Policy.Subject.Countries) > 0 {
		exist := existValueInArray(ps.Policy.Subject.Countries, *(ps.Default.Subject.Country))
		if !exist {
			return fmt.Errorf("specified default country value: %s  doesn't match with specified policy country", *(ps.Default.Subject.Country))
		}
	}

	if ps.Default.KeyPair.KeyType != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
		exist := existValueInArray(ps.Policy.KeyPair.KeyTypes, *(ps.Default.KeyPair.KeyType))
		if !exist {
			return fmt.Errorf("specified default key type value: %s  doesn't match with specified policy key type", *(ps.Default.KeyPair.KeyType))
		}
	}

	if ps.Default.KeyPair.RsaKeySize != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
		exist := existIntInArray(ps.Policy.KeyPair.RsaKeySizes, []int{*(ps.Default.KeyPair.RsaKeySize)})
		if !exist {
			return fmt.Errorf("specified default rsa key size value: %s  doesn't match with specified policy rsa key size", *(ps.Default.KeyPair.KeyType))
		}
	}

	return nil
}

func getInvalidCloudRsaKeySizeValue(specifiedRSAKeys []int) *int {

	for _, currentUserVal := range specifiedRSAKeys {
		valid := false
		for _, rsaKey := range CloudRsaKeySize {
			if currentUserVal == rsaKey {
				valid = true
				break
			}
		}
		if !valid {
			return &currentUserVal
		}
	}
	return nil
}

func getSubjectAltNames(names SubjectAltNames) map[string]bool {

	var subjectAltNames map[string]bool
	subjectAltNames = make(map[string]bool)

	if names.DnsAllowed != nil {
		subjectAltNames["dnsAllowed"] = *(names.UpnAllowed)
	}

	if names.IpAllowed != nil {
		subjectAltNames["ipAllowed"] = *(names.IpAllowed)
	}

	if names.EmailAllowed != nil {
		subjectAltNames["emailAllowed"] = *(names.EmailAllowed)
	}

	if names.UriAllowed != nil {
		subjectAltNames["uriAllowed"] = *(names.UriAllowed)
	}

	if names.UpnAllowed != nil {
		subjectAltNames["upnAllowed"] = *(names.UpnAllowed)
	}

	return subjectAltNames

}

func BuildCloudCit(ps *PolicySpecification) CloudPolicyRequest {
	var cloudPolicyRequest CloudPolicyRequest

	//certificateAuthority":"CA_TYPE\\CA_ACOUNT_KEY\\VENDOR_PRODUCT_NAME", "\\VED\\Policy\\Certificate Authorities\\Microsoft CA\\QA Venafi CA - Server 90 Days",
	cloudPolicyRequest.CertificateAuthority = *(ps.Policy.CertificateAuthority)
	cloudPolicyRequest.CertificateAuthorityProductOptionId = "06d705c1-ae81-11e9-bdc4-e3fc25835e95"

	//we need to get certificate authority....
	product := Product{
		CertificateAuthority: *(ps.Policy.CertificateAuthority),
		ProductName:          "Default Product",
		ValidityPeriod:       fmt.Sprint("P", strconv.Itoa(*(ps.Policy.MaxValidDays)), "D"),
	}
	cloudPolicyRequest.Product = product

	if len(ps.Policy.Domains) > 0 {
		regexValues := convertToRegex(ps.Policy.Domains)
		cloudPolicyRequest.SubjectCNRegexes = regexValues
		cloudPolicyRequest.SanRegexes = regexValues//in cloud subject CN and SAN have the same values and we use domains as those values
	} else {
		cloudPolicyRequest.SubjectCNRegexes = []string{".*"}
		cloudPolicyRequest.SanRegexes = []string{".*"}
	}

	if len(ps.Policy.Subject.Orgs) > 0 {
		cloudPolicyRequest.SubjectORegexes = ps.Policy.Subject.Orgs
	} else {
		cloudPolicyRequest.SubjectORegexes = []string{".*"}
	}

	if len(ps.Policy.Subject.OrgUnits) > 0 {
		cloudPolicyRequest.SubjectOURegexes = ps.Policy.Subject.OrgUnits
	} else {
		cloudPolicyRequest.SubjectOURegexes = []string{".*"}
	}

	if len(ps.Policy.Subject.Localities) > 0 {
		cloudPolicyRequest.SubjectLRegexes = ps.Policy.Subject.Localities
	} else {
		cloudPolicyRequest.SubjectLRegexes = []string{".*"}
	}

	if len(ps.Policy.Subject.States) > 0 {
		cloudPolicyRequest.SubjectSTRegexes = ps.Policy.Subject.States
	} else {
		cloudPolicyRequest.SubjectSTRegexes = []string{".*"}
	}

	if len(ps.Policy.Subject.Countries) > 0 {
		cloudPolicyRequest.SubjectCValues = ps.Policy.Subject.Countries
	} else {
		cloudPolicyRequest.SubjectCValues = []string{".*"}
	}

	keyTypes := KeyTypes{
		KeyType:    ps.Policy.KeyPair.KeyTypes[0],
		KeyLengths: ps.Policy.KeyPair.RsaKeySizes,
	}

	var keyTypesArr []KeyTypes

	keyTypesArr = append(keyTypesArr, keyTypes)

	cloudPolicyRequest.KeyTypes = keyTypesArr

	if ps.Policy.KeyPair.ReuseAllowed != nil {
		cloudPolicyRequest.KeyReuse = ps.Policy.KeyPair.ReuseAllowed
	}

	//build recommended settings

	var recommendedSettings RecommendedSettings
	shouldCreateRS := false

	/*if ps.Default.Domain != nil{ ignore for now
		recommendedSettings.SubjectCNRegexes = []string{*(ps.Default.Domain)}//whan value should be put here.
		shouldCreateRS = true
	}*/

	if ps.Default.Subject.Org != nil {
		recommendedSettings.SubjectOValue = *(ps.Default.Subject.Org)
		shouldCreateRS = true
	}
	if ps.Default.Subject.OrgUnits != nil {
		recommendedSettings.SubjectOUValue = ps.Default.Subject.OrgUnits[0]
		shouldCreateRS = true
	}
	if ps.Default.Subject.Locality != nil {
		recommendedSettings.SubjectLValue = *(ps.Default.Subject.Locality)
		shouldCreateRS = true
	}
	if ps.Default.Subject.State != nil {
		recommendedSettings.SubjectSTValue = *(ps.Default.Subject.State)
		shouldCreateRS = true
	}

	if ps.Default.Subject.Country != nil {
		recommendedSettings.SubjectCValue = *(ps.Default.Subject.Country)
		shouldCreateRS = true
	}

	if ps.Default.KeyPair.KeyType != nil {
		var key Key
		key.Type = *(ps.Default.KeyPair.KeyType)
		if ps.Default.KeyPair.RsaKeySize != nil {
			key.Length = *(ps.Default.KeyPair.RsaKeySize)
		} else {
			//default
			key.Length = 2048
		}
		recommendedSettings.key = key

		shouldCreateRS = true
	}

	//SanRegexes is ignored now.

	if shouldCreateRS {
		falseValue := false
		recommendedSettings.keyReuse = &falseValue
		cloudPolicyRequest.RecommendedSettings = &recommendedSettings
	}

	return cloudPolicyRequest
}

func convertToRegex(values []string) []string {
	//"venafi.com" -> ".*\.venafi\.com"
	var regexVals []string
	for _, current := range values {
		currentRegex := strings.ReplaceAll(current, ".", "\\.")
		currentRegex = fmt.Sprint(".*\\.", currentRegex)
		regexVals = append(regexVals, currentRegex)
	}
	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func GetApplicationName(zone string) string{
	data := strings.Split(zone, "\\")
	if data != nil && data[0] != "" {
		return data[0]
	}
	return ""
}

func GetZoneName(zone string) string{
	data := strings.Split(zone, "\\")
	if data != nil && data[1] != "" {
		return data[1]
	}
	return ""
}
