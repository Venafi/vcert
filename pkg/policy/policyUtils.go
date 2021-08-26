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
	extension = strings.ToLower(extension)
	if extension == ".yml" {
		extension = YamlExtension
	}

	return extension
}

func GetParent(p string) string {
	lastIndex := strings.LastIndex(p, "\\")
	parentPath := p[:lastIndex]
	return parentPath
}

func ValidateTppPolicySpecification(ps *PolicySpecification) error {

	if ps.Policy != nil {
		err := validatePolicySubject(ps)
		if err != nil {
			return err
		}

		err = validateKeyPair(ps)
		if err != nil {
			return err
		}
	}

	err := validateDefaultSubject(ps)
	if err != nil {
		return err
	}

	err = validateDefaultKeyPairWithPolicySubject(ps)
	if err != nil {
		return err
	}

	err = validateDefaultKeyPair(ps)
	if err != nil {
		return err
	}

	if ps.Default != nil && ps.Default.AutoInstalled != nil && ps.Policy != nil && ps.Policy.AutoInstalled != nil {
		if *(ps.Default.AutoInstalled) != *(ps.Policy.AutoInstalled) {
			return fmt.Errorf("default autoInstalled attribute value doesn't match with policy's autoInstalled attribute value")
		}
	}

	return nil
}

func validatePolicySubject(ps *PolicySpecification) error {

	if ps.Policy.Subject == nil {
		return nil
	}
	subject := ps.Policy.Subject

	if len(subject.Orgs) > 1 {
		return fmt.Errorf("attribute orgs has more than one value")
	}
	if len(subject.Localities) > 1 {
		return fmt.Errorf("attribute localities has more than one value")
	}
	if len(subject.States) > 1 {
		return fmt.Errorf("attribute states has more than one value")
	}
	if len(subject.Countries) > 1 {
		return fmt.Errorf("attribute countries has more than one value")
	}

	if len(subject.Countries[0]) != 2 {
		return fmt.Errorf("number of country's characters, doesn't match to two characters")
	}

	return nil
}

func validateKeyPair(ps *PolicySpecification) error {
	if ps.Policy.KeyPair == nil {
		return nil
	}
	keyPair := ps.Policy.KeyPair

	//validate algorithm
	if len(keyPair.KeyTypes) > 1 {
		return fmt.Errorf("attribute keyTypes has more than one value")
	}
	if len(keyPair.KeyTypes) > 0 && !existStringInArray(keyPair.KeyTypes, TppKeyType) {
		return fmt.Errorf("specified keyTypes doesn't match with the supported ones")
	}

	//validate key bit strength
	if len(keyPair.RsaKeySizes) > 1 {
		return fmt.Errorf("attribute rsaKeySizes has more than one value")
	}
	if len(keyPair.RsaKeySizes) > 0 && !existIntInArray(keyPair.RsaKeySizes, TppRsaKeySize) {
		return fmt.Errorf("specified rsaKeySizes doesn't match with the supported ones")
	}

	//validate elliptic curve
	if len(keyPair.EllipticCurves) > 1 {
		return fmt.Errorf("attribute ellipticCurves has more than one value")
	}
	if len(keyPair.EllipticCurves) > 0 && !existStringInArray(keyPair.EllipticCurves, TppEllipticCurves) {
		return fmt.Errorf("specified ellipticCurves doesn't match with the supported ones")
	}

	return nil
}

func existStringInArray(userValue []string, supportedValues []string) bool {
	for _, uv := range userValue {
		match := false
		for _, sv := range supportedValues {
			if uv == sv {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func existIntInArray(userValue []int, supportedValues []int) bool {
	for _, uv := range userValue {
		match := false
		for _, sv := range supportedValues {
			if uv == sv {
				match = true
			}
		}
		if !match {
			return false
		}
	}

	return true
}

func validateDefaultSubject(ps *PolicySpecification) error {

	if ps.Default != nil && ps.Default.Subject != nil {

		defaultSubject := ps.Default.Subject

		if ps.Policy != nil && ps.Policy.Subject != nil {

			policySubject := ps.Policy.Subject

			if policySubject.Orgs != nil && policySubject.Orgs[0] != "" && defaultSubject.Org != nil && *(defaultSubject.Org) != "" {
				if policySubject.Orgs[0] != *(defaultSubject.Org) {
					return fmt.Errorf("policy default org doesn't match with policy's orgs value")
				}
			}

			if len(policySubject.OrgUnits) > 0 && len(defaultSubject.OrgUnits) > 0 {
				if !existStringInArray(defaultSubject.OrgUnits, policySubject.OrgUnits) {
					return fmt.Errorf("policy default orgUnits doesn't match with policy's orgUnits value")
				}
			}

			if policySubject.Localities != nil && policySubject.Localities[0] != "" && defaultSubject.Locality != nil && *(defaultSubject.Locality) != "" {
				if policySubject.Localities[0] != *(defaultSubject.Locality) {
					return fmt.Errorf("policy default locality doesn't match with policy's localities value")
				}
			}
			if policySubject.States != nil && policySubject.States[0] != "" && defaultSubject.State != nil && *(defaultSubject.State) != "" {
				if policySubject.States[0] != *(defaultSubject.State) {
					return fmt.Errorf("policy default state doesn't match with policy's states value")
				}
			}
			if policySubject.Countries != nil && policySubject.Countries[0] != "" && defaultSubject.Country != nil && *(defaultSubject.Country) != "" {
				if policySubject.Countries[0] != *(defaultSubject.Country) {
					return fmt.Errorf("policy default country doesn't match with policy's countries value")
				}
			}
			if defaultSubject.Country != nil && *(defaultSubject.Country) != "" {
				if len(*(defaultSubject.Country)) != 2 {
					return fmt.Errorf("number of defualt country's characters, doesn't match to two characters")
				}
			}
		} else {
			//there is nothing to validate
			return nil
		}
	}

	return nil
}

func validateDefaultKeyPairWithPolicySubject(ps *PolicySpecification) error {
	if ps.Default == nil || ps.Default.KeyPair == nil || ps.Policy == nil || ps.Policy.KeyPair == nil {
		return nil
	}
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

	if policyKeyPair.ServiceGenerated != nil && defaultKeyPair.ServiceGenerated != nil {
		if *(policyKeyPair.ServiceGenerated) != *(defaultKeyPair.ServiceGenerated) {
			return fmt.Errorf("policy default serviceGenerated generated doesn't match with policy's serviceGenerated value")
		}
	}

	return nil
}

func validateDefaultKeyPair(ps *PolicySpecification) error {

	if ps.Default == nil {
		return nil
	}

	if ps.Default.KeyPair == nil {
		return nil
	}

	keyPair := ps.Default.KeyPair

	if keyPair.KeyType != nil && *(keyPair.KeyType) != "" && !existStringInArray([]string{*(keyPair.KeyType)}, TppKeyType) {
		return fmt.Errorf("specified default keyType doesn't match with the supported ones")
	}

	//validate key bit strength
	if keyPair.RsaKeySize != nil && *(keyPair.RsaKeySize) > 0 && !existIntInArray([]int{*(keyPair.RsaKeySize)}, TppRsaKeySize) {
		return fmt.Errorf("specified default rsaKeySize doesn't match with the supported ones")
	}

	//validate elliptic curve
	if keyPair.EllipticCurve != nil && *(keyPair.EllipticCurve) != "" && !existStringInArray([]string{*(keyPair.EllipticCurve)}, TppEllipticCurves) {
		return fmt.Errorf("specified default ellipticCurve doesn't match with the supported ones")
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
	if ps.Policy != nil {
		tppPolicy.DomainSuffixWhitelist = ps.Policy.Domains
	}

	if ps.Policy != nil && ps.Policy.WildcardAllowed != nil {

		if *(ps.Policy.WildcardAllowed) { //this is true so we revert it to false(0)
			intValZero := 0
			tppPolicy.ProhibitWildcard = &intValZero
		} else {
			intValOne := 1
			tppPolicy.ProhibitWildcard = &intValOne
		}

	}

	if ps.Policy != nil && ps.Policy.CertificateAuthority != nil {
		tppPolicy.CertificateAuthority = ps.Policy.CertificateAuthority
	}

	managementType := TppManagementTypeEnrollment
	if ps.Policy != nil && ps.Policy.AutoInstalled != nil {
		if *(ps.Policy.AutoInstalled) {
			managementType = TppManagementTypeProvisioning
		}
		tppPolicy.ManagementType = createLockedAttribute(managementType, true)
	} else if ps.Default != nil && ps.Default.AutoInstalled != nil {
		if *(ps.Default.AutoInstalled) {
			managementType = TppManagementTypeProvisioning
		}
		tppPolicy.ManagementType = createLockedAttribute(managementType, false)
	}

	//policy subject attributes
	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Orgs) > 0 && ps.Policy.Subject.Orgs[0] != "" {
		tppPolicy.Organization = createLockedAttribute(ps.Policy.Subject.Orgs[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && *(ps.Default.Subject.Org) != "" {
		tppPolicy.Organization = createLockedAttribute(*(ps.Default.Subject.Org), false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.OrgUnits) > 0 && ps.Policy.Subject.OrgUnits[0] != "" {
		tppPolicy.OrganizationalUnit = createLockedArrayAttribute(ps.Policy.Subject.OrgUnits, true)
	} else if ps.Default != nil && ps.Default.Subject != nil && len(ps.Default.Subject.OrgUnits) > 0 && ps.Default.Subject.OrgUnits[0] != "" {
		tppPolicy.OrganizationalUnit = createLockedArrayAttribute(ps.Default.Subject.OrgUnits, false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Localities) > 0 && ps.Policy.Subject.Localities[0] != "" {
		tppPolicy.City = createLockedAttribute(ps.Policy.Subject.Localities[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && (ps.Default.Subject.Locality != nil) && (*(ps.Default.Subject.Locality) != "") {
		tppPolicy.City = createLockedAttribute(*(ps.Default.Subject.Locality), false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.States) > 0 && ps.Policy.Subject.States[0] != "" {
		tppPolicy.State = createLockedAttribute(ps.Policy.Subject.States[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && (ps.Default.Subject.State != nil) && (*(ps.Default.Subject.State) != "") {
		tppPolicy.State = createLockedAttribute(*(ps.Default.Subject.State), false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Countries) > 0 && ps.Policy.Subject.Countries[0] != "" {
		tppPolicy.Country = createLockedAttribute(ps.Policy.Subject.Countries[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && (ps.Default.Subject.Country != nil) && (*(ps.Default.Subject.Country) != "") {
		tppPolicy.Country = createLockedAttribute(*(ps.Default.Subject.Country), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 && ps.Policy.KeyPair.KeyTypes[0] != "" {
		tppPolicy.KeyAlgorithm = createLockedAttribute(ps.Policy.KeyPair.KeyTypes[0], true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.KeyType != nil) && (*(ps.Default.KeyPair.KeyType) != "") {
		tppPolicy.KeyAlgorithm = createLockedAttribute(*(ps.Default.KeyPair.KeyType), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 && ps.Policy.KeyPair.RsaKeySizes[0] != 0 {
		rsaKey := ps.Policy.KeyPair.RsaKeySizes[0]
		tppPolicy.KeyBitStrength = createLockedAttribute(strconv.Itoa(rsaKey), true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.RsaKeySize != nil) && *(ps.Default.KeyPair.RsaKeySize) != 0 {
		tppPolicy.KeyBitStrength = createLockedAttribute(strconv.Itoa(*(ps.Default.KeyPair.RsaKeySize)), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.EllipticCurves) > 0 && ps.Policy.KeyPair.EllipticCurves[0] != "" {
		tppPolicy.EllipticCurve = createLockedAttribute(ps.Policy.KeyPair.EllipticCurves[0], true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.EllipticCurve != nil) && (*(ps.Default.KeyPair.EllipticCurve) != "") {
		tppPolicy.EllipticCurve = createLockedAttribute(*(ps.Default.KeyPair.EllipticCurve), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ServiceGenerated != nil {
		strVal := "1"
		if *(ps.Policy.KeyPair.ServiceGenerated) {
			strVal = "0"
		}
		tppPolicy.ManualCsr = createLockedAttribute(strVal, true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.ServiceGenerated != nil) {
		strVal := "1"
		if *(ps.Default.KeyPair.ServiceGenerated) {
			strVal = "0"
		}
		tppPolicy.ManualCsr = createLockedAttribute(strVal, false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ReuseAllowed != nil {

		var intVal int
		if *(ps.Policy.KeyPair.ReuseAllowed) {
			intVal = 1
		} else {
			intVal = 0
		}

		tppPolicy.AllowPrivateKeyReuse = &intVal
		tppPolicy.WantRenewal = &intVal
	}

	if ps.Policy != nil && ps.Policy.SubjectAltNames != nil {
		prohibitedSANType := getProhibitedSanTypes(*(ps.Policy.SubjectAltNames))
		if prohibitedSANType != nil {
			tppPolicy.ProhibitedSANType = prohibitedSANType
		}
	}

	return tppPolicy
}

func createLockedAttribute(value string, locked bool) *LockedAttribute {
	lockedAtr := LockedAttribute{
		Value:  value,
		Locked: locked,
	}
	return &lockedAtr
}

func createLockedArrayAttribute(value []string, locked bool) *LockedArrayAttribute {
	lockedAtr := LockedArrayAttribute{
		Value:  value,
		Locked: locked,
	}
	return &lockedAtr
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

func BuildPolicySpecificationForTPP(checkPolicyResp CheckPolicyResponse) (*PolicySpecification, error) {

	if checkPolicyResp.Policy == nil {
		return nil, fmt.Errorf("policy is nul")
	}

	policy := checkPolicyResp.Policy
	var ps PolicySpecification

	/*ps.Users = tppPolicy.Contact
	ps.Approvers = tppPolicy.Approver*/

	var p Policy

	if policy.WhitelistedDomains != nil {
		p.Domains = policy.WhitelistedDomains
	}

	if policy.CertificateAuthority.Value != "" {
		p.CertificateAuthority = &policy.CertificateAuthority.Value
	}

	var subject Subject
	shouldCreateSubject := false
	var defaultSubject DefaultSubject
	shouldCreateDefSubject := false

	var keyPair KeyPair
	shouldCreateKeyPair := false
	var defaultKeyPair DefaultKeyPair
	shouldCreateDefKeyPair := false

	var def Default

	p.WildcardAllowed = &policy.WildcardsAllowed

	if policy.ManagementType.Value != "" {
		boolVal := false
		if policy.ManagementType.Value == TppManagementTypeProvisioning {
			boolVal = true
		}
		if policy.ManagementType.Locked {
			p.AutoInstalled = &boolVal
		} else {
			def.AutoInstalled = &boolVal
		}
	}

	//resolve subject's attributes

	//resolve org
	if policy.Subject.Organization.Value != "" {
		if policy.Subject.Organization.Locked {
			shouldCreateSubject = true
			subject.Orgs = []string{policy.Subject.Organization.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.Org = &policy.Subject.Organization.Value
		}
	}

	//resolve orgUnit

	if len(policy.Subject.OrganizationalUnit.Value) > 0 {
		if policy.Subject.OrganizationalUnit.Locked {
			shouldCreateSubject = true
			subject.OrgUnits = policy.Subject.OrganizationalUnit.Value
		} else {
			shouldCreateDefSubject = true
			defaultSubject.OrgUnits = policy.Subject.OrganizationalUnit.Value
		}
	}

	//resolve localities
	if policy.Subject.City.Value != "" {
		if policy.Subject.City.Locked {
			shouldCreateSubject = true
			subject.Localities = []string{policy.Subject.City.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.Locality = &policy.Subject.City.Value
		}
	}

	//resolve states

	if policy.Subject.State.Value != "" {
		if policy.Subject.State.Locked {
			shouldCreateSubject = true
			subject.States = []string{policy.Subject.State.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.State = &policy.Subject.State.Value
		}
	}

	//resolve countries
	if policy.Subject.Country.Value != "" {
		if policy.Subject.Country.Locked {
			shouldCreateSubject = true
			subject.Countries = []string{policy.Subject.Country.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.Country = &policy.Subject.Country.Value
		}
	}

	//resolve key pair's attributes

	//resolve keyTypes
	if policy.KeyPairResponse.KeyAlgorithm.Value != "" {
		if policy.KeyPairResponse.KeyAlgorithm.Locked {
			keyPair.KeyTypes = []string{policy.KeyPairResponse.KeyAlgorithm.Value}
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.KeyType = &policy.KeyPairResponse.KeyAlgorithm.Value
		}
	}

	//resolve rsaKeySizes

	if policy.KeyPairResponse.KeySize.Value > 0 {
		if policy.KeyPairResponse.KeySize.Locked {
			keyPair.RsaKeySizes = []int{policy.KeyPairResponse.KeySize.Value}
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.RsaKeySize = &policy.KeyPairResponse.KeySize.Value
		}
	}
	//resolve ellipticCurves
	/*if tppPolicy.EllipticCurve != nil {
		if tppPolicy.EllipticCurve.Locked {
			shouldCreateKeyPair = true
			keyPair.EllipticCurves = []string{tppPolicy.EllipticCurve.Value}
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.EllipticCurve = &tppPolicy.EllipticCurve.Value
		}
	}*/

	//resolve generationType

	value := policy.CsrGeneration.Value
	if value != "" {
		booleanValue := true

		//this mean that is a generated csr so ServiceGenerated is false
		if value == UserProvided {
			booleanValue = false
		}

		if policy.CsrGeneration.Locked {
			keyPair.ServiceGenerated = &booleanValue
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.ServiceGenerated = &booleanValue
		}
	}

	keyPair.ReuseAllowed = &policy.PrivateKeyReuseAllowed
	shouldCreateKeyPair = true

	//assign policy's subject and key pair values
	if shouldCreateSubject {
		p.Subject = &subject
	}
	if shouldCreateKeyPair {
		p.KeyPair = &keyPair
	}
	subjectAltNames := resolveSubjectAltNames((*policy))

	if subjectAltNames != nil {
		p.SubjectAltNames = subjectAltNames
	}

	//set policy and defaults to policy specification.
	ps.Policy = &p

	if shouldCreateDefSubject {
		def.Subject = &defaultSubject
	}
	if shouldCreateDefKeyPair {
		def.KeyPair = &defaultKeyPair
	}

	if shouldCreateDefSubject || shouldCreateDefKeyPair || def.AutoInstalled != nil {
		ps.Default = &def
	}

	return &ps, nil

}

func resolveSubjectAltNames(policy PolicyResponse) *SubjectAltNames {

	trueVal := true
	falseVal := false
	var subjectAltName SubjectAltNames

	if policy.SubjAltNameDnsAllowed {
		subjectAltName.DnsAllowed = &trueVal
	} else {
		subjectAltName.DnsAllowed = &falseVal
	}

	if policy.SubjAltNameIpAllowed {
		subjectAltName.IpAllowed = &trueVal
	} else {
		subjectAltName.IpAllowed = &falseVal
	}

	if policy.SubjAltNameEmailAllowed {
		subjectAltName.EmailAllowed = &trueVal
	} else {
		subjectAltName.EmailAllowed = &falseVal
	}

	if policy.SubjAltNameUriAllowed {
		subjectAltName.UriAllowed = &trueVal
	} else {
		subjectAltName.UriAllowed = &falseVal
	}

	if policy.SubjAltNameUpnAllowed {
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

func validateDefaultStringCloudValues(array []string, value string) bool {
	if len(array) == 1 {
		if array[0] == AllowAll { // this means that we are allowing everything
			return true
		}
	}
	return existValueInArray(array, value)
}

func validateDefaultSubjectOrgsCloudValues(defaultValues []string, policyValues []string) bool {
	if len(policyValues) == 1 {
		if policyValues[0] == AllowAll { // this means that we are allowing everything
			return true
		}
	}
	return existStringInArray(defaultValues, policyValues)
}

func ValidateCloudPolicySpecification(ps *PolicySpecification) error {

	//validate key type
	if ps.Policy != nil {
		if ps.Policy.KeyPair != nil {
			if len(ps.Policy.KeyPair.KeyTypes) > 1 {
				return fmt.Errorf("attribute keyTypes has more than one value")
			}

			if ps.Policy.KeyPair.KeyTypes[0] != "RSA" {
				return fmt.Errorf("specified attribute keyTypes value is not supported on Venafi cloud")
			}

			//validate key KeyTypes:keyLengths
			if len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
				unSupported := getInvalidCloudRsaKeySizeValue(ps.Policy.KeyPair.RsaKeySizes)
				if unSupported != nil {
					return fmt.Errorf("specified attribute key lenght value: %s is not supported on Venafi cloud", strconv.Itoa(*(unSupported)))
				}
			}
		}

		//validate subjectCNRegexes & sanRegexes
		if ps.Policy.SubjectAltNames != nil {
			subjectAltNames := getSubjectAltNames(*(ps.Policy.SubjectAltNames))
			if len(subjectAltNames) > 0 {
				for k, v := range subjectAltNames {
					if k != "dnsAllowed" && v {
						return fmt.Errorf("specified subjectAltNames: %s value is true, this value is not allowed ", k)
					}
				}
			}
		}

		//if defaults are define validate that them matches with policy values
		if ps.Policy.Subject != nil {
			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.Org != nil && len(ps.Policy.Subject.Orgs) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.Orgs, *(ps.Default.Subject.Org))
				if !exist {
					return fmt.Errorf("specified default org value: %s  doesn't match with specified policy org", *(ps.Default.Subject.Org))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && len(ps.Default.Subject.OrgUnits) > 0 && len(ps.Policy.Subject.OrgUnits) > 0 {
				exist := validateDefaultSubjectOrgsCloudValues(ps.Default.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
				if !exist {
					return fmt.Errorf("specified default org unit value: %s  doesn't match with specified policy org unit", *(ps.Default.Subject.Org))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.Locality != nil && len(ps.Policy.Subject.Localities) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.Localities, *(ps.Default.Subject.Locality))
				if !exist {
					return fmt.Errorf("specified default locality value: %s  doesn't match with specified policy locality", *(ps.Default.Subject.Locality))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.State != nil && len(ps.Policy.Subject.States) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.States, *(ps.Default.Subject.State))
				if !exist {
					return fmt.Errorf("specified default state value: %s  doesn't match with specified policy state", *(ps.Default.Subject.State))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.Country != nil && len(ps.Policy.Subject.Countries) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.Countries, *(ps.Default.Subject.Country))
				if !exist {
					return fmt.Errorf("specified default country value: %s  doesn't match with specified policy country", *(ps.Default.Subject.Country))
				}
			}
		}

		if ps.Policy.KeyPair != nil {
			if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.KeyType != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
				exist := existValueInArray(ps.Policy.KeyPair.KeyTypes, *(ps.Default.KeyPair.KeyType))
				if !exist {
					return fmt.Errorf("specified default key type value: %s  doesn't match with specified policy key type", *(ps.Default.KeyPair.KeyType))
				}
			}

			if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.RsaKeySize != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
				exist := existIntInArray([]int{*(ps.Default.KeyPair.RsaKeySize)}, ps.Policy.KeyPair.RsaKeySizes)
				if !exist {
					return fmt.Errorf("specified default rsa key size value: %s  doesn't match with specified policy rsa key size", strconv.Itoa(*(ps.Default.KeyPair.RsaKeySize)))
				}
			}
		}
	}

	//now in case that policy is empty but defaults key types and rsa sizes not, we need to validate them
	if ps.Default != nil && ps.Default.KeyPair != nil {

		if ps.Default.KeyPair.KeyType != nil && *(ps.Default.KeyPair.KeyType) != "" {
			if *(ps.Default.KeyPair.KeyType) != "RSA" {
				return fmt.Errorf("specified default attribute keyType value is not supported on Venafi cloud")
			}
		}

		//validate key KeyTypes:keyLengths
		if ps.Default.KeyPair.RsaKeySize != nil && *(ps.Default.KeyPair.RsaKeySize) != 0 {
			unSupported := getInvalidCloudRsaKeySizeValue([]int{*(ps.Default.KeyPair.RsaKeySize)})
			if unSupported != nil {
				return fmt.Errorf("specified attribute key lenght value: %s is not supported on Venafi cloud", strconv.Itoa(*(unSupported)))
			}
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

	subjectAltNames := make(map[string]bool)

	if names.DnsAllowed != nil {
		subjectAltNames["dnsAllowed"] = *(names.DnsAllowed)
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

func BuildCloudCitRequest(ps *PolicySpecification, ca *CADetails) (*CloudPolicyRequest, error) {
	var cloudPolicyRequest CloudPolicyRequest
	var certAuth CertificateAuthorityInfo
	var err error
	var period int
	if ps.Policy != nil && ps.Policy.CertificateAuthority != nil && *(ps.Policy.CertificateAuthority) != "" {
		certAuth, err = GetCertAuthorityInfo(*(ps.Policy.CertificateAuthority))
		if err != nil {
			return nil, err
		}
	} else {
		certAuth, err = GetCertAuthorityInfo(DefaultCA)
		if err != nil {
			return nil, err
		}
	}

	cloudPolicyRequest.CertificateAuthority = certAuth.CAType
	cloudPolicyRequest.CertificateAuthorityProductOptionId = *(ca.CertificateAuthorityProductOptionId)

	if ps.Policy != nil && ps.Policy.MaxValidDays != nil {
		period = *(ps.Policy.MaxValidDays)
		if period == 0 {
			period = 365
		}
	} else {
		period = 365
	}

	product := Product{
		CertificateAuthority: certAuth.CAType,
		ProductName:          certAuth.VendorProductName,
		ValidityPeriod:       fmt.Sprint("P", strconv.Itoa(period), "D"),
	}

	if certAuth.CAType == CloudDigicertCA {
		alg := "SHA256"
		autoRen := false
		product.HashAlgorithm = &alg
		product.AutoRenew = &autoRen
		product.OrganizationId = ca.CertificateAuthorityOrganizationId
	}

	if certAuth.CAType == CloudEntrustCA {
		td := TrackingData{
			CertificateAuthority: CloudEntrustCA,
			RequesterName:        CloudRequesterName,
			RequesterEmail:       CloudRequesterEmail,
			RequesterPhone:       CloudRequesterPhone,
		}
		cloudPolicyRequest.TrackingData = &td
	}

	cloudPolicyRequest.Product = product

	if ps.Policy != nil && len(ps.Policy.Domains) > 0 {
		regexValues := ConvertToRegex(ps.Policy.Domains, IsWildcardAllowed(*(ps)))
		cloudPolicyRequest.SubjectCNRegexes = regexValues
		if ps.Policy.SubjectAltNames != nil && ps.Policy.SubjectAltNames.DnsAllowed != nil {
			if *(ps.Policy.SubjectAltNames.DnsAllowed) {
				cloudPolicyRequest.SanRegexes = regexValues //in cloud subject CN and SAN have the same values and we use domains as those values
			} else {
				cloudPolicyRequest.SanRegexes = nil
			}
		} else {
			cloudPolicyRequest.SanRegexes = regexValues //in cloud subject CN and SAN have the same values and we use domains as those values
		}
	} else {
		cloudPolicyRequest.SubjectCNRegexes = []string{".*"}
		cloudPolicyRequest.SanRegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Orgs) > 0 {
		cloudPolicyRequest.SubjectORegexes = ps.Policy.Subject.Orgs
	} else {
		cloudPolicyRequest.SubjectORegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.OrgUnits) > 0 {
		cloudPolicyRequest.SubjectOURegexes = ps.Policy.Subject.OrgUnits
	} else {
		cloudPolicyRequest.SubjectOURegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Localities) > 0 {
		cloudPolicyRequest.SubjectLRegexes = ps.Policy.Subject.Localities
	} else {
		cloudPolicyRequest.SubjectLRegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.States) > 0 {
		cloudPolicyRequest.SubjectSTRegexes = ps.Policy.Subject.States
	} else {
		cloudPolicyRequest.SubjectSTRegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Countries) > 0 {
		cloudPolicyRequest.SubjectCValues = ps.Policy.Subject.Countries
	} else {
		cloudPolicyRequest.SubjectCValues = []string{".*"}
	}

	var keyTypes KeyTypes
	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
		keyTypes.KeyType = ps.Policy.KeyPair.KeyTypes[0]
	} else {
		keyTypes.KeyType = "RSA"
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
		keyTypes.KeyLengths = ps.Policy.KeyPair.RsaKeySizes
	} else {
		// on this case we need to look if there is a default if so then we can use it.
		if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.RsaKeySize != nil {
			keyTypes.KeyLengths = []int{*(ps.Default.KeyPair.RsaKeySize)}
		} else {
			keyTypes.KeyLengths = []int{2048}
		}

	}

	var keyTypesArr []KeyTypes

	keyTypesArr = append(keyTypesArr, keyTypes)

	if len(keyTypesArr) > 0 {
		cloudPolicyRequest.KeyTypes = keyTypesArr
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ReuseAllowed != nil {
		cloudPolicyRequest.KeyReuse = ps.Policy.KeyPair.ReuseAllowed
	} else {
		falseValue := false
		cloudPolicyRequest.KeyReuse = &falseValue
	}

	//build recommended settings

	var recommendedSettings RecommendedSettings
	shouldCreateSubjectRS := false
	shouldCreateKPRS := false

	/*if ps.Default.Domain != nil { ignore for now
		recommendedSettings.SubjectCNRegexes = []string{*(ps.Default.Domain)}//whan value should be put here.
		shouldCreateSubjectRS = true
	}*/
	if ps.Default != nil && ps.Default.Subject != nil {
		if ps.Default.Subject.Org != nil {
			recommendedSettings.SubjectOValue = ps.Default.Subject.Org
			shouldCreateSubjectRS = true
		}
		if ps.Default.Subject.OrgUnits != nil {
			recommendedSettings.SubjectOUValue = &ps.Default.Subject.OrgUnits[0]
			shouldCreateSubjectRS = true
		}
		if ps.Default.Subject.Locality != nil {
			recommendedSettings.SubjectLValue = ps.Default.Subject.Locality
			shouldCreateSubjectRS = true
		}
		if ps.Default.Subject.State != nil {
			recommendedSettings.SubjectSTValue = ps.Default.Subject.State
			shouldCreateSubjectRS = true
		}

		if ps.Default.Subject.Country != nil {
			recommendedSettings.SubjectCValue = ps.Default.Subject.Country
			shouldCreateSubjectRS = true
		}
	}

	var key Key
	if ps.Default != nil && ps.Default.KeyPair != nil {
		if ps.Default.KeyPair.KeyType != nil {

			key.Type = *(ps.Default.KeyPair.KeyType)
			if ps.Default.KeyPair.RsaKeySize != nil {
				key.Length = *(ps.Default.KeyPair.RsaKeySize)
			} else {
				//default
				key.Length = 2048
			}

			shouldCreateKPRS = true
		}
	}
	//SanRegexes is ignored now.

	if shouldCreateKPRS {
		recommendedSettings.Key = &key
	}

	if shouldCreateKPRS || shouldCreateSubjectRS {
		cloudPolicyRequest.RecommendedSettings = &recommendedSettings
	}

	return &cloudPolicyRequest, nil
}

func ConvertToRegex(values []string, wildcardAllowed bool) []string {
	var regexVals []string
	for _, current := range values {
		currentRegex := strings.ReplaceAll(current, ".", "\\.")
		if wildcardAllowed {
			currentRegex = fmt.Sprint("[*a-z]{1}[a-z0-9.-]*\\.", currentRegex)
		} else {
			currentRegex = fmt.Sprint("[a-z]{1}[a-z0-9.-]*\\.", currentRegex)
		}
		regexVals = append(regexVals, currentRegex)
	}
	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func RemoveRegex(values []string) []string {
	var regexVals []string
	for _, current := range values {

		current = strings.TrimPrefix(current, "[*a-z]{1}[a-z0-9.-]*\\.")
		current = strings.TrimPrefix(current, "[a-z]{1}[a-z0-9.-]*\\.")

		current = strings.ReplaceAll(current, "\\.", ".")

		regexVals = append(regexVals, current)
	}
	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func GetApplicationName(zone string) string {
	data := strings.Split(zone, "\\")
	if data != nil && data[0] != "" {
		return data[0]
	}
	return ""
}

func GetCitName(zone string) string {
	data := strings.Split(zone, "\\")
	if len(data) == 2 {
		return data[1]
	}
	return ""
}

func GetCertAuthorityInfo(certificateAuthority string) (CertificateAuthorityInfo, error) {

	var caInfo CertificateAuthorityInfo
	data := strings.Split(certificateAuthority, "\\")

	if len(data) < 3 {
		return caInfo, fmt.Errorf("certificate Authority is invalid, please provide a valid value with this structure: ca_type\\ca_account_key\\vendor_product_name")
	}

	caInfo = CertificateAuthorityInfo{
		CAType:            data[0],
		CAAccountKey:      data[1],
		VendorProductName: data[2],
	}

	return caInfo, nil
}

func IsWildcardAllowed(ps PolicySpecification) bool {
	if ps.Policy != nil && ps.Policy.WildcardAllowed != nil {
		return *(ps.Policy.WildcardAllowed)
	}
	return false
}

func IsPolicyEmpty(ps *PolicySpecification) bool {
	if ps.Policy == nil {
		return true
	}

	policy := ps.Policy

	if policy.WildcardAllowed != nil {
		return false
	}
	if policy.SubjectAltNames != nil {
		san := policy.SubjectAltNames

		if san.DnsAllowed != nil {
			return false
		}

		if san.UriAllowed != nil {
			return false
		}

		if san.EmailAllowed != nil {
			return false
		}

		if san.IpAllowed != nil {
			return false
		}

		if san.UpnAllowed != nil {
			return false
		}
	}

	if policy.CertificateAuthority != nil && *(policy.CertificateAuthority) != "" {
		return false
	}

	if policy.MaxValidDays != nil {
		return false
	}

	if len(policy.Domains) > 0 {
		return false
	}

	if policy.Subject != nil {

		subject := policy.Subject

		if len(subject.OrgUnits) > 0 {
			return false
		}
		if len(subject.Countries) > 0 {
			return false
		}
		if len(subject.States) > 0 {
			return false
		}
		if len(subject.Localities) > 0 {
			return false
		}
		if len(subject.Orgs) > 0 {
			return false
		}

	}

	if policy.KeyPair != nil {
		keyPair := policy.KeyPair
		if keyPair.ReuseAllowed != nil {
			return false
		}
		if len(keyPair.RsaKeySizes) > 0 {
			return false
		}
		if len(keyPair.KeyTypes) > 0 {
			return false
		}
		if len(keyPair.EllipticCurves) > 0 {
			return false
		}
		if keyPair.ServiceGenerated != nil {
			return false
		}
	}

	return true
}

func IsDefaultEmpty(ps *PolicySpecification) bool {

	if ps.Default == nil {
		return true
	}

	def := ps.Default

	if def.Domain != nil && *(def.Domain) != "" {
		return false
	}

	if def.KeyPair != nil {
		keyPair := def.KeyPair

		if keyPair.ServiceGenerated != nil {
			return false
		}

		if keyPair.EllipticCurve != nil && *(keyPair.EllipticCurve) != "" {
			return false
		}

		if keyPair.RsaKeySize != nil {
			return false
		}
		if keyPair.KeyType != nil && *(keyPair.KeyType) != "" {
			return false
		}

	}

	if def.Subject != nil {
		subject := def.Subject

		if len(subject.OrgUnits) > 0 {
			return false
		}

		if subject.Org != nil && *(subject.Org) != "" {
			return false
		}

		if subject.State != nil && *(subject.State) != "" {
			return false
		}

		if subject.Country != nil && *(subject.Country) != "" {
			return false
		}

		if subject.Locality != nil && *(subject.Locality) != "" {
			return false
		}

	}

	return true
}
