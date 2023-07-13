package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// there is no way for creating an array as constant, so creating a variable
// this is the nearest to a constant on arrays.
var TppKeyType = []string{"RSA", "ECDSA"}
var TppRsaKeySize = []int{512, 1024, 2048, 3072, 4096}
var CloudRsaKeySize = []int{1024, 2048, 3072, 4096}
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

func GetPolicySpecificationFromFile(policySpecLocation string, verify bool) (*PolicySpecification, error) {
	file, bytes, err := GetFileAndBytes(policySpecLocation)
	if err != nil {
		return nil, err
	}
	file.Close() // the file contents are read already

	fileExt := GetFileType(policySpecLocation)
	fileExt = strings.ToLower(fileExt)

	if verify {
		err = VerifyPolicySpec(bytes, fileExt)
		if err != nil {
			err = fmt.Errorf("policy specification file is not valid: %s", err)
			return nil, err
		}
	}

	//based on the extension call the appropriate method to feed the policySpecification
	//structure.
	var policySpecification PolicySpecification
	if fileExt == JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return nil, err
		}
	} else if fileExt == YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("the specified file is not supported")
	}

	return &policySpecification, nil
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

	if len(subject.Countries) > 0 {
		if len(subject.Countries[0]) != 2 {
			return fmt.Errorf("number of country's characters, doesn't match to two characters")
		}
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

		if len(san.IpConstraints) > 0 {
			return false
		}

		if len(san.UriProtocols) > 0 {
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

func VerifyPolicySpec(bytes []byte, fileExt string) error {

	var err error
	var policySpecification PolicySpecification

	if fileExt == JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else if fileExt == YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("the specified file is not supported")
	}

	return nil
}

func GetFileAndBytes(p string) (*os.File, []byte, error) {
	file, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	return file, bytes, nil
}
func GetPolicySpec() *PolicySpecification {

	emptyString := ""
	intVal := 0
	falseBool := false

	specification := PolicySpecification{
		Policy: &Policy{
			CertificateAuthority: &emptyString,
			Domains:              []string{""},
			WildcardAllowed:      &falseBool,
			AutoInstalled:        &falseBool,
			MaxValidDays:         &intVal,
			Subject: &Subject{
				Orgs:       []string{""},
				OrgUnits:   []string{""},
				Localities: []string{""},
				States:     []string{""},
				Countries:  []string{""},
			},
			KeyPair: &KeyPair{
				KeyTypes:         []string{""},
				RsaKeySizes:      []int{0},
				ServiceGenerated: &falseBool,
				ReuseAllowed:     &falseBool,
				EllipticCurves:   []string{""},
			},
			SubjectAltNames: &SubjectAltNames{
				DnsAllowed:    &falseBool,
				IpAllowed:     &falseBool,
				EmailAllowed:  &falseBool,
				UriAllowed:    &falseBool,
				UpnAllowed:    &falseBool,
				UriProtocols:  []string{""},
				IpConstraints: []string{""},
			},
		},
		Default: &Default{
			Domain: &emptyString,
			Subject: &DefaultSubject{
				Org:      &emptyString,
				OrgUnits: []string{""},
				Locality: &emptyString,
				State:    &emptyString,
				Country:  &emptyString,
			},
			KeyPair: &DefaultKeyPair{
				KeyType:          &emptyString,
				RsaKeySize:       &intVal,
				EllipticCurve:    &emptyString,
				ServiceGenerated: &falseBool,
			},
		},
	}
	return &specification
}
