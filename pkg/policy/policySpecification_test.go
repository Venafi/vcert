package policy

import (
	"encoding/json"
	"fmt"
	t "log"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func getPolicySpecificationFromFile(f string) *PolicySpecification {

	file, bytes, err := GetFileAndBytes(f)

	fileExt := GetFileType(f)
	fileExt = strings.ToLower(fileExt)

	err = VerifyPolicySpec(bytes, fileExt)
	if err != nil {
		t.Fatalf("Error verifying policy specification\nError: %s", err)
	}

	//based on the extension call the appropriate method to feed the policySpecification
	//structure.
	var policySpecification PolicySpecification
	if fileExt == JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			t.Fatalf("Error Unmarshalling policy specification\nError: %s", err)
		}
	} else if fileExt == YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			t.Fatalf("Error unmarshalling policy specification\nError: %s", err)
		}
	} else {
		err = fmt.Errorf("the specified file is not supported")
		t.Fatalf("Error unmarshalling policy specification\nError: %s", err)

	}
	if &policySpecification == nil {
		err = fmt.Errorf("policy specification is nil")
		t.Fatalf("Error openning policy specification\nError: %s", err)
	}
	defer file.Close()
	return &policySpecification
}

func TestValidateGetSpecificationFromYml(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification.yml")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	err = ValidateCloudPolicySpecification(policySpecification)
	if err != nil {
		t.Fatalf("Error validating policy specification\nError: %s", err)
	}
}

func TestValidateCloudPolicySpecification(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	err = ValidateCloudPolicySpecification(policySpecification)
	if err != nil {
		t.Fatalf("Error validating policy specification\nError: %s", err)
	}
}

func TestValidateTPPPolicyData(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	err = validateDefaultKeyPair(policySpecification)
	if err != nil {
		t.Fatalf("Error validating default \nError: %s", err)
	}

	err = validatePolicySubject(policySpecification)
	if err != nil {
		t.Fatalf("Error validating policy subject\nError: %s", err)
	}

}

func TestBuildTppPolicy(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	tppPol := BuildTppPolicy(policySpecification)

	if tppPol.Country == nil {
		t.Fatal("country property is nil")
	}

	if tppPol.State == nil {
		t.Fatal("state property is nil")
	}

	if tppPol.OrganizationalUnit == nil {
		t.Fatal("ou property is nil")
	}

	if tppPol.City == nil {
		t.Fatal("city property is nil")
	}

	if tppPol.KeyAlgorithm == nil {
		t.Fatal("key algorithm property is nil")
	}

}

func TestBuildTppPolicyWithDefaults(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_tpp_management.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	tppPol := BuildTppPolicy(policySpecification)

	assert.NotEmpty(t, tppPol)

}

func TestValidateTppPolicySpecification(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_tpp.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	err = ValidateTppPolicySpecification(policySpecification)
	if err != nil {
		t.Fatalf("Error validating policy specification\nError: %s", err)
	}
}

func TestEmptyPolicy(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/empty_policy.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	isEmpty := IsPolicyEmpty(policySpecification)
	if !isEmpty {
		t.Fatalf("Policy in policy specification is not empty")
	}

	isEmpty = IsDefaultEmpty(policySpecification)
	if !isEmpty {
		t.Fatalf("Default in policy specification is not empty")
	}
}

func TestBuildCloudCitRequest(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)
	prodId := "testiong"
	var orgId int64
	orgId = 1234
	cd := CADetails{
		CertificateAuthorityProductOptionId: &prodId,
		CertificateAuthorityOrganizationId:  &orgId,
	}

	_, err = BuildCloudCitRequest(policySpecification, &cd)

	if err != nil {
		t.Fatalf("Error building cit \nError: %s", err)
	}
}

func TestBuildCloudCitRequestWithEmptyPS(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/empty_policy.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)
	prodId := "testiong"
	var orgId int64
	orgId = 1234
	cd := CADetails{
		CertificateAuthorityProductOptionId: &prodId,
		CertificateAuthorityOrganizationId:  &orgId,
	}

	_, err = BuildCloudCitRequest(policySpecification, &cd)

	if err != nil {
		t.Fatalf("Error building cit \nError: %s", err)
	}
}

func TestBuildPolicySpecificationForTPP(t *testing.T) {

	policy := getPolicyResponse(false)

	policyResp := CheckPolicyResponse{
		Error:  "",
		Policy: &policy,
	}

	_, err := BuildPolicySpecificationForTPP(policyResp)
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
}
func TestBuildPolicySpecificationForTPPLocked(t *testing.T) {

	policy := getPolicyResponse(true)

	policyResp := CheckPolicyResponse{
		Error:  "",
		Policy: &policy,
	}

	_, err := BuildPolicySpecificationForTPP(policyResp)
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
}

// TestBuildPolicySpecificationForTPPPkixParameterSet covers TPP 25.1+ policy folders, which lock
// allowed key algorithms via KeyPair.PkixParameterSet.Values instead of the deprecated
// KeyAlgorithm/KeySize/EllipticCurve Locked flags.
func TestBuildPolicySpecificationForTPPPkixParameterSet(t *testing.T) {
	tppPolicy := getPolicyResponse(true)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{
		Locked: true,
		Value: []string{
			"1.3.6.1.4.1.28783.10.1.1.4096",
			"1.3.6.1.4.1.28783.10.1.1.8192",
		},
	}

	ps, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}

	if ps.Policy == nil || ps.Policy.KeyPair == nil {
		t.Fatal("expected a key pair policy to be set")
	}
	keyPair := ps.Policy.KeyPair
	if len(keyPair.KeyTypes) != 1 || keyPair.KeyTypes[0] != "RSA" {
		t.Fatalf("expected KeyTypes [RSA], got %v", keyPair.KeyTypes)
	}
	if len(keyPair.RsaKeySizes) != 2 || keyPair.RsaKeySizes[0] != 4096 || keyPair.RsaKeySizes[1] != 8192 {
		t.Fatalf("expected RsaKeySizes [4096 8192], got %v", keyPair.RsaKeySizes)
	}
	if len(keyPair.EllipticCurves) != 0 {
		t.Fatalf("expected no EllipticCurves, got %v", keyPair.EllipticCurves)
	}
	if len(keyPair.PkixParameterSet) != 2 || keyPair.PkixParameterSet[0] != "1.3.6.1.4.1.28783.10.1.1.4096" || keyPair.PkixParameterSet[1] != "1.3.6.1.4.1.28783.10.1.1.8192" {
		t.Fatalf("expected the OIDs to be carried through verbatim, got %v", keyPair.PkixParameterSet)
	}

	// The whole point of carrying the OIDs through is that getpolicy output is valid setpolicy
	// input; the decoded multi-valued rsaKeySizes must not trip setpolicy's validation.
	if err := validateKeyPair(ps); err != nil {
		t.Fatalf("getpolicy output is rejected as setpolicy input: %v", err)
	}
}

// TestBuildPolicySpecificationForTPPPkixParameterSetEcc checks the key type name matches the
// KeyAlgorithmsToPKIX key that setpolicy writes back with, rather than the "ECDSA" spelling.
func TestBuildPolicySpecificationForTPPPkixParameterSetEcc(t *testing.T) {
	tppPolicy := getPolicyResponse(true)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{
		Locked: true,
		Value:  []string{"1.3.6.1.4.1.28783.10.2.1.384"},
	}

	ps, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
	keyPair := ps.Policy.KeyPair
	if len(keyPair.KeyTypes) != 1 || keyPair.KeyTypes[0] != "ECC" {
		t.Fatalf("expected KeyTypes [ECC], got %v", keyPair.KeyTypes)
	}
	if len(keyPair.EllipticCurves) != 1 || keyPair.EllipticCurves[0] != "P384" {
		t.Fatalf("expected EllipticCurves [P384], got %v", keyPair.EllipticCurves)
	}
	if _, ok := KeyAlgorithmsToPKIX[keyPair.KeyTypes[0]]; !ok {
		t.Fatalf("keyType %q has no entry in KeyAlgorithmsToPKIX, so setpolicy would write no key algorithm restriction", keyPair.KeyTypes[0])
	}
	if err := validateKeyPair(ps); err != nil {
		t.Fatalf("getpolicy output is rejected as setpolicy input: %v", err)
	}
}

// TestBuildPolicySpecificationForTPPPkixParameterSetNotLocked checks that a folder which only
// recommends an algorithm keeps its defaults, rather than losing them on a getpolicy round trip.
func TestBuildPolicySpecificationForTPPPkixParameterSetNotLocked(t *testing.T) {
	tppPolicy := getPolicyResponse(true)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{
		Locked: false,
		Value:  []string{"1.3.6.1.4.1.28783.10.1.1.4096"},
	}

	ps, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.PkixParameterSet) > 0 {
		t.Fatalf("an unlocked PKIX parameter set must not become a policy restriction, got %v", ps.Policy.KeyPair.PkixParameterSet)
	}
	if ps.Default == nil || ps.Default.KeyPair == nil {
		t.Fatal("expected a default key pair to be set")
	}
	defaultKeyPair := ps.Default.KeyPair
	if defaultKeyPair.PkixParameterSetDefault == nil || *(defaultKeyPair.PkixParameterSetDefault) != "1.3.6.1.4.1.28783.10.1.1.4096" {
		t.Fatalf("expected pkixParameterSetDefault to be set, got %v", defaultKeyPair.PkixParameterSetDefault)
	}
	if defaultKeyPair.RsaKeySize == nil || *(defaultKeyPair.RsaKeySize) != 4096 {
		t.Fatalf("expected a default rsaKeySize of 4096, got %v", defaultKeyPair.RsaKeySize)
	}
	if err := validateDefaultKeyPair(ps); err != nil {
		t.Fatalf("getpolicy output is rejected as setpolicy input: %v", err)
	}
}

// TestBuildPolicySpecificationForTPPPkixParameterSetPartiallyUnrecognized checks that one OID this
// build has never heard of does not make the whole zone unreadable.
func TestBuildPolicySpecificationForTPPPkixParameterSetPartiallyUnrecognized(t *testing.T) {
	tppPolicy := getPolicyResponse(true)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{
		Locked: true,
		Value:  []string{"1.2.3.4.5", "1.3.6.1.4.1.28783.10.1.1.4096"},
	}

	ps, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
	keyPair := ps.Policy.KeyPair
	if len(keyPair.RsaKeySizes) != 1 || keyPair.RsaKeySizes[0] != 4096 {
		t.Fatalf("expected only the recognized OID to be honoured, got %v", keyPair.RsaKeySizes)
	}
	if len(keyPair.PkixParameterSet) != 1 || keyPair.PkixParameterSet[0] != "1.3.6.1.4.1.28783.10.1.1.4096" {
		t.Fatalf("expected the unrecognized OID to be dropped, got %v", keyPair.PkixParameterSet)
	}
}

func TestBuildPolicySpecificationForTPPPkixParameterSetUnrecognizedOID(t *testing.T) {
	tppPolicy := getPolicyResponse(true)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{
		Locked: true,
		Value:  []string{"1.2.3.4.5"},
	}

	_, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	if err == nil {
		t.Fatal("expected an error when no PKIX parameter set OID is recognized")
	}
	if !strings.Contains(err.Error(), "no key algorithm that this version of vcert recognizes") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestBuildPolicySpecificationForTPPPkixParameterSetLockedEmpty checks the fail-closed behaviour:
// TPP 25.1+ leaves the deprecated fields unlocked, so falling back to them would report the folder
// as allowing every key size and curve.
func TestBuildPolicySpecificationForTPPPkixParameterSetLockedEmpty(t *testing.T) {
	tppPolicy := getPolicyResponse(true)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{Locked: true}

	_, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	if err == nil {
		t.Fatal("expected an error when the policy locks an empty PKIX parameter set")
	}
	if !strings.Contains(err.Error(), "allows no key algorithms") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestPkixToKeyAlgorithmsIsInverseOfKeyAlgorithmsToPKIX guards against the two directions drifting
// apart, which is what let the getpolicy/setpolicy ECC round trip break.
func TestPkixToKeyAlgorithmsIsInverseOfKeyAlgorithmsToPKIX(t *testing.T) {
	for keyType, parameters := range KeyAlgorithmsToPKIX {
		for parameter, oid := range parameters {
			algorithm, ok := PkixToKeyAlgorithms[oid]
			if !ok {
				t.Fatalf("OID %s (%s %s) has no reverse mapping", oid, keyType, parameter)
			}
			if algorithm.KeyType != keyType {
				t.Fatalf("OID %s maps back to key type %q, expected %q", oid, algorithm.KeyType, keyType)
			}
			if keyType == "RSA" {
				if strconv.Itoa(algorithm.KeySize) != parameter {
					t.Fatalf("OID %s maps back to RSA size %d, expected %s", oid, algorithm.KeySize, parameter)
				}
				if !existIntInArray([]int{algorithm.KeySize}, TppRsaKeySize) {
					t.Fatalf("RSA size %d has a PKIX OID but is missing from TppRsaKeySize, so setpolicy would reject it", algorithm.KeySize)
				}
			} else if algorithm.Curve != parameter {
				t.Fatalf("OID %s maps back to curve %q, expected %q", oid, algorithm.Curve, parameter)
			}
		}
	}
}

func TestGetZoneInfo(t *testing.T) {
	originalAPP := "DevOps"
	originalCit := "Open Source"
	zone := originalAPP + "\\" + originalCit
	app := GetApplicationName(zone)
	cit := GetCitName(zone)

	if originalAPP != app {
		t.Fatalf("app name is different, expected: %s but get: %s", originalAPP, app)
	}

	if originalCit != cit {
		t.Fatalf("cit name is different, expected: %s but get: %s", originalCit, cit)
	}
}

func TestGetEmptyPolicySpec(t *testing.T) {
	//get the policy specification template
	spec := GetPolicySpec()
	if spec == nil {
		t.Fatal("policy specification is nil")
	}

	isEmpty := IsPolicyEmpty(spec)
	//policy spec shouldn't be empty, should have attributes.
	if isEmpty {
		t.Fatal("policy specification is empty")
	}
}

func getPolicyResponse(lockedAttribute bool) PolicyResponse {
	return PolicyResponse{
		CertificateAuthority: LockedAttribute{
			Value:  "test ca",
			Locked: lockedAttribute,
		},
		CsrGeneration: LockedAttribute{
			Value:  "0",
			Locked: lockedAttribute,
		},
		KeyGeneration: LockedAttribute{
			Value:  "",
			Locked: lockedAttribute,
		},
		KeyPairResponse: KeyPairResponse{
			KeyAlgorithm: LockedAttribute{
				Value:  "RSA",
				Locked: lockedAttribute,
			},
			KeySize: LockedIntAttribute{
				Value:  2048,
				Locked: lockedAttribute,
			},
		},
		ManagementType: LockedAttribute{
			Value:  "Provisioning",
			Locked: lockedAttribute,
		},
		PrivateKeyReuseAllowed:  false,
		SubjAltNameDnsAllowed:   false,
		SubjAltNameEmailAllowed: false,
		SubjAltNameIpAllowed:    false,
		SubjAltNameUpnAllowed:   false,
		SubjAltNameUriAllowed:   false,
		Subject: SubjectResponse{
			City: LockedAttribute{
				Value:  "Merida",
				Locked: lockedAttribute,
			},
			Country: LockedAttribute{
				Value:  "MX",
				Locked: lockedAttribute,
			},
			Organization: LockedAttribute{
				Value:  "Venafi",
				Locked: lockedAttribute,
			},
			OrganizationalUnit: LockedArrayAttribute{
				Value:  []string{"DevOps", "QA"},
				Locked: lockedAttribute,
			},
			State: LockedAttribute{
				Value:  "Yucatan",
				Locked: lockedAttribute,
			},
		},
		UniqueSubjectEnforced: false,
		WhitelistedDomains:    []string{"venafi.com", "kwantec.com"},
		WildcardsAllowed:      false,
	}
}
