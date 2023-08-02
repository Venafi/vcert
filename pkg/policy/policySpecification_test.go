package policy

import (
	"encoding/json"
	"fmt"
	t "log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smartystreets/assertions"
	"gopkg.in/yaml.v2"
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

	assertions.ShouldNotBeEmpty(tppPol)

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
