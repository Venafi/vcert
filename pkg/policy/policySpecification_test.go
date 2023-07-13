package policy

import (
	"path/filepath"
	"testing"

	"github.com/smartystreets/assertions"
)

func TestValidateTPPPolicyData(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

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

	policySpecification, err := GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

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

	policySpecification, err := GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	tppPol := BuildTppPolicy(policySpecification)

	assertions.ShouldNotBeEmpty(tppPol)

}

func TestValidateTppPolicySpecification(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_tpp.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

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

	policySpecification, err := GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	isEmpty := IsPolicyEmpty(policySpecification)
	if !isEmpty {
		t.Fatalf("Policy in policy specification is not empty")
	}

	isEmpty = IsDefaultEmpty(policySpecification)
	if !isEmpty {
		t.Fatalf("Default in policy specification is not empty")
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
