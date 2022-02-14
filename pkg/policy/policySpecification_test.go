package policy

import (
	"encoding/json"
	"fmt"
	"github.com/smartystreets/assertions"
	"gopkg.in/yaml.v2"
	t "log"
	"path/filepath"
	"strings"
	"testing"
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

func TestValidateTPPPolicyData(t *testing.T){
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

func TestBuildTppPolicy(t *testing.T){
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

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

func TestEmptyPolicy(t *testing.T){
	absPath, err := filepath.Abs("../../test-files/empty_policy.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)

	isEmpty := IsPolicyEmpty(policySpecification)
	if !isEmpty{
		t.Fatalf("Policy in policy specification is not empty")
	}

	isEmpty = IsDefaultEmpty(policySpecification)
	if !isEmpty{
		t.Fatalf("Default in policy specification is not empty")
	}
}

func TestBuildCloudCitRequest(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_tpp.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification := getPolicySpecificationFromFile(absPath)
	prodId := "testiong"
	var orgId  int64
	orgId = 1234
	cd := CADetails{
		CertificateAuthorityProductOptionId: &prodId,
		CertificateAuthorityOrganizationId:  &orgId,
	}

	_, err = BuildCloudCitRequest(policySpecification, &cd)

	if err != nil{
		t.Fatalf("Error building cit \nError: %s", err)
	}
}