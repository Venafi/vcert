package policy

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func cloudPolicySpecificationForTest(t *testing.T) (*PolicySpecification, *CADetails) {
	t.Helper()
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")
	require.NoError(t, err)
	prodId := "testing"
	orgId := int64(1234)
	return getPolicySpecificationFromFile(absPath), &CADetails{CertificateAuthorityProductOptionId: &prodId, CertificateAuthorityOrganizationId: &orgId}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func TestIsMLDSAKeyType(t *testing.T) {
	for _, keyType := range []string{"MLDSA", "mldsa", "ML-DSA", "ML_DSA"} {
		require.True(t, IsMLDSAKeyType(keyType), keyType)
	}
	for _, keyType := range []string{"RSA", "EC", "ML-DSA-65", ""} {
		require.False(t, IsMLDSAKeyType(keyType), keyType)
	}
}

func TestBuildCloudCitRequestMLDSA(t *testing.T) {
	ps, ca := cloudPolicySpecificationForTest(t)
	ps.Policy.KeyPair.KeyTypes = []string{"RSA", "MLDSA"}
	ps.Policy.KeyPair.MLDSAKeyStrengths = []int{65, 44}
	defaultKeyType, defaultStrength := "MLDSA", 65
	ps.Default.KeyPair.KeyType = &defaultKeyType
	ps.Default.KeyPair.MLDSAKeyStrength = &defaultStrength
	ps.Default.KeyPair.RsaKeySize = nil
	require.NoError(t, ValidateCloudPolicySpecification(ps))

	req, err := BuildCloudCitRequest(ps, ca)
	require.NoError(t, err)

	var sent map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(mustJSON(t, req)), &sent))
	// keyTypes and keyAlgorithmTypes can't be combined, and ML-DSA is only available in keyAlgorithmTypes
	require.NotContains(t, sent, "keyTypes")
	require.JSONEq(t, `[{"keyType":"RSA","keyLengths":[2048]},{"keyType":"ML_DSA","keyStrengths":[44,65]}]`, mustJSON(t, sent["keyAlgorithmTypes"]))
	recommended := sent["recommendedSettings"].(map[string]interface{})
	require.NotContains(t, recommended, "key")
	require.JSONEq(t, `{"keyType":"ML_DSA","keyStrength":65}`, mustJSON(t, recommended["keyAlgorithm"]))
}

func TestBuildCloudCitRequestMLDSARecommendedRSA(t *testing.T) {
	ps, ca := cloudPolicySpecificationForTest(t)
	ps.Policy.KeyPair.KeyTypes = []string{"RSA", "MLDSA"}

	req, err := BuildCloudCitRequest(ps, ca)
	require.NoError(t, err)
	require.Nil(t, req.KeyTypes)
	// no strengths listed: ML-DSA-65 is allowed
	require.Equal(t, []KeyType{{KeyType: "RSA", KeyLengths: []int{2048}}, {KeyType: CloudKeyTypeMLDSA, KeyStrengths: []int{65}}}, req.KeyAlgorithmTypes)
	require.Nil(t, req.RecommendedSettings.Key)
	require.Equal(t, &KeyAlgorithm{KeyType: "RSA", KeyLength: 2048}, req.RecommendedSettings.KeyAlgorithm)
}

func TestBuildCloudCitRequestMLDSAFromDefaultOnly(t *testing.T) {
	ps, ca := cloudPolicySpecificationForTest(t)
	ps.Policy.KeyPair.KeyTypes = nil
	defaultKeyType, defaultStrength := "MLDSA", 87
	ps.Default.KeyPair.KeyType = &defaultKeyType
	ps.Default.KeyPair.MLDSAKeyStrength = &defaultStrength

	req, err := BuildCloudCitRequest(ps, ca)
	require.NoError(t, err)
	require.Equal(t, []KeyType{{KeyType: "RSA", KeyLengths: []int{2048}}, {KeyType: CloudKeyTypeMLDSA, KeyStrengths: []int{87}}}, req.KeyAlgorithmTypes)
	require.Equal(t, &KeyAlgorithm{KeyType: CloudKeyTypeMLDSA, KeyStrength: 87}, req.RecommendedSettings.KeyAlgorithm)
}

func TestBuildCloudCitRequestWithoutMLDSAUsesKeyTypes(t *testing.T) {
	ps, ca := cloudPolicySpecificationForTest(t)
	req, err := BuildCloudCitRequest(ps, ca)
	require.NoError(t, err)
	require.NotContains(t, mustJSON(t, req), "keyAlgorithm")
	require.Equal(t, []KeyType{{KeyType: "RSA", KeyLengths: []int{2048}}}, req.KeyTypes)
	require.Equal(t, &Key{Type: "RSA", Length: 2048}, req.RecommendedSettings.Key)
}

func TestValidateMLDSAPolicySpecification(t *testing.T) {
	ps, _ := cloudPolicySpecificationForTest(t)
	ps.Policy.KeyPair.KeyTypes = []string{"MLDSA"}
	ps.Policy.KeyPair.MLDSAKeyStrengths = []int{50}
	ps.Default.KeyPair = nil
	require.ErrorContains(t, ValidateCloudPolicySpecification(ps), "mldsaKeyStrengths value: 50")

	ps.Policy.KeyPair.MLDSAKeyStrengths = []int{65}
	defaultKeyType, defaultStrength := "MLDSA", 87
	ps.Default.KeyPair = &DefaultKeyPair{KeyType: &defaultKeyType, MLDSAKeyStrength: &defaultStrength}
	require.ErrorContains(t, ValidateCloudPolicySpecification(ps), "doesn't match with specified policy mldsa key strengths")

	defaultStrength = 65
	require.NoError(t, ValidateCloudPolicySpecification(ps))

}

func TestTppPolicyMLDSA(t *testing.T) {
	defaultKeyType, defaultStrength := "MLDSA", 65
	ps := &PolicySpecification{
		Policy:  &Policy{KeyPair: &KeyPair{KeyTypes: []string{"RSA", "MLDSA"}, RsaKeySizes: []int{2048, 4096}, MLDSAKeyStrengths: []int{44, 65}}},
		Default: &Default{KeyPair: &DefaultKeyPair{KeyType: &defaultKeyType, MLDSAKeyStrength: &defaultStrength}},
	}
	require.NoError(t, ValidateTppPolicySpecification(ps))

	// ML-DSA can only be written as a PKIX parameter set, which covers every allowed key type
	tppPolicy := BuildTppPolicy(ps)
	require.NotNil(t, tppPolicy.PkixParameterSet)
	require.True(t, tppPolicy.PkixParameterSet.Locked)
	require.Equal(t, []string{
		"1.3.6.1.4.1.28783.10.1.1.2048", "1.3.6.1.4.1.28783.10.1.1.4096",
		"1.3.6.1.4.1.28783.10.4.44", "1.3.6.1.4.1.28783.10.4.65",
	}, tppPolicy.PkixParameterSet.Value)
	require.Equal(t, "1.3.6.1.4.1.28783.10.4.65", tppPolicy.PkixParameterSetDefault.Value)
	require.Nil(t, tppPolicy.KeyAlgorithm, "the deprecated Key Algorithm attribute can't hold ML-DSA")
	require.Nil(t, tppPolicy.KeyBitStrength)

	// an ML-DSA default without listed key types only sets the default
	ps = &PolicySpecification{Default: &Default{KeyPair: &DefaultKeyPair{KeyType: &defaultKeyType}}}
	tppPolicy = BuildTppPolicy(ps)
	require.Nil(t, tppPolicy.PkixParameterSet)
	require.Equal(t, "1.3.6.1.4.1.28783.10.4.65", tppPolicy.PkixParameterSetDefault.Value)

	// policies without ML-DSA keep using the deprecated attributes
	rsa := "RSA"
	tppPolicy = BuildTppPolicy(&PolicySpecification{Policy: &Policy{KeyPair: &KeyPair{KeyTypes: []string{rsa}, RsaKeySizes: []int{2048}}}})
	require.Nil(t, tppPolicy.PkixParameterSet)
	require.Equal(t, "RSA", tppPolicy.KeyAlgorithm.Value)

	// unsupported strengths are rejected
	ps = &PolicySpecification{Policy: &Policy{KeyPair: &KeyPair{KeyTypes: []string{"MLDSA"}, MLDSAKeyStrengths: []int{50}}}}
	require.ErrorContains(t, ValidateTppPolicySpecification(ps), "mldsaKeyStrengths value: 50")
}

func TestBuildPolicySpecificationForTPPMLDSA(t *testing.T) {
	tppPolicy := getPolicyResponse(false)
	tppPolicy.KeyPairResponse.PkixParameterSet = LockedArrayAttribute{
		Locked: true,
		Value:  []string{"1.3.6.1.4.1.28783.10.1.1.2048", "1.3.6.1.4.1.28783.10.4.44", "1.3.6.1.4.1.28783.10.4.65"},
	}
	tppPolicy.KeyPairResponse.DefaultPkixParameterSet = LockedAttribute{Value: "1.3.6.1.4.1.28783.10.4.65"}

	ps, err := BuildPolicySpecificationForTPP(CheckPolicyResponse{Policy: &tppPolicy})
	require.NoError(t, err)
	require.Equal(t, []string{"RSA", "MLDSA"}, ps.Policy.KeyPair.KeyTypes)
	require.Equal(t, []int{2048}, ps.Policy.KeyPair.RsaKeySizes)
	require.Equal(t, []int{44, 65}, ps.Policy.KeyPair.MLDSAKeyStrengths)
	require.Equal(t, "MLDSA", *ps.Default.KeyPair.KeyType)
	require.Equal(t, 65, *ps.Default.KeyPair.MLDSAKeyStrength)
	require.Nil(t, ps.Default.KeyPair.RsaKeySize)

	// getpolicy output is accepted as setpolicy input, and written back verbatim
	require.NoError(t, ValidateTppPolicySpecification(ps))
	require.Equal(t, tppPolicy.KeyPairResponse.PkixParameterSet.Value, BuildTppPolicy(ps).PkixParameterSet.Value)
}
