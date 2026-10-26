package policy

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

const (
	// CloudKeyTypeMLDSA is the key type CyberArk Certificate Manager, SaaS and NGTS use for ML-DSA in an issuing
	// template's keyAlgorithmTypes and recommended key. The parameter set is carried separately as a key strength.
	CloudKeyTypeMLDSA = "ML_DSA"

	// KeyTypeMLDSA is the policy specification key type for ML-DSA, with the strengths in mldsaKeyStrengths and the
	// default strength in mldsaKeyStrength
	KeyTypeMLDSA = "MLDSA"

	// defaultMLDSAKeyStrength is allowed when a policy specification allows ML-DSA without listing strengths
	defaultMLDSAKeyStrength = 65

	// defaultRSAKeySize and defaultEllipticCurve are allowed when a policy specification allows RSA or ECDSA
	// without listing sizes or curves
	defaultRSAKeySize    = 2048
	defaultEllipticCurve = "P256"
)

// IsMLDSAKeyType returns true when a policy specification key type is ML-DSA
func IsMLDSAKeyType(keyType string) bool {
	normalized := strings.NewReplacer("-", "", "_", "").Replace(strings.ToUpper(keyType))
	return normalized == KeyTypeMLDSA
}

// mldsaKeyStrengths returns the ML-DSA strengths allowed by the policy specification, or nil when it doesn't
// allow ML-DSA. When the policy doesn't list key types, an ML-DSA default key type is allowed, in the same way that
// the default RSA key size is.
func mldsaKeyStrengths(ps *PolicySpecification) []int {
	allowed := false
	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
		allowed = slices.ContainsFunc(ps.Policy.KeyPair.KeyTypes, IsMLDSAKeyType)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.KeyType != nil {
		allowed = IsMLDSAKeyType(*(ps.Default.KeyPair.KeyType))
	}
	if !allowed {
		return nil
	}

	var strengths []int
	switch {
	case ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.MLDSAKeyStrengths) > 0:
		strengths = slices.Clone(ps.Policy.KeyPair.MLDSAKeyStrengths)
	case ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.MLDSAKeyStrength != nil:
		strengths = []int{*(ps.Default.KeyPair.MLDSAKeyStrength)}
	default:
		strengths = []int{defaultMLDSAKeyStrength}
	}
	sort.Ints(strengths)
	return slices.Compact(strengths)
}

// validateMLDSAKeyStrengths checks the ML-DSA strengths of a policy specification
func validateMLDSAKeyStrengths(ps *PolicySpecification) error {
	supported := certificate.AllSupportedMLDSAStrengths()
	if ps.Policy != nil && ps.Policy.KeyPair != nil {
		for _, strength := range ps.Policy.KeyPair.MLDSAKeyStrengths {
			if !slices.Contains(supported, strength) {
				return fmt.Errorf("specified attribute mldsaKeyStrengths value: %d is not supported, must be one of %v", strength, supported)
			}
		}
	}
	if ps.Default == nil || ps.Default.KeyPair == nil || ps.Default.KeyPair.MLDSAKeyStrength == nil {
		return nil
	}
	strength := *(ps.Default.KeyPair.MLDSAKeyStrength)
	if !slices.Contains(supported, strength) {
		return fmt.Errorf("specified default attribute mldsaKeyStrength value: %d is not supported, must be one of %v", strength, supported)
	}
	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.MLDSAKeyStrengths) > 0 &&
		!slices.Contains(ps.Policy.KeyPair.MLDSAKeyStrengths, strength) {
		return fmt.Errorf("specified default mldsa key strength value: %d doesn't match with specified policy mldsa key strengths", strength)
	}
	return nil
}

// tppPkixParameterSetForMLDSA returns the PKIX parameter set OIDs to write for a policy specification that allows
// ML-DSA, and the OID of its default key algorithm. CyberArk Certificate Manager, Self-Hosted can only express ML-DSA
// as PKIX parameter set OIDs (TPP 25.1+), so every allowed key type is written that way. allowed is nil when the
// policy doesn't list key types, and both are empty when the policy specification doesn't involve ML-DSA or sets
// pkixParameterSet itself.
func tppPkixParameterSetForMLDSA(ps *PolicySpecification) (allowed []string, defaultOid string) {
	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.PkixParameterSet) > 0 {
		return nil, ""
	}
	strengths := mldsaKeyStrengths(ps)
	if strengths == nil {
		return nil, ""
	}

	var defaultKeyPair *DefaultKeyPair
	if ps.Default != nil {
		defaultKeyPair = ps.Default.KeyPair
	}
	rsaSizes, curves := []int{defaultRSAKeySize}, []string{defaultEllipticCurve}
	if defaultKeyPair != nil && defaultKeyPair.RsaKeySize != nil {
		rsaSizes = []int{*(defaultKeyPair.RsaKeySize)}
	}
	if defaultKeyPair != nil && defaultKeyPair.EllipticCurve != nil && *(defaultKeyPair.EllipticCurve) != "" {
		curves = []string{*(defaultKeyPair.EllipticCurve)}
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
		keyPair := ps.Policy.KeyPair
		if len(keyPair.RsaKeySizes) > 0 {
			rsaSizes = keyPair.RsaKeySizes
		}
		if len(keyPair.EllipticCurves) > 0 {
			curves = keyPair.EllipticCurves
		}
		for _, keyType := range keyPair.KeyTypes {
			allowed = append(allowed, tppPkixOids(keyType, rsaSizes, curves, strengths)...)
		}
	}

	if defaultKeyPair != nil && defaultKeyPair.KeyType != nil && *(defaultKeyPair.KeyType) != "" {
		defaultStrengths := strengths[:1]
		if defaultKeyPair.MLDSAKeyStrength != nil {
			defaultStrengths = []int{*(defaultKeyPair.MLDSAKeyStrength)}
		}
		if oids := tppPkixOids(*(defaultKeyPair.KeyType), rsaSizes[:1], curves[:1], defaultStrengths); len(oids) > 0 {
			defaultOid = oids[0]
		}
	}
	return allowed, defaultOid
}

// tppPkixOids returns the PKIX parameter set OIDs of a policy specification key type
func tppPkixOids(keyType string, rsaSizes []int, curves []string, strengths []int) []string {
	var oids []string
	switch {
	case strings.EqualFold(keyType, "RSA"):
		for _, size := range rsaSizes {
			oids = append(oids, KeyAlgorithmsToPKIX["RSA"][strconv.Itoa(size)])
		}
	case IsMLDSAKeyType(keyType):
		for _, strength := range strengths {
			oids = append(oids, KeyAlgorithmsToPKIX[KeyTypeMLDSA][strconv.Itoa(strength)])
		}
	case existStringInArray([]string{keyType}, TppKeyType):
		for _, curve := range curves {
			oids = append(oids, KeyAlgorithmsToPKIX["ECC"][strings.ToUpper(curve)])
		}
	}
	return slices.DeleteFunc(oids, func(oid string) bool { return oid == "" })
}
