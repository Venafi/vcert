package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Venafi/vcert/v5/pkg/verror"
)

// KeyType represents the types of supported keys
type KeyType int

const (
	// KeyTypeRSA represents a key type of RSA
	KeyTypeRSA KeyType = iota
	// KeyTypeECDSA represents a key type of ECDSA
	KeyTypeECDSA
	// KeyTypeED25519 represents a key type of ED25519
	KeyTypeED25519
	// KeyTypeMLDSA44 represents the post-quantum ML-DSA-44 signature scheme (FIPS 204)
	KeyTypeMLDSA44
	// KeyTypeMLDSA65 represents the post-quantum ML-DSA-65 signature scheme (FIPS 204)
	KeyTypeMLDSA65
	// KeyTypeMLDSA87 represents the post-quantum ML-DSA-87 signature scheme (FIPS 204)
	KeyTypeMLDSA87

	// String representations of the KeyType types
	strKeyTypeECDSA   = "ECDSA"
	strKeyTypeRSA     = "RSA"
	strKeyTypeED25519 = "ED25519"
	strKeyTypeMLDSA44 = "ML-DSA-44"
	strKeyTypeMLDSA65 = "ML-DSA-65"
	strKeyTypeMLDSA87 = "ML-DSA-87"
)

// String returns a string representation of this object
func (kt *KeyType) String() string {
	switch *kt {
	case KeyTypeRSA:
		return strKeyTypeRSA
	case KeyTypeECDSA:
		return strKeyTypeECDSA
	case KeyTypeED25519:
		return strKeyTypeED25519
	case KeyTypeMLDSA44:
		return strKeyTypeMLDSA44
	case KeyTypeMLDSA65:
		return strKeyTypeMLDSA65
	case KeyTypeMLDSA87:
		return strKeyTypeMLDSA87
	default:
		return ""
	}
}

func (kt *KeyType) X509Type() x509.PublicKeyAlgorithm {
	switch *kt {
	case KeyTypeRSA:
		return x509.RSA
	case KeyTypeECDSA:
		return x509.ECDSA
	case KeyTypeED25519:
		return x509.Ed25519
	case KeyTypeMLDSA44, KeyTypeMLDSA65, KeyTypeMLDSA87:
		return x509.MLDSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

// Set the key type via a string
func (kt *KeyType) Set(value, curveValue string) error {
	switch strings.ToUpper(value) {
	case strKeyTypeRSA:
		*kt = KeyTypeRSA
		return nil
	case strKeyTypeECDSA, "EC", "ECC":
		curve := EllipticCurveNotSet
		if err := curve.Set(curveValue); err != nil {
			return err
		}
		if curve == EllipticCurveED25519 {
			*kt = KeyTypeED25519
			return nil
		}

		*kt = KeyTypeECDSA
		return nil
	}
	return fmt.Errorf("%w: unknown key type: %s", verror.VcertError, value) //todo: check all calls
}

func parseKeyType(value string) (KeyType, error) {
	switch strings.ToUpper(value) {
	case strKeyTypeECDSA:
		return KeyTypeECDSA, nil
	case strKeyTypeRSA:
		return KeyTypeRSA, nil
	case strKeyTypeED25519:
		return KeyTypeED25519, nil
	case strKeyTypeMLDSA44:
		return KeyTypeMLDSA44, nil
	case strKeyTypeMLDSA65:
		return KeyTypeMLDSA65, nil
	case strKeyTypeMLDSA87:
		return KeyTypeMLDSA87, nil
	default:
		return -1, fmt.Errorf("%w: unknown key type: %s", verror.VcertError, value)
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (kt KeyType) MarshalYAML() (interface{}, error) {
	return kt.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (kt *KeyType) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*kt, err = parseKeyType(strValue)
	if err != nil {
		return err
	}
	return nil
}
