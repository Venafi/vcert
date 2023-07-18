package certrequest

import (
	"strings"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"gopkg.in/yaml.v3"
)

// KeyType represents the types of supported keys
type KeyType int

const (
	// KeyTypeUnknown represents an invalid Key Type
	KeyTypeUnknown KeyType = iota
	// KeyTypeRSA represents a key type of RSA
	KeyTypeRSA
	// KeyTypeECDSA represents a key type of ECDSA
	KeyTypeECDSA

	// String representations of the KeyType types
	strKeyTypeECDSA   = "ecdsa"
	strKeyTypeRSA     = "rsa"
	strKeyTypeUnknown = "unknown"
)

// String returns a string representation of this object
func (kt *KeyType) String() string {
	switch *kt {
	case KeyTypeECDSA:
		return strKeyTypeECDSA
	case KeyTypeRSA:
		return strKeyTypeRSA
	default:
		return strKeyTypeUnknown
	}
}

func parseKeyType(value string) (KeyType, error) {
	switch strings.ToLower(value) {
	case strKeyTypeECDSA:
		return KeyTypeECDSA, nil
	case strKeyTypeRSA:
		return KeyTypeRSA, nil
	default:
		return KeyTypeUnknown, nil
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

// ToVCert returns the representation in vcert of this value
func (kt *KeyType) ToVCert() vcert.KeyType {
	switch *kt {
	case KeyTypeRSA:
		return vcert.KeyTypeRSA
	case KeyTypeECDSA:
		return vcert.KeyTypeECDSA
	default:
		return vcert.KeyTypeRSA
	}
}
