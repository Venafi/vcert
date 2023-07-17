package certrequest

import (
	"strings"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"gopkg.in/yaml.v3"
)

// EllipticCurve represents the types of supported elliptic curves
type EllipticCurve int

const (
	// EccUnknown represents an invalid curve
	EccUnknown EllipticCurve = iota
	// EccP256 represents the P256 curve
	EccP256
	// EccP384 represents the P384 curve
	EccP384
	// EccP521 represents the P521 curve
	EccP521
	// EccED25519 represents the ED25519 curve
	EccED25519

	// String representations of the EllipticCurve types
	strEccP256    = "P256"
	strEccP384    = "P384"
	strEccP521    = "P521"
	strEccED25519 = "ED25519"
	strEccUnknown = "unknown"
)

// String returns a string representation of this object
func (ec *EllipticCurve) String() string {
	switch *ec {
	case EccP256:
		return strEccP256
	case EccP384:
		return strEccP384
	case EccP521:
		return strEccP521
	case EccED25519:
		return strEccED25519
	default:
		return strEccUnknown
	}
}

func parseEllipticCurve(value string) (EllipticCurve, error) {
	switch strings.ToUpper(value) {
	case strEccP256:
		return EccP256, nil
	case strEccP384:
		return EccP384, nil
	case strEccP521:
		return EccP521, nil
	case strEccED25519:
		return EccED25519, nil
	default:
		return EccUnknown, nil
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (ec EllipticCurve) MarshalYAML() (interface{}, error) {
	return ec.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (ec *EllipticCurve) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*ec, err = parseEllipticCurve(strValue)
	if err != nil {
		return err
	}
	return nil
}

// ToVCert returns the representation in vcert of this value
func (ec *EllipticCurve) ToVCert() vcert.EllipticCurve {
	switch *ec {
	case EccP256:
		return vcert.EllipticCurveP256
	case EccP384:
		return vcert.EllipticCurveP384
	case EccP521:
		return vcert.EllipticCurveP521
	case EccED25519:
		return vcert.EllipticCurveED25519
	default:
		return vcert.EllipticCurveDefault
	}
}
