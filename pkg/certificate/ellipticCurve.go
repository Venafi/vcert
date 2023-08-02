package certificate

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// EllipticCurve represents the types of supported elliptic curves
type EllipticCurve int

const (
	// EllipticCurveNotSet represents a value not set
	EllipticCurveNotSet EllipticCurve = iota
	// EllipticCurveP521 represents the P521 curve
	EllipticCurveP521
	// EllipticCurveP256 represents the P256 curve
	EllipticCurveP256
	// EllipticCurveP384 represents the P384 curve
	EllipticCurveP384
	// EllipticCurveED25519 represents the ED25519 curve
	EllipticCurveED25519
	// EllipticCurveDefault represents the default curve value
	EllipticCurveDefault = EllipticCurveP256

	// String representations of the EllipticCurve types
	strEccP256    = "P256"
	strEccP384    = "P384"
	strEccP521    = "P521"
	strEccED25519 = "ED25519"
)

func (ec *EllipticCurve) String() string {
	switch *ec {
	case EllipticCurveP521:
		return strEccP521
	case EllipticCurveP384:
		return strEccP384
	case EllipticCurveP256:
		return strEccP256
	case EllipticCurveED25519:
		return strEccED25519
	default:
		return ""
	}
}

// Set EllipticCurve value via a string
func (ec *EllipticCurve) Set(value string) error {
	switch strings.ToUpper(value) {
	case strEccP521, "P-521":
		*ec = EllipticCurveP521
	case strEccP384, "P-384":
		*ec = EllipticCurveP384
	case strEccP256, "P-256":
		*ec = EllipticCurveP256
	case strEccED25519:
		*ec = EllipticCurveED25519
	default:
		*ec = EllipticCurveDefault
	}

	return nil
}

func parseEllipticCurve(value string) EllipticCurve {
	switch strings.ToUpper(value) {
	case strEccP256, "P-256":
		return EllipticCurveP256
	case strEccP384, "P-384":
		return EllipticCurveP384
	case strEccP521, "P-521":
		return EllipticCurveP521
	case strEccED25519:
		return EllipticCurveED25519
	default:
		return EllipticCurveDefault
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

	*ec = parseEllipticCurve(strValue)

	return nil
}

func AllSupportedCurves() []EllipticCurve {
	return []EllipticCurve{EllipticCurveP521, EllipticCurveP256, EllipticCurveP384, EllipticCurveED25519}
}
