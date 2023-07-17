package domain

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// ConnectionType represents the type of connection for certificate issuance:
// TPP, TLSPC, Firefly, etc.
type ConnectionType int64

const (
	// CTypeUnknown represents an invalid ConnectionType
	CTypeUnknown ConnectionType = iota
	// CTypeTPP represents a connection to TPP
	CTypeTPP
	// CTypeVaaS represents a connection to VaaS
	CTypeVaaS
	// CTypeFirefly represents a connection to Firefly
	CTypeFirefly

	// String representations of the ConnectionType types
	stringCTypeTPP     = "TPP"
	stringCTypeVaaS    = "VAAS"
	stringCTypeFirefly = "FIREFLY"
	stringCTypeUnknown = "Unknown"

	// Some alias names for TPP & VaaS
	stringCTypeTLSPDC = "TLSPDC"
	stringCTypeTLSPC  = "TLSPC"
)

// String returns a string representation of this object
func (ct *ConnectionType) String() string {
	switch *ct {
	case CTypeTPP:
		return stringCTypeTPP
	case CTypeVaaS:
		return stringCTypeVaaS
	case CTypeFirefly:
		return stringCTypeFirefly
	default:
		return stringCTypeUnknown
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (ct ConnectionType) MarshalYAML() (interface{}, error) {
	return ct.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (ct *ConnectionType) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*ct, err = parseConnectionType(strValue)
	if err != nil {
		return err
	}
	return nil
}

func parseConnectionType(strConnectionType string) (ConnectionType, error) {
	switch strings.ToUpper(strConnectionType) {
	case stringCTypeTPP, stringCTypeTLSPDC:
		return CTypeTPP, nil
	case stringCTypeVaaS, stringCTypeTLSPC:
		return CTypeVaaS, nil
	case stringCTypeFirefly:
		return CTypeFirefly, nil
	default:
		return CTypeUnknown, nil
	}
}
