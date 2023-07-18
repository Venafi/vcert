package certrequest

import (
	"strings"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"gopkg.in/yaml.v3"
)

// ChainOption represents the options to be used with the certificate chain
type ChainOption int

const (
	// ChainOptionUnknown represents an invalid option
	ChainOptionUnknown ChainOption = iota
	// ChainOptionIgnore specifies the chain should be ignored
	ChainOptionIgnore
	// ChainOptionRootFirst specifies the root certificate should be in the first position of the chain
	ChainOptionRootFirst
	// ChainOptionRootLast specifies the root certificate should be in the last position of the chain
	ChainOptionRootLast

	// String representations of the ChainOption types
	strChainOptionIgnore    = "ignore"
	strChainOptionRootFirst = "root-first"
	strChainOptionRootLast  = "root-last"
	strChainOptionUnknown   = "unknown"
)

// String returns a string representation of this object
func (co *ChainOption) String() string {
	switch *co {
	case ChainOptionIgnore:
		return strChainOptionIgnore
	case ChainOptionRootFirst:
		return strChainOptionRootFirst
	case ChainOptionRootLast:
		return strChainOptionRootLast
	default:
		return strChainOptionUnknown
	}
}

func parseChainOption(value string) (ChainOption, error) {
	switch strings.ToLower(value) {
	case strChainOptionIgnore:
		return ChainOptionIgnore, nil
	case strChainOptionRootFirst:
		return ChainOptionRootFirst, nil
	case strChainOptionRootLast:
		return ChainOptionRootLast, nil
	default:
		return ChainOptionUnknown, nil
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (co ChainOption) MarshalYAML() (interface{}, error) {
	return co.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (co *ChainOption) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*co, err = parseChainOption(strValue)
	if err != nil {
		return err
	}
	return nil
}

// ToVCert returns the representation in vcert of this value
func (co *ChainOption) ToVCert() vcert.ChainOption {
	switch *co {
	case ChainOptionRootFirst:
		return vcert.ChainOptionRootFirst
	case ChainOptionRootLast:
		return vcert.ChainOptionRootLast
	case ChainOptionIgnore:
		return vcert.ChainOptionIgnore
	default:
		return vcert.ChainOptionRootLast
	}
}
