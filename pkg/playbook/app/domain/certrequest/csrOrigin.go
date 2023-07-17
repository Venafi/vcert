package certrequest

import (
	"strings"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
	"gopkg.in/yaml.v3"
)

// CsrOriginOption represents the options available for the origin of a CSR
type CsrOriginOption int

const (
	// CSRUnknown represents an invalid option
	CSRUnknown CsrOriginOption = iota
	// CSRLocalGenerated - vcert will generate the CSR on the host machine
	CSRLocalGenerated
	// CSRServiceGenerated - server generates CSR internally based on zone configuration and data from Request
	CSRServiceGenerated
	// CSRUserProvided - client provides CSR from external resource and vcert library just check and send this CSR to server
	CSRUserProvided

	// String representations of the CsrOriginOption types
	strCSRLocalGenerated   = "local"
	strCSRServiceGenerated = "service"
	strCSRUserProvided     = "user"
	strCSRUnknown          = "unknown"
)

// String returns a string representation of this object
func (csr *CsrOriginOption) String() string {
	switch *csr {
	case CSRLocalGenerated:
		return strCSRLocalGenerated
	case CSRServiceGenerated:
		return strCSRServiceGenerated
	case CSRUserProvided:
		return strCSRUserProvided
	default:
		return strCSRUnknown
	}
}

func parseCSROrigin(value string) (CsrOriginOption, error) {
	switch strings.ToLower(value) {
	case strCSRLocalGenerated:
		return CSRLocalGenerated, nil
	case strCSRServiceGenerated:
		return CSRServiceGenerated, nil
	case strCSRUserProvided:
		return CSRUserProvided, nil
	default:
		return CSRUnknown, nil
	}
}

// MarshalYAML customizes the behavior of ChainOption when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (csr CsrOriginOption) MarshalYAML() (interface{}, error) {
	return csr.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (csr *CsrOriginOption) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}
	*csr, err = parseCSROrigin(strValue)
	if err != nil {
		return err
	}
	return nil
}

// ToVCert returns the representation in vcert of this value
func (csr *CsrOriginOption) ToVCert() vcert.CSrOriginOption {
	switch *csr {
	case CSRLocalGenerated:
		return vcert.LocalGeneratedCSR
	case CSRServiceGenerated:
		return vcert.ServiceGeneratedCSR
	case CSRUserProvided:
		return vcert.UserProvidedCSR
	default:
		return vcert.ServiceGeneratedCSR
	}
}
