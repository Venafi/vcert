package certrequest

import (
	"strings"

	vcert "github.com/Venafi/vcert/v4/pkg/certificate"
)

// Location represents a Device that needs enrollment or provisioning
type Location struct {
	Instance   string `yaml:"instance,omitempty"`
	TLSAddress string `yaml:"tlsAddress,omitempty"`
	Replace    bool   `yaml:"replace,omitempty"`
}

// ToVCert returns the representation in vcert of this value
func (l *Location) ToVCert() *vcert.Location {
	if l.Instance == "" {
		return nil
	}

	segments := strings.Split(l.Instance, ":")
	instance := segments[0]
	workload := ""
	if len(segments) > 1 {
		workload = segments[1]
	}

	return &vcert.Location{
		Instance:   instance,
		Workload:   workload,
		TLSAddress: l.TLSAddress,
		Replace:    l.Replace,
	}
}
