package domain

import (
	"errors"
	"fmt"
)

const (
	DefaultFilepath = "./playbook.yaml"
	tlspcURL        = "api.venafi.cloud"
)

// Playbook represents a set of tasks  to run.
//
// The Config object holds the values required to connect to a Venafi platform.
//
// A task includes:
//   - a Request object that defines the values of the certificate to request
//   - a list of locations where the certificate will be installed
type Playbook struct {
	CertificateTasks CertificateTasks `yaml:"certificates,omitempty"`
	Config           Config           `yaml:"config,omitempty"`
	Location         string           `yaml:"-"`
}

// NewPlaybook returns a Playbook with some default values
func NewPlaybook() Playbook {
	return Playbook{
		CertificateTasks: make(CertificateTasks, 0),
		Config: Config{
			Connection: Connection{
				Type:            CTypeVaaS,
				URL:             tlspcURL,
				TrustBundlePath: "",
			},
		},
		Location: DefaultFilepath,
	}
}

// IsValid returns true if the playbook object has the minimum required values to run
func (p Playbook) IsValid() (bool, error) {
	var rErr error = nil
	rValid := true

	// Check that the specified config is valid
	valid, err := p.Config.IsValid()
	rErr = errors.Join(rErr, err)
	rValid = rValid && valid

	// There is at least one task to execute
	if len(p.CertificateTasks) < 1 {
		rValid = false
		rErr = errors.Join(rErr, ErrNoTasks)
	}

	taskNames := make(map[string]bool)
	// Check that the included certificate tasks are valid
	for _, t := range p.CertificateTasks {
		// Check that there are not multiple tasks with the same name
		if !taskNames[t.Name] {
			taskNames[t.Name] = true
		} else {
			rErr = errors.Join(rErr, fmt.Errorf("\ttask '%s' is defined multiple times", t.Name))
			rValid = false
		}

		_, err := t.IsValid()
		if err != nil {
			rErr = errors.Join(rErr, fmt.Errorf("\ttask '%s' is invalid: \n%w", t.Name, err))
			rValid = false
		}
	}

	return rValid, rErr

}
