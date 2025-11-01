/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package domain

import (
	"errors"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/venafi"
)

const (
	DefaultFilepath = "./playbook.yaml"
	tlspcURL        = "api.venafi.cloud"
)

// Playbook represents a set of tasks  to run.
//
// The Config object holds the values required to connect to a CyberArk platform.
//
// A task includes:
//   - a Request object that defines the values of the certificate to request
//   - a list of locations where the certificate will be installed
type Playbook struct {
	CertificateTasks CertificateTasks `yaml:"certificateTasks,omitempty"`
	Config           Config           `yaml:"config,omitempty"`
	Location         string           `yaml:"-"`
}

// NewPlaybook returns a Playbook with some default values
func NewPlaybook() Playbook {
	return Playbook{
		CertificateTasks: make(CertificateTasks, 0),
		Config: Config{
			Connection: Connection{
				Platform:        venafi.TLSPCloud,
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
			rErr = errors.Join(rErr, fmt.Errorf("task '%s' is defined multiple times", t.Name))
			rValid = false
		}

		_, err := t.IsValid()
		if err != nil {
			rErr = errors.Join(rErr, fmt.Errorf("task '%s' is invalid: %w", t.Name, err))
			rValid = false
		}
	}

	return rValid, rErr

}
