/*
 * Copyright 2023 Venafi, Inc.
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
)

// CertificateTask represents a task to be run:
// A certificate to be requested/renewed and installed in one (or more) location(s)
type CertificateTask struct {
	Name          string          `yaml:"name,omitempty"`
	Request       PlaybookRequest `yaml:"request,omitempty"`
	Installations Installations   `yaml:"installations,omitempty"`
	RenewBefore   string          `yaml:"renewBefore,omitempty"`
	SetEnvVars    []string        `yaml:"setEnvVars,omitempty"`
}

// CertificateTasks is a slice of CertificateTask
type CertificateTasks []CertificateTask

// IsValid returns true if the CertificateTask has the minimum required fields to be run
func (task CertificateTask) IsValid() (bool, error) {
	var rErr error = nil
	rValid := true

	// Each certificate request needs a zone, required field
	if task.Request.Zone == "" {
		rValid = false
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", ErrNoRequestZone))
	}

	if task.Request.Subject.CommonName == "" {
		rValid = false
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", ErrNoRequestCN))
	}

	// This task has no installations defined
	if task.Installations == nil || len(task.Installations) < 1 {
		rValid = false
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", ErrNoInstallations))
	}

	// Validate each installation
	for i, installation := range task.Installations {
		_, err := installation.IsValid()
		if err != nil {
			rErr = errors.Join(rErr, fmt.Errorf("\t\tinstallations[%d]:\n%w", i, err))
			rValid = false
		}
	}

	return rValid, rErr
}
