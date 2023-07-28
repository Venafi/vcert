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

package installer

import (
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
)

// Installer represents the interface for all installers.
// A new Installer must implement this interface to be picked up.
type Installer interface {

	// Check is the method in charge of making the validations to install a new certificate:
	// 1. Does the certificate exists? > Install if it doesn't.
	// 2. Does the certificate is about to expire? Renew if about to expire.
	// Returns true if the certificate needs to be installed.
	Check(renewBefore string, request domain.PlaybookRequest) (bool, error)

	// Backup takes the certificate request and backs up the current version prior to overwriting
	Backup() error

	// Install takes the certificate bundle and moves it to the location specified in the installer
	Install(request domain.PlaybookRequest, pcc certificate.PEMCollection) error

	// AfterInstallActions runs any instructions declared in the Installer on a terminal.
	//
	// No validations happen over the content of the AfterAction string, so caution is advised
	AfterInstallActions() error

	// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
	// "0" for successful validation and "1" for a validation failure
	// No validations happen over the content of the InstallValidation string, so caution is advised
	InstallValidationActions() (string, error)
}
