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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/util"
)

// PEMInstaller represents an installation that will use the PEM format for the certificate bundle
type PEMInstaller struct {
	domain.Installation
}

// NewPEMInstaller returns a new installer of type PEM with the values defined in inst
func NewPEMInstaller(inst domain.Installation) PEMInstaller {
	return PEMInstaller{inst}
}

// Check is the method in charge of making the validations to install a new certificate:
// 1. Does the certificate exists? > Install if it doesn't.
// 2. Does the certificate is about to expire? Renew if about to expire.
// Returns true if the certificate needs to be installed.
func (r PEMInstaller) Check(_ string, renewBefore string, _ domain.PlaybookRequest) (bool, error) {
	certPath := filepath.Join(r.Location, r.PEMCertFilename)
	zap.L().Debug(fmt.Sprintf("checking certificate at: %s", certPath))

	// Check certificate file exists
	certExists, err := util.FileExists(certPath)
	if err != nil {
		return false, err
	}
	if !certExists {
		return true, nil
	}

	// Load Certificate
	cert, err := loadPEMCertificate(certPath)
	if err != nil {
		return false, err
	}

	// Check certificate expiration
	renew := needRenewal(cert, renewBefore)

	return renew, nil
}

// Prepare takes the certificate, chain and private key and converts them to the specific format required for the installer
func (r PEMInstaller) Prepare(request certificate.Request, pcc certificate.PEMCollection) (*certificate.PEMCollection, error) {
	return prepareCertificateForBundle(request, pcc)
}

// Backup takes the certificate request and backs up the current version prior to overwriting
func (r PEMInstaller) Backup(_ string, _ certificate.Request) error {
	certPath := filepath.Join(r.Location, r.PEMCertFilename)
	keyPath := filepath.Join(r.Location, r.PEMKeyFilename)
	chainPath := filepath.Join(r.Location, r.PEMChainFilename)

	// Check certificate file exists
	certExists, err := util.FileExists(certPath)
	if err != nil {
		return err
	}
	if !certExists {
		zap.L().Info(fmt.Sprintf("new certificate location specified, no backup taken"))
		return nil
	}

	resources := []struct {
		oldLocation string
		newLocation string
	}{
		{oldLocation: certPath, newLocation: fmt.Sprintf("%s.bak", certPath)},
		{oldLocation: keyPath, newLocation: fmt.Sprintf("%s.bak", keyPath)},
		{oldLocation: chainPath, newLocation: fmt.Sprintf("%s.bak", chainPath)},
	}

	for _, resource := range resources {
		fileExists, err := util.FileExists(resource.oldLocation)
		if err != nil {
			return err
		} else if !fileExists {
			zap.L().Info(fmt.Sprintf("file %s does not exist, no backup taken", resource.oldLocation))
			continue
		}
		err = util.CopyFile(resource.oldLocation, resource.newLocation)
		if err != nil {
			return err
		}
	}

	return nil
}

// Install takes the certificate bundle and moves it to the location specified in the installer
func (r PEMInstaller) Install(_ string, _ certificate.Request, pcc certificate.PEMCollection) error {
	err := os.MkdirAll(r.Location, 0750)
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not create certificate directory path %s: %s", r.Location, err.Error()))
		return err
	}

	resources := []struct {
		path    string
		content []byte
	}{
		{path: filepath.Join(r.Location, r.PEMCertFilename), content: []byte(pcc.Certificate)},
		{path: filepath.Join(r.Location, r.PEMKeyFilename), content: []byte(pcc.PrivateKey)},
		{path: filepath.Join(r.Location, r.PEMChainFilename), content: []byte(strings.Join(pcc.Chain, ""))},
	}

	for _, resource := range resources {
		if len(resource.content) == 0 {
			continue
		}
		err = util.WriteFile(resource.path, resource.content)
		if err != nil {
			return err
		}
	}

	return nil
}

// AfterInstallActions runs any instructions declared in the Installer on a terminal.
//
// No validations happen over the content of the AfterAction string, so caution is advised
func (r PEMInstaller) AfterInstallActions() error {
	_, err := util.ExecuteScript(r.AfterAction)
	return err
}

// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
// "0" for successful validation and "1" for a validation failure
// No validations happen over the content of the InstallValidation string, so caution is advised
func (r PEMInstaller) InstallValidationActions() (string, error) {
	validationResult, err := util.ExecuteScript(r.InstallValidation)
	if err != nil {
		return "", err
	}

	return validationResult, err
}
