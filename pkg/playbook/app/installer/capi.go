//go:build windows

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
	"strings"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/playbook/util"
	"github.com/Venafi/vcert/v5/pkg/playbook/util/capistore"
)

// CAPIInstaller represents an installation that will happen in the Windows CAPI store
type CAPIInstaller struct {
	domain.Installation
}

// NewCAPIInstaller returns a new installer of type CAPI with the values defined in inst
func NewCAPIInstaller(inst domain.Installation) CAPIInstaller {
	return CAPIInstaller{inst}
}

// Check is the method in charge of making the validations to install a new certificate:
// 1. Does the certificate exists? > Install if it doesn't.
// 2. Does the certificate is about to expire? Renew if about to expire.
// Returns true if the certificate needs to be installed.
func (r CAPIInstaller) Check(renewBefore string, request domain.PlaybookRequest) (bool, error) {
	zap.L().Debug("checking certificate", zap.String("location", r.Location))

	friendlyName := request.Subject.CommonName
	if request.FriendlyName != "" {
		friendlyName = request.FriendlyName
	}

	storeLocation, storeName, err := getCertStore(r.Location)
	if err != nil {
		zap.L().Error("failed to get certificate store", zap.Error(err))
		return true, err
	}

	config := capistore.InstallationConfig{
		FriendlyName:  friendlyName,
		StoreLocation: storeLocation,
		StoreName:     storeName,
	}

	ps := capistore.NewPowerShell()

	certPem, err := ps.RetrieveCertificateFromCAPI(config)
	if err != nil {
		zap.L().Error("failed to retrieve certificate from CAPI store", zap.Error(err))
		return true, err
	}

	// Certificate was not found.
	if certPem == "" {
		zap.L().Info("certificate not found")
		return true, nil
	}

	// Check certificate expiration
	cert, err := parsePEMCertificate([]byte(certPem))
	if err != nil {
		return false, err
	}

	// Check certificate expiration
	renew := needRenewal(cert, renewBefore)

	return renew, nil
}

// Backup takes the certificate request and backs up the current version prior to overwriting
func (r CAPIInstaller) Backup() error {
	zap.L().Debug("certificate is backed up by default for CAPI")
	return nil
}

// Install takes the certificate bundle and moves it to the location specified in the installer
func (r CAPIInstaller) Install(request domain.PlaybookRequest, pcc certificate.PEMCollection) error {
	zap.L().Debug("installing certificate", zap.String("location", r.Location))

	content, err := packageAsPKCS12(pcc, request.KeyPassword)
	if err != nil {
		zap.L().Error("could not package certificate as PKCS12", zap.Error(err))
		return err
	}

	friendlyName := request.Subject.CommonName
	if request.FriendlyName != "" {
		friendlyName = request.FriendlyName
	}

	storeLocation, storeName, err := getCertStore(r.Location)
	if err != nil {
		zap.L().Error("failed to get certificate store", zap.Error(err))
		return err
	}

	config := capistore.InstallationConfig{
		PFX:             content,
		FriendlyName:    friendlyName,
		IsNonExportable: r.CAPIIsNonExportable,
		Password:        request.KeyPassword,
		StoreLocation:   storeLocation,
		StoreName:       storeName,
	}

	ps := capistore.NewPowerShell()

	err = ps.InstallCertificateToCAPI(config)
	if err != nil {
		zap.L().Error("failed to install certificate in CAPI store", zap.Error(err))
		return err
	}

	return nil
}

// AfterInstallActions runs any instructions declared in the Installer on a terminal.
//
// No validations happen over the content of the AfterAction string, so caution is advised
func (r CAPIInstaller) AfterInstallActions() error {
	zap.L().Debug("running after-install actions", zap.String("location", r.Location))

	_, err := util.ExecuteScript(r.AfterAction)
	return err
}

// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
// "0" for successful validation and "1" for a validation failure
// No validations happen over the content of the InstallValidation string, so caution is advised
func (r CAPIInstaller) InstallValidationActions() (string, error) {
	zap.L().Debug("running install validation actions", zap.String("location", r.Location))
	validationResult, err := util.ExecuteScript(r.InstallValidation)
	if err != nil {
		return "", err
	}

	return validationResult, err
}

func getCertStore(location string) (string, string, error) {
	segments := strings.Split(location, "\\")

	if len(segments) != 2 {
		return "", "", fmt.Errorf("invalid CAPI location: '%s'. Should be in form of 'StoreLocation\\StoreName' (i.e. 'LocalMachine\\My')", location)
	}

	return segments[0], segments[1], nil
}
