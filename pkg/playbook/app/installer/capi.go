//go:build windows

package installer

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/util"
	"github.com/Venafi/vcert/v4/pkg/playbook/util/capistore"
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
func (r CAPIInstaller) Check(_ string, renewBefore string, request domain.PlaybookRequest) (bool, error) {
	zap.L().Debug(fmt.Sprintf("checking certificate at: %s", r.Location))

	friendlyName := request.Subject.CommonName
	if request.FriendlyName != "" {
		friendlyName = request.FriendlyName
	}

	storeLocation, storeName, err := getCertStore(r.Location)
	if err != nil {
		zap.L().Error(err.Error())
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
		zap.L().Error(fmt.Sprintf("failed to retrieve cetificate from CAPI store: %s", err.Error()))
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

// Prepare takes the certificate, chain and private key and converts them to the specific format required for the installer
func (r CAPIInstaller) Prepare(request certificate.Request, pcc certificate.PEMCollection) (*certificate.PEMCollection, error) {
	return prepareCertificateForBundle(request, pcc)
}

// Backup takes the certificate request and backs up the current version prior to overwriting
func (r CAPIInstaller) Backup(_ string, request certificate.Request) error {
	//Certificates are backed up by default for CAPI
	return nil
}

// Install takes the certificate bundle and moves it to the location specified in the installer
func (r CAPIInstaller) Install(_ string, request certificate.Request, pcc certificate.PEMCollection) error {
	content, err := packageAsPKCS12(pcc, request.KeyPassword)
	if err != nil {
		zap.L().Error("could not package certificate as PKCS12")
		return err
	}

	friendlyName := request.Subject.CommonName
	if request.FriendlyName != "" {
		friendlyName = request.FriendlyName
	}

	storeLocation, storeName, err := getCertStore(r.Location)
	if err != nil {
		zap.L().Error(err.Error())
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
		zap.L().Error(fmt.Sprintf("failed to install cetificate in CAPI store: %s", err.Error()))
		return err
	}

	return nil
}

// AfterInstallActions runs any instructions declared in the Installer on a terminal.
//
// No validations happen over the content of the AfterAction string, so caution is advised
func (r CAPIInstaller) AfterInstallActions() error {
	_, err := util.ExecuteScript(r.AfterAction)
	return err
}

// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
// "0" for successful validation and "1" for a validation failure
// No validations happen over the content of the InstallValidation string, so caution is advised
func (r CAPIInstaller) InstallValidationActions() (string, error) {
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
