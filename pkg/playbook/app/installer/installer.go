package installer

import (
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain/certrequest"
)

// Installer represents the interface for all installers.
// A new Installer must implement this interface to be picked up.
type Installer interface {
	// Check is the method in charge of making the validations to install a new certificate:
	// 1. Does the certificate exists? > Install if it doesn't.
	// 2. Does the certificate is about to expire? Renew if about to expire.
	// Returns true if the certificate needs to be installed.
	Check(certFile string, renewBefore string, request certrequest.Request) (bool, error)

	// Prepare takes the certificate, chain and private key and converts them to the specific format required for the installer
	Prepare(request certificate.Request, pcc certificate.PEMCollection) (*certificate.PEMCollection, error)

	// Backup takes the certificate request and backs up the current version prior to overwriting
	Backup(filename string, request certificate.Request) error

	// Install takes the certificate bundle and moves it to the location specified in the installer
	Install(filename string, request certificate.Request, pcc certificate.PEMCollection) error

	// AfterInstallActions runs any instructions declared in the Installer on a terminal.
	//
	// No validations happen over the content of the AfterAction string, so caution is advised
	AfterInstallActions() error

	// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
	// "0" for successful validation and "1" for a validation failure
	// No validations happen over the content of the InsatllValidation string, so caution is advised
	InstallValidationActions() (string, error)
}
