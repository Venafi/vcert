package domain

import (
	"fmt"
	"runtime"
	"strings"
)

// Installation represents a location in which a certificate will be installed,
// along with the format in which it will be installed
type Installation struct {
	AfterAction         string           `yaml:"afterInstallAction,omitempty"`
	BackupFiles         bool             `yaml:"backupFiles,omitempty"`
	CAPIIsNonExportable bool             `yaml:"capiIsNonExportable,omitempty"`
	InstallValidation   string           `yaml:"installValidationAction,omitempty"`
	JKSAlias            string           `yaml:"jksAlias,omitempty"`
	JKSPassword         string           `yaml:"jksPassword,omitempty"`
	Location            string           `yaml:"location,omitempty"`
	PEMCertFilename     string           `yaml:"pemCertFilename,omitempty"`
	PEMChainFilename    string           `yaml:"pemChainFilename,omitempty"`
	PEMKeyFilename      string           `yaml:"pemKeyFilename,omitempty"`
	Type                InstallationType `yaml:"type,omitempty"`
}

// Installations is a slice of Installation
type Installations []Installation

func (installation Installation) IsValid() (bool, error) {
	switch installation.Type {
	case TypeJKS:
		if err := validateJKS(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypePEM:
		if err := validatePEM(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypePKCS12:
		if err := validateP12(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypeCAPI:
		if err := validateCAPI(installation); err != nil {
			return false, fmt.Errorf("\t\t\t%w", err)
		}
	case TypeUnknown:
		return false, fmt.Errorf("\t\t\t%w", ErrUndefinedInstallationType)
	default:
		return false, fmt.Errorf("\t\t\t%w", ErrUndefinedInstallationType)
	}

	return true, nil
}

const (
	capiLocationCurrentUser  = "currentuser"
	capiLocationLocalMachine = "localmachine"
)

var validStoreNames = []string{"addressbook", "authroot", "certificateauthority", "disallowed", "my", "root", "trustedpeople", "trustedpublisher"}

func validateCAPI(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}

	if runtime.GOOS != "windows" {
		return ErrCAPIOnNonWindows
	}

	// Ensure proper location specified
	segments := strings.Split(installation.Location, "\\")

	// CAPI Location must be in form of <string>\<string>
	if len(segments) != 2 {
		return ErrMalformedCAPILocation
	}

	location := strings.ToLower(segments[0])
	if location != capiLocationCurrentUser && location != capiLocationLocalMachine {
		return ErrInvalidCAPILocation
	}

	// valid store names from https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename?view=net-7.0
	// Although it is unlikely that you'd want to install a certificate and private key in anything but "my", here for completeness
	isValidStoreName := false
	for _, v := range validStoreNames {
		if v == strings.ToLower(segments[1]) {
			isValidStoreName = true
			break
		}
	}

	if !isValidStoreName {
		return ErrInvalidCAPIStoreName
	}

	return nil
}

// JKSMinPasswordLength represents the minimum length a JKS password must have per the JKS specification
const JKSMinPasswordLength = 6

func validateJKS(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}

	if installation.JKSAlias == "" {
		return ErrNoJKSAlias
	}
	if installation.JKSPassword == "" {
		return ErrNoJKSPassword
	}
	if len(installation.JKSPassword) < JKSMinPasswordLength {
		return ErrJKSPasswordLength
	}
	return nil
}

func validatePEM(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}

	if installation.PEMCertFilename == "" {
		return ErrNoPEMCertFilename
	}
	if installation.PEMChainFilename == "" {
		return ErrNoPEMChainFilename
	}
	if installation.PEMKeyFilename == "" {
		return ErrNoPEMKeyFilename
	}
	return nil
}

func validateP12(installation Installation) error {
	if installation.Location == "" {
		return ErrNoInstallationLocation
	}
	return nil
}
