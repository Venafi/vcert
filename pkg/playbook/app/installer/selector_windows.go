//go:build windows

package installer

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
)

// GetInstaller returns a proper installer according to the type defined in inst
func GetInstaller(inst domain.Installation) Installer {
	switch inst.Type {
	case domain.TypeCAPI:
		return NewCAPIInstaller(inst)
	case domain.TypeJKS:
		return NewJKSInstaller(inst)
	case domain.TypePEM:
		return NewPEMInstaller(inst)
	case domain.TypePKCS12:
		return NewPKCS12Installer(inst)
	default:
		zap.L().Fatal(fmt.Sprintf("Runner not found for installation type: %s", inst.Type.String()))
		return nil
	}
}
