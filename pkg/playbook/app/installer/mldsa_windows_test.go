//go:build windows

package installer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
)

func TestMLDSACAPIInstallRejected(t *testing.T) {
	bundle, _ := mldsaBundle(t)
	err := NewCAPIInstaller(domain.Installation{CAPILocation: "LocalMachine\\My"}).Install(*bundle)
	require.ErrorContains(t, err, "ML-DSA certificates are not supported by the CAPI installer")
}
