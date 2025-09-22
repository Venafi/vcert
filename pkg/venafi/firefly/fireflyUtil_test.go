package firefly

import (
	"testing"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/stretchr/testify/assert"
)

func TestGetRSASize(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		rsaSizeGotten, err := GetRSASize(0)
		assert.Nil(t, err)
		assert.Equal(t, certificate.DefaultRSAlength, rsaSizeGotten)
	})
	t.Run("2048", func(t *testing.T) {
		rsaSizeGotten, err := GetRSASize(2048)
		assert.Nil(t, err)
		assert.Equal(t, certificate.DefaultRSAlength, rsaSizeGotten)
	})
	t.Run("3072", func(t *testing.T) {
		rsaSizeGotten, err := GetRSASize(3072)
		assert.Nil(t, err)
		assert.Equal(t, 3072, rsaSizeGotten)
	})
	t.Run("4096", func(t *testing.T) {
		rsaSizeGotten, err := GetRSASize(4096)
		assert.Nil(t, err)
		assert.Equal(t, 4096, rsaSizeGotten)
	})
	t.Run("unsupported", func(t *testing.T) {
		_, err := GetRSASize(1024)
		if assert.Errorf(t, err, "I was expected an error but is nil") {
			assert.ErrorContains(t, err, "key size 1024 is not supported. Valid RSA sizes for CyberArk Workload Identity Manager are ")
		}
	})
}
