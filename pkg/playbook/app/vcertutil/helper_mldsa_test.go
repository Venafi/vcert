package vcertutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
)

func TestSetKeyTypeMLDSA(t *testing.T) {
	// the playbook keySize of an ML-DSA key is its strength, which never becomes an RSA key size
	vcertRequest := &certificate.Request{}
	setKeyType(domain.PlaybookRequest{KeyType: certificate.KeyTypeMLDSA, KeyLength: 87}, vcertRequest)
	require.Equal(t, certificate.KeyTypeMLDSA, vcertRequest.KeyType)
	require.Equal(t, 87, vcertRequest.KeyStrength)
	require.Zero(t, vcertRequest.KeyLength)
}
