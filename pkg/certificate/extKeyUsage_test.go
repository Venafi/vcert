package certificate

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExtKeyUsage_Parse(t *testing.T) {

	t.Run("Any", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("Any")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageAny, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "Any", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageAnyOid, oid)
		})
	})
	t.Run("ServerAuth", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("ServerAuth")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageServerAuth, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "ServerAuth", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageServerAuthOid, oid)
		})
	})
	t.Run("ClientAuth", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("ClientAuth")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageClientAuth, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "ClientAuth", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageClientAuthOid, oid)
		})
	})
	t.Run("CodeSigning", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("CodeSigning")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageCodeSigning, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "CodeSigning", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageCodeSigningOid, oid)
		})
	})
	t.Run("EmailProtection", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("EmailProtection")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageEmailProtection, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "EmailProtection", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageEmailProtectionOid, oid)
		})
	})
	t.Run("IPSECEndSystem", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("IPSECEndSystem")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageIPSECEndSystem, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "IPSECEndSystem", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageIPSECEndSystemOid, oid)
		})
	})
	t.Run("IPSECTunnel", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("IPSECTunnel")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageIPSECTunnel, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "IPSECTunnel", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageIPSECTunnelOid, oid)
		})
	})
	t.Run("IPSECUser", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("IPSECUser")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageIPSECUser, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "IPSECUser", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageIPSECUserOid, oid)
		})
	})
	t.Run("TimeStamping", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("TimeStamping")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageTimeStamping, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "TimeStamping", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageTimeStampingOid, oid)
		})
	})
	t.Run("OCSPSigning", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("OCSPSigning")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageOCSPSigning, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "OCSPSigning", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageOCSPSigningOid, oid)
		})
	})
	t.Run("MicrosoftServerGatedCrypto", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("MicrosoftServerGatedCrypto")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageMicrosoftServerGatedCrypto, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "MicrosoftServerGatedCrypto", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageMicrosoftServerGatedCryptoOid, oid)
		})
	})
	t.Run("NetscapeServerGatedCrypto", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("NetscapeServerGatedCrypto")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageNetscapeServerGatedCrypto, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "NetscapeServerGatedCrypto", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageNetscapeServerGatedCryptoOid, oid)
		})
	})
	t.Run("MicrosoftCommercialCodeSigning", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("MicrosoftCommercialCodeSigning")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageMicrosoftCommercialCodeSigning, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "MicrosoftCommercialCodeSigning", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageMicrosoftCommercialCodeSigningOid, oid)
		})
	})
	t.Run("MicrosoftKernelCodeSigning", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("MicrosoftKernelCodeSigning")
		require.NoError(t, err)
		require.Equal(t, ExtKeyUsageMicrosoftKernelCodeSigning, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "MicrosoftKernelCodeSigning", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.NoError(t, err)
			require.Equal(t, ExtKeyUsageMicrosoftKernelCodeSigningOid, oid)
		})
	})
	t.Run("UnknownExtKeyUsage", func(t *testing.T) {
		eku, err := ParseExtKeyUsage("UnknownExtKeyUsage")
		require.Error(t, err)
		require.Equal(t, UnknownExtKeyUsage, eku)
		t.Run("String", func(t *testing.T) {
			require.Equal(t, "UnknownExtKeyUsage", eku.String())
		})
		t.Run("OID", func(t *testing.T) {
			oid, err := eku.Oid()
			require.Error(t, err)
			require.Nil(t, oid)
		})
	})
}
