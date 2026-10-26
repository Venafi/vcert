package installer

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

const mldsaTestPassword = "s3cret!"

// mldsaBundle returns the PEM collection the playbook builds for a locally generated ML-DSA key, ready for bundling
func mldsaBundle(t *testing.T) (*certificate.PEMCollection, *mldsa.PrivateKey) {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mldsa.vcert.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	require.NoError(t, err)

	request := certificate.Request{CsrOrigin: certificate.LocalGeneratedCSR, PrivateKey: priv, KeyPassword: mldsaTestPassword}
	pcc := certificate.PEMCollection{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	bundle, err := prepareCertificateForBundle(request, pcc, true)
	require.NoError(t, err)
	return bundle, priv
}

func TestMLDSAGetPrivateKey(t *testing.T) {
	bundle, priv := mldsaBundle(t)
	key, err := getPrivateKey(bundle.PrivateKey, mldsaTestPassword)
	require.NoError(t, err)
	require.True(t, priv.Equal(key))
}

func TestMLDSAPackageAsPKCS12(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		bundle, priv := mldsaBundle(t)
		p12, err := packageAsPKCS12(*bundle, mldsaTestPassword, legacy)
		require.NoError(t, err)
		key, cert, _, err := pkcs12.DecodeChain(p12, mldsaTestPassword)
		require.NoError(t, err)
		require.True(t, priv.Equal(key))
		require.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
	}
}

func TestMLDSAPackageAsJKS(t *testing.T) {
	bundle, priv := mldsaBundle(t)
	jks, err := packageAsJKS(*bundle, mldsaTestPassword, "mldsa", "st0re!")
	require.NoError(t, err)

	ks := keystore.New()
	require.NoError(t, ks.Load(bytes.NewReader(jks), []byte("st0re!")))
	entry, err := ks.GetPrivateKeyEntry("mldsa", []byte(mldsaTestPassword))
	require.NoError(t, err)
	key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
	require.NoError(t, err)
	require.True(t, priv.Equal(key))
}
