package main

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
	"github.com/Venafi/vcert/v5/pkg/util"
)

func TestMLDSARejectsLegacyPem(t *testing.T) {
	defer func() { flags = commandFlags{} }()

	flags = commandFlags{csrOption: "local", keyTypeString: "mldsa", keySize: 65, format: util.LegacyPem}
	require.ErrorContains(t, validateCommonFlags(commandEnrollName), "legacy-pem")

	for _, format := range []string{"", "pem", "json", P12Format, LegacyP12Format, JKSFormat} {
		flags = commandFlags{csrOption: "local", keyTypeString: "mldsa", keySize: 65, format: format}
		require.NoError(t, validateCommonFlags(commandEnrollName), format)
	}
}

// mldsaOutput returns an Output holding a self-signed ML-DSA certificate and its private key, prepared the way the
// enroll command prepares it for the PKCS#12 and JKS formats (encrypted PKCS#8, then decrypted)
func mldsaOutput(t *testing.T, password string) (*Output, *mldsa.PrivateKey) {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
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

	pcc := &certificate.PEMCollection{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	require.NoError(t, pcc.AddPrivateKey(priv, []byte(password), P12Format))
	decrypted, err := util.DecryptPkcs8PrivateKey(pcc.PrivateKey, password)
	require.NoError(t, err)
	return &Output{Certificate: pcc.Certificate, PrivateKey: decrypted}, priv
}

func TestMLDSAAsPKCS12(t *testing.T) {
	for _, format := range []string{P12Format, LegacyP12Format} {
		t.Run(format, func(t *testing.T) {
			out, priv := mldsaOutput(t, "s3cret!")
			p12, err := out.AsPKCS12(&Config{Format: format, KeyPassword: "s3cret!"})
			require.NoError(t, err)
			key, cert, _, err := pkcs12.DecodeChain(p12, "s3cret!")
			require.NoError(t, err)
			require.True(t, priv.Equal(key))
			require.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
		})
	}
}

func TestMLDSAAsJKS(t *testing.T) {
	out, priv := mldsaOutput(t, "s3cret!")
	jks, err := out.AsJKS(&Config{Format: JKSFormat, KeyPassword: "s3cret!", JKSAlias: "mldsa", JKSPassword: "st0re!"})
	require.NoError(t, err)

	ks := keystore.New()
	require.NoError(t, ks.Load(bytes.NewReader(jks), []byte("st0re!")))
	entry, err := ks.GetPrivateKeyEntry("mldsa", []byte("s3cret!"))
	require.NoError(t, err)
	key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
	require.NoError(t, err)
	require.True(t, priv.Equal(key))
}
