/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ngts

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const edgeTestCompanyID = "5c8f6a1e-2b3d-11ee-8000-000000000001"

// newKeystoreCaptureConnector returns a connector whose server records the keystore request for
// certificate "cert-1" and answers it with HTTP 400, so retrieveServiceGeneratedCertData stops there.
func newKeystoreCaptureConnector(t *testing.T, captured *KeyStoreRequest) *Connector {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates/cert-1/keystore") {
			require.NoError(t, json.NewDecoder(r.Body).Decode(captured))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	conn, err := NewConnector(server.URL, "zone", false, nil)
	require.NoError(t, err)
	conn.SetHTTPClient(server.Client())
	conn.accessToken = "dummy-token"
	return conn
}

// VC-62432: VSatellites with VSAT_HPKE keys need the key password encrypted with HPKE; a NaCl
// sealed box made from the first 32 bytes of the P-384 key could not be decrypted.
func TestRetrieveServiceGeneratedCertDataHPKEKeyPassword(t *testing.T) {
	priv, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var captured KeyStoreRequest
	conn := newKeystoreCaptureConnector(t, &captured)

	req := &certificate.Request{CertID: "cert-1", KeyPassword: "T1795127555-abcd.temp.pwd"}
	dek := &EdgeEncryptionKey{
		Key:          base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		KeyAlgorithm: util.EdgeKeyAlgorithmVSatHPKE,
		CompanyId:    edgeTestCompanyID,
	}
	_, err = retrieveServiceGeneratedCertData(conn, req, dek)
	require.ErrorContains(t, err, "failed to retrieve KeyStore")

	raw, err := base64.StdEncoding.DecodeString(captured.EncryptedPrivateKeyPassphrase)
	require.NoError(t, err)
	encLen := len(priv.PublicKey().Bytes())
	require.Greater(t, len(raw), encLen)
	privateKey, err := hpke.NewDHKEMPrivateKey(priv)
	require.NoError(t, err)
	info := []byte(edgeTestCompanyID)
	recipient, err := hpke.NewRecipient(raw[:encLen], privateKey, hpke.HKDFSHA512(), hpke.AES256GCM(), info)
	require.NoError(t, err)
	password, err := recipient.Open(info, raw[encLen:])
	require.NoError(t, err)
	require.Equal(t, req.KeyPassword, string(password))
}

func TestRetrieveServiceGeneratedCertDataED25519KeyPassword(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var captured KeyStoreRequest
	conn := newKeystoreCaptureConnector(t, &captured)

	req := &certificate.Request{CertID: "cert-1", KeyPassword: "T1795127555-abcd.temp.pwd"}
	dek := &EdgeEncryptionKey{Key: base64.StdEncoding.EncodeToString(pub[:]), KeyAlgorithm: util.EdgeKeyAlgorithmED25519}
	_, err = retrieveServiceGeneratedCertData(conn, req, dek)
	require.ErrorContains(t, err, "failed to retrieve KeyStore")

	sealed, err := base64.StdEncoding.DecodeString(captured.EncryptedPrivateKeyPassphrase)
	require.NoError(t, err)
	password, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	require.True(t, ok, "sealed box did not open")
	require.Equal(t, req.KeyPassword, string(password))
}

func TestRetrieveServiceGeneratedCertDataUnknownKeyAlgorithm(t *testing.T) {
	var captured KeyStoreRequest
	conn := newKeystoreCaptureConnector(t, &captured)
	dek := &EdgeEncryptionKey{Key: base64.StdEncoding.EncodeToString(make([]byte, 32)), KeyAlgorithm: "RSA"}
	_, err := retrieveServiceGeneratedCertData(conn, &certificate.Request{CertID: "cert-1", KeyPassword: "pwd"}, dek)
	require.ErrorContains(t, err, "unsupported VSatellite encryption key algorithm")
	require.Empty(t, captured.EncryptedPrivateKeyPassphrase, "no keystore request should be sent")
}

func TestParseDEKInfoReadsAlgorithmAndCompany(t *testing.T) {
	body := []byte(`{"id":"dek-1","companyId":"` + edgeTestCompanyID + `","key":"QUJD","keyAlgorithm":"VSAT_HPKE"}`)
	dek, err := parseDEKInfo(http.StatusOK, "200 OK", body)
	require.NoError(t, err)
	require.Equal(t, "QUJD", dek.Key)
	require.Equal(t, util.EdgeKeyAlgorithmVSatHPKE, dek.KeyAlgorithm)
	require.Equal(t, edgeTestCompanyID, dek.CompanyId)
}
