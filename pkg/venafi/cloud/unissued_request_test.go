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
package cloud

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

// newUnissuedRequestConnector returns a connector whose server reports that certificate request "req-1" exists but
// has not produced a certificate yet: its status has no certificate IDs.
func newUnissuedRequestConnector(t *testing.T) *Connector {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificaterequests/req-1") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"req-1","status":"REQUESTED","certificateIds":[]}`))
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	conn, err := NewConnector(server.URL, "zone", false, nil)
	require.NoError(t, err)
	// getURL always builds https URLs, so use a TLS server and trust it.
	conn.SetHTTPClient(server.Client())
	conn.accessToken = "dummy-token"
	return conn
}

func requireUnissuedError(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.True(t, errors.Is(err, verror.UserDataError), "unexpected error type: %v", err)
	require.Contains(t, err.Error(), "certificate request req-1 has no issued certificate yet")
	require.Contains(t, err.Error(), `status "REQUESTED"`)
}

func TestRetireCertificateUnissuedRequest(t *testing.T) {
	conn := newUnissuedRequestConnector(t)
	err := conn.RetireCertificate(&certificate.RetireRequest{CertificateDN: "req-1"})
	requireUnissuedError(t, err)
}

func TestRenewCertificateUnissuedRequest(t *testing.T) {
	conn := newUnissuedRequestConnector(t)
	_, err := conn.RenewCertificate(&certificate.RenewalRequest{
		CertificateDN:      "req-1",
		CertificateRequest: &certificate.Request{},
	})
	requireUnissuedError(t, err)
}

func TestIssuedCertificateID(t *testing.T) {
	id, err := issuedCertificateID("req-1", &certificateStatus{Status: "ISSUED", CertificateIdsList: []string{"cert-1", "cert-2"}})
	require.NoError(t, err)
	require.Equal(t, "cert-1", id)

	_, err = issuedCertificateID("req-1", nil)
	require.ErrorIs(t, err, verror.UserDataError)
}
