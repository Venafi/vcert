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

// These TPP tests live in the external venafi_test package because the tpp connector test
// package gates every test behind a live TPP (its init() authenticates against TPP_URL).
// A mocked HTTP test placed there would never run in a credential-free build. Here we drive
// the exported tpp.Connector against an httptest server, so no live TPP is required.
package venafi_test

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"

	"github.com/stretchr/testify/require"
)

// tppPolicyMockServer returns an HTTPS test server capturing the method, path and body of
// the request it receives, replying with the given JSON body and a 200 status.
func tppPolicyMockServer(t *testing.T, method, path *string, body *[]byte, respBody string) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*method = r.Method
		*path = r.URL.Path
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %s", err)
		}
		*body = b
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(server.Close)

	ca := x509.NewCertPool()
	ca.AddCert(server.Certificate())
	return server, ca
}

func TestTPPDeletePolicy(t *testing.T) {
	tests := []struct {
		name          string
		policyName    string
		recursive     bool
		wantObjectDN  string
		wantRecursive int
	}{
		{
			name:          "already fully qualified, non-recursive",
			policyName:    "\\VED\\Policy\\devops\\vcert",
			recursive:     false,
			wantObjectDN:  "\\VED\\Policy\\devops\\vcert",
			wantRecursive: 0,
		},
		{
			name:          "short name gets normalized, recursive",
			policyName:    "devops\\vcert",
			recursive:     true,
			wantObjectDN:  "\\VED\\Policy\\devops\\vcert",
			wantRecursive: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var method, path string
			var body []byte
			server, ca := tppPolicyMockServer(t, &method, &path, &body, `{"Result":1}`)

			conn, err := tpp.NewConnector(server.URL, `\VED\Policy\devops`, true, ca)
			require.NoError(t, err)

			err = conn.DeletePolicy(tt.policyName, tt.recursive)
			require.NoError(t, err)

			require.Equal(t, http.MethodPost, method)
			require.Equal(t, "/vedsdk/config/delete", path)

			var got struct {
				ObjectDN  string `json:"ObjectDN"`
				Recursive int    `json:"Recursive"`
			}
			require.NoError(t, json.Unmarshal(body, &got))
			require.Equal(t, tt.wantObjectDN, got.ObjectDN)
			require.Equal(t, tt.wantRecursive, got.Recursive)
		})
	}
}

func TestTPPDeletePolicyError(t *testing.T) {
	var method, path string
	var body []byte
	server, ca := tppPolicyMockServer(t, &method, &path, &body,
		`{"Result":1,"Error":"Failed to delete object DN: \\VED\\Policy\\devops\\vcert"}`)

	conn, err := tpp.NewConnector(server.URL, `\VED\Policy\devops`, true, ca)
	require.NoError(t, err)

	err = conn.DeletePolicy("\\VED\\Policy\\devops\\vcert", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed to delete object DN")
}

func TestTPPRenamePolicy(t *testing.T) {
	var method, path string
	var body []byte
	server, ca := tppPolicyMockServer(t, &method, &path, &body, `{"Result":1}`)

	conn, err := tpp.NewConnector(server.URL, `\VED\Policy\devops`, true, ca)
	require.NoError(t, err)

	// short names on both sides should be normalized to fully qualified DNs
	err = conn.RenamePolicy("devops\\vcert", "devops\\vcert-renamed")
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, method)
	require.Equal(t, "/vedsdk/config/renameobject", path)

	var got struct {
		ObjectDN    string `json:"ObjectDN"`
		NewObjectDN string `json:"NewObjectDN"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, "\\VED\\Policy\\devops\\vcert", got.ObjectDN)
	require.Equal(t, "\\VED\\Policy\\devops\\vcert-renamed", got.NewObjectDN)
}

func TestTPPRenamePolicyError(t *testing.T) {
	var method, path string
	var body []byte
	server, ca := tppPolicyMockServer(t, &method, &path, &body,
		`{"Result":1,"Error":"Failed to rename object"}`)

	conn, err := tpp.NewConnector(server.URL, `\VED\Policy\devops`, true, ca)
	require.NoError(t, err)

	err = conn.RenamePolicy("\\VED\\Policy\\devops\\vcert", "\\VED\\Policy\\devops\\vcert-renamed")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed to rename object")
}
