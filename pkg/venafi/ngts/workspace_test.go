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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const testWorkspaceID = "1234567890"

func TestWithWorkspaceID(t *testing.T) {
	testCases := []struct {
		name        string
		rawURL      string
		workspaceID string
		expected    string
		expectError bool
	}{
		{
			name:        "empty workspace leaves the url untouched",
			rawURL:      "https://api.example.com/ngts/outagedetection/v1/certificates",
			workspaceID: "",
			expected:    "https://api.example.com/ngts/outagedetection/v1/certificates",
		},
		{
			name:        "adds the workspace to a url with no query string",
			rawURL:      "https://api.example.com/ngts/outagedetection/v1/certificates",
			workspaceID: testWorkspaceID,
			expected:    "https://api.example.com/ngts/outagedetection/v1/certificates?workspace_id=1234567890",
		},
		{
			// This is the real shape produced by RetrieveCertificate, which appends
			// its own query string by hand before the request is made.
			name:        "preserves an existing query string",
			rawURL:      "https://api.example.com/ngts/v1/certificates/abc/contents?chainOrder=EE_FIRST&format=PEM",
			workspaceID: testWorkspaceID,
			expected:    "https://api.example.com/ngts/v1/certificates/abc/contents?chainOrder=EE_FIRST&format=PEM&workspace_id=1234567890",
		},
		{
			name:        "is idempotent",
			rawURL:      "https://api.example.com/ngts/v1/certificates?workspace_id=1234567890",
			workspaceID: testWorkspaceID,
			expected:    "https://api.example.com/ngts/v1/certificates?workspace_id=1234567890",
		},
		{
			name:        "overwrites a different workspace already present",
			rawURL:      "https://api.example.com/ngts/v1/certificates?workspace_id=9999999999",
			workspaceID: testWorkspaceID,
			expected:    "https://api.example.com/ngts/v1/certificates?workspace_id=1234567890",
		},
		{
			name:        "empty workspace does not touch an unparseable url",
			rawURL:      "://not-a-url",
			workspaceID: "",
			expected:    "://not-a-url",
		},
		{
			name:        "returns an error for an unparseable url",
			rawURL:      "://not-a-url",
			workspaceID: testWorkspaceID,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := withWorkspaceID(tc.rawURL, tc.workspaceID)
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestSetWorkspace(t *testing.T) {
	conn, err := NewConnector("https://api.example.com/ngts", "zone", false, nil)
	require.NoError(t, err)

	assert.Empty(t, conn.workspaceID, "a new connector should have no workspace")

	conn.SetWorkspace(testWorkspaceID)
	assert.Equal(t, testWorkspaceID, conn.workspaceID)

	// The connector must satisfy the optional interface that client.go looks for,
	// otherwise vcert.NewClient silently drops the workspace.
	var _ endpoint.WorkspaceSetter = conn
}

func TestGetGraphqlURLIncludesWorkspace(t *testing.T) {
	conn, err := NewConnector("https://api.example.com/ngts", "zone", false, nil)
	require.NoError(t, err)

	got, err := conn.getGraphqlURL()
	require.NoError(t, err)
	assert.NotContains(t, got, "workspace_id", "no workspace set should mean no workspace parameter")

	conn.SetWorkspace(testWorkspaceID)
	got, err = conn.getGraphqlURL()
	require.NoError(t, err)
	assert.Contains(t, got, "workspace_id=1234567890")
}

// TestRequestSendsWorkspace covers the single choke point that every NGTS REST
// call passes through.
func TestRequestSendsWorkspace(t *testing.T) {
	testCases := []struct {
		name              string
		workspaceID       string
		expectedWorkspace string
	}{
		{
			name:              "workspace is sent when set",
			workspaceID:       testWorkspaceID,
			expectedWorkspace: testWorkspaceID,
		},
		{
			// Regression guard: everyone who does not use workspaces must keep
			// sending exactly the requests they sent before.
			name:              "no workspace parameter when unset",
			workspaceID:       "",
			expectedWorkspace: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var gotWorkspace string
			var gotOtherParam string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotWorkspace = r.URL.Query().Get("workspace_id")
				gotOtherParam = r.URL.Query().Get("format")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			conn, err := NewConnector(server.URL, "zone", false, nil)
			require.NoError(t, err)
			conn.SetWorkspace(tc.workspaceID)
			conn.accessToken = "dummy-token"

			// Includes a pre-existing query parameter to prove it survives.
			statusCode, _, _, err := conn.request(http.MethodGet, server.URL+"/v1/certificates?format=PEM", nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, statusCode)

			assert.Equal(t, tc.expectedWorkspace, gotWorkspace)
			assert.Equal(t, "PEM", gotOtherParam, "existing query parameters must be preserved")
		})
	}
}

// TestGetAccessTokenDoesNotSendWorkspace guards against re-adding the workspace
// to the token request. The token endpoint ignores workspace_id (tokens minted
// with and without it carry identical claims), so sending it only implies a
// scoping that does not happen. The workspace is applied per API request.
func TestGetAccessTokenDoesNotSendWorkspace(t *testing.T) {
	testCases := []struct {
		name           string
		workspaceID    string
		tokenURLSuffix string
	}{
		{name: "no workspace_id even when a workspace is set", workspaceID: testWorkspaceID},
		{name: "no workspace_id when no workspace is set", workspaceID: ""},
		{name: "existing token url query parameters are preserved", workspaceID: testWorkspaceID, tokenURLSuffix: "?foo=bar"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hasWorkspace bool
			var gotFoo string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hasWorkspace = r.URL.Query().Has("workspace_id")
				gotFoo = r.URL.Query().Get("foo")

				token, err := createMockJWT(time.Now().Add(time.Hour))
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(AccessTokenResponse{
					AccessToken: token,
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})
			}))
			defer server.Close()

			conn, err := NewConnector(server.URL, "zone", false, nil)
			require.NoError(t, err)
			conn.SetWorkspace(tc.workspaceID)

			resp, err := conn.GetAccessToken(&endpoint.Authentication{
				ClientId:     "client-id",
				ClientSecret: "client-secret",
				TokenURL:     server.URL + "/v1/oauth/v2.0/token" + tc.tokenURLSuffix,
				Scope:        "tsg_id:1000000001",
			})
			require.NoError(t, err)
			require.NotEmpty(t, resp.AccessToken)

			assert.False(t, hasWorkspace, "the token request must not carry workspace_id")
			if tc.tokenURLSuffix != "" {
				assert.Equal(t, "bar", gotFoo, "existing token url query parameters must be preserved")
			}
		})
	}
}

// TestCertificateAuthorityLookupSendsWorkspace follows a real caller through
// Connector.request: setpolicy resolves the CA ("BUILTIN\Built-In CA\Default
// Product") via GET /v1/certificateauthorities/{type}/accounts before it writes
// the policy. That lookup must carry the workspace like every other call.
func TestCertificateAuthorityLookupSendsWorkspace(t *testing.T) {
	const accountsResponse = `{"accounts":[{
		"account":{"id":"211cbcb0-b390-11f1-a4fc-c116a3907611","Key":"Built-In CA","certificateAuthority":"BUILTIN"},
		"productOptions":[{"productName":"Default Product","id":"21298df0-b390-11f1-a4fc-c116a3907611"}]}]}`

	testCases := []struct {
		name              string
		workspaceID       string
		expectedWorkspace string
	}{
		{name: "workspace is sent when set", workspaceID: testWorkspaceID, expectedWorkspace: testWorkspaceID},
		{name: "no workspace parameter when unset", workspaceID: "", expectedWorkspace: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotWorkspace string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotWorkspace = r.URL.Query().Get("workspace_id")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(accountsResponse))
			}))
			defer server.Close()

			conn, err := NewConnector(server.URL, "zone", false, nil)
			require.NoError(t, err)
			// getURL always builds https URLs, so use a TLS server and trust it.
			conn.SetHTTPClient(server.Client())
			conn.SetWorkspace(tc.workspaceID)
			conn.accessToken = "dummy-token"

			details, err := getCertificateAuthorityDetails(`BUILTIN\Built-In CA\Default Product`, conn)
			require.NoError(t, err)
			require.NotNil(t, details.CertificateAuthorityProductOptionId)

			assert.Equal(t, "/v1/certificateauthorities/BUILTIN/accounts", gotPath)
			assert.Equal(t, tc.expectedWorkspace, gotWorkspace)
			assert.Equal(t, "21298df0-b390-11f1-a4fc-c116a3907611", *details.CertificateAuthorityProductOptionId)
		})
	}
}

// TestCertificateAuthorityLookupReportsHTTPStatus: a non-200 from the CA
// accounts endpoint must surface the status. Before the check, a JSON error
// body unmarshalled into an empty account list and was reported as
// "specified CA doesn't exist", sending users after a CA name that was fine.
func TestCertificateAuthorityLookupReportsHTTPStatus(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "403 with a JSON error body", statusCode: http.StatusForbidden, body: `{"errors":[{"code":1002,"message":"Unauthorized request"}]}`},
		{name: "502 with an HTML body", statusCode: http.StatusBadGateway, body: `<html><body>502 Bad Gateway</body></html>`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			conn, err := NewConnector(server.URL, "zone", false, nil)
			require.NoError(t, err)
			conn.SetHTTPClient(server.Client())
			conn.accessToken = "dummy-token"

			_, err = getCertificateAuthorityDetails(`BUILTIN\Built-In CA\Default Product`, conn)
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("StatusCode: %d", tc.statusCode))
			assert.NotContains(t, err.Error(), "specified CA doesn't exist")
		})
	}
}
