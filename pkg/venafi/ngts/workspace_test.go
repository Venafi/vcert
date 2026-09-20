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

// TestGetAccessTokenSendsWorkspace covers minting a token against a workspace,
// so the workspace is carried by the token and not only by later requests.
func TestGetAccessTokenSendsWorkspace(t *testing.T) {
	testCases := []struct {
		name              string
		workspaceID       string
		tokenURLSuffix    string
		expectedWorkspace string
	}{
		{
			name:              "workspace is appended to the token url",
			workspaceID:       testWorkspaceID,
			expectedWorkspace: testWorkspaceID,
		},
		{
			name:              "token url is untouched when no workspace is set",
			workspaceID:       "",
			expectedWorkspace: "",
		},
		{
			name:              "workspace is merged into a token url that already has a query string",
			workspaceID:       testWorkspaceID,
			tokenURLSuffix:    "?foo=bar",
			expectedWorkspace: testWorkspaceID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var gotWorkspace string
			var gotFoo string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotWorkspace = r.URL.Query().Get("workspace_id")
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

			assert.Equal(t, tc.expectedWorkspace, gotWorkspace)
			if tc.tokenURLSuffix != "" {
				assert.Equal(t, "bar", gotFoo, "existing token url query parameters must be preserved")
			}
		})
	}
}
