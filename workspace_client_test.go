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

package vcert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

// Workspaces are an NGTS-only concept. NewClient enforces that through an
// optional endpoint.WorkspaceSetter interface rather than by widening
// endpoint.Connector, which means the guard is easy to break silently: adding
// the method to another connector, or dropping the check, would compile fine.
// These tests pin the behaviour down.

// TestNewClientRejectsWorkspaceOnNonNGTS asserts that supplying a workspace to
// a connector that does not implement endpoint.WorkspaceSetter is a hard error
// rather than a silently ignored setting.
func TestNewClientRejectsWorkspaceOnNonNGTS(t *testing.T) {
	cases := []struct {
		name          string
		connectorType endpoint.ConnectorType
		baseURL       string // TPP refuses to construct without one
	}{
		{"TPP", endpoint.ConnectorTypeTPP, "https://tpp.example.com/vedsdk/"},
		{"Cloud", endpoint.ConnectorTypeCloud, ""},
		{"Firefly", endpoint.ConnectorTypeFirefly, ""},
		{"Fake", endpoint.ConnectorTypeFake, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ConnectorType: tc.connectorType,
				BaseUrl:       tc.baseURL,
				Zone:          "some-zone",
				Workspace:     "1234567890",
			}

			// false => do not authenticate; we only care about client construction.
			conn, err := cfg.NewClient(false)

			require.Error(t, err, "a workspace on %s must be rejected", tc.name)
			assert.Nil(t, conn)
			assert.ErrorIs(t, err, verror.UserDataError)
			assert.Contains(t, err.Error(), "does not support workspaces")
		})
	}
}

// TestNewClientAcceptsWorkspaceOnNGTS is the positive counterpart: the NGTS
// connector does implement WorkspaceSetter, so the same config must succeed.
func TestNewClientAcceptsWorkspaceOnNGTS(t *testing.T) {
	cfg := &Config{
		ConnectorType: endpoint.ConnectorTypeNGTS,
		Zone:          "some-zone",
		Workspace:     "1234567890",
	}

	conn, err := cfg.NewClient(false)

	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Implements(t, (*endpoint.WorkspaceSetter)(nil), conn)
}

// TestNewClientWithoutWorkspaceIsUnaffected guards the regression path: every
// connector must still construct normally when no workspace is supplied, so
// that adding the feature cannot break the platforms that do not use it.
func TestNewClientWithoutWorkspaceIsUnaffected(t *testing.T) {
	cases := []struct {
		name          string
		connectorType endpoint.ConnectorType
		baseURL       string // TPP refuses to construct without one
	}{
		{"TPP", endpoint.ConnectorTypeTPP, "https://tpp.example.com/vedsdk/"},
		{"Cloud", endpoint.ConnectorTypeCloud, ""},
		{"Firefly", endpoint.ConnectorTypeFirefly, ""},
		{"Fake", endpoint.ConnectorTypeFake, ""},
		{"NGTS", endpoint.ConnectorTypeNGTS, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ConnectorType: tc.connectorType,
				BaseUrl:       tc.baseURL,
				Zone:          "some-zone",
			}

			conn, err := cfg.NewClient(false)

			require.NoError(t, err)
			assert.NotNil(t, conn)
		})
	}
}
