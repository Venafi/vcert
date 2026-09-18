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

// These tests live in an external package (venafi_test) on purpose: the cloud and ngts
// connector test packages gate every test behind live credentials in their init(), so a
// not-supported assertion placed there would never run in a credential-free build. Here we
// only need the exported connector types and methods, which require no network or auth.
package venafi_test

import (
	"testing"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/firefly"
	"github.com/Venafi/vcert/v5/pkg/venafi/ngts"

	"github.com/stretchr/testify/require"
)

// notSupportedConnectors are the platforms that do not implement policy folder
// delete/rename. They must return a clear error and must never panic.
func notSupportedConnectors() map[string]endpoint.Connector {
	return map[string]endpoint.Connector{
		"cloud":   &cloud.Connector{},
		"ngts":    &ngts.Connector{},
		"firefly": &firefly.Connector{},
	}
}

func TestDeletePolicyNotSupported(t *testing.T) {
	for name, c := range notSupportedConnectors() {
		c := c
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				err := c.DeletePolicy("some-zone", false)
				require.Error(t, err)
				require.Contains(t, err.Error(), "not supported by endpoint")
			})
		})
	}
}

func TestRenamePolicyNotSupported(t *testing.T) {
	for name, c := range notSupportedConnectors() {
		c := c
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				err := c.RenamePolicy("some-zone", "new-zone")
				require.Error(t, err)
				require.Contains(t, err.Error(), "not supported by endpoint")
			})
		})
	}
}
