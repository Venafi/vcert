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

package main

import (
	"os"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/venafi"
)

const workspaceTestValue = "1234567890"

func TestBuildConfigNGTSSetsWorkspace(t *testing.T) {
	flags = commandFlags{
		url:       "https://api.example.com/ngts",
		token:     "a-token",
		workspace: workspaceTestValue,
	}

	cfg, err := buildConfigNGTS(&flags)
	if err != nil {
		t.Fatalf("failed to build NGTS config: %s", err)
	}

	if cfg.Workspace != workspaceTestValue {
		t.Fatalf("expected workspace %q, got %q", workspaceTestValue, cfg.Workspace)
	}
}

func TestBuildConfigNGTSWithoutWorkspace(t *testing.T) {
	flags = commandFlags{
		url:   "https://api.example.com/ngts",
		token: "a-token",
	}

	cfg, err := buildConfigNGTS(&flags)
	if err != nil {
		t.Fatalf("failed to build NGTS config: %s", err)
	}

	if cfg.Workspace != "" {
		t.Fatalf("expected an empty workspace, got %q", cfg.Workspace)
	}
}

func TestWorkspaceFlagFromEnvironment(t *testing.T) {
	flags = commandFlags{}
	defer func() {
		unsetEnvironmentVariables()
		flags = commandFlags{}
	}()

	os.Setenv(vCertPlatform, "ngts")
	os.Setenv(vCertURL, "https://api.example.com/ngts")
	os.Setenv(vCertToken, "a-token")
	os.Setenv(vcertWorkspace, workspaceTestValue)

	flags.platform = venafi.NGTS

	cfg, err := buildConfig(getCliContext(commandGetCredName), &flags)
	if err != nil {
		t.Fatalf("failed to build vcert config: %s", err)
	}

	if cfg.Workspace != workspaceTestValue {
		t.Fatalf("expected workspace %q from the environment, got %q", workspaceTestValue, cfg.Workspace)
	}
}

func TestValidateWorkspaceFlag(t *testing.T) {
	testCases := []struct {
		name      string
		workspace string
		platform  venafi.Platform
		expectErr bool
	}{
		{
			name:      "no workspace is always fine",
			workspace: "",
			platform:  venafi.TPP,
		},
		{
			name:      "numeric workspace on NGTS",
			workspace: workspaceTestValue,
			platform:  venafi.NGTS,
		},
		{
			name:      "short numeric workspace on NGTS",
			workspace: "7",
			platform:  venafi.NGTS,
		},
		{
			name:      "workspace rejected on TPP",
			workspace: workspaceTestValue,
			platform:  venafi.TPP,
			expectErr: true,
		},
		{
			name:      "workspace rejected on VCP",
			workspace: workspaceTestValue,
			platform:  venafi.TLSPCloud,
			expectErr: true,
		},
		{
			name:      "workspace rejected when the platform was not specified",
			workspace: workspaceTestValue,
			platform:  venafi.Undefined,
			expectErr: true,
		},
		{
			name:      "workspace name rejected in place of an id",
			workspace: "my-workspace",
			platform:  venafi.NGTS,
			expectErr: true,
		},
		{
			name:      "workspace id longer than a uint32 rejected",
			workspace: "12345678901",
			platform:  venafi.NGTS,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags = commandFlags{
				workspace: tc.workspace,
				platform:  tc.platform,
			}
			defer func() { flags = commandFlags{} }()

			err := validateWorkspaceFlag()
			if tc.expectErr && err == nil {
				t.Fatalf("expected an error for workspace %q on platform %s", tc.workspace, tc.platform)
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("unexpected error for workspace %q on platform %s: %s", tc.workspace, tc.platform, err)
			}
		})
	}
}
