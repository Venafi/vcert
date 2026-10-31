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
	"strings"
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

// TestGetPolicyValidatesWorkspace covers a gap that is easy to reintroduce:
// getpolicy exposes --workspace but does not route through
// validateConnectionFlags, so it calls the workspace gate directly.
func TestGetPolicyValidatesWorkspace(t *testing.T) {
	testCases := []struct {
		name      string
		workspace string
		platform  venafi.Platform
		expectErr bool
	}{
		{name: "numeric workspace on NGTS", workspace: workspaceTestValue, platform: venafi.NGTS},
		{name: "workspace rejected on TPP", workspace: workspaceTestValue, platform: venafi.TPP, expectErr: true},
		{name: "workspace name rejected in place of an id", workspace: "my-workspace", platform: venafi.NGTS, expectErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags = commandFlags{workspace: tc.workspace, platform: tc.platform, policyName: "some-zone", token: "a-token"}
			defer func() { flags = commandFlags{} }()

			err := validateGetPolicyFlags(commandGetePolicyName)
			if tc.expectErr && err == nil {
				t.Fatalf("expected an error for workspace %q on platform %s", tc.workspace, tc.platform)
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("unexpected error for workspace %q on platform %s: %s", tc.workspace, tc.platform, err)
			}
		})
	}
}

// TestSetPolicyRefusesWorkspace: NGTS request policies belong to the tenant and
// can only be changed with the tenant selected, so a workspace-scoped setpolicy
// is refused outright, even a valid NGTS workspace. setpolicy has no --workspace
// flag, but VCERT_WORKSPACE applies to every command, so both paths are covered.
func TestSetPolicyRefusesWorkspace(t *testing.T) {
	testCases := []struct {
		name      string
		flagValue string
		envValue  string
		verify    bool
		expectErr bool
	}{
		{name: "no workspace is fine"},
		{name: "valid NGTS workspace from the environment is refused", envValue: workspaceTestValue, expectErr: true},
		{name: "workspace set on the flags struct is refused", flagValue: workspaceTestValue, expectErr: true},
		{name: "--verify is offline and ignores the workspace", envValue: workspaceTestValue, verify: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(vcertWorkspace, tc.envValue)
			flags = commandFlags{
				workspace:          tc.flagValue,
				platform:           venafi.NGTS,
				verifyPolicyConfig: tc.verify,
				// Satisfy the validator's own required-field checks so that any
				// error can only have come from the workspace refusal.
				policyName:         "some-zone",
				policySpecLocation: "/tmp/policy.json",
			}
			if !tc.verify {
				flags.token = "a-token"
			}
			defer func() { flags = commandFlags{} }()

			err := validateSetPolicyFlags(commandCreatePolicyName)
			if tc.expectErr {
				if err == nil || !strings.Contains(err.Error(), "cannot run in a workspace") {
					t.Fatalf("expected the workspace refusal, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

// TestSetPolicyHasNoWorkspaceFlag keeps --workspace off setpolicy.
func TestSetPolicyHasNoWorkspaceFlag(t *testing.T) {
	for _, f := range createPolicyFlags {
		for _, name := range f.Names() {
			if name == "workspace" {
				t.Fatal("setpolicy must not expose --workspace: request policies are tenant-scoped")
			}
		}
	}
}
