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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

const azureConfigJSON = `{
  "$comment": "test data",
  "owningTeamName": "DevOpsTeam",
  "cloudProviders": [
    {
      "$comment": "secret comes from the environment",
      "clientId": "app-1",
      "tenantId": "tenant-1",
      "clientSecretExpires": "2027-01-31",
      "clientSecretJenkinsCredentialId": "vcert-azure-crud-client-secret-01",
      "cloudKeystores": [
        {"keyVaultName": "vcert-auto-do-not-delete", "canProvision": true},
        {"keyVaultName": "vaas-auto-do-not-delete", "canProvision": false}
      ]
    }
  ]
}`

func TestLoadAzureConfigReadsTheSecretFromTheEnvironment(t *testing.T) {
	cfg, err := loadAzureConfig(writeConfig(t, azureConfigJSON), env(map[string]string{"AZURE_CRUD_CLIENT_SECRET_0": "s3cret"}), testNow)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	p := cfg.CloudProviders[0]
	if cfg.OwningTeamName != "DevOpsTeam" || p.ClientSecret != "s3cret" || len(p.CloudKeystores) != 2 || !p.CloudKeystores[0].CanProvision {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
}

func TestLoadAzureConfigRequiresASecret(t *testing.T) {
	_, err := loadAzureConfig(writeConfig(t, azureConfigJSON), env(nil), testNow)
	if err == nil || !strings.Contains(err.Error(), "AZURE_CRUD_CLIENT_SECRET_0") {
		t.Fatalf("expected a missing secret error naming the variable, got %v", err)
	}
}

func TestLoadAzureConfigRejectsAnExpiredSecret(t *testing.T) {
	_, err := loadAzureConfig(writeConfig(t, azureConfigJSON), env(map[string]string{"AZURE_CRUD_CLIENT_SECRET_0": "s3cret"}),
		time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "expired on 2027-01-31") || !strings.Contains(err.Error(), "app-1") {
		t.Fatalf("expected an expired secret error, got %v", err)
	}
}

const awsConfigJSON = `{
  "owningTeamName": "DevOpsTeam",
  "cloudProviders": [
    {
      "awsAccountId": "%s",
      "awsIamRoleName": "ci-role",
      "awsAccessKeyId": "AKIA1",
      "cloudKeystores": [{"awsRegion": "us-east-2", "canProvision": true}]
    }
  ]
}`

func TestLoadAWSConfig(t *testing.T) {
	path := writeConfig(t, strings.Replace(awsConfigJSON, "%s", "123456789012", 1))
	cfg, err := loadAWSConfig(path, env(map[string]string{"AWS_CRUD_SECRET_ACCESS_KEY_0": "aws-secret"}))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	p := cfg.CloudProviders[0]
	if p.SecretAccessKey != "aws-secret" || p.CloudKeystores[0].Region != "us-east-2" {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
}

func TestLoadAWSConfigValidates(t *testing.T) {
	tests := map[string]struct {
		account string
		env     map[string]string
		want    string
	}{
		"13-digit account":              {"0123456789012", map[string]string{"AWS_CRUD_SECRET_ACCESS_KEY_0": "x"}, "12-digit"},
		"no key to delete certificates": {"123456789012", nil, "AWS_CRUD_SECRET_ACCESS_KEY_0"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := loadAWSConfig(writeConfig(t, strings.Replace(awsConfigJSON, "%s", tc.account, 1)), env(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunDoesNothingForASkippedSetup(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := (&state{Target: targetVCP, Skipped: true, SkipReason: "another run"}).save(statePath); err != nil {
		t.Fatal(err)
	}
	azurePath := writeConfig(t, azureConfigJSON)
	t.Setenv("AZURE_CRUD_CLIENT_SECRET_0", "s3cret")
	// no connection settings: check and teardown must not try to connect
	t.Setenv("CLOUD_APIKEY", "")
	for _, command := range []string{"check", "teardown"} {
		if code := run([]string{command, "-target", "vcp", "-state", statePath, "-azure-config", azurePath}); code != 0 {
			t.Fatalf("%s exited with %d", command, code)
		}
	}
	// nor when setup never ran
	missing := filepath.Join(dir, "missing.json")
	if code := run([]string{"teardown", "-target", "vcp", "-state", missing, "-azure-config", azurePath}); code != 0 {
		t.Fatalf("teardown without a state file exited with %d", code)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"setup", "-target", "tpp", "-state", "s", "-aws-config", "a"},
		{"setup", "-target", "vcp", "-aws-config", "a"},
		{"setup", "-target", "vcp", "-state", "s"},
	} {
		if code := run(args); code != 2 {
			t.Fatalf("%v exited with %d, want 2", args, code)
		}
	}
}
