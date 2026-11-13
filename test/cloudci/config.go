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
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"
)

// The CRUD configuration files describe the cloud accounts the CI may create
// cloud providers and keystores for. See README.md for the format. Secrets may
// be left out of the files, in which case they are read from environment
// variables named after the provider's position in the file (see
// awsSecretEnvVar and azureSecretEnvVar), which the pipeline binds from the
// Jenkins credentials the files reference.

type awsCRUDConfig struct {
	OwningTeamName string             `json:"owningTeamName"`
	CloudProviders []awsProviderEntry `json:"cloudProviders"`
}

type awsProviderEntry struct {
	AccountID       string             `json:"awsAccountId"`
	IAMRoleName     string             `json:"awsIamRoleName"`
	AccessKeyID     string             `json:"awsAccessKeyId"`
	SecretAccessKey string             `json:"awsSecretAccessKey"`
	CloudKeystores  []awsKeystoreEntry `json:"cloudKeystores"`
}

type awsKeystoreEntry struct {
	Region       string `json:"awsRegion"`
	CanProvision bool   `json:"canProvision"`
}

type azureCRUDConfig struct {
	OwningTeamName string               `json:"owningTeamName"`
	CloudProviders []azureProviderEntry `json:"cloudProviders"`
}

type azureProviderEntry struct {
	ClientID            string               `json:"clientId"`
	TenantID            string               `json:"tenantId"`
	ClientSecret        string               `json:"clientSecret"`
	ClientSecretExpires string               `json:"clientSecretExpires"`
	CloudKeystores      []azureKeystoreEntry `json:"cloudKeystores"`
}

type azureKeystoreEntry struct {
	KeyVaultName string `json:"keyVaultName"`
	CanProvision bool   `json:"canProvision"`
}

func awsSecretEnvVar(providerIndex int) string {
	return "AWS_CRUD_SECRET_ACCESS_KEY_" + strconv.Itoa(providerIndex)
}

func azureSecretEnvVar(providerIndex int) string {
	return "AZURE_CRUD_CLIENT_SECRET_" + strconv.Itoa(providerIndex)
}

var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

func loadAWSConfig(path string, getenv func(string) string) (*awsCRUDConfig, error) {
	var cfg awsCRUDConfig
	if err := readJSONFile(path, &cfg); err != nil {
		return nil, err
	}
	accounts := map[string]int{}
	for i := range cfg.CloudProviders {
		p := &cfg.CloudProviders[i]
		if !awsAccountIDPattern.MatchString(p.AccountID) {
			return nil, fmt.Errorf("%s: cloudProviders[%d].awsAccountId must be a 12-digit AWS account ID", path, i)
		}
		// a tenant allows only one cloud provider per AWS account
		if first, ok := accounts[p.AccountID]; ok {
			return nil, fmt.Errorf("%s: cloudProviders[%d] and cloudProviders[%d] both use AWS account %s", path, first, i, p.AccountID)
		}
		accounts[p.AccountID] = i
		if p.IAMRoleName == "" {
			return nil, fmt.Errorf("%s: cloudProviders[%d].awsIamRoleName is required", path, i)
		}
		if p.SecretAccessKey == "" {
			p.SecretAccessKey = getenv(awsSecretEnvVar(i))
		}
		regions := map[string]bool{}
		for j, k := range p.CloudKeystores {
			if k.Region == "" {
				return nil, fmt.Errorf("%s: cloudProviders[%d].cloudKeystores[%d].awsRegion is required", path, i, j)
			}
			if regions[k.Region] {
				return nil, fmt.Errorf("%s: cloudProviders[%d] has two keystores in region %s", path, i, k.Region)
			}
			regions[k.Region] = true
			// the access key is only used to delete provisioned certificates from ACM
			if k.CanProvision && (p.AccessKeyID == "" || p.SecretAccessKey == "") {
				return nil, fmt.Errorf("%s: cloudProviders[%d] (account %s) has a keystore that can provision but no access key "+
					"to delete the provisioned certificates: set awsAccessKeyId, and awsSecretAccessKey or %s",
					path, i, p.AccountID, awsSecretEnvVar(i))
			}
		}
	}
	return &cfg, nil
}

func loadAzureConfig(path string, getenv func(string) string, now time.Time) (*azureCRUDConfig, error) {
	var cfg azureCRUDConfig
	if err := readJSONFile(path, &cfg); err != nil {
		return nil, err
	}
	apps := map[string]int{}
	for i := range cfg.CloudProviders {
		p := &cfg.CloudProviders[i]
		if p.ClientID == "" || p.TenantID == "" {
			return nil, fmt.Errorf("%s: cloudProviders[%d] requires clientId and tenantId", path, i)
		}
		// a tenant allows only one cloud provider per Azure app
		app := p.ClientID + "/" + p.TenantID
		if first, ok := apps[app]; ok {
			return nil, fmt.Errorf("%s: cloudProviders[%d] and cloudProviders[%d] both use Azure app %s", path, first, i, p.ClientID)
		}
		apps[app] = i
		if p.ClientSecret == "" {
			p.ClientSecret = getenv(azureSecretEnvVar(i))
		}
		if p.ClientSecret == "" {
			return nil, fmt.Errorf("%s: cloudProviders[%d] (client %s) has no client secret: set clientSecret or %s",
				path, i, p.ClientID, azureSecretEnvVar(i))
		}
		if p.ClientSecretExpires != "" {
			expires, err := time.Parse("2006-01-02", p.ClientSecretExpires)
			if err != nil {
				return nil, fmt.Errorf("%s: cloudProviders[%d].clientSecretExpires must be a YYYY-MM-DD date: %w", path, i, err)
			}
			if !now.Before(expires) {
				return nil, fmt.Errorf("the client secret of Azure app %s expired on %s: create a new secret for the app, "+
					"store it in the Jenkins credential, and update clientSecretExpires in %s", p.ClientID, p.ClientSecretExpires, path)
			}
			if expires.Sub(now) < 14*24*time.Hour {
				logf("WARNING: the client secret of Azure app %s expires on %s", p.ClientID, p.ClientSecretExpires)
			}
		}
		vaults := map[string]bool{}
		for j, k := range p.CloudKeystores {
			if k.KeyVaultName == "" {
				return nil, fmt.Errorf("%s: cloudProviders[%d].cloudKeystores[%d].keyVaultName is required", path, i, j)
			}
			if vaults[k.KeyVaultName] {
				return nil, fmt.Errorf("%s: cloudProviders[%d] has two keystores for key vault %s", path, i, k.KeyVaultName)
			}
			vaults[k.KeyVaultName] = true
		}
	}
	return &cfg, nil
}

func readJSONFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("cannot parse %s: %w", path, err)
	}
	return nil
}
