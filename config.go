/*
 * Copyright 2018-2023 Venafi, Inc.
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
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"

	"gopkg.in/ini.v1"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const (
	//common keys
	platformUrlKey = "url"
	trustBundleKey = "trust_bundle"

	//Firefly keys
	fireflyUrlKey          = "firefly_url"
	fireflyTokenUrlKey     = "oauth_token_url"    // #nosec G101 // False positive
	fireflyAccessTokenKey  = "oauth_access_token" // #nosec G101 // False positive
	fireflyClientIdKey     = "oauth_client_id"
	fireflyClientSecretKey = "oauth_client_secret" // #nosec G101 // False positive
	fireflyUserKey         = "oauth_user"
	fireflyPasswordKey     = "oauth_password"
	fireflyDeviceUrlKey    = "oauth_device_url"
	fireflyAudienceKey     = "oauth_audience"
	fireflyScopeKey        = "oauth_scope"
	fireflyZoneKey         = "firefly_zone"
)

// Config is a basic structure for high level initiating connector to Trust Platform (TPP)/Venafi Cloud
type Config struct {
	// ConnectorType specify what do you want to use. May be "Cloud", "TPP" or "Fake" for development.
	ConnectorType endpoint.ConnectorType
	// BaseUrl should be specified for Venafi Platform. Optional for Cloud implementations that do not use https://venafi.cloud/.
	BaseUrl string
	// Zone is name of a policy zone in Venafi Platform or Cloud. For TPP, if necessary, escape backslash symbols.   For example,  "test\\zone" or `test\zone`.
	Zone string
	// Credentials should contain either User and Password for TPP connections or an APIKey for Cloud.
	Credentials *endpoint.Authentication
	// ConnectionTrust  may contain a trusted CA or certificate of server if you use self-signed certificate.
	ConnectionTrust string // *x509.CertPool
	LogVerbose      bool
	// http.Client to use durring construction
	Client *http.Client
	// UserAgent is the value of the UserAgent header in HTTP requests to Venafi
	// API endpoints.
	// If nil, the default is `vcert/v5`.
	// Further reading: https://www.rfc-editor.org/rfc/rfc9110#field.user-agent
	UserAgent *string
}

// LoadConfigFromFile is deprecated. In the future will be rewritten.
func LoadConfigFromFile(path, section string) (cfg Config, err error) {

	if section == "" {
		// nolint:staticcheck
		section = ini.DEFAULT_SECTION
	}
	log.Printf("Loading configuration from %s section %s", path, section)

	fname, err := expand(path)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	iniFile, err := ini.Load(fname)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	err = validateFile(iniFile)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	ok := func() bool {
		for _, s := range iniFile.Sections() {
			if s.Name() == section {
				return true
			}
		}
		return false
	}()
	if !ok {
		return cfg, fmt.Errorf("section %s has not been found in %s", section, path)
	}

	var m dict = iniFile.Section(section).KeysHash()

	var connectorType endpoint.ConnectorType
	var baseUrl string
	var auth = &endpoint.Authentication{}
	if m.has("tpp_user") || m.has("access_token") {
		connectorType = endpoint.ConnectorTypeTPP
		if m["tpp_url"] != "" {
			baseUrl = m["tpp_url"]
		} else if m[platformUrlKey] != "" {
			baseUrl = m[platformUrlKey]
		}
		auth.AccessToken = m["access_token"]
		auth.User = m["tpp_user"]
		auth.Password = m["tpp_password"]
		if m.has("tpp_zone") {
			cfg.Zone = m["tpp_zone"]
		}
		if m.has("cloud_zone") {
			cfg.Zone = m["cloud_zone"]
		}
	} else if m.has("cloud_apikey") {
		connectorType = endpoint.ConnectorTypeCloud
		if m["cloud_url"] != "" {
			baseUrl = m["cloud_url"]
		} else if m[platformUrlKey] != "" {
			baseUrl = m[platformUrlKey]
		}
		auth.APIKey = m["cloud_apikey"]
		if m.has("cloud_zone") {
			cfg.Zone = m["cloud_zone"]
		}
	} else if m.has(fireflyClientIdKey) || m.has(fireflyAccessTokenKey) {
		connectorType = endpoint.ConnectorTypeFirefly

		idp := &endpoint.OAuthProvider{}
		auth.IdentityProvider = idp

		if m[fireflyUrlKey] != "" {
			baseUrl = m[fireflyUrlKey]
		} else if m[platformUrlKey] != "" {
			baseUrl = m[platformUrlKey]
		}
		auth.AccessToken = m[fireflyAccessTokenKey]
		auth.User = m[fireflyUserKey]
		auth.Password = m[fireflyPasswordKey]
		auth.ClientId = m[fireflyClientIdKey]
		auth.ClientSecret = m[fireflyClientSecretKey]
		auth.Scope = m[fireflyScopeKey]

		idp.TokenURL = m[fireflyTokenUrlKey]
		idp.Audience = m[fireflyAudienceKey]
		idp.DeviceURL = m[fireflyDeviceUrlKey]

		cfg.Zone = m[fireflyZoneKey]
	} else if m.has("test_mode") && m["test_mode"] == "true" {
		connectorType = endpoint.ConnectorTypeFake
	} else {
		return cfg, fmt.Errorf("failed to load config: connector type cannot be defined")
	}

	if m.has(trustBundleKey) {
		fname, err := expand(m[trustBundleKey])
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		data, err := os.ReadFile(fname)
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	}

	cfg.ConnectorType = connectorType
	cfg.Credentials = auth
	cfg.BaseUrl = baseUrl

	return
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

type dict map[string]string

func (d dict) has(key string) bool {
	if _, ok := d[key]; ok {
		return true
	}
	return false
}

type set map[string]bool

func (d set) has(key string) bool {
	if _, ok := d[key]; ok {
		return true
	}
	return false
}

func validateSection(s *ini.Section) error {
	var TPPValidKeys set = map[string]bool{
		platformUrlKey: true,
		"access_token": true,
		"tpp_url":      true,
		"tpp_user":     true,
		"tpp_password": true,
		"tpp_zone":     true,
		trustBundleKey: true,
	}
	var CloudValidKeys set = map[string]bool{
		platformUrlKey: true,
		trustBundleKey: true,
		"cloud_url":    true,
		"cloud_apikey": true,
		"cloud_zone":   true,
	}
	var FireflyValidKeys set = map[string]bool{
		platformUrlKey:         true,
		fireflyUrlKey:          true,
		fireflyTokenUrlKey:     true,
		fireflyAccessTokenKey:  true,
		fireflyClientIdKey:     true,
		fireflyClientSecretKey: true,
		fireflyUserKey:         true,
		fireflyPasswordKey:     true,
		fireflyDeviceUrlKey:    true,
		fireflyAudienceKey:     true,
		fireflyScopeKey:        true,
		trustBundleKey:         true,
		fireflyZoneKey:         true,
	}

	log.Printf("Validating configuration section %s", s.Name())
	var m dict = s.KeysHash()

	if m.has("access_token") && m.has("cloud_apikey") && m.has(fireflyAccessTokenKey) {
		return fmt.Errorf("configuration issue in section %s: only one between TPP token, cloud api key or OAuth token can be set", s.Name())
	}
	if m.has("tpp_user") || m.has("access_token") || m.has("tpp_password") {
		// looks like TPP config section
		for k := range m {
			if !TPPValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in TPP section %s", k, s.Name())
			}
		}
		if m.has("tpp_user") && m.has("access_token") {
			return fmt.Errorf("configuration issue in section %s: could not have both TPP user and access token", s.Name())
		}
		if !m.has("tpp_user") && !m.has("access_token") {
			return fmt.Errorf("configuration issue in section %s: missing TPP user", s.Name())
		}
		if !m.has("tpp_password") && !m.has("access_token") {
			return fmt.Errorf("configuration issue in section %s: missing TPP password", s.Name())
		}
	} else if m.has("cloud_apikey") {
		// looks like Cloud config section
		for k := range m {
			if !CloudValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in Cloud section %s", k, s.Name())
			}
		}
	} else if m.has(fireflyClientIdKey) || m.has(fireflyAccessTokenKey) {
		// looks like TPP config section
		for k := range m {
			if !FireflyValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in Firefly section %s", k, s.Name())
			}
		}

		if m.has(fireflyClientIdKey) {
			//if it's not set any Flow Grant
			if (!m.has(fireflyUserKey) || !m.has(fireflyPasswordKey)) && !m.has(fireflyClientSecretKey) && !m.has(fireflyDeviceUrlKey) {
				return fmt.Errorf("configuration issue in section %s: The OAuth Client ID is set but is not set any OAuth Flow grant", s.Name())
			}

			if m.has(fireflyUserKey) && !m.has(fireflyPasswordKey) {
				return fmt.Errorf("configuration issue in section %s: The OAuth password is required when the OAuth username is provided", s.Name())
			}

			if !m.has(fireflyUserKey) && m.has(fireflyPasswordKey) {
				return fmt.Errorf("configuration issue in section %s: The OAuth username is required when the OAuth password is provided", s.Name())
			}

			if m.has(fireflyUserKey) && m.has(fireflyClientSecretKey) {
				return fmt.Errorf("configuration issue in section %s: The OAuth Resource Owner Password Flow and Credential Flow grants are set but only one flow grant is accepted", s.Name())
			}

			if m.has(fireflyUserKey) && m.has(fireflyDeviceUrlKey) {
				return fmt.Errorf("configuration issue in section %s: The OAuth Resource Owner Password Flow and Device Flow grants are set but only one flow grant is accepted", s.Name())
			}
		}
	} else if m.has("test_mode") {
		// it's ok

	} else if m.has(platformUrlKey) {
		return fmt.Errorf("could not determine connection endpoint with only url information in section %s", s.Name())
	} else {
		return fmt.Errorf("section %s looks empty", s.Name())
	}
	return nil
}

func validateFile(f *ini.File) error {

	for _, section := range f.Sections() {
		if len(section.Keys()) == 0 {
			if len(f.Sections()) > 1 {
				// empty section is not valid. skipping it if there are more sections in the file
				log.Printf("Warning: empty section %s", section.Name())
				continue
			}
		}
		err := validateSection(section)
		if err != nil {
			return err
		}
	}
	return nil
}
