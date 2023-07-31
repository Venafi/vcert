/*
 * Copyright 2023 Venafi, Inc.
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

package domain

// Subject represents the X.509 distinguished names of the certificate.
// This only includes the common elements of a DN
type Subject struct {
	CommonName   string   `yaml:"commonName,omitempty"`
	Country      string   `yaml:"country,omitempty"`
	Locality     string   `yaml:"locality,omitempty"`
	Organization string   `yaml:"organization,omitempty"`
	OrgUnits     []string `yaml:"orgUnits,omitempty"`
	Province     string   `yaml:"state,omitempty"`
}
