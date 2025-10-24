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

// Config contains all the values necessary to connect to a given Venafi platform: TPP or TLSPC
type Config struct {
	Connection   Connection `yaml:"connection,omitempty"`
	ForceRenew   bool       `yaml:"-"`
	PreRunAction string     `yaml:"prerunaction,omitempty"`
}

// IsValid Ensures the provided connection configuration is valid and logical
func (c Config) IsValid() (bool, error) {
	return c.Connection.IsValid()
}
