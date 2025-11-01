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

package parser

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// WritePlaybook takes an object and serializes it to a file in the given location
func WritePlaybook(object interface{}, location string) error {
	data, err := yaml.Marshal(object)
	if err != nil {
		return fmt.Errorf("could not marshall playbook object: %w", err)
	}

	err = os.WriteFile(location, data, 0600)
	if err != nil {
		return fmt.Errorf("could not write playbook file: %w", err)
	}

	return nil
}
