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

import "fmt"

var (
	// ErrNoLocation is thrown when no location is provided for the Playbook file
	ErrNoLocation = fmt.Errorf("playbook location was not provided")
	// ErrReadFile is thrown when the Playbook file cannot be read/accessed
	ErrReadFile = fmt.Errorf("could not read playbook file")
	// ErrTextTplParsing is thrown when the templates in the Playbook file cannot be parsed.
	//
	// E.g. {{ Env "Hostname" }}
	ErrTextTplParsing = fmt.Errorf("failed to parse the playbook file")
	// ErrFileUnmarshall is thrown when the content of the Playbook file cannot be successfully unmarshalled into a domain.Playbook object
	ErrFileUnmarshall = fmt.Errorf("failed to unmarshal the playbook file")
)
