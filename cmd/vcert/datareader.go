/*
 * Copyright 2020-2024 Venafi, Inc.
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
	"fmt"
	"os"
	"strings"
)

const filePrefix = "file:"

func readData(commandName string) error {
	if strings.HasPrefix(flags.distinguishedName, filePrefix) {
		fileName := flags.distinguishedName[5:]
		bytes, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Failed to read Certificate DN: %s", err)
		}
		flags.distinguishedName = strings.TrimSpace(string(bytes))
	}
	if strings.HasPrefix(flags.keyPassword, filePrefix) {
		fileName := flags.keyPassword[5:]
		bytes, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Failed to read password from file: %s", err)
		}
		flags.keyPassword = strings.TrimSpace(string(bytes))
	}
	var err error
	if strings.HasPrefix(flags.thumbprint, filePrefix) {
		certFileName := flags.thumbprint[5:]
		flags.thumbprint, err = readThumbprintFromFile(certFileName)
		if err != nil {
			return fmt.Errorf("Failed to read certificate fingerprint: %s", err)
		}
	}

	if strings.HasPrefix(flags.externalJWT, filePrefix) {
		fileName := flags.externalJWT[5:]
		bytes, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("failed to read external JWT from file: %w", err)
		}
		flags.externalJWT = strings.TrimSpace(string(bytes))
	}

	if err = readPasswordsFromInputFlags(commandName, &flags); err != nil {
		return fmt.Errorf("Failed to read password from input: %s", err)
	}
	return nil
}
