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
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/howeyc/gopass"
)

func readPasswordsFromInputFlags(commandName string, cf *commandFlags) error {
	lineIndex := 0

	if (commandName == commandEnrollName && cf.url != "") ||
		(commandName == commandPickupName && cf.url != "") ||
		(commandName == commandGetCredName && cf.url != "") {
		if cf.clientP12 != "" && cf.clientP12PW == "" {
			fmt.Printf("Enter password for %s:", cf.clientP12)
			input, err := gopass.GetPasswdMasked()
			if err != nil {
				return err
			}
			cf.clientP12PW = string(input)
		} else if cf.password == "" && !cf.noPrompt && cf.token == "" && cf.userName != "" {
			fmt.Printf("Enter password for %s:", cf.userName)
			input, err := gopass.GetPasswdMasked()
			if err != nil {
				return err
			}
			cf.password = string(input)
		} else {
			temp, err := readPasswordsFromInputFlag(cf.password, lineIndex)
			if err != nil {
				return err
			}
			if cf.password == cf.keyPassword { //increase the line index if the password values refer to the same files
				lineIndex++
			}
			cf.password = temp
		}
	}

	cloudSerViceGenerated := IsCSRServiceVaaSGenerated(commandName)

	if commandName == commandSshPickupName || commandName == commandSshEnrollName || commandName == commandEnrollName ||
		commandName == commandGenCSRName || commandName == commandRenewName || commandName == commandPickupName &&
		(cf.format == P12Format || cf.format == LegacyP12Format || cf.format == JKSFormat || cloudSerViceGenerated) {
		var keyPasswordNotNeeded = false

		keyPasswordNotNeeded = keyPasswordNotNeeded || (cf.csrOption == "service" && cf.noPickup)
		keyPasswordNotNeeded = keyPasswordNotNeeded || (strings.Index(cf.csrOption, "file:") == 0)
		if commandName == commandSshEnrollName {
			keyPasswordNotNeeded = keyPasswordNotNeeded || (cf.sshCertPubKey != SshCertPubKeyServ && cf.sshCertPubKey != SshCertPubKeyLocal) || cf.sshCertKeyPassphrase != ""
		}

		if commandName == commandSshPickupName {
			keyPasswordNotNeeded = cf.sshCertKeyPassphrase != ""
		}

		if cloudSerViceGenerated {
			keyPasswordNotNeeded = false
		}

		if !keyPasswordNotNeeded {
			if cf.keyPassword == "" && !cf.noPrompt {
				fmt.Printf("Enter key passphrase:")
				input, err := gopass.GetPasswdMasked()
				if err != nil {
					return err
				}
				fmt.Printf("Verifying - Enter key passphrase:")
				verify, err := gopass.GetPasswdMasked()
				if err != nil {
					return err
				}
				if !doValuesMatch(input, verify) {
					return fmt.Errorf("Passphrases don't match")
				}
				cf.keyPassword = string(input)
			} else if cf.keyPassword == "" && cf.noPrompt && commandName == commandPickupName {
				//TODO: cover with test
				return fmt.Errorf("key password must be provided")
			} else {
				temp, err := readPasswordsFromInputFlag(cf.keyPassword, lineIndex)
				if err != nil {
					return err
				}
				cf.keyPassword = temp
			}
		}
	}

	return nil
}

func readPasswordsFromInputFlag(flagVar string, index int) (string, error) {
	reg := regexp.MustCompile("^(?:F|f)(?:I|i)(?:L|l)(?:E|e):(?P<value>.*?$)")
	groups := reg.SubexpNames()
	matches := reg.FindAllStringSubmatch(flagVar, -1)
	for _, m := range matches {
		for grpIdx, value := range m {
			if groups[grpIdx] == "value" {
				return readPasswordFromFile(value, index)
			}
		}
	}

	reg = regexp.MustCompile("^(?:P|p)(?:A|a)(?:S|s)(?:S|s):(?P<value>.*?$)")
	groups = reg.SubexpNames()
	matches = reg.FindAllStringSubmatch(flagVar, -1)
	for _, m := range matches {
		for grpIdx, value := range m {
			if groups[grpIdx] == "value" {
				return value, nil
			}
		}
	}

	return flagVar, nil
}

func readPasswordFromFile(path string, index int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if index > len(lines)-1 {
		return "", fmt.Errorf("File did not contain enough data to read from line %d", index)
	}
	return lines[index], nil
}
