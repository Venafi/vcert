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
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
)

var errorTemplate = "%w: %s"

// ReadPlaybook reads the file in location, parses the content and returns a Playbook object
func ReadPlaybook(location string) (domain.Playbook, error) {
	playbook := domain.NewPlaybook()

	//Set location. Otherwise, use default
	if location != "" {
		playbook.Location = location
	}

	data, err := readFile(location)

	if err != nil {
		return playbook, err
	}

	data, err = parseConfigTemplate(data)
	if err != nil {
		return playbook, fmt.Errorf(errorTemplate, ErrTextTplParsing, err.Error())
	}

	err = yaml.Unmarshal(data, &playbook)
	if err != nil {
		return playbook, fmt.Errorf(errorTemplate, ErrFileUnmarshall, err.Error())
	}

	zap.L().Info("playbook successfully parsed")
	return playbook, nil
}

// ReadPlaybookRaw reads the file in location and parses the content to a map.
//
// This is specially useful to avoid parsing the template values in the file
func ReadPlaybookRaw(location string) (map[string]interface{}, error) {
	data, err := readFile(location)
	if err != nil {
		return nil, err
	}

	dataMap := make(map[string]interface{})
	err = yaml.Unmarshal(data, &dataMap)
	if err != nil {
		return nil, fmt.Errorf(errorTemplate, ErrFileUnmarshall, err.Error())
	}

	zap.L().Info("playbook data successfully parsed")
	return dataMap, nil
}

func readFile(location string) ([]byte, error) {
	var data []byte

	if location == "" {
		return data, ErrNoLocation
	}

	// The location is an invalid URL
	zap.L().Debug("reading from local file system")
	data, err := os.ReadFile(location)

	if err != nil {
		return data, fmt.Errorf(errorTemplate, ErrReadFile, err.Error())
	}

	return data, nil
}

func parseConfigTemplate(b []byte) ([]byte, error) {
	// Valid functions for the config file template
	fm := template.FuncMap{
		"Env": func(es ...string) (string, error) {
			if len(es) == 1 {
				e := es[0]
				value, found := os.LookupEnv(e)
				if found {
					return value, nil
				}
				return "", fmt.Errorf("environment variable not defined: %s", e)
			} else if len(es) == 2 {
				e := es[0]
				d := es[1]
				value, found := os.LookupEnv(e)
				if found {
					return value, nil
				} else {
					return d, nil
				}
			} else {
				return "", fmt.Errorf("unsupported number of inputs provided: %d", len(es))
			}
		},
		"Hostname": func() string {
			hostname, err := os.Hostname()
			if err != nil {
				zap.L().Warn("failed to automatically determine hostname", zap.Error(err))
				return ""
			}
			return hostname
		},
		"ToLower": strings.ToLower,
		"ToUpper": strings.ToUpper,
	}

	// Parse the YAML config template file
	tpl, err := template.New("config").Funcs(fm).Parse(string(b))
	if err != nil {
		return nil, err
	}

	// Get a bytes buffer to store results in
	buf := &bytes.Buffer{}

	err = tpl.Execute(buf, nil)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
