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
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"
)

// namePrefix marks every cloud provider and keystore created by the CI. The
// lifecycle never modifies or deletes objects without it.
const namePrefix = "vcert-ci-"

var ciNamePattern = regexp.MustCompile(`^` + namePrefix + `([0-9]+)-`)

// ciName returns the name of an object created by the CI. It embeds the
// creation time, so that objects left behind by a crashed run can be told
// apart from those of a run still in progress.
func ciName(created time.Time, runID string, suffix string) string {
	return fmt.Sprintf("%s%d-%s-%s", namePrefix, created.Unix(), runID, suffix)
}

// ciCreated returns the creation time embedded in a CI object name, and
// false for names that were not created by the CI
func ciCreated(name string) (time.Time, bool) {
	m := ciNamePattern.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

const (
	kindAWS   = "aws"
	kindAzure = "azure"
)

// state is what setup created, saved for check and teardown. It holds no
// secrets: those are read again from the configuration.
type state struct {
	Target     string          `json:"target"`
	RunID      string          `json:"runId"`
	Skipped    bool            `json:"skipped"`
	SkipReason string          `json:"skipReason,omitempty"`
	Providers  []providerState `json:"providers"`
	Keystores  []keystoreState `json:"keystores"`
	// Env holds the variables the provisioning tests (aruba) read to find the
	// keystores to provision to
	Env map[string]string `json:"env"`
}

type providerState struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	ConfigIndex int    `json:"configIndex"`
}

type keystoreState struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	ProviderID   string `json:"providerId"`
	ConfigIndex  int    `json:"configIndex"`
	CanProvision bool   `json:"canProvision"`
	// AWS region or Azure key vault name
	Location string `json:"location"`
}

func (s *state) save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// loadState returns nil when there is no state file, as when setup did not run
func loadState(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("cannot parse state file %s: %w", path, err)
	}
	return &s, nil
}
