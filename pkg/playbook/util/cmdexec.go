//go:build !windows

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

package util

import (
	"bytes"
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// ExecuteScript takes the afterAction input and passes it to a Cmd struct to be executed.
//
// No validation is done over the afterAction string, so caution is advised.
func ExecuteScript(afterAction string) (string, error) {
	zap.L().Debug(fmt.Sprintf("running After-install actions: %s", afterAction))

	cmd := exec.Command("sh", "-c", afterAction)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not run after-install action: %s", err.Error()))
		return "", err
	}
	zap.L().Debug(fmt.Sprintf("after-install output: %s", out.String()))
	return out.String(), nil
}
