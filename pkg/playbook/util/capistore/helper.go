//go:build windows

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

package capistore

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const validInputRegex string = `^[A-Za-z0-9\s-_\.]+$` // regex for validating keystore and binding fields to prevent commandline injection

func psBool(b bool) string {
	if b {
		return "1" // Represents True
	}
	return "0" // Represents False
}

func containsInjectableData(value string) error {
	if len(value) == 0 {
		return nil
	}

	re := regexp.MustCompile(validInputRegex)
	if !re.MatchString(value) {
		return errors.New("the input contained invalid characters")
	}
	return nil
}

func copyScript(script, scriptPath string) error {
	input := []byte(script)

	err := os.WriteFile(scriptPath, input, 0644)
	if err != nil {
		zap.L().Error("Error creating script file")
		return err
	}

	return nil
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, "\t ") && !strings.HasSuffix(s, "'") && !strings.HasPrefix(s, "'") {
		return fmt.Sprintf("'%s'", s)
	}
	return s
}
