/*
 * Copyright 2018 Venafi, Inc.
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

package tpp

import (
	"strings"
	"testing"
)

func TestNewResponseError(t *testing.T) {
	var err error
	s := `
		{
			"ErrorDetails": "Failed to load certificate list due to a query error, please check the query parameters and try again. Error details: The query parameter Thumbprint did not match any known query possibilities, please check your parameters and try again.\r\n"
		}
	`

	err = NewResponseError(nil)
	if err == nil {
		t.Fatal("error cannot be nil")
	}

	err = NewResponseError([]byte(s))
	if !strings.Contains(err.Error(), "Failed to load certificate") {
		t.Fatal("failed to parse error message")
	}
}
