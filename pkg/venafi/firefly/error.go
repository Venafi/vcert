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

package firefly

import (
	"encoding/json"
	"fmt"
)

type responseError struct {
	ErrorKey         string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewResponseError(b []byte) (*responseError, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("failed to parser empty error message")
	}
	var data = &responseError{}
	err := json.Unmarshal(b, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parser server error: %s", err)
	}
	return data, nil
}

func (e *responseError) Error() string {
	return "error: " + e.ErrorKey + " - error description: " + e.ErrorDescription
}
