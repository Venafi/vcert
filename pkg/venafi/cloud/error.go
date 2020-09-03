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

package cloud

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/verror"
)

type responseError struct {
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Args    interface{} `json:"args,omitempty"`
}

type jsonData struct {
	Errors []responseError `json:"errors,omitempty"`
}

func parseResponseErrors(b []byte) ([]responseError, error) {
	var data jsonData
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return data.Errors, nil
}
