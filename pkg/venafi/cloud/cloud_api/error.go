/*
 * Copyright 2022 Venafi, Inc.
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

package cloud_api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

type HttpStatusError struct {
	StatusCode int
}

func (e HttpStatusError) Error() string {
	return fmt.Sprintf("HTTP status code %d", e.StatusCode)
}

func IsHttpStatusError(err error, statusCode int) bool {
	statusError := HttpStatusError{}
	return errors.As(err, &statusError) && statusError.StatusCode == statusCode
}

type InvalidResponseBody struct {
	HttpStatusError HttpStatusError
}

func (e InvalidResponseBody) Unwrap() error {
	return e.HttpStatusError
}

func (e InvalidResponseBody) Error() string {
	return fmt.Sprintf("%s: could not read error response body", e.HttpStatusError)
}

type UnstructuredResponseBody struct {
	HttpStatusError HttpStatusError
	Body            string
}

func (e UnstructuredResponseBody) Unwrap() error {
	return e.HttpStatusError
}

func (e UnstructuredResponseBody) Error() string {
	return fmt.Sprintf("%s: %s", e.HttpStatusError, e.Body)
}

type StructuredResponseBody struct {
	HttpStatusError HttpStatusError
	Body            cloud_structs.ResponseErrors
}

func (e StructuredResponseBody) Unwrap() error {
	return e.HttpStatusError
}

func (e StructuredResponseBody) Error() string {
	return fmt.Sprintf("%s: %v", e.HttpStatusError, e.Body)
}

func parseResponseErrors(statusCode int, body io.Reader) error {
	statusCodeErr := HttpStatusError{StatusCode: statusCode}

	responseBytes, err := io.ReadAll(body)
	if err != nil {
		return InvalidResponseBody{HttpStatusError: statusCodeErr}
	}

	var responseErrors cloud_structs.ResponseErrors

	decoder := json.NewDecoder(bytes.NewBuffer(responseBytes))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&responseErrors)
	if err == nil {
		return StructuredResponseBody{HttpStatusError: statusCodeErr, Body: responseErrors}
	} else {
		return UnstructuredResponseBody{HttpStatusError: statusCodeErr, Body: string(responseBytes)}
	}
}
