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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewResponseErrorWithDescription(t *testing.T) {
	var jsonError = []byte(`{"error": "error_short", "error_description": "error description"}`)

	respError, err := NewResponseError(jsonError)
	assert.Nil(t, err)
	assert.NotNil(t, respError)
	assert.Equal(t, "error_short", respError.ErrorKey)
	assert.Equal(t, "error description", respError.ErrorDescription)
	assert.Equal(t, "error_short: error description", respError.Error())
}

func TestNewResponseErrorWithoutDescription(t *testing.T) {
	var jsonError = []byte(`{"error": "error_short"}`)

	respError, err := NewResponseError(jsonError)
	assert.Nil(t, err)
	assert.NotNil(t, respError)
	assert.Equal(t, "error_short", respError.ErrorKey)
	assert.Equal(t, "", respError.ErrorDescription)
	assert.Equal(t, "error_short", respError.Error())
}

func TestNewResponseErrorNilData(t *testing.T) {

	respError, err := NewResponseError(nil)
	if assert.Errorf(t, err, "I was expected an error but is nil") {
		assert.Error(t, err, "failed to parser empty error message")
	}
	assert.Nil(t, respError)
}

func TestNewResponseErrorWrongData(t *testing.T) {

	var jsonError = []byte(`"error": "error_short"`) //omitted the curly brackets to test the unmarshal error

	respError, err := NewResponseError(jsonError)
	if assert.Errorf(t, err, "I was expected an error but is nil") {
		assert.Error(t, err, "failed to parser empty error message")
	}
	assert.Nil(t, respError)
}
