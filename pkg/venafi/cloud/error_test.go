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
	"strings"
	"testing"
)

func TestParseResponseErrors(t *testing.T) {
	data := []byte("{\"errors\":[{\"code\":10128,\"message\":\"Invalid change in apiKey status\",\"args\":[]}]}")
	errors, err := parseResponseErrors(data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if len(errors) != 1 {
		t.Fatalf("Parsed error count was not what was expected.  Expected: 1 Actual: %d", len(errors))
	}
}

func TestParseResponseError(t *testing.T) {
	data := []byte("{\"code\":10128,\"message\":\"Invalid change in apiKey status\",\"args\":[]}")
	e, err := parseResponseError(data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if e.Code != 10128 {
		t.Fatalf("ParseResponseError returned incorrect code.  Expected: 10128 Actual: %d", e.Code)
	}
}

func TestParseResponseErrorWithArgs(t *testing.T) {
	data := []byte("{\"errors\": [{\"code\": 10726,\"message\": \"Distinguished name component CN with value \\\"test.venafi.io\\\" is invalid\",\"args\": [\"CN\",\"test.venafi.io\",[\".*.example.com\",\".*.example.org\",\".*.example.net\",\".*.invalid\",\".*.local\",\".*.localhost\",\".*.test\"]]}]}")
	errors, err := parseResponseErrors(data)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if len(errors) != 1 {
		t.Fatalf("ParseResponseErrors returned incorrect error count.  Expected: 1 Actual: %d", len(errors))
	}
	if errors[0].Code != 10726 {
		t.Fatalf("ParseResponseErrors returned incorrect code.  Expected: 10726 Actual: %d", errors[0].Code)
	}

	a, err := errors[0].parseResponseArgs()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if !strings.Contains(a, ".*.invalid") {
		t.Fatalf("ErrorResponse.Args did not contain expected string: .*.invalid  Actual: %s", a)
	}
}
