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
	"fmt"
	"strings"
	"testing"
)

func TestGetURL(t *testing.T) {
	rootUrl := "https://api2.projectc.venafi.com/v1/"

	url := string(urlUserAccounts.Absolute(rootUrl))
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", rootUrl, urlUserAccounts)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", rootUrl, urlUserAccounts), url)
	}

	url = string(urlCertificateRequests.Absolute(rootUrl))
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", rootUrl, urlCertificateRequests)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", rootUrl, urlCertificateRequests), url)
	}

	url = string(urlCertificateRetrievePem.Absolute(rootUrl))
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", rootUrl, urlCertificateRetrievePem)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", rootUrl, urlCertificateRetrievePem), url)
	}
}
