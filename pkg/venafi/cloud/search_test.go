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
	"testing"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

func TestSearchRequest(t *testing.T) {

	// encoding to JSON
	req := &cloud_structs.SearchRequest{
		Expression: &cloud_structs.Expression{
			Operands: []cloud_structs.Operand{
				{
					Field:    "fingerprint",
					Operator: cloud_structs.MATCH,
					Value:    "A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6",
				},
			},
		},
		Paging: &cloud_structs.Paging{10, 10},
	}
	var expectedJson = `{"expression":{"operands":[{"field":"fingerprint","operator":"MATCH","value":"A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6"}]},"paging":{"pageNumber":10,"pageSize":10}}`

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expectedJson {
		t.Fatalf("expected different JSON:\nhave:     %s\nexpected: %s", data, expectedJson)
	}
	t.Logf("%s\n", data)

	// decoding from JSON
	var req2 = &cloud_structs.SearchRequest{}
	err = json.Unmarshal(data, req2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v\n", req2)
	data2, err := json.Marshal(req2)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(data2) {
		t.Fatalf("one expected to be the same as another:\none:   %s\nother: %s", data, data2)
	}

	// if Paging is not specified, it should not be included to JSON
	req = &cloud_structs.SearchRequest{
		Expression: &cloud_structs.Expression{
			Operands: []cloud_structs.Operand{
				{
					Field:    "fingerprint",
					Operator: cloud_structs.MATCH,
					Value:    "A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6",
				},
			},
		},
	}
	expectedJson = `{"expression":{"operands":[{"field":"fingerprint","operator":"MATCH","value":"A7BDECDA0B67D5CEF28D6C8C7D7CFA882E3DC9D6"}]}}`

	data, err = json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expectedJson {
		t.Fatalf("expected different JSON:\nhave:     %s\nexpected: %s", data, expectedJson)
	}
}

func TestGetAppNameFromZone(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty",
			input:    "",
			expected: "",
		},
		{
			name:     "App",
			input:    "Just The App Name",
			expected: "Just The App Name",
		},
		{
			name:     "App+Cit",
			input:    "The application\\With Cit",
			expected: "The application",
		},
		{
			name:     "App+Cit Complex",
			input:    "The complex application\\name\\and the cit",
			expected: "The complex application\\name",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			appName := getAppNameFromZone(testCase.input)
			if testCase.expected != appName {
				t.Errorf("unmatched application name\nExpected:\n%v\nGot:\n%v", testCase.expected, appName)
			}
		})
	}
}

type FormatSearchCertificateArgumentsMock struct {
	cn              string
	sans            *certificate.Sans
	certMinTimeLeft time.Duration
}

func TestFormatSearchCertificateArguments(t *testing.T) {
	testCases := []struct {
		name     string
		input    FormatSearchCertificateArgumentsMock
		expected *cloud_structs.SearchRequest
	}{
		{
			// test empty arguments, should return just the validityPeriodDays
			// argument
			name:  "Empty",
			input: FormatSearchCertificateArgumentsMock{},
			expected: &cloud_structs.SearchRequest{
				Expression: &cloud_structs.Expression{
					Operator: cloud_structs.AND,
					Operands: []cloud_structs.Operand{
						{
							Field:    "validityPeriodDays",
							Operator: cloud_structs.GTE,
							Value:    0,
						},
					},
				},
			},
		},
		{
			// test with just CN, should return subjectCN and validityPeriodDays
			// arguments
			name: "CN",
			input: FormatSearchCertificateArgumentsMock{
				cn: "test.example.com",
			},
			expected: &cloud_structs.SearchRequest{
				Expression: &cloud_structs.Expression{
					Operator: cloud_structs.AND,
					Operands: []cloud_structs.Operand{
						{
							Field:    "validityPeriodDays",
							Operator: cloud_structs.GTE,
							Value:    0,
						},
						{
							Field:    "subjectCN",
							Operator: cloud_structs.EQ,
							Value:    "test.example.com",
						},
					},
				},
			},
		},
		{
			// test with just 1 DNS, should return subjectAlternativeNameDns and
			// validityPeriodDays arguments
			name: "SANS_1",
			input: FormatSearchCertificateArgumentsMock{
				sans: &certificate.Sans{DNS: []string{"one.example.com"}},
			},
			expected: &cloud_structs.SearchRequest{
				Expression: &cloud_structs.Expression{
					Operator: cloud_structs.AND,
					Operands: []cloud_structs.Operand{
						{
							Field:    "validityPeriodDays",
							Operator: cloud_structs.GTE,
							Value:    0,
						},
						{
							Field:    "subjectAlternativeNameDns",
							Operator: cloud_structs.IN,
							Values:   []string{"one.example.com"},
						},
					},
				},
			},
		},
		{
			// test with just 2 DNS, should return both subjectAlternativeNameDns and
			// validityPeriodDays arguments
			name: "SANS_2",
			input: FormatSearchCertificateArgumentsMock{
				sans: &certificate.Sans{DNS: []string{"one.example.com", "two.example.com"}},
			},
			expected: &cloud_structs.SearchRequest{
				Expression: &cloud_structs.Expression{
					Operator: cloud_structs.AND,
					Operands: []cloud_structs.Operand{
						{
							Field:    "validityPeriodDays",
							Operator: cloud_structs.GTE,
							Value:    0,
						},
						{
							Field:    "subjectAlternativeNameDns",
							Operator: cloud_structs.IN,
							Values:   []string{"one.example.com", "two.example.com"},
						},
					},
				},
			},
		},
		{
			// test with CN and 1 DNS, should return the subjectCN, 1
			// subjectAlternativeNameDns and validityPeriodDays arguments
			name: "CN SANS_1",
			input: FormatSearchCertificateArgumentsMock{
				cn:   "one.example.com",
				sans: &certificate.Sans{DNS: []string{"one.example.com"}},
			},
			expected: &cloud_structs.SearchRequest{
				Expression: &cloud_structs.Expression{
					Operator: cloud_structs.AND,
					Operands: []cloud_structs.Operand{
						{
							Field:    "validityPeriodDays",
							Operator: cloud_structs.GTE,
							Value:    0,
						},
						{
							Field:    "subjectAlternativeNameDns",
							Operator: cloud_structs.IN,
							Values:   []string{"one.example.com"},
						},
						{
							Field:    "subjectCN",
							Operator: cloud_structs.EQ,
							Value:    "one.example.com",
						},
					},
				},
			},
		},
		{
			// test with CN and 2 DNS, should return the subjectCN, 2
			// subjectAlternativeNameDns and validityPeriodDays arguments
			name: "CN SANS_2",
			input: FormatSearchCertificateArgumentsMock{
				cn:   "one.example.com",
				sans: &certificate.Sans{DNS: []string{"one.example.com", "two.example.com"}},
			},
			expected: &cloud_structs.SearchRequest{
				Expression: &cloud_structs.Expression{
					Operator: cloud_structs.AND,
					Operands: []cloud_structs.Operand{
						{
							Field:    "validityPeriodDays",
							Operator: cloud_structs.GTE,
							Value:    0,
						},
						{
							Field:    "subjectAlternativeNameDns",
							Operator: cloud_structs.IN,
							Values:   []string{"one.example.com", "two.example.com"},
						},
						{
							Field:    "subjectCN",
							Operator: cloud_structs.EQ,
							Value:    "one.example.com",
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req := formatSearchCertificateArguments(testCase.input.cn, testCase.input.sans, testCase.input.certMinTimeLeft)
			// stringify the instances
			expected := util.GetJsonAsString(testCase.expected)
			request := util.GetJsonAsString(req)
			// compare as string
			matches := expected == request
			if !matches {
				t.Errorf("unmatched regexp\nExpected:\n%v\nGot:\n%v", expected, request)
			}
		})
	}
}
