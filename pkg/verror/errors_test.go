package verror

import (
	"testing"
)

// Parameters `Platform` and `StatusCode` are always printed (and thus implicitly
// required), but the error message in general depends upon other all parameters
// passed to the Error structure object.
//
// If `Status` and `StatusCode` are provided, `Status` will take precedence
// | Platform | Status | StatusCode | Operation | Body | Message                                                                                             |
// | x        | x      | x          |           |      | unexpected status code on %{platform}. Status: %{status}                                            |
// | x        | x      | x          | x         |      | unexpected status code on %{platform} %{action}. Status: %{status}                                  |
// | x        | x      | x          | x         | x    | unexpected status code on %{platform} %{action}. \n Status:\n %{status}. \n Body:\n %{body} \n      |
// | x        | x      | x          |           | x    | unexpected status code on %{platform}. \n Status:\n %{status}. \n Body:\n %{body} \n                |
// | x        |        | x          |           |      | unexpected status code on %{platform}. Status: %{status_code}                                       |
// | x        |        | x          | x         |      | unexpected status code on %{platform} %{action}. Status: %{status_code}                             |
// | x        |        | x          | x         | x    | unexpected status code on %{platform} %{action}. \n Status:\n %{status_code}. \n Body:\n %{body} \n |
// | x        |        | x          |           | x    | unexpected status code on %{platform}. \n Status:\n %{status_code}. \n Body:\n %{body} \n           |
//
// The following unit tests will cover those cases in that order.

// Format string for when test fails, displays both strings for comparison (might want to diff them instead?)
const stringDontMatch = "Error messages do not match: \n Expected:\n%v\n Got: \n%v"

// Error Mock for creating test cases
type VCertConnectorUnexpectedStatusErrorMock struct {
	Status string
	StatusCode int
	Body []byte
	Platform string
	Operation string
}

func Test_VCertConnectorUnexpectedStatusError(t *testing.T) {
	testCases := []struct {
		testName string
		testMessage string
		testError VCertConnectorUnexpectedStatusErrorMock
	} {
		// Test with Platform, Status and StatusCode:
		{
			testName: "Platform Status StatusCode",
			testMessage: "unexpected status code on TPP. Status: 401 Unauthorized",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "401 Unauthorized",
				StatusCode: 401,
				Platform: "TPP",
			},
		},
		// Test with Platform, Status, StatusCode and Operation:
		{
			testName: "Platform Status StatusCode Operation",
			testMessage: "unexpected status code on VaaS certificate search. Status: 500 Internal Server Error",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "500 Internal Server Error",
				StatusCode: 500,
				Platform: "VaaS",
				Operation: "certificate search",
			},
		},
		// Test with Platform, Status, StatusCode, Operation and Body:
		{
			testName: "Platform Status StatusCode Operation Body",
			testMessage: "unexpected status code on TPP DN to GUID request.\n Status:\n 400 Bad Request. \n Body:\n the body \n",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "400 Bad Request",
				StatusCode: 400,
				Platform: "TPP",
				Operation: "DN to GUID request",
				Body: []byte("the body"),
			},
		},
		// Test with Platform, Status, StatusCode and Body:
		{
			testName: "Platform Status StatusCode Body",
			testMessage: "unexpected status code on TPP.\n Status:\n 502 Bad Gateway. \n Body:\n the body \n",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "502 Bad Gateway",
				StatusCode: 502,
				Platform: "TPP",
				Body: []byte("the body"),
			},
		},
		// Test with Platform and StatusCode:
		{
			testName: "Platform StatusCode",
			testMessage: "unexpected status code on TPP. Status: 401",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				StatusCode: 401,
				Platform: "TPP",
			},
		},
		// Test with Platform, StatusCode and Operation:
		{
			testName: "Platform StatusCode Operation",
			testMessage: "unexpected status code on VaaS certificate search. Status: 500",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				StatusCode: 500,
				Platform: "VaaS",
				Operation: "certificate search",
			},
		},
		// Test with Platform, StatusCode, Operation and Body:
		{
			testName: "Platform StatusCode Operation Body",
			testMessage: "unexpected status code on TPP DN to GUID request.\n Status:\n 400. \n Body:\n the body \n",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				StatusCode: 400,
				Platform: "TPP",
				Operation: "DN to GUID request",
				Body: []byte("the body"),
			},
		},
		// Test with Platform, StatusCode and Body:
		{
			testName: "Platform StatusCode Body",
			testMessage: "unexpected status code on TPP.\n Status:\n 502. \n Body:\n the body \n",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				StatusCode: 502,
				Platform: "TPP",
				Body: []byte("the body"),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			err := VCertConnectorUnexpectedStatusError{}
			err.Status = testCase.testError.Status
			err.StatusCode = testCase.testError.StatusCode
			err.Body = testCase.testError.Body
			err.Platform = testCase.testError.Platform
			err.Operation = testCase.testError.Operation

			errString := err.Error()

			if errString != testCase.testMessage {
				t.Errorf(stringDontMatch, testCase.testMessage, errString)
			}

		})
	}
}
