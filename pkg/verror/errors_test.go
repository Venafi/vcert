package verror

import (
	"testing"
)

// Parameters `Platform` and `Status` are always printed (and thus implicitly
// required), but the error message in general depends upon other all parameters
// passed to the Error structure object.
//
// | Platform | Status | Operation | Body | Message                                                                                    |
// | x        | x      |           |      | unexpected status code on %{platform}. Status: %{status}                                   |
// | x        | x      | x         |      | unexpected status code on %{platform} %{action}. Status: %{status}                         |
// | x        | x      | x         | x    | unexpected status code on %{platform} %{action}. \n Status:\n %status. \n Body:\n %body \n |
// | x        | x      |           | x    | unexpected status code on %{platform}. \n Status:\n %{status}. \n Body:\n %{body} \n       |
//
// The following unit tests will cover those cases in that order.

// Format string for when test fails, displays both strings for comparison (might want to diff them instead?)
const stringDontMatch = "Error messages do not match: \n Expected:\n%v\n Got: \n%v"

// Error Mock for creating test cases
type VCertConnectorUnexpectedStatusErrorMock struct {
	Status string
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
		// Test with Platform and Status:
		{
			testName: "Platform Status",
			testMessage: "unexpected status code on TPP. Status: 401",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "401",
				Platform: "TPP",
			},
		},
		// Test with Platform, Status and Operation:
		{
			testName: "Platform Status Operation",
			testMessage: "unexpected status code on VaaS certificate search. Status: 500",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "500",
				Platform: "VaaS",
				Operation: "certificate search",
			},
		},
		// Test with Platform, Status, Operation and Body:
		{
			testName: "Platform Status Operation Body",
			testMessage: "unexpected status code on TPP DN to GUID request.\n Status:\n 400. \n Body:\n the body \n",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "400",
				Platform: "TPP",
				Operation: "DN to GUID request",
				Body: []byte("the body"),
			},
		},
		// Test with Platform, Status and Body:
		{
			testName: "Platform Status Body",
			testMessage: "unexpected status code on TPP.\n Status:\n 501. \n Body:\n the body \n",
			testError: VCertConnectorUnexpectedStatusErrorMock{
				Status: "501",
				Platform: "TPP",
				Body: []byte("the body"),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			err := VCertConnectorUnexpectedStatusError{}
			err.Status = testCase.testError.Status
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
