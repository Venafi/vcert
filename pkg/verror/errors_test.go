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

// Fixtures
const (
	errStatus = "401"
	// Test with Platform and Status:
	testString1 = "unexpected status code on TPP. Status: 401"
	// Test with Platform, Status and Operation:
	testString2 = "unexpected status code on TPP certificate search. Status: 401"
	// Test with Platform, Status, Operation and Body:
	testString3 = "unexpected status code on TPP certificate search.\n Status:\n 401. \n Body:\n the body \n"
	// Test with Platform, Status and Body:
	testString4 = "unexpected status code on TPP.\n Status:\n 401. \n Body:\n the body \n"
	// Format string for when test fails, displays both strings for comparison (might want to diff them instead?)
	stringDontMatch = "Error messages do not match: \n errString:\n%v\n testString: \n%v"
)

// Test with Platform and Status:
func Test_Case1_VCertConnectorUnexpectedStatusError(t *testing.T) {
	err := VCertConnectorUnexpectedStatusError{Platform: "TPP"}
	err.Status = errStatus
	errString := err.Error()
	testString := testString1
	if errString != testString {
		t.Fatalf(stringDontMatch, errString, testString)
	}
}

// Test with Platform, Status and Operation:
func Test_Case2_VCertConnectorUnexpectedStatusError(t *testing.T) {
	err := VCertConnectorUnexpectedStatusError{Platform: "TPP", Operation: "certificate search"}
	err.Status = errStatus
	errString := err.Error()
	testString := testString2
	if errString != testString {
		t.Fatalf(stringDontMatch, errString, testString)
	}
}

// Test with Platform, Status, Operation and Body:
func Test_Case3_VCertConnectorUnexpectedStatusError(t *testing.T) {
	err := VCertConnectorUnexpectedStatusError{Platform: "TPP", Operation: "certificate search"}
	err.Status = errStatus
	err.Body = []byte("the body")
	errString := err.Error()
	testString := testString3
	if errString != testString {
		t.Fatalf(stringDontMatch, errString, testString)
	}
}

// Test with Platform, Status and Body:
func Test_Case4_VCertConnectorUnexpectedStatusError(t *testing.T) {
	err := VCertConnectorUnexpectedStatusError{Platform: "TPP"}
	err.Status = errStatus
	err.Body = []byte("the body")
	errString := err.Error()
	testString := testString4
	if errString != testString {
		t.Fatalf(stringDontMatch, errString, testString)
	}
}
