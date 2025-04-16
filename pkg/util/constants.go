package util

import (
	"fmt"
)

const (
	PathSeparator           = "\\"
	ApplicationServerTypeID = "784938d1-ef0d-11eb-9461-7bb533ba575b"
)

var (
	// We load this variable from build command instead of reusing the vcert one to avoid circular dependencies
	versionString string
	// DefaultUserAgent is the default value of the UserAgent header in HTTP
	// requests to Venafi API endpoints.
	DefaultUserAgent = fmt.Sprintf("vcert-sdk/%s", getVersionString()[1:])
)

func getVersionString() string {
	if versionString == "" {
		return "Unknown"
	}
	return versionString
}
