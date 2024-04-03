package util

import (
	"fmt"

	"github.com/Venafi/vcert/v5"
)

const (
	PathSeparator           = "\\"
	ApplicationServerTypeID = "784938d1-ef0d-11eb-9461-7bb533ba575b"
)

// DefaultUserAgent is the default value of the UserAgent header in HTTP
// requests to Venafi API endpoints.
var DefaultUserAgent = fmt.Sprintf("vcert-sdk/%s", vcert.GetFormattedVersionString()[1:])
