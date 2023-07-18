package util

var versionString string

// GetFormattedVersionString gets a friendly printable string to represent the version
func GetFormattedVersionString() string {
	if versionString == "" {
		versionString = "Unknown"
	}
	return versionString
}
