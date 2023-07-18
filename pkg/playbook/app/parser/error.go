package parser

import "fmt"

var (
	// ErrNoLocation is thrown when no location is provided for the Playbook file
	ErrNoLocation = fmt.Errorf("playbook location was not provided")
	// ErrReadFile is thrown when the Playbook file cannot be read/accessed
	ErrReadFile = fmt.Errorf("could not read playbook file")
	// ErrTextTplParsing is thrown when the templates in the Playbook file cannot be parsed.
	//
	// E.g. {{ Env "Hostname" }}
	ErrTextTplParsing = fmt.Errorf("failed to parse the playbook file")
	// ErrFileUnmarshall is thrown when the content of the Playbook file cannot be successfully unmarshalled into a domain.Playbook object
	ErrFileUnmarshall = fmt.Errorf("failed to unmarshal the playbook file")
)
