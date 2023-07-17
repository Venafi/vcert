package parser

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// WritePlaybook takes an object and serializes it to a file in the given location
func WritePlaybook(object interface{}, location string) error {
	data, err := yaml.Marshal(object)
	if err != nil {
		return fmt.Errorf("could not marshall playbook object: %w", err)
	}

	err = os.WriteFile(location, data, 0600)
	if err != nil {
		return fmt.Errorf("could not write playbook file: %w", err)
	}

	return nil
}
