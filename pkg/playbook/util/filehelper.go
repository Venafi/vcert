package util

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// FileExists returns true if  a file exists and is accessible on the given certPath
func FileExists(certPath string) (bool, error) {
	_, err := os.Stat(certPath)
	if err != nil {
		// Certificate does not exist in location. Install
		if errors.Is(err, os.ErrNotExist) {
			zap.L().Debug(fmt.Sprintf("certificate file does not exist at location %s", certPath))
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// WriteFile saves the content in the given location. Creates any folders necessary for this action
func WriteFile(location string, content []byte) error {
	dirPath := filepath.Dir(location)
	err := os.MkdirAll(dirPath, 0750)
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not create certificate directory path %s: %s", location, err.Error()))
		return err
	}

	err = os.WriteFile(location, content, 0600)
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not write certificate to file %s: %s", location, err.Error()))
		return err
	}
	return nil
}

func CopyFile(source string, destination string) error {
	zap.L().Debug(fmt.Sprintf("checking certificate at: %s", source))

	zap.L().Debug(fmt.Sprintf("Copying file from %s to %s", source, destination))
	sourceFileStat, err := os.Stat(source)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", source)
	}

	sourceFile, err := os.Create(source)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	_, err = io.Copy(destinationFile, sourceFile)
	return err
}
