/*
 * Copyright 2023 Venafi, Inc.
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
			zap.L().Debug("certificate file does not exist at location", zap.String("location", certPath))
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
		zap.L().Error("could not create certificate directory path", zap.String("location", location),
			zap.Error(err))
		return err
	}

	err = os.WriteFile(location, content, 0600)
	if err != nil {
		zap.L().Error("could not write certificate to file", zap.String("file", location), zap.Error(err))
		return err
	}
	return nil
}

// CopyFile makes a copy of the given source to the given destination using Go's native copy function io.Copy
func CopyFile(source string, destination string) error {
	zap.L().Debug("checking file", zap.String("location", source))

	sourceFileStat, err := os.Stat(source)
	if err != nil {
		zap.L().Error("failed to stat file", zap.String("file", source), zap.Error(err))
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		m := "file is not a regular file"
		zap.L().Error(m, zap.String("file", source))
		return fmt.Errorf("%s: %s", m, source)
	}

	sourceFile, err := os.Create(source)
	if err != nil {
		zap.L().Error("failed to create/truncate file", zap.String("file", source), zap.Error(err))
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(destination)
	if err != nil {
		zap.L().Error("failed to create/truncate file", zap.String("file", destination), zap.Error(err))
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		zap.L().Error("failed to copy file", zap.String("source", source),
			zap.String("destination", destination), zap.Error(err))
		return err
	}
	zap.L().Debug("file successfully copied", zap.String("source", source),
		zap.String("destination", destination))

	return nil
}
