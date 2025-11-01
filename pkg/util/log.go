/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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

import "go.uber.org/zap"

// ConfigureLogger sets the default values for the cli logger
func ConfigureLogger(debug bool) error {
	zc := zap.NewDevelopmentConfig()
	if !debug {
		zc.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		zc.DisableStacktrace = true
	}
	l, err := zc.Build()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(l)

	return nil
}
