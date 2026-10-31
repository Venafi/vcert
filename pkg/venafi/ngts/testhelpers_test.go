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

// Test helpers shared by the credential-free unit tests and the
// `integration`-tagged tests. Deliberately NOT behind the integration build
// tag so that a plain `go test ./...` can still compile this package.

package ngts

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// createMockJWT builds a syntactically valid but unsigned JWT with the given
// expiry. The signature is a fixed placeholder — nothing verifies it; the token
// only needs to parse so expiry handling can be exercised.
func createMockJWT(expiryTime time.Time) (string, error) {
	// JWT Header (algorithm and type)
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// JWT Payload (claims)
	now := time.Now()
	payload := map[string]any{
		"exp":   expiryTime.Unix(),
		"iat":   now.Unix(),
		"sub":   "test-subject",
		"scope": "test-scope",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// For testing, we don't need a real signature, just a dummy one
	signature := "dummy-signature-for-testing"
	signatureEncoded := base64.RawURLEncoding.EncodeToString([]byte(signature))

	// Combine: header.payload.signature
	token := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded)
	return token, nil
}
