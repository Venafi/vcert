/*
 * Copyright 2018-2021 Venafi, Inc.
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

package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func ConvertCertToOpenSSHAgentFormat(privateKeyData string, certificateData string) (interface{}, *ssh.Certificate, error) {

	privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyData))
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing private key data: %v", err)
	}

	certEncoded := strings.Split(certificateData, " ")[1]
	if len(certEncoded) < 1 {
		return nil, nil, fmt.Errorf("invalid certificate data")
	}

	certRawBytes, err := base64.StdEncoding.DecodeString(certEncoded)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode certificate: %v", err)
	}

	certPubKey, err := ssh.ParsePublicKey(certRawBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificate %v", err)
	}
	cert := certPubKey.(*ssh.Certificate)
	return privateKey, cert, nil
}
