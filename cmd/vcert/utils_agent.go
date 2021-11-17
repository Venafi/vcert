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
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// The environment variable pointing to the Unix socket the OpenSSH agent is running on
	SSHAuthSock = "SSH_AUTH_SOCK"
)

func AddKeyToOpenSSHAgent(privateKeyData string, certificateData string) error {
	key, cert, err := ConvertCertToOpenSSHAgentFormat(privateKeyData, certificateData)

	if err != nil {
		return err
	}

	return addKeyToOpenSSHAgent(key, cert)
}

func addKeyToOpenSSHAgent(key interface{}, cert *ssh.Certificate) error {

	if cert == nil || key == nil {
		return fmt.Errorf("private key or certificate not provided. Could not add them to OpenSSH agent")
	}
	openSSHAgent, err := connectToSSHAgent()
	if err != nil || openSSHAgent == nil {
		return fmt.Errorf("failed to comunicate with the OpenSSH agent. Error %s", err)
	}

	var keysCountBegining int
	// Remember how many keys are in the agent before adding the new one
	if keys, err := openSSHAgent.List(); err != nil {
		return fmt.Errorf("unable to interact with the OpenSSH agent: %v", err)
	} else if len(keys) > 0 {
		//logf("%d key(s) already present", len(keys))
		keysCountBegining = len(keys)
	}

	// FIXME: Get rig of the following code
	lifetimeSecs := uint32(8 * 60 * 60) // 8 hours

	if cert.ValidBefore > 0 {
		lifetimeSecs = uint32(cert.ValidBefore - uint64(time.Now().Unix()))
	}

	// Attempt to insert the private key with certificate
	err = openSSHAgent.Add(agent.AddedKey{
		PrivateKey:   key,
		Certificate:  cert,
		Comment:      cert.KeyId,
		LifetimeSecs: lifetimeSecs,
	})

	if err != nil {
		return fmt.Errorf("could not insert '%T' to OpenSSH agent: %v", key, err)
	}

	// Check if the key was added
	if keys, err := openSSHAgent.List(); err != nil {
		return fmt.Errorf("could not list the keys in OpenSSH agent. Error: %v", err)
	} else if len(keys) < keysCountBegining+1 {
		return fmt.Errorf("could not insert '%T' to OpenSSH agent. Error: %v", key, err)
	}
	logf("SSH certificate '%s' has been successfully added to OpenSSH agent.", cert.KeyId)
	return nil
}

// Connects to the OpenSSH agent
func connectToSSHAgent() (agent.Agent, error) {
	socketPath := os.Getenv(SSHAuthSock)
	if socketPath == "" {
		bin, err := exec.LookPath("ssh-agent")
		if err != nil || bin == "" {
			return nil, fmt.Errorf("OpenSSH agent is not running and we could not find OpenSSH agent executable")
		}

		return nil, fmt.Errorf("OpenSSH agent is not running. You need to start it by executing: eval `%s`", bin)
	}

	conn, err := Dial(socketPath)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to OpenSSH agent on socket: %q. Error: %v", socketPath, err)
	}

	// FIXME: Make it Debug
	//logf("Connected to OpenSSH agent on socket: %q", socketPath)
	return agent.NewClient(conn), nil
}

// Dial creates net.Conn to a SSH agent listening on a Unix socket.
func Dial(socket string) (net.Conn, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
