/*
 * Copyright 2018-2023 Venafi, Inc.
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
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

const (
	commandGenCSRName       = "gencsr"
	commandEnrollName       = "enroll"
	commandPickupName       = "pickup"
	commandRevokeName       = "revoke"
	commandRenewName        = "renew"
	commandRetireName       = "retire"
	commandGetCredName      = "getcred"
	commandCheckCredName    = "checkcred"
	commandVoidCredName     = "voidcred"
	commandCreatePolicyName = "setpolicy"
	commandGetePolicyName   = "getpolicy"
	commandSshPickupName    = "sshpickup"
	commandSshEnrollName    = "sshenroll"
	commandSshGetConfigName = "sshgetconfig"
)

var (
	flags commandFlags
)

type commandFlags struct {
	apiKey               string
	appInfo              string
	audience             string
	caDN                 string
	certFile             string
	chainFile            string
	chainOption          string
	clientId             string
	clientSecret         string
	clientP12            string
	clientP12PW          string
	commonName           string
	config               string
	country              string
	csrFile              string
	csrOption            string
	customFields         []string
	distinguishedName    string
	dnsSans              stringSlice
	emailSans            rfc822NameSlice
	file                 string
	format               string
	friendlyName         string
	insecure             bool
	instance             string
	ipSans               ipSlice
	jksAlias             string
	jksPassword          string
	keyCurve             certificate.EllipticCurve
	keyCurveString       string
	keyFile              string
	keyPassword          string
	keySize              int
	keyType              *certificate.KeyType
	keyTypeString        string
	locality             string
	noPickup             bool
	noPrompt             bool
	noRetire             bool
	org                  string
	orgUnits             stringSlice
	pickupID             string
	pickupIDFile         string
	profile              string
	replaceInstance      bool
	revocationReason     string
	scope                string
	sshCred              bool
	pmCred               bool
	state                string
	testMode             bool
	testModeDelay        int
	thumbprint           string
	timeout              int
	tlsAddress           string
	email                string
	password             string
	token                string
	userName             string
	trustBundle          string
	upnSans              rfc822NameSlice
	uriSans              uriSlice
	url                  string
	tokenURL             string
	verbose              bool
	zone                 string
	omitSans             bool
	csrFormat            string
	credFormat           string
	validDays            string
	validPeriod          string
	platformString       string
	platform             venafi.PlatformType
	policyName           string
	policySpecLocation   string
	policyConfigStarter  bool
	verifyPolicyConfig   bool
	sshCertKeyId         string
	sshCertObjectName    string
	sshCertDestAddrs     stringSlice
	sshCertValidHours    int
	sshCertTemplate      string
	sshCertFolder        string
	sshCertPubKeyData    string
	sshCertForceCommand  string
	sshCertSourceAddrs   stringSlice
	sshCertPickupId      string
	sshCertGuid          string
	sshCertPubKey        string
	sshCertKeySize       int
	sshCertKeyPassphrase string
	sshCertExtension     stringSlice
	sshCertPrincipal     stringSlice
	sshCertWindows       bool
	sshFileCertEnroll    string
	sshFileGetConfig     string
}
