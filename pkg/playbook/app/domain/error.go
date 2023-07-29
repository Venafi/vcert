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

package domain

import "fmt"

var (
	// ErrNoConfig is thrown when the Playbook has no config section
	ErrNoConfig = fmt.Errorf("no config found on playbook")
	// ErrNoTasks is thrown when the Playbook has no certificates section
	ErrNoTasks = fmt.Errorf("no tasks found on playbook")
	// ErrNoInstallations is thrown when any task (item in Certificates section) has no installations defined
	ErrNoInstallations = fmt.Errorf("no installations found on certificate task")

	// ErrNoRequestZone is thrown when a certificate request is specified without a zone
	ErrNoRequestZone = fmt.Errorf("request.zone is required and was not found")
	// ErrNoRequestCN si thrown when a certificate request does not contain subject.CommonName
	ErrNoRequestCN = fmt.Errorf("request.subject.commonName is required and was not found")

	// ErrNoCredentials is thrown when the Playbook has no config section
	ErrNoCredentials = fmt.Errorf("no credentials defined on playbook")
	// ErrMultipleCredentials is thrown when the config.credentials section has both apikey and accessToken declared
	ErrMultipleCredentials = fmt.Errorf("credentials for multiple platforms set. Only one of ApiKey or AccessToken/RefreshToken pair should be declared")
	// ErrNoTPPURL is thrown when accessToken and/or refreshToken are declared in config.credentials but no url is specified
	ErrNoTPPURL = fmt.Errorf("no url defined. TPP platform requires an url to the TPP instance")
	// ErrTrustBundleNotExist is thrown when config.trustBundle is set but the path does not exist or cannot be read
	ErrTrustBundleNotExist = fmt.Errorf("trustBundle path does not exist")

	// ErrNoJKSAlias is thrown when certificates.installations[].type is JKS but no jksAlias is set
	ErrNoJKSAlias = fmt.Errorf("jksAlias should not be empty when installing a certificate in JKS format")
	// ErrNoJKSPassword is thrown when certificates.installations[].type is JKS but no jksPassword is set
	ErrNoJKSPassword = fmt.Errorf("jksPassword should not be empty when installing a certificate in JKS format")
	// ErrJKSPasswordLength is thrown when certificates.installations[].type is JKS but the jksPassword length is shorter than the minimum required
	ErrJKSPasswordLength = fmt.Errorf("jksPassword must be at least 6 characters long")

	// ErrNoChainFile is thrown when certificates.installations[].type is PEM but no pemChainFilename is set
	ErrNoChainFile = fmt.Errorf("chainFile should not be empty when installing a certificate in PEM format")
	// ErrNoKeyFile is thrown when certificates.installations[].type is PEM but no pemKeyFilename is set
	ErrNoKeyFile = fmt.Errorf("keyFile should not be empty when installing a certificate in PEM format")

	// ErrUndefinedInstallationFormat is thrown when certificates.installations[].type is unknown
	ErrUndefinedInstallationFormat = fmt.Errorf("unknown installation format specified")
	// ErrNoInstallationFile is thrown when certificates.installations[].File is not set
	ErrNoInstallationFile = fmt.Errorf("installation file not specified")

	// ErrCAPIOnNonWindows is thrown when certificates.installations[].type is CAPI but running on a non-windows build
	ErrCAPIOnNonWindows = fmt.Errorf("unable to specify CAPI installation type on non-windows system")
	// ErrMalformedCAPILocation is thrown when certificates.installations[].type is CAPI but the location is malformed
	ErrMalformedCAPILocation = fmt.Errorf("invalid CAPI location. Should be in form of 'StoreLocation\\StoreName' (i.e. 'LocalMachine\\My')")
	// ErrInvalidCAPILocation is thrown when certificates.installations[].type is CAPI but the location is malformed
	ErrInvalidCAPILocation = fmt.Errorf("invalid CAPI location. Should be either 'LocalMachine' or 'CurrentUser' (i.e. 'LocalMachine\\My')")
	// ErrInvalidCAPIStoreName is thrown when certificates.installations[].type is CAPI but the location is malformed
	ErrInvalidCAPIStoreName = fmt.Errorf("invalid CAPI store name. Should contain a valid storeName after the '\\' (i.e. 'LocalMachine\\My')")
)
