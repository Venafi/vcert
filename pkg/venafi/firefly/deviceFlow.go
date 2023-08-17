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

package firefly

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/verror"
	"golang.org/x/oauth2"
)

// DeviceCred It's the representation of the info returned when a Device Code is requested
// to the OAuth 2.0 Identity Provider to request an access code
type DeviceCred struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"` //Google use this to return the URL to share to the user
	VerificationURI string `json:"verification_uri"` // others like Okta, Auth0 and WSO2 use this one to return the URI to share to the user
	Interval        int64  `json:"interval"`
	ExpiresIn       int64  `json:"expires_in"`
}

func (c *Connector) getDeviceAccessToken(auth *endpoint.Authentication) (token *oauth2.Token, err error) {

	//requesting the device code
	devCred, err := c.requestDeviceCode(auth)

	if err != nil {
		return
	}

	//setting as default verificationURL the value returned in VerificationURI given that is the used for the most of the
	// OAuth IdP like Okta, Auth0 and WSO2 return the verification_uri to show to the user
	verificationURL := devCred.VerificationURI
	//if that is empty then trying to use the VerificationURL given google uses verification_url to
	//return the verification_uri to show to the user
	if verificationURL == "" {
		verificationURL = devCred.VerificationURL
	}

	fmt.Printf("Please open de following URL in your web browser:\n\n%v\n\n and then enter the code:\n\n%v\n\nIt will expire in %dm and %ds\n\n", verificationURL, devCred.UserCode, devCred.ExpiresIn/60, devCred.ExpiresIn%60)

	//waiting for the user authorization
	token, err = c.waitForDeviceAuthorization(devCred, auth)
	if err == nil {
		fmt.Println("Successfully authorized device.")
	}
	return
}

func (c *Connector) requestDeviceCode(auth *endpoint.Authentication) (*DeviceCred, error) {
	data := url.Values{
		"client_id": {auth.ClientId},
	}

	//There are IdPs like Okta and Auth0 which provides the support for default scopes, so it's possible for
	//these that the scope is empty
	if auth.Scope != "" {
		data.Add("scope", auth.Scope)
	}

	//audience is only supported by Okta and Auth0
	if auth.IdentityProvider.Audience != "" {
		data.Add("audience", auth.IdentityProvider.Audience)
	}

	statusCode, status, body, err := c.request("POST", urlResource(auth.IdentityProvider.DeviceURL), data)

	if err != nil {
		return nil, err
	}
	//parsing the response
	return parseDeviceCodeRequestResult(statusCode, status, body)
}

func parseDeviceCodeRequestResult(httpStatusCode int, httpStatus string, body []byte) (*DeviceCred, error) {
	switch httpStatusCode {
	case http.StatusOK:
		return parseDeviceCodeRequestData(body)
	default:
		respError, err := NewResponseError(body)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("unexpected status code requesting Device Code. Status: %s error: %w", httpStatus, respError)
	}
}

func parseDeviceCodeRequestData(b []byte) (*DeviceCred, error) {
	var data DeviceCred
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &data, nil
}

func (c *Connector) waitForDeviceAuthorization(devCred *DeviceCred, auth *endpoint.Authentication) (*oauth2.Token, error) {

	data := url.Values{"client_id": {auth.ClientId},
		"device_code": {devCred.DeviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	// Google requires the client-secret also to request the accessToken
	if auth.ClientSecret != "" {
		data.Add("client_secret", auth.ClientSecret)
	}

	//polling the authorization
	for {
		//requesting the authorization
		statusCode, _, body, err := c.request("POST", urlResource(auth.IdentityProvider.TokenURL), data)
		if err != nil {
			return nil, err
		}

		//parsing the response
		token, err := parseWaitingDeviceAuthorizationRequestResult(statusCode, body)

		//if there is not any error, then the token was gotten
		if err == nil {
			return token, err
		}

		//verifying the error gotten
		switch GetDevAuthStatus(err.Error()) {
		case AuthorizationPending:
			time.Sleep(time.Duration(devCred.Interval) * time.Second)
		case SlowDown:
			devCred.Interval += 5
			time.Sleep(time.Duration(devCred.Interval) * time.Second)
		case AccessDenied:
			return nil, fmt.Errorf("the access from device was denied by the user")
		case ExpiredToken:
			return nil, fmt.Errorf("the device code expired")
		default:
			return nil, fmt.Errorf("the authorization failed. %w", err)
		}
	}
}

func parseWaitingDeviceAuthorizationRequestResult(httpStatusCode int, body []byte) (*oauth2.Token, error) {
	switch httpStatusCode {
	case http.StatusOK:
		//Based on the oauth2.internal.tokenJSON which complains the
		// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
		type jsonToken struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type,omitempty"`
			RefreshToken string `json:"refresh_token,omitempty"`
			ExpiresIn    int32  `json:"expires_in,omitempty"`
			Scope        string `json:"scope,omitempty"`
		}

		var data jsonToken
		err := json.Unmarshal(body, &data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
		}

		//creating an oauth2.Token and matching it with the deviceAccessToken gotten
		token := oauth2.Token{
			AccessToken:  data.AccessToken,
			TokenType:    data.TokenType,
			RefreshToken: data.RefreshToken,
		}

		if data.ExpiresIn > 0 {
			token.Expiry = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)
		}

		return &token, nil
	default:
		respError, err := NewResponseError(body)
		if err != nil {
			return nil, err
		}

		return nil, respError
	}
}
