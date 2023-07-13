/*
 * Copyright 2022 Venafi, Inc.
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

package cloud_structs

import (
	"time"
)

// RESP: GET outagedetection/v1/users/%s
type User struct {
	Username           string    `json:"username,omitempty"`
	ID                 string    `json:"id,omitempty"`
	CompanyID          string    `json:"companyId,omitempty"`
	EmailAddress       string    `json:"emailAddress,omitempty"`
	UserType           string    `json:"userType,omitempty"`
	UserAccountType    string    `json:"userAccountType,omitempty"`
	UserStatus         string    `json:"userStatus,omitempty"`
	CreationDateString string    `json:"creationDate,omitempty"`
	CreationDate       time.Time `json:"-"`
}

// RESP: GET outagedetection/v1/users/username/%s
type Users struct {
	Users []User `json:"users"`
}

// REQ: POST outagedetection/v1/useraccounts
type UserAccount struct {
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Firstname       string `json:"firstname,omitempty"`
	Lastname        string `json:"lastname,omitempty"`
	CompanyID       string `json:"companyId,omitempty"`
	CompanyName     string `json:"companyName,omitempty"`
	UserAccountType string `json:"userAccountType,omitempty"`
}

// RESP: GET outagedetection/v1/useraccounts
// RESP: POST outagedetection/v1/useraccounts
type UserDetails struct {
	User    *User    `json:"user,omitempty"`
	Company *company `json:"company,omitempty"`
	APIKey  *apiKey  `json:"apiKey,omitempty"`
}

type company struct {
	ID                 string    `json:"id,omitempty"`
	Name               string    `json:"name,omitempty"`
	CompanyType        string    `json:"companyType,omitempty"`
	Active             bool      `json:"active,omitempty"`
	CreationDateString string    `json:"creationDate,omitempty"`
	CreationDate       time.Time `json:"-"`
	Domains            []string  `json:"domains,omitempty"`
}

type apiKey struct {
	Key                     string    `json:"key,omitempty"`
	UserID                  string    `json:"userId,omitempty"`
	Username                string    `json:"username,omitempty"`
	CompanyID               string    `json:"companyId,omitempty"`
	APITypes                []string  `json:"apitypes,omitempty"`
	APIVersion              string    `json:"apiVersion,omitempty"`
	APIKeyStatus            string    `json:"apiKeyStatus,omitempty"`
	CreationDateString      string    `json:"creationDate,omitempty"`
	CreationDate            time.Time `json:"-"`
	ValidityStartDateString string    `json:"validityStartDate,omitempty"`
	ValidityStartDate       time.Time `json:"-"`
	ValidityEndDateString   string    `json:"validityEndDate,omitempty"`
	ValidityEndDate         time.Time `json:"-"`
}

// RESP: GET outagedetection/v1/teams
type Teams struct {
	Teams []team `json:"teams"`
}

type team struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CompanyID string `json:"companyId"`
}
