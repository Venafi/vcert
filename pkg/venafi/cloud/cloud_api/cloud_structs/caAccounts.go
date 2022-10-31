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

// RESP: GET outagedetection/v1/certificateauthorities/%s/accounts
type CaAccounts struct {
	Accounts []CaAccount `json:"accounts"`
}

// RESP: GET outagedetection/v1/certificateauthorities/%s/accounts/%s
type CaAccount struct {
	Account       Account         `json:"account"`
	ProductOption []ProductOption `json:"productOptions"`
}

type Account struct {
	Id                   string `json:"id"`
	Key                  string `json:"Key"`
	CertificateAuthority string `json:"certificateAuthority"`
}

type ProductOption struct {
	ProductName    string         `json:"productName"`
	Id             string         `json:"id"`
	ProductDetails ProductDetails `json:"productDetails"`
}

type ProductDetails struct {
	ProductTemplate ProductTemplate `json:"productTemplate"`
}

type ProductTemplate struct {
	OrganizationId int64 `json:"organizationId"`
}
