/*
 * Copyright 2018 Venafi, Inc.
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

package test

import (
	"os"
)

type Context struct {
	TPPurl            string
	TPPuser           string
	TPPPassword       string
	TPPaccessToken    string
	TPPZone           string
	TPPZoneRestricted string
	TPPRefreshToken   string
	ClientID          string
	CloudUrl          string
	CloudAPIkey       string
	CloudZone         string
}

func GetEnvContext() *Context {
	//TODO: should rewrite to our standart variable names, TPPURL, TPPUSER etc
	c := &Context{}

	c.TPPurl = os.Getenv("VCERT_TPP_URL")
	c.TPPuser = os.Getenv("VCERT_TPP_USER")
	c.TPPPassword = os.Getenv("VCERT_TPP_PASSWORD")
	c.ClientID = os.Getenv("CLIENT_ID")
	c.TPPZone = os.Getenv("VCERT_TPP_ZONE")
	c.TPPZoneRestricted = os.Getenv("TPPZONE_RESTRICTED")

	c.CloudUrl = os.Getenv("VCERT_CLOUD_URL")
	c.CloudAPIkey = os.Getenv("VCERT_CLOUD_APIKEY")
	c.CloudZone = os.Getenv("VCERT_CLOUD_ZONE")

	return c
}
