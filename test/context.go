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

package test

import (
	"os"
)

type Context struct {
	TPPurl                     string
	TPPuser                    string
	TPPPassword                string
	TPPaccessToken             string
	TPPZone                    string
	TPPZoneRestricted          string
	TPPZoneECDSA               string
	TPPRefreshToken            string
	ClientID                   string
	CloudUrl                   string
	CloudAPIkey                string
	CloudZone                  string
	VAASzoneEC                 string
	CloudZoneRestricted        string
	NGTSUrl                    string
	NGTSClientID               string
	NGTSClientSecret           string
	NGTSTokenURL               string
	NGTSScope                  string
	NGTSZone                   string
	NGTSZoneRestricted         string
	NGTSCAName                 string
	NGTSDigicertCAName         string
	NGTSEntrustCAName          string
	NGTSPolicyManagementSample string
	NGTSzoneEC                 string
}

func GetEnvContext() *Context {
	//TODO: should rewrite to our standart variable names, TPPURL, TPPUSER etc
	c := &Context{}

	c.TPPurl = os.Getenv("TPP_URL")
	c.TPPuser = os.Getenv("TPP_USER")
	c.TPPPassword = os.Getenv("TPP_PASSWORD")
	c.ClientID = os.Getenv("CLIENT_ID")
	c.TPPZone = os.Getenv("TPP_ZONE")
	c.TPPZoneRestricted = os.Getenv("TPP_ZONE_RESTRICTED")
	c.TPPZoneECDSA = os.Getenv("TPP_ZONE_ECDSA")

	c.CloudUrl = os.Getenv("CLOUD_URL")
	c.CloudAPIkey = os.Getenv("CLOUD_APIKEY")
	c.CloudZone = os.Getenv("CLOUD_ZONE")
	c.VAASzoneEC = os.Getenv("VAAS_ZONE_EC")
	c.CloudZoneRestricted = os.Getenv("CLOUD_ZONE_RESTRICTED")

	c.NGTSUrl = os.Getenv("NGTS_URL")
	c.NGTSClientID = os.Getenv("NGTS_CLIENT_ID")
	c.NGTSClientSecret = os.Getenv("NGTS_CLIENT_SECRET")
	c.NGTSTokenURL = os.Getenv("NGTS_TOKEN_URL")
	c.NGTSScope = os.Getenv("NGTS_SCOPE")
	c.NGTSZone = os.Getenv("NGTS_ZONE")
	c.NGTSZoneRestricted = os.Getenv("NGTS_ZONE_RESTRICTED")
	c.NGTSCAName = os.Getenv("NGTS_CA_NAME")
	c.NGTSDigicertCAName = os.Getenv("NGTS_DIGICERT_CA_NAME")
	c.NGTSEntrustCAName = os.Getenv("NGTS_ENTRUST_CA_NAME")
	c.NGTSPolicyManagementSample = os.Getenv("NGTS_POLICY_MANAGEMENT_SAMPLE")
	c.NGTSzoneEC = os.Getenv("NGTS_ZONE_EC")

	return c
}
