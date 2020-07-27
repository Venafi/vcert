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

package main

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"io/ioutil"
	"log"
	"os"
)

var mockConfig, cloudConfig, tppConfig *vcert.Config

func init() {
	mockConfig = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeFake,
	}

	cloudConfig = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       os.Getenv("CLOUD_URL"),
		Credentials:   &endpoint.Authentication{APIKey: os.Getenv("CLOUD_APIKEY")},
		Zone:          os.Getenv("CLOUD_ZONE"),
	}

	tppConfig = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       os.Getenv("TPP_URL"),
		Credentials: &endpoint.Authentication{
			User:     os.Getenv("TPP_USER"),
			Password: os.Getenv("TPP_PASSWORD")},
		Zone: os.Getenv("TPP_ZONE"),
	}
	trustBundleFilePath := os.Getenv("TRUST_BUNDLE_PATH")
	if trustBundleFilePath != "" {
		buf, err := ioutil.ReadFile(trustBundleFilePath)
		if err != nil {
			panic(err)
		}
		tppConfig.ConnectionTrust = string(buf)
	}

}

var pp = func(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	log.Println(string(b))
}
