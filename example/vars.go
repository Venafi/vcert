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
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"log"
	"os"
)

var mockConfig = &vcert.Config{
	ConnectorType: endpoint.ConnectorTypeFake,
}
var cloudConfig = &vcert.Config{
	ConnectorType: endpoint.ConnectorTypeCloud,
	BaseUrl:       os.Getenv("VCERT_CLOUD_URL"),
	Credentials:   &endpoint.Authentication{APIKey: os.Getenv("VCERT_CLOUD_APIKEY")},
	Zone:          os.Getenv("VCERT_CLOUD_ZONE"),
}
var tppConfig = &vcert.Config{
	ConnectorType: endpoint.ConnectorTypeTPP,
	BaseUrl:       os.Getenv("VCERT_TPP_URL"),
	Credentials: &endpoint.Authentication{
		User:     os.Getenv("VCERT_TPP_USER"),
		Password: os.Getenv("VCERT_TPP_PASSWORD")},
	Zone: os.Getenv("VCERT_TPP_ZONE"),
}

var pp = func(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	log.Println(string(b))
}
