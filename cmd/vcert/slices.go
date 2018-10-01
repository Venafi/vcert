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
	"fmt"
	"net"
)

type stringSlice []string

func (ss *stringSlice) String() string {
	var ret string
	for _, s := range *ss {
		ret += fmt.Sprintf("%s\n", s)
	}
	return ret
}

func (ss *stringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

const emailRegex = "[[:alnum:]][\\w\\.-]*[[:alnum:]]@[[:alnum:]][\\w\\.-]*[[:alnum:]]\\.[[:alpha:]][a-z\\.]*[[:alpha:]]$"

type emailSlice []string

func (es *emailSlice) String() string {
	var ret string
	for _, s := range *es {
		ret += fmt.Sprintf("%s\n", s)
	}
	return ret
}

func (es *emailSlice) Set(value string) error {
	if isValidEmailAddress(value) {
		*es = append(*es, value)
		return nil
	}
	return fmt.Errorf("Failed to convert %s to an Email Address", value)
}

type ipSlice []net.IP

func (is *ipSlice) String() string {
	var ret string
	for _, s := range *is {
		ret += fmt.Sprintf("%s\n", s)
	}
	return ret
}

func (is *ipSlice) Set(value string) error {
	temp := net.ParseIP(value)
	if temp != nil {
		*is = append(*is, temp)
		return nil
	}
	return fmt.Errorf("Failed to convert %s to an IP Address", value)
}
