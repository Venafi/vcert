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
	"bytes"
	"fmt"
	"os"
	"unicode"
)

func wrapArgumentDescriptionText(text string) string {
	const limit = 80
	buf := bytes.NewBuffer(make([]byte, 0, len(text)))

	var (
		current int
		word    bytes.Buffer
		space   bytes.Buffer
	)

	for _, char := range text {
		if unicode.IsSpace(char) {
			if space.Len() == 0 || word.Len() > 0 {
				current += space.Len() + word.Len()
				space.WriteTo(buf)
				space.Reset()
				word.WriteTo(buf)
				word.Reset()
			}

			space.WriteRune(char)
		} else {

			word.WriteRune(char)

			if current+space.Len()+word.Len() > limit && word.Len() < limit {
				buf.WriteRune('\n')
				buf.WriteRune('\t')
				current = 0
				space.Reset()
			}
		}
	}

	if word.Len() == 0 {
		if current+space.Len() <= limit {
			space.WriteTo(buf)
		}
	} else {
		space.WriteTo(buf)
		word.WriteTo(buf)
	}

	return buf.String()
}

func showvcertUsage() {
	fmt.Printf("%s\n", GetFormattedVersionString())
	fmt.Printf("\tTo gain access to the Venafi Cloud service, use the 'register' action.\n")
	fmt.Printf("\tTo generate a certificate signing request (CSR), use the 'gencsr' action.\n")
	fmt.Printf("\tTo enroll a certificate, use the 'enroll' action.\n")
	fmt.Printf("\tTo retrieve a certificate, use the 'pickup' action.\n")
	fmt.Printf("\tTo renew a certificate, use the 'renew' action.\n")
	fmt.Printf("\tTo revoke a certificate, use the 'revoke' action.\n")
	fmt.Printf("\tFor additional help run '%s <action> -h'\n\n", os.Args[0])
}
