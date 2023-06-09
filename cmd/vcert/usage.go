/*
 * Copyright 2018-2021 Venafi, Inc.
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
				// nolint: errcheck
				space.WriteTo(buf)
				space.Reset()
				// nolint: errcheck
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
			// nolint: errcheck
			space.WriteTo(buf)
		}
	} else {
		// nolint: errcheck
		space.WriteTo(buf)
		// nolint: errcheck
		word.WriteTo(buf)
	}

	return buf.String()
}

func showvcertUsage() {
	fmt.Printf("\tTo obtain a new token for authentication, use the 'getcred' action.\n")
	fmt.Printf("\tTo check whether an authentication token is valid, use the 'checkcred' action.\n")
	fmt.Printf("\tTo invalidate an authentication token, use the 'voidcred' action.\n")
	fmt.Printf("\tTo generate a certificate signing request (CSR), use the 'gencsr' action.\n")
	fmt.Printf("\tTo enroll a certificate, use the 'enroll' action.\n")
	fmt.Printf("\tTo retrieve a certificate, use the 'pickup' action.\n")
	fmt.Printf("\tTo renew a certificate, use the 'renew' action.\n")
	fmt.Printf("\tTo revoke a certificate, use the 'revoke' action.\n")
	fmt.Printf("\tTo retire a certificate, use the 'retire' action.\n")
	fmt.Printf("\tTo retrieve certificate policy, use the 'getpolicy' action.\n")
	fmt.Printf("\tTo apply certificate policy, use the 'setpolicy' action.\n")
}
