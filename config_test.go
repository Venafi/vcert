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

package vcert

import (
	"io/ioutil"
	"os"
	"testing"
)

const validTestModeConfig = `
test_mode = true`

const invalidTestModeConfig = `
test_mode = false`

const validTPPConfigDeprecated = `# all fine here
tpp_url = https://ha-tpp1.example.com:5008/vedsdk
tpp_user = admin
tpp_password = xxx
tpp_zone = devops\vcert`

const validTPPConfig = `# all fine here
url = https://ha-tpp1.example.com:5008/vedsdk
access_token = ns1dofUPmsdxTLQS2hM1gQ==
tpp_zone = devops\vcert`

const emptyConfig = ``

const invalidTPPConfig = `# cloud zone cannot be used in TPP section
url = https://ha-tpp1.example.com:5008/vedsdk
access_token = ns1dofUPmsdxTLQS2hM1gQ==
tpp_zone = devops\vcert
cloud_zone = Default`

const invalidTPPConfig2 = `# missing password
url = https://ha-tpp1.example.com:5008/vedsdk
tpp_user = admin
#tpp_password = xxx
tpp_zone = devops\vcert`

const invalidTPPConfig3 = `# trust bundle cannot be loaded
url = https://ha-tpp1.example.com:5008/vedsdk
access_token = ns1dofUPmsdxTLQS2hM1gQ==
tpp_zone = devops\vcert
trust_bundle = ~/.vcert/file.does-not-exist`

const validCloudConfig = `
url = https://api.dev12.qa.venafi.io/v1
cloud_apikey = xxxxxxxx-b256-4c43-a4d4-15372ce2d548
cloud_zone = Default`

const validCloudConfig2 = `
cloud_apikey = xxxxxxxx-b256-4c43-a4d4-15372ce2d548`

const invalidCloudConfig = `# tpp user is illegal
url = https://api.dev12.qa.venafi.io/v1
cloud_apikey = xxxxxxxx-b256-4c43-a4d4-15372ce2d548
tpp_user = admin
cloud_zone = Default`

const validNgtsConfig1 = `
url = https://xyz.api.sase.paloaltonetworks.com/ngts
ngts_token_url = https://xyz.test.appsvc.paloaltonetworks.com/auth/v1/test2/access_token
ngts_scope = tsg_id:0123456789
ngts_client_id = test_client_id
ngts_client_secret = 1234d146-0ccc-11b2-001b-a111aa11a11a
ngts_zone = test\vcert
`

const validNgtsConfig2 = `
url = https://xyz.api.sase.paloaltonetworks.com/ngts
ngts_access_token = test_access_token
ngts_zone = test\vcert
`

// no token url
const invalidNgtsConfig = `
url = https://xyz.api.sase.paloaltonetworks.com/ngts
ngts_scope = tsg_id:0123456789
ngts_client_id = test_client_id
ngts_client_secret = 1234d146-0ccc-11b2-001b-a111aa11a11a
ngts_zone = test\vcert
`

// no access token and client id
const invalidNgtsConfig2 = `
url = https://xyz.api.sase.paloaltonetworks.com/ngts
ngts_scope = tsg_id:0123456789
ngts_client_secret = 1234d146-0ccc-11b2-001b-a111aa11a11a
ngts_zone = test\vcert
`

// no access token and client secret
const invalidNgtsConfig3 = `
url = https://xyz.api.sase.paloaltonetworks.com/ngts
ngts_scope = tsg_id:0123456789
ngts_client_id = test_client_id
ngts_zone = test\vcert
`

func TestLoadFromFile(t *testing.T) {
	var cases = []struct {
		valid   bool
		content string
	}{
		{true, validTestModeConfig},
		{true, validTPPConfig},
		{true, validTPPConfigDeprecated},
		{true, validCloudConfig},
		{true, validCloudConfig},
		{true, validCloudConfig2},
		{false, emptyConfig},
		{false, invalidTestModeConfig},
		{false, invalidTPPConfig},
		{false, invalidTPPConfig2},
		{false, invalidTPPConfig3},
		{false, invalidCloudConfig},
		{true, validNgtsConfig1},
		{true, validNgtsConfig2},
		{false, invalidNgtsConfig},
		{false, invalidNgtsConfig2},
		{false, invalidNgtsConfig3},
	}
	for _, test_case := range cases {
		tmpfile, err := ioutil.TempFile("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		err = ioutil.WriteFile(tmpfile.Name(), []byte(test_case.content), 0644)
		if err != nil {
			t.Fatal(err)
		}

		_, err = LoadConfigFromFile(tmpfile.Name(), "")
		if test_case.valid {
			if err != nil {
				t.Logf("config: %s", test_case.content)
				t.Fatal(err)
			}
		} else {
			if err == nil {
				t.Fatalf("it should fail to load config: \n%s", test_case.content)
			}
		}
	}
}
