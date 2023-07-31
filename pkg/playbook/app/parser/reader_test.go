/*
 * Copyright 2023 Venafi, Inc.
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

package parser

import (
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type ReaderSuite struct {
	suite.Suite
	errorTestCases []struct {
		name     string
		location string
		err      error
	}
	playbookFolder string
	accessToken    string
	refreshToken   string
	server         http.Server
}

func (s *ReaderSuite) SetupTest() {
	s.playbookFolder = "../../../../test-files/playbook"
	s.accessToken = RandomString(12)
	s.refreshToken = RandomString(12)

	s.errorTestCases = []struct {
		name     string
		location string
		err      error
	}{
		{
			name:     "NoLocation",
			location: "",
			err:      ErrNoLocation,
		},
		{
			name:     "ReadFileFail",
			location: filepath.Join(s.playbookFolder, "foo.yml"),
			err:      ErrReadFile,
		},
		{
			name:     "TemplateParsingFail",
			location: filepath.Join(s.playbookFolder, "bad_tpl.yaml"),
			err:      ErrTextTplParsing,
		},
		{
			name:     "UnmarshallFail",
			location: filepath.Join(s.playbookFolder, "bad_sample.yaml"),
			err:      ErrFileUnmarshall,
		},
	}

	err := os.Setenv("TPP_ACCESS_TOKEN", s.accessToken)
	s.Nil(err)
	err = os.Setenv("TPP_REFRESH_TOKEN", s.refreshToken)
	s.Nil(err)
}

func TestReader(t *testing.T) {
	suite.Run(t, new(ReaderSuite))
}

func (s *ReaderSuite) TestReader_ReadPlaybook() {
	s.Run("LocalFile", func() {
		pb, err := ReadPlaybook(filepath.Join(s.playbookFolder, "sample.yaml"))
		s.Nil(err)
		s.NotNil(pb)
		s.NotEmpty(pb.CertificateTasks)
	})
}

func (s *ReaderSuite) TestReader_ReadPlaybookTpl() {
	pb, err := ReadPlaybook(filepath.Join(s.playbookFolder, "sample_tpl.yaml"))
	s.Nil(err)
	s.NotNil(pb)
	s.NotEmpty(pb.CertificateTasks)
	s.Equal(s.accessToken, pb.Config.Connection.Credentials.AccessToken)
	s.Equal(s.refreshToken, pb.Config.Connection.Credentials.RefreshToken)

}

func (s *ReaderSuite) TestReader_ReadPlaybookRaw() {
	dataMap, err := ReadPlaybookRaw(filepath.Join(s.playbookFolder, "sample_tpl.yaml"))
	s.Nil(err)
	s.NotNil(dataMap)
	accessTokenTpl := "{{ Env \"TPP_ACCESS_TOKEN\" }}"
	refreshTokenTpl := "{{ Env \"TPP_REFRESH_TOKEN\" }}"
	s.Equal(accessTokenTpl, dataMap["config"].(map[string]interface{})["connection"].(map[string]interface{})["credentials"].(map[string]interface{})["accessToken"])
	s.Equal(refreshTokenTpl, dataMap["config"].(map[string]interface{})["connection"].(map[string]interface{})["credentials"].(map[string]interface{})["refreshToken"])
}

func (s *ReaderSuite) TestReader_Errors() {
	for _, tc := range s.errorTestCases {
		s.Run(tc.name, func() {
			_, err := ReadPlaybook(tc.location)
			s.NotNil(err)
			s.ErrorIs(err, tc.err)
		})
	}
}

func RandomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
