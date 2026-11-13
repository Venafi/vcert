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

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSignAWSRequestMatchesTheAWSExample signs the example request from the
// AWS Signature Version 4 documentation and compares with its signature
func TestSignAWSRequestMatchesTheAWSExample(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signAWSRequest(req, nil, "us-east-1", "iam", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("unexpected Authorization header\n got: %s\nwant: %s", got, want)
	}
}

func TestDeleteACMCertificate(t *testing.T) {
	var target, body, auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target = r.Header.Get("X-Amz-Target")
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		if strings.Contains(body, "missing") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"not found"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c := newCloudCleaner()
	var region string
	c.acmEndpoint = func(r string) string { region = r; return server.URL }

	arn := "arn:aws:acm:us-east-2:123456789012:certificate/abc"
	if err := c.deleteACMCertificate(arn, "AKIA1", "secret"); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if region != "us-east-2" || target != "CertificateManager.DeleteCertificate" || body != `{"CertificateArn":"`+arn+`"}` {
		t.Fatalf("unexpected request: region %s, target %s, body %s", region, target, body)
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIA1/") || !strings.Contains(auth, "/us-east-2/acm/aws4_request") {
		t.Fatalf("unexpected Authorization header %s", auth)
	}

	// a certificate that is already gone counts as deleted
	if err := c.deleteACMCertificate("arn:aws:acm:us-east-2:123456789012:certificate/missing", "AKIA1", "secret"); err != nil {
		t.Fatalf("unexpected error for a missing certificate: %s", err)
	}
	if err := c.deleteACMCertificate("not-an-arn", "AKIA1", "secret"); err == nil {
		t.Fatalf("expected an error for an invalid ARN")
	}
}

func TestDeleteAzureCertificateDeletesAndPurges(t *testing.T) {
	var calls []string
	purgeAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("scope") != "https://vault.azure.net/.default" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
			return
		case r.Header.Get("Authorization") != "Bearer tok":
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasPrefix(r.URL.Path, "/vault/certificates/"):
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/vault/deletedcertificates/"):
			// the deletion is still in progress for the first attempt
			purgeAttempts++
			if purgeAttempts == 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	c := newCloudCleaner()
	c.azureLoginURL = server.URL
	c.keyVaultURL = func(vault string) string { return server.URL + "/" + vault }
	c.purgeRetryInterval = time.Millisecond

	if err := c.deleteAzureCertificate("vault", "cert-1", "tenant", "app", "s3cret"); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	want := []string{"DELETE /vault/certificates/cert-1", "DELETE /vault/deletedcertificates/cert-1", "DELETE /vault/deletedcertificates/cert-1"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected calls %v", calls)
	}

	if err := c.deleteAzureCertificate("vault", "cert-1", "tenant", "app", "wrong"); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected a token error, got %v", err)
	}
}
