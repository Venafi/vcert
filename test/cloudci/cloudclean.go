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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Deleting the certificates the tests provisioned from the cloud. This uses the
// cloud REST APIs directly, so that vcert does not depend on the cloud SDKs.

// cloudCleaner deletes certificates from AWS Certificate Manager and Azure Key
// Vault. The endpoint fields default to the public cloud endpoints and can be
// pointed at test servers.
type cloudCleaner struct {
	client *http.Client
	now    func() time.Time
	// acmEndpoint returns the ACM endpoint of a region
	acmEndpoint func(region string) string
	// azureLoginURL is the Azure AD endpoint the token is requested from
	azureLoginURL string
	// keyVaultURL returns the URL of a key vault
	keyVaultURL func(vault string) string
	// purgeRetryInterval is the wait between attempts to purge a certificate
	// that is still being deleted
	purgeRetryInterval time.Duration
}

func newCloudCleaner() *cloudCleaner {
	return &cloudCleaner{
		client:             &http.Client{Timeout: 30 * time.Second},
		now:                time.Now,
		acmEndpoint:        func(region string) string { return "https://acm." + region + ".amazonaws.com" },
		azureLoginURL:      "https://login.microsoftonline.com",
		keyVaultURL:        func(vault string) string { return "https://" + vault + ".vault.azure.net" },
		purgeRetryInterval: 3 * time.Second,
	}
}

// deleteACMCertificate deletes a certificate from AWS Certificate Manager. A
// certificate that no longer exists counts as deleted.
func (c *cloudCleaner) deleteACMCertificate(arn string, accessKeyID string, secretAccessKey string) error {
	region, err := regionFromARN(arn)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"CertificateArn": arn})
	endpoint := c.acmEndpoint(region)
	req, err := http.NewRequest(http.MethodPost, endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "CertificateManager.DeleteCertificate")
	signAWSRequest(req, body, region, "acm", accessKeyID, secretAccessKey, c.now())

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot delete ACM certificate %s: %w", arn, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if strings.Contains(string(respBody), "ResourceNotFoundException") {
		return nil
	}
	return fmt.Errorf("cannot delete ACM certificate %s: HTTP %d: %s", arn, resp.StatusCode, strings.TrimSpace(string(respBody)))
}

func regionFromARN(arn string) (string, error) {
	// arn:aws:acm:<region>:<account>:certificate/<id>
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[3] == "" {
		return "", fmt.Errorf("not a certificate ARN: %q", arn)
	}
	return parts[3], nil
}

// signAWSRequest signs a request with AWS Signature Version 4, as described in
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
func signAWSRequest(req *http.Request, payload []byte, region string, service string, accessKeyID string, secretAccessKey string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	headers := map[string]string{"host": req.Host}
	for name, values := range req.Header {
		headers[strings.ToLower(name)] = strings.TrimSpace(strings.Join(values, ","))
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		path,
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		hexSHA256(payload),
	}, "\n")

	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hexSHA256([]byte(canonicalRequest))

	key := hmacSHA256([]byte("AWS4"+secretAccessKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, scope, signedHeaders, signature))
}

func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vs := append([]string(nil), values[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsEscape(k)+"="+awsEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func awsEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// deleteAzureCertificate deletes a certificate from an Azure key vault and
// purges it, so that it does not stay in the vault's deleted certificates for
// the retention period. A certificate that no longer exists counts as deleted.
func (c *cloudCleaner) deleteAzureCertificate(vault string, name string, tenantID string, clientID string, clientSecret string) error {
	token, err := c.azureToken(tenantID, clientID, clientSecret)
	if err != nil {
		return err
	}
	base := c.keyVaultURL(vault)

	status, body, err := c.azureRequest(http.MethodDelete, base+"/certificates/"+url.PathEscape(name)+"?api-version=7.4", token)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("cannot delete certificate %s from key vault %s: HTTP %d: %s", name, vault, status, body)
	}

	// The deletion completes asynchronously; until then purging returns a
	// conflict, or not found while the deleted certificate is not listed yet
	purgeURL := base + "/deletedcertificates/" + url.PathEscape(name) + "?api-version=7.4"
	for attempt := 1; ; attempt++ {
		status, body, err = c.azureRequest(http.MethodDelete, purgeURL, token)
		if err != nil {
			return err
		}
		switch {
		case status == http.StatusNoContent || status == http.StatusOK:
			return nil
		case (status == http.StatusConflict || status == http.StatusNotFound) && attempt < 10:
			time.Sleep(c.purgeRetryInterval)
		case status == http.StatusNotFound:
			// never listed as deleted: it did not exist, or the vault does not
			// keep deleted certificates
			return nil
		default:
			return fmt.Errorf("cannot purge certificate %s from key vault %s: HTTP %d: %s", name, vault, status, body)
		}
	}
}

func (c *cloudCleaner) azureToken(tenantID string, clientID string, clientSecret string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://vault.azure.net/.default"},
	}
	resp, err := c.client.PostForm(c.azureLoginURL+"/"+url.PathEscape(tenantID)+"/oauth2/v2.0/token", form)
	if err != nil {
		return "", fmt.Errorf("cannot get an Azure token for app %s: %w", clientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var token struct {
		AccessToken      string `json:"access_token"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&token)
	if resp.StatusCode != http.StatusOK || token.AccessToken == "" {
		return "", fmt.Errorf("cannot get an Azure token for app %s: HTTP %d: %s", clientID, resp.StatusCode, token.ErrorDescription)
	}
	return token.AccessToken, nil
}

func (c *cloudCleaner) azureRequest(method string, target string, token string) (int, string, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}
