package util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/youmark/pkcs8"
)

const (
	LegacyPem = "legacy-pem"
	//nolint: gosec  // Ignoring false positive "G101 Potential hardcoded credentials"
	HeaderTpplApikey = "tppl-api-key"
	OauthTokenType   = "Bearer"
	DefaultTimeout   = 180 // seconds
)

func ConvertSecondsToTime(t int64) time.Time {
	return time.Unix(0, t*int64(time.Second))
}

func GetJsonAsString(i interface{}) (s string) {
	byte, _ := json.MarshalIndent(i, "", "  ")
	s = string(byte)
	return
}

func DecryptPkcs8PrivateKey(privateKey, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))
	key, _, err := pkcs8.ParsePrivateKey(block.Bytes, []byte(password))

	if err != nil {
		return "", err
	}

	var pemType string

	switch key.(type) {
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		pemType = "PRIVATE KEY"
	default:
		return "", fmt.Errorf("failed to determine private key type")
	}
	privateKeyBytes, err := pkcs8.MarshalPrivateKey(key, nil, nil)

	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: privateKeyBytes})

	return string(pemBytes), nil
}

func EncryptPkcs1PrivateKey(privateKey, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))

	keyType := GetPrivateKeyType(privateKey, password)
	var encrypted *pem.Block
	var err error
	if keyType == "RSA PRIVATE KEY" {
		encrypted, err = X509EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", block.Bytes, []byte(password), PEMCipherAES256)
		if err != nil {
			return "", nil
		}
	} else if keyType == "EC PRIVATE KEY" {
		encrypted, err = X509EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", block.Bytes, []byte(password), PEMCipherAES256)
		if err != nil {
			return "", nil
		}
	}
	return string(pem.EncodeToMemory(encrypted)), nil
}

func GetBooleanRef(val bool) *bool {
	return &val
}

func GetIntRef(val int) *int {
	return &val
}

func GetPrivateKeyType(pk, pass string) string {

	p, _ := pem.Decode([]byte(pk))
	if p == nil {
		return ""
	}

	var keyType string
	switch p.Type {
	case "EC PRIVATE KEY":
		keyType = "EC PRIVATE KEY"
	case "RSA PRIVATE KEY":
		keyType = "RSA PRIVATE KEY"
	default:
		keyType = ""
	}

	return keyType
}

// TODO: test this function
func ArrayContainsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func NormalizeUrl(url string) string {
	modified := strings.ToLower(url)
	reg := regexp.MustCompile("^http(|s)://")
	if reg.FindStringIndex(modified) == nil {
		modified = "https://" + modified
	} else {
		modified = reg.ReplaceAllString(modified, "https://")
	}
	if !strings.HasSuffix(modified, "/") {
		modified = modified + "/"
	}
	return modified
}

func StringPointerToString(input *string) string {
	if input != nil {
		return *input
	}
	return ""
}

func GetKeystoreOptionsString(cloudProviderID *string, cloudKeystoreID *string, cloudProviderName *string, cloudKeystoreName *string) string {
	msg := ""
	if cloudProviderID != nil {
		msg += fmt.Sprintf("Cloud Provider ID: %s, ", *cloudProviderID)
	}
	if cloudKeystoreID != nil {
		msg += fmt.Sprintf("Cloud Keystore ID: %s, ", *cloudKeystoreID)
	}
	if cloudProviderName != nil {
		msg += fmt.Sprintf("Cloud Provider Name: %s, ", *cloudProviderName)
	}
	if cloudKeystoreName != nil {
		msg += fmt.Sprintf("Cloud Keystore Name: %s", *cloudKeystoreName)
	}

	return msg
}

// GetQuotedStrings returns a string of the slice values surrounded by double quotes
// and separated by commas
func GetQuotedStrings(values []string) string {

	quotedStrings := make([]string, len(values))

	// Iterate through of each value and quote it
	for i, s := range values {
		quotedStrings[i] = strconv.Quote(s)
	}

	// Joining the quoted strings and separating them with commas
	return strings.Join(quotedStrings, ", ")
}
